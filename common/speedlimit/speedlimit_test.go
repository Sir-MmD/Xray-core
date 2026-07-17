package speedlimit

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// write replaces the sidecar and moves its mtime forward, so that a reload is
// detected deterministically rather than depending on clock granularity.
func write(t *testing.T, path, body string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Add(age)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func newTestTable(t *testing.T, body string) (*table, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "speedlimits.json")
	write(t, path, body, 0)
	tb := &table{path: path}
	tb.reloadIfChanged()
	return tb, path
}

// sample mirrors the panel writer's real output: every ips entry is CIDR (bare
// addresses are widened to /32 before they are written), and an account with no
// IPs serializes an empty array rather than null.
const sample = `{"users":[
	{"email":"a@x","downBps":655360,"upBps":262144,"ips":["10.0.0.5/32","10.7.8.8/29"]},
	{"email":"b@x","downBps":1310720,"upBps":0,"ips":["10.9.0.0/24"]},
	{"email":"native@x","downBps":100,"upBps":100,"ips":[]}
]}`

// TestEnvUnsetDisabled pins the default: with XRAY_SPEEDLIMIT_FILE unset the
// package never builds a table, so the core behaves exactly as stock Xray. The
// test binary's init ran without the variable, so this asserts the real state.
func TestEnvUnsetDisabled(t *testing.T) {
	if os.Getenv(EnvPath) != "" {
		t.Skip("XRAY_SPEEDLIMIT_FILE is set in the environment")
	}
	if defaultTable != nil {
		t.Fatal("expected no table when the env var is unset")
	}
	if l := LookupSession(nil, nil); l != nil {
		t.Fatal("expected nil limits when disabled")
	}
}

func TestLookup(t *testing.T) {
	tb, _ := newTestTable(t, sample)

	cases := []struct {
		name  string
		email string
		ip    string
		want  string // "" means expect nil
	}{
		{"exact /32", "", "10.0.0.5", "a@x"},
		{"cidr /29 first host", "", "10.7.8.8", "a@x"},
		{"cidr /29 last host", "", "10.7.8.15", "a@x"},
		{"cidr /24", "", "10.9.0.77", "b@x"},
		{"unknown ip", "", "192.0.2.1", ""},
		{"ip just past /29", "", "10.7.8.16", ""},
		{"email wins, no ip needed", "native@x", "", "native@x"},
		{"unlimited email is a miss", "nobody@x", "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ip net.IP
			if c.ip != "" {
				ip = net.ParseIP(c.ip)
			}
			got := tb.lookup(c.email, ip)
			if c.want == "" {
				if got != nil {
					t.Fatalf("want nil, got limits")
				}
				return
			}
			if got == nil {
				t.Fatalf("want %s, got nil", c.want)
			}
			if got != tb.idx.byEmail[c.want] {
				t.Fatalf("resolved to the wrong account, want %s", c.want)
			}
		})
	}
}

// TestLookupIPv4In16Byte guards the unmap step: net.ParseIP hands back IPv4 in
// 16-byte v4-in-v6 form, which netip.Prefix.Contains refuses to compare against
// a 32-bit prefix.
func TestLookupIPv4In16Byte(t *testing.T) {
	tb, _ := newTestTable(t, sample)
	ip := net.ParseIP("10.0.0.5").To16()
	if len(ip) != 16 {
		t.Fatal("expected a 16-byte representation")
	}
	if tb.lookup("", ip) == nil {
		t.Fatal("16-byte IPv4 failed to match a /32")
	}
}

// TestReloadRerates is the core of the hot-reload contract: an open connection
// holds the *rate.Limiter, so a reload must re-rate it in place rather than
// swap in a new one.
func TestReloadRerates(t *testing.T) {
	tb, path := newTestTable(t, sample)

	before := tb.lookup("", net.ParseIP("10.0.0.5"))
	if before == nil {
		t.Fatal("setup: no limits for a@x")
	}
	if got := before.Down.Limit(); got != rate.Limit(655360) {
		t.Fatalf("down limit = %v, want 655360", got)
	}
	if got := before.Up.Limit(); got != rate.Limit(262144) {
		t.Fatalf("up limit = %v, want 262144", got)
	}
	downLimiter := before.Down

	write(t, path, `{"users":[{"email":"a@x","downBps":1000,"upBps":0,"ips":["10.0.0.5/32"]}]}`, time.Second)
	tb.reloadIfChanged()

	after := tb.lookup("", net.ParseIP("10.0.0.5"))
	if after == nil {
		t.Fatal("a@x disappeared after reload")
	}
	if after != before {
		t.Fatal("Limits was replaced; in-flight connections would keep the old rate")
	}
	if after.Down != downLimiter {
		t.Fatal("Down limiter was recreated instead of re-rated")
	}
	if got := after.Down.Limit(); got != rate.Limit(1000) {
		t.Fatalf("down limit = %v, want the re-rated 1000", got)
	}
	// upBps 0 means that direction became unlimited.
	if got := after.Up.Limit(); got != rate.Inf {
		t.Fatalf("up limit = %v, want Inf", got)
	}
	if got := after.Down.Burst(); got != minBurst {
		t.Fatalf("burst = %d, want the %d floor", got, minBurst)
	}
}

// TestReloadRemovedAccountGoesUnlimited covers the account that vanishes from
// the file while it still has connections open: dropping it from the index is
// not enough, its buckets must be opened up.
func TestReloadRemovedAccountGoesUnlimited(t *testing.T) {
	tb, path := newTestTable(t, sample)
	held := tb.lookup("", net.ParseIP("10.0.0.5"))
	if held == nil {
		t.Fatal("setup: no limits for a@x")
	}

	write(t, path, `{"users":[{"email":"b@x","downBps":1310720,"upBps":0,"ips":["10.9.0.0/24"]}]}`, time.Second)
	tb.reloadIfChanged()

	if tb.lookup("", net.ParseIP("10.0.0.5")) != nil {
		t.Fatal("a@x should be gone from the index")
	}
	if held.Down.Limit() != rate.Inf || held.Up.Limit() != rate.Inf {
		t.Fatal("a reference held by an open connection is still throttled")
	}
}

func TestReloadMalformedKeepsLastGood(t *testing.T) {
	tb, path := newTestTable(t, sample)
	good := tb.lookup("", net.ParseIP("10.0.0.5"))
	if good == nil {
		t.Fatal("setup: no limits for a@x")
	}

	for _, bad := range []string{
		`{"users":[{"email":"a@x","downBps":`, // truncated, the crashed-writer case
		`not json at all`,
		`{"users":[{"email":"","downBps":1}]}`,            // no key to index on
		`{"users":[{"email":"a@x","ips":["not-an-ip"]}]}`, // unparseable prefix
		// The bad entry sorts after a good one, so this only holds if validation
		// completes before any limiter is re-rated.
		`{"users":[{"email":"a@x","downBps":1},{"email":"b@x","ips":["oops"]}]}`,
		// Duplicate emails would merge two accounts onto one bucket.
		`{"users":[{"email":"a@x","downBps":1},{"email":"a@x","downBps":2}]}`,
	} {
		write(t, path, bad, 2*time.Second)
		tb.reloadIfChanged()

		got := tb.lookup("", net.ParseIP("10.0.0.5"))
		if got != good {
			t.Fatalf("malformed input %q lost the last good state", bad)
		}
		if got.Down.Limit() != rate.Limit(655360) {
			t.Fatalf("malformed input %q changed the rate", bad)
		}
	}
}

// TestReloadEmptyDocumentClearsLimits pins the writer's contract: {"users":[]}
// is the empty state, and it is a VALID document, not a malformed one. It must
// remove every limit. Holding the last good state here would strand accounts
// throttled forever after their limit was lifted, and {"users":[]} is the
// steady-state file on any deployment not using the feature.
func TestReloadEmptyDocumentClearsLimits(t *testing.T) {
	tb, path := newTestTable(t, sample)
	held := tb.lookup("", net.ParseIP("10.0.0.5"))
	if held == nil {
		t.Fatal("setup: no limits for a@x")
	}

	write(t, path, `{"users":[]}`, time.Second)
	tb.reloadIfChanged()

	if tb.lookup("", net.ParseIP("10.0.0.5")) != nil {
		t.Fatal("empty document did not clear the IP index")
	}
	if tb.lookup("native@x", nil) != nil {
		t.Fatal("empty document did not clear the email index")
	}
	if held.Down.Limit() != rate.Inf || held.Up.Limit() != rate.Inf {
		t.Fatal("a connection open across the change is still throttled")
	}
}

func TestReloadMissingFileKeepsLastGood(t *testing.T) {
	tb, path := newTestTable(t, sample)
	good := tb.lookup("", net.ParseIP("10.0.0.5"))

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tb.reloadIfChanged()

	if tb.lookup("", net.ParseIP("10.0.0.5")) != good {
		t.Fatal("a missing file dropped the limits")
	}
}

func TestBurstFor(t *testing.T) {
	if got := burstFor(0); got != minBurst {
		t.Fatalf("burstFor(0) = %d, want the %d floor", got, minBurst)
	}
	if got := burstFor(1024); got != minBurst {
		t.Fatalf("burstFor(1024) = %d, want the %d floor", got, minBurst)
	}
	// Above the floor the bucket is one second deep.
	if got := burstFor(4 << 20); got != 4<<20 {
		t.Fatalf("burstFor(4MiB) = %d, want one second of traffic", got)
	}
	if got := burstFor(1 << 40); got != maxBurst {
		t.Fatalf("burstFor(1TiB) = %d, want the %d cap (int overflow guard)", got, maxBurst)
	}
}

type countingWriter struct{ n int64 }

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.n += int64(mb.Len())
	buf.ReleaseMulti(mb)
	return nil
}

func makeMB(t *testing.T, size int) buf.MultiBuffer {
	t.Helper()
	var mb buf.MultiBuffer
	for size > 0 {
		b := buf.New()
		n := size
		if n > int(b.Cap()) {
			n = int(b.Cap())
		}
		b.Extend(int32(n))
		mb = append(mb, b)
		size -= n
	}
	return mb
}

// TestWriteLargerThanBurstDoesNotError is the regression test for the trap this
// package exists to dodge: rate.Limiter.WaitN errors instead of blocking when a
// request exceeds the burst, and Xray writes whole MultiBuffers.
func TestWriteLargerThanBurstDoesNotError(t *testing.T) {
	const size = 800 * 1024
	const burst = 1024

	// Control: prove the trap is real at these numbers, so this test cannot pass
	// vacuously if x/time/rate ever changes its behaviour.
	naive := rate.NewLimiter(rate.Limit(64<<20), burst)
	if err := naive.WaitN(context.Background(), size); err == nil {
		t.Fatal("expected an unchunked WaitN over the burst to error; the trap this test guards is gone")
	}

	inner := &countingWriter{}
	// A deliberately shallow bucket, shallower than burstFor would ever build, so
	// that only the chunking in wait() can carry the write.
	w := NewWriter(context.Background(), inner, rate.NewLimiter(rate.Limit(64<<20), burst))

	if err := w.WriteMultiBuffer(makeMB(t, size)); err != nil {
		t.Fatalf("write of %d bytes against a %d burst errored: %v", size, burst, err)
	}
	if inner.n != size {
		t.Fatalf("wrote %d bytes, want %d", inner.n, size)
	}
}

// TestWriteRealisticBurstIsUnchunked checks the other defence: at a bucket built
// by burstFor, a normal MultiBuffer fits in one chunk and is not delayed.
func TestWriteRealisticBurstIsUnchunked(t *testing.T) {
	inner := &countingWriter{}
	l := rate.NewLimiter(rateOf(65536), burstFor(65536)) // 64 KB/s, floored burst
	w := NewWriter(context.Background(), inner, l)

	start := time.Now()
	if err := w.WriteMultiBuffer(makeMB(t, 64*1024)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("first write into a full bucket took %v, want no delay", d)
	}
	if inner.n != 64*1024 {
		t.Fatalf("wrote %d bytes, want %d", inner.n, 64*1024)
	}
}

// TestNilLimiterIsPassThrough pins the zero-overhead path: an unlimited
// direction must not allocate a wrapper at all.
func TestNilLimiterIsPassThrough(t *testing.T) {
	inner := &countingWriter{}
	if got := NewWriter(context.Background(), inner, nil); got != buf.Writer(inner) {
		t.Fatal("a nil limiter should return the writer untouched")
	}
	r := buf.Reader(&buf.MultiBufferContainer{})
	if got := NewReader(context.Background(), r, nil); got != r {
		t.Fatal("a nil limiter should return the reader untouched")
	}
}

// TestWaitAbortsOnContextCancel: a closed connection must not park a goroutine
// on a bucket nobody is draining.
func TestWaitAbortsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := rate.NewLimiter(rate.Limit(1), minBurst)
	if err := wait(ctx, l, 10*minBurst); err == nil {
		t.Fatal("expected a cancelled context to abort the wait")
	}
}

func TestPacingIsApproximatelyTheLimit(t *testing.T) {
	inner := &countingWriter{}
	const bps = 256 * 1024
	l := rate.NewLimiter(rateOf(bps), burstFor(bps))
	w := NewWriter(context.Background(), inner, l)

	// Drain the initial burst, which is free by design, then measure.
	if err := w.WriteMultiBuffer(makeMB(t, minBurst)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := w.WriteMultiBuffer(makeMB(t, bps/4)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond || elapsed > 400*time.Millisecond {
		t.Fatalf("a quarter second of traffic took %v, want roughly 250ms", elapsed)
	}
}
