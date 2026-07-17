package speedlimit

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"
)

// newInboundCtx builds a dispatch context shaped like the one an inbound worker
// hands to the dispatcher, and returns its cancel.
//
// The cancel is the point of the helper: app/proxyman/inbound/worker.go derives
// every connection's context with context.WithCancel and calls that cancel the
// moment the proxy stops handling the connection, so calling it here is what a
// closing client connection does in production.
//
// An empty email models the tunnel protocols, where dokodemo-door allocates a
// MemoryUser with no email and the account is resolved from the source address.
func newInboundCtx(email, ip string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	inb := &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress(ip), 12345),
		User:   &protocol.MemoryUser{Email: email},
	}
	return session.ContextWithInbound(ctx, inb), cancel
}

// dialCtx admits one connection and returns the context the dispatcher would
// carry onward, which is the one holding the eviction token, plus its cancel.
func dialCtx(t *testing.T, tb *table, email, ip string) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := newInboundCtx(email, ip)
	ctx, err := tb.admit(ctx)
	if err != nil {
		cancel()
		t.Fatalf("admit from %s was refused: %v", ip, err)
	}
	return ctx, cancel
}

// dial admits one connection and returns its cancel, failing the test if the
// dispatch was refused.
func dial(t *testing.T, tb *table, email, ip string) context.CancelFunc {
	t.Helper()
	_, cancel := dialCtx(t, tb, email, ip)
	return cancel
}

// refused admits one connection expecting refusal, and cancels it the way the
// inbound proxy would after the dispatcher returned an error.
func refused(t *testing.T, tb *table, email, ip string) {
	t.Helper()
	ctx, cancel := newInboundCtx(email, ip)
	defer cancel()
	if _, err := tb.admit(ctx); err == nil {
		t.Fatalf("admit from %s was allowed, want a refusal", ip)
	}
}

func ipCount(l *Limits) int {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()
	return len(l.ips)
}

// refcount is the number of live connections the address holds, which is the
// size of its connection set.
func refcount(l *Limits, ip string) int {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()
	e := l.ips[netip.MustParseAddr(ip)]
	if e == nil {
		return 0
	}
	return len(e.conns)
}

func holdsIP(l *Limits, ip string) bool {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()
	_, ok := l.ips[netip.MustParseAddr(ip)]
	return ok
}

// waitForIPCount polls because context.AfterFunc runs the release on its own
// goroutine, so a release is ordered after cancel but not synchronous with it.
func waitForIPCount(t *testing.T, l *Limits, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ipCount(l) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("holding %d addresses, want %d", ipCount(l), want)
}

const ipSample = `{"users":[
	{"email":"k1@x","downBps":0,"upBps":0,"ipLimit":1,"ips":[]},
	{"email":"k2@x","downBps":0,"upBps":0,"ipLimit":2,"ips":["10.0.0.5/32"]},
	{"email":"rate@x","downBps":65536,"upBps":0,"ips":[]}
]}`

// TestKnownIPIsAlwaysAdmitted is the load-bearing rule. A device opens dozens of
// concurrent connections; refusing its 50th because K is 1 would break ordinary
// browsing while protecting nothing, since they all share the one address.
func TestKnownIPIsAlwaysAdmitted(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)
	l := tb.lookup("k1@x", nil)
	if l == nil {
		t.Fatal("setup: no entry for k1@x")
	}

	const conns = 50
	cancels := make([]context.CancelFunc, 0, conns)
	for i := 0; i < conns; i++ {
		cancels = append(cancels, dial(t, tb, "k1@x", "198.51.100.7"))
	}

	if got := ipCount(l); got != 1 {
		t.Fatalf("%d connections from one address hold %d slots, want 1", conns, got)
	}
	if got := refcount(l, "198.51.100.7"); got != conns {
		t.Fatalf("refcount = %d, want %d", got, conns)
	}

	// The address keeps its slot until its LAST connection ends.
	for _, c := range cancels[:conns-1] {
		c()
	}
	waitForIPCount(t, l, 1)
	if got := ipCount(l); got != 1 {
		t.Fatalf("address freed its slot with a connection still open")
	}
	cancels[conns-1]()
	waitForIPCount(t, l, 0)
}

func TestNewIPBeyondKIsRefused(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)
	l := tb.lookup("k2@x", nil)
	if l == nil {
		t.Fatal("setup: no entry for k2@x")
	}

	a := dial(t, tb, "k2@x", "198.51.100.1")
	dial(t, tb, "k2@x", "198.51.100.2")
	// K distinct addresses are now live, so a third is the K+1th.
	refused(t, tb, "k2@x", "198.51.100.3")

	// Both incumbents keep working, including on new connections.
	dial(t, tb, "k2@x", "198.51.100.1")
	dial(t, tb, "k2@x", "198.51.100.2")

	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses, want 2", got)
	}

	// Freeing an incumbent's slot lets the newcomer in.
	a()
	waitForIPCount(t, l, 2) // .1 still has its second connection
	dial(t, tb, "k2@x", "198.51.100.1")
}

// TestReleaseOnContextDoneFreesTheSlot is the highest-risk detail in the whole
// feature: if a dispatch context ever outlived its client connection the slot
// would leak and the account would lock itself out, which from the user's side
// is exactly the fail2ban bug this replaces.
func TestReleaseOnContextDoneFreesTheSlot(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)
	l := tb.lookup("k1@x", nil)

	cancel := dial(t, tb, "k1@x", "198.51.100.1")
	refused(t, tb, "k1@x", "198.51.100.2")

	cancel()
	waitForIPCount(t, l, 0)

	// The freed slot is usable, by a DIFFERENT address.
	dial(t, tb, "k1@x", "198.51.100.2")
	if got := refcount(l, "198.51.100.2"); got != 1 {
		t.Fatalf("refcount = %d, want 1", got)
	}
}

// TestRefusedDispatchReleasesNothing pins rule "only release what you
// allocated": a refusal registers no AfterFunc, so the cancel that follows it
// must not decrement the incumbent that refused it.
func TestRefusedDispatchReleasesNothing(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)
	l := tb.lookup("k1@x", nil)

	dial(t, tb, "k1@x", "198.51.100.1")

	for i := 0; i < 10; i++ {
		// refused() cancels the context on the way out, exactly as the inbound proxy
		// does once the dispatcher hands it an error.
		refused(t, tb, "k1@x", "198.51.100.2")
	}

	// Give any (wrongly) registered release a chance to run before asserting.
	time.Sleep(50 * time.Millisecond)
	if got := ipCount(l); got != 1 {
		t.Fatalf("holding %d addresses after 10 refusals, want 1", got)
	}
	if got := refcount(l, "198.51.100.1"); got != 1 {
		t.Fatalf("incumbent refcount = %d, want 1: a refusal decremented it", got)
	}
}

// TestAbsentIPLimitAllocatesNothing pins the common case. An account with no IP
// limit, and an account absent from the sidecar entirely, must both cost nothing
// beyond the lookup.
func TestAbsentIPLimitAllocatesNothing(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)

	for _, c := range []struct {
		name  string
		email string
	}{
		{"rate limited but no ip limit", "rate@x"},
		{"absent from the sidecar", "nobody@x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := newInboundCtx(c.email, "198.51.100.1")
			defer cancel()
			if got := testing.AllocsPerRun(100, func() {
				if _, err := tb.admit(ctx); err != nil {
					t.Fatal(err)
				}
			}); got != 0 {
				t.Fatalf("admit allocated %v times, want 0", got)
			}
		})
	}

	if l := tb.lookup("rate@x", nil); l == nil || ipCount(l) != 0 {
		t.Fatal("an account with no ip limit built a tally")
	}
}

// TestOldSidecarWithoutIPLimitStillParses is the backward-compatibility pin: a
// file written before the ipLimit and strategy fields existed must load and
// leave its accounts IP-unlimited.
func TestOldSidecarWithoutIPLimitStillParses(t *testing.T) {
	tb, _ := newTestTable(t, sample)

	l := tb.lookup("native@x", nil)
	if l == nil {
		t.Fatal("an old sidecar failed to load")
	}
	if l.ipLimit != 0 {
		t.Fatalf("ipLimit = %d, want 0 (unlimited) when the field is absent", l.ipLimit)
	}
	if l.evictOldest {
		t.Fatal("an absent strategy must be reject, the stricter reading")
	}
	// Many addresses, no limit, no tally.
	for i := 1; i <= 5; i++ {
		dial(t, tb, "native@x", fmt.Sprintf("198.51.100.%d", i))
	}
	if got := ipCount(l); got != 0 {
		t.Fatalf("an unlimited account tracked %d addresses, want none", got)
	}
}

// TestReloadChangesKInPlace: the *Limits is shared with live connections, so a
// reload must re-rate K on it rather than swap it, and must not lose the tally.
func TestReloadChangesKInPlace(t *testing.T) {
	tb, path := newTestTable(t, ipSample)
	l := tb.lookup("k2@x", nil)

	dial(t, tb, "k2@x", "198.51.100.1")
	dial(t, tb, "k2@x", "198.51.100.2")
	refused(t, tb, "k2@x", "198.51.100.3")

	write(t, path, `{"users":[{"email":"k2@x","ipLimit":3,"ips":["10.0.0.5/32"]}]}`, time.Second)
	tb.reloadIfChanged()

	if after := tb.lookup("k2@x", nil); after != l {
		t.Fatal("Limits was replaced; the live refcounts would have been lost")
	}
	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses after reload, want the 2 that were live", got)
	}
	if got := refcount(l, "198.51.100.1"); got != 1 {
		t.Fatalf("refcount = %d, want the live 1 preserved across reload", got)
	}
	// The raised K takes effect immediately.
	dial(t, tb, "k2@x", "198.51.100.3")

	// Lowering K below what is live evicts nobody: reject refuses at admission and
	// never kills, and a known IP is always admitted.
	write(t, path, `{"users":[{"email":"k2@x","ipLimit":1,"ips":["10.0.0.5/32"]}]}`, 2*time.Second)
	tb.reloadIfChanged()
	if got := ipCount(l); got != 3 {
		t.Fatalf("lowering K dropped live addresses: holding %d, want 3", got)
	}
	dial(t, tb, "k2@x", "198.51.100.1")
	refused(t, tb, "k2@x", "198.51.100.4")
}

// TestReloadRemovingLimitFreesEveryone covers both ways an operator lifts a
// limit: zeroing the field, and dropping the account from the file.
func TestReloadRemovingLimitFreesEveryone(t *testing.T) {
	t.Run("ipLimit zeroed", func(t *testing.T) {
		tb, path := newTestTable(t, ipSample)
		l := tb.lookup("k1@x", nil)
		dial(t, tb, "k1@x", "198.51.100.1")
		refused(t, tb, "k1@x", "198.51.100.2")

		write(t, path, `{"users":[{"email":"k1@x","downBps":0,"upBps":0,"ipLimit":0,"ips":[]}]}`, time.Second)
		tb.reloadIfChanged()

		if tb.lookup("k1@x", nil) != l {
			t.Fatal("Limits was replaced")
		}
		for i := 2; i <= 6; i++ {
			dial(t, tb, "k1@x", fmt.Sprintf("198.51.100.%d", i))
		}
	})

	t.Run("account dropped from the file", func(t *testing.T) {
		tb, path := newTestTable(t, ipSample)
		dial(t, tb, "k1@x", "198.51.100.1")
		refused(t, tb, "k1@x", "198.51.100.2")

		write(t, path, `{"users":[]}`, time.Second)
		tb.reloadIfChanged()

		if tb.lookup("k1@x", nil) != nil {
			t.Fatal("k1@x should be gone from the index")
		}
		for i := 2; i <= 6; i++ {
			dial(t, tb, "k1@x", fmt.Sprintf("198.51.100.%d", i))
		}
	})
}

// TestIPLimitByResolvedSource covers the tunnel lane: no email on the session,
// so the account is resolved from the source address through the IP index. The
// panel does not set ipLimit for those protocols, but the core has no protocol
// awareness and must behave if it ever does.
func TestIPLimitBySourceLookup(t *testing.T) {
	tb, _ := newTestTable(t, ipSample)
	l := tb.lookup("k2@x", nil)

	// 10.0.0.5 belongs to k2@x, whose ipLimit is 2.
	dial(t, tb, "", "10.0.0.5")
	if got := refcount(l, "10.0.0.5"); got != 1 {
		t.Fatalf("refcount = %d, want the source-resolved account to be charged", got)
	}
}

// TestAdmitConcurrent is the race test: many goroutines racing on one account's
// tally must never over-admit past K.
func TestAdmitConcurrent(t *testing.T) {
	tb, _ := newTestTable(t, `{"users":[{"email":"a@x","ipLimit":4,"ips":[]}]}`)
	l := tb.lookup("a@x", nil)

	const goroutines = 64
	const distinctIPs = 8

	var wg sync.WaitGroup
	var admitted atomic.Int64
	var mu sync.Mutex
	var cancels []context.CancelFunc

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := newInboundCtx("a@x", fmt.Sprintf("198.51.100.%d", i%distinctIPs))
			if _, err := tb.admit(ctx); err != nil {
				cancel()
				return
			}
			admitted.Add(1)
			mu.Lock()
			cancels = append(cancels, cancel)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Exactly K addresses win, whichever they are, and every connection from a
	// winning address is admitted.
	if got := ipCount(l); got != 4 {
		t.Fatalf("holding %d addresses, want exactly K=4", got)
	}
	if got := admitted.Load(); got != goroutines/distinctIPs*4 {
		t.Fatalf("admitted %d, want the %d connections of the 4 winning addresses", got, goroutines/distinctIPs*4)
	}

	for _, c := range cancels {
		c()
	}
	waitForIPCount(t, l, 0)
}

// acceptSample is the strategy matrix. None of these accounts has a rate limit,
// which is the shape the panel writes for a client that has an IP limit and no
// speed limit, and the shape in which an eviction has no rate-limiting wrapper
// to ride on.
const acceptSample = `{"users":[
	{"email":"acc@x","ipLimit":2,"strategy":"accept","ips":[]},
	{"email":"acc1@x","ipLimit":1,"strategy":"accept","ips":[]},
	{"email":"other@x","ipLimit":2,"strategy":"accept","ips":[]}
]}`

// killed reports whether the connection admitted on ctx has been evicted, which
// is what the io wrappers check.
func killed(ctx context.Context) bool {
	c := connFromContext(ctx)
	return c != nil && c.killed.Load()
}

// idleReader models a client sitting there saying nothing: in production a read
// that reaches it blocks until the client speaks or connIdle fires. An evicted
// connection must not reach it, so this records the visit rather than blocking,
// which would turn a regression into a hung test instead of a failed one.
type idleReader struct{ reached atomic.Bool }

func (r *idleReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.reached.Store(true)
	return nil, nil
}

// TestAcceptEvictsOldestIP is phase 2's headline: at K, a new address takes the
// OLDEST address's slot instead of being refused.
func TestAcceptEvictsOldestIP(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)
	l := tb.lookup("acc@x", nil)
	if l == nil {
		t.Fatal("setup: no entry for acc@x")
	}

	// .9 is dialled first but sorts LAST, so a comparison that fell back on the
	// address rather than the time would evict .2 and fail this test.
	oldCtx, _ := dialCtx(t, tb, "acc@x", "198.51.100.9")
	time.Sleep(2 * time.Millisecond) // separate the first-seen stamps
	youngCtx, _ := dialCtx(t, tb, "acc@x", "198.51.100.2")

	// At K with a new address: admitted, and the oldest goes.
	newCtx, _ := dialCtx(t, tb, "acc@x", "198.51.100.3")

	if holdsIP(l, "198.51.100.9") {
		t.Fatal("the oldest address kept its slot")
	}
	if !holdsIP(l, "198.51.100.2") || !holdsIP(l, "198.51.100.3") {
		t.Fatal("the wrong address was evicted")
	}
	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses, want K=2", got)
	}
	if !killed(oldCtx) {
		t.Fatal("the evicted connection was not killed")
	}
	if killed(youngCtx) || killed(newCtx) {
		t.Fatal("eviction killed a connection it should not have")
	}
}

// TestEvictedConnectionErrsOnNextReadAndWrite is the kill path itself. Setting
// the flag is nothing on its own: it only becomes an eviction because the io
// wrappers read it, in both directions, and the proxy's copy loop takes the
// error and closes the connection.
//
// acc@x has NO rate limit, so this also pins the trap: the wrappers must be
// installed for an account whose only limit is an IP limit, or the kill sets a
// flag nobody ever reads.
func TestEvictedConnectionErrsOnNextReadAndWrite(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)
	l := tb.lookup("acc1@x", nil)
	if l.Up.Limit() != rate.Inf || l.Down.Limit() != rate.Inf {
		t.Fatal("setup: acc1@x is supposed to have no rate limit")
	}

	victimCtx, _ := dialCtx(t, tb, "acc1@x", "198.51.100.1")

	// The dispatcher's own wiring: getLink pairs the two directions' writers,
	// WrapLink a reader and a writer, all built from the dispatch context.
	inner := &countingWriter{}
	w := NewWriter(victimCtx, inner, l.Down)
	idle := &idleReader{}
	r := NewReader(victimCtx, idle, l.Up)

	// Before the eviction both directions work.
	if err := w.WriteMultiBuffer(makeMB(t, 128)); err != nil {
		t.Fatalf("write before eviction: %v", err)
	}
	if _, err := r.ReadMultiBuffer(); err != nil {
		t.Fatalf("read before eviction: %v", err)
	}
	if !idle.reached.Load() {
		t.Fatal("the read never reached the wrapped reader")
	}
	idle.reached.Store(false)

	// K is 1, so this newcomer evicts the victim.
	dial(t, tb, "acc1@x", "198.51.100.2")

	if err := w.WriteMultiBuffer(makeMB(t, 128)); err != errEvicted {
		t.Fatalf("write after eviction returned %v, want errEvicted", err)
	}
	if inner.n != 128 {
		t.Fatalf("the evicted connection wrote %d bytes, want only the 128 from before it was evicted", inner.n)
	}
	if _, err := r.ReadMultiBuffer(); err != errEvicted {
		t.Fatalf("read after eviction returned %v, want errEvicted", err)
	}
	if idle.reached.Load() {
		t.Fatal("an evicted read went back to waiting on the client instead of failing")
	}
}

// waitParked blocks until the writer goroutine has stopped completing writes,
// which is how the test knows it is blocked INSIDE the pipe rather than merely
// slow. Without this the eviction below could land between two writes and be
// caught by the flag, which is the state the whole test exists to avoid.
func waitParked(t *testing.T, wrote *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n := wrote.Load()
		time.Sleep(50 * time.Millisecond)
		if n > 0 && wrote.Load() == n {
			return
		}
	}
	t.Fatal("the writer never filled the pipe, so it never parked")
}

// TestEvictionUnblocksAWriterParkedInAFullPipe is the regression the flag-only
// kill shipped, and the reason the test above was not enough to catch it.
//
// That test writes into a countingWriter, which returns instantly, so its
// wrapper always comes back to test the flag between two buffers. The real chain
// writes into a PIPE, and a pipe whose reader is slower than its writer fills up
// and parks the writer inside the write itself. The wrapper is then never
// reached again, so a flag-only kill is deferred by however long the client
// takes to drain the pipe, and forever for a client that has stopped reading.
// That is the steady state of exactly the connection an operator evicts, so the
// strategy measured as "admit everyone, evict nobody" on a live server while
// every unit test passed.
func TestEvictionUnblocksAWriterParkedInAFullPipe(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)
	l := tb.lookup("acc1@x", nil)
	if l == nil {
		t.Fatal("setup: no entry for acc1@x")
	}

	victimCtx, _ := dialCtx(t, tb, "acc1@x", "198.51.100.1")

	// getLink's wiring, with the writer it really has. Nothing ever reads pr,
	// which is what a client that has stopped reading looks like from here.
	pr, pw := pipe.New(pipe.WithSizeLimit(4096))
	w := NewWriter(victimCtx, pw, l.Down)
	// So that a failing run unwinds its goroutine instead of leaking it parked.
	t.Cleanup(func() { common.Interrupt(pw) })

	var wrote atomic.Int64
	done := make(chan error, 1)
	go func() {
		for {
			if err := w.WriteMultiBuffer(makeMB(t, 2048)); err != nil {
				done <- err
				return
			}
			wrote.Add(1)
		}
	}()

	waitParked(t, &wrote)
	select {
	case err := <-done:
		t.Fatalf("setup: the writer stopped on %v instead of parking in the pipe", err)
	default:
	}

	// K is 1, so this newcomer evicts the victim.
	dial(t, tb, "acc1@x", "198.51.100.2")

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the evicted writer returned nil, want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the evicted writer is STILL parked in its pipe 5s after the eviction: " +
			"the kill only flags the connection, and a parked write never returns to test the flag")
	}

	// The other half: a kill that unparks the writer but leaves the pipe holding
	// its bytes would still hand them to the client being evicted. The read must
	// fail rather than yield the buffered data.
	if _, err := pr.ReadMultiBuffer(); err == nil {
		t.Fatal("the evicted connection's pipe still served its buffered bytes to the client")
	}
}

// TestKillWrapperWithoutALimiter pins the wrappers' contract at the extreme: a
// nil limiter is a pass-through UNLESS the connection is evictable, in which
// case the wrapper exists only to carry the kill.
func TestKillWrapperWithoutALimiter(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)

	victimCtx, _ := dialCtx(t, tb, "acc1@x", "198.51.100.1")
	inner := &countingWriter{}
	w := NewWriter(victimCtx, inner, nil)
	if w == buf.Writer(inner) {
		t.Fatal("an evictable connection was left unwrapped; its eviction would do nothing")
	}
	if err := w.WriteMultiBuffer(makeMB(t, 64)); err != nil {
		t.Fatalf("write with no limiter: %v", err)
	}

	dial(t, tb, "acc1@x", "198.51.100.2") // evicts .1

	if err := w.WriteMultiBuffer(makeMB(t, 64)); err != errEvicted {
		t.Fatalf("write after eviction returned %v, want errEvicted", err)
	}

	// And with neither a limiter nor a token there is nothing to enforce, so the
	// zero-overhead path stands (see also TestNilLimiterIsPassThrough).
	plain, cancel := newInboundCtx("acc1@x", "198.51.100.3")
	defer cancel()
	if got := NewWriter(plain, inner, nil); got != buf.Writer(inner) {
		t.Fatal("a connection with no limits at all was wrapped")
	}
}

// TestEvictionFreesTheSlotAndDoesNotDoubleDecrement is rule "release exactly
// what you allocated" under eviction. The victim's release is already registered
// and fires later, when its connection finally closes; by then its entry is gone
// and the address may even be back with a NEW entry, which the stale release
// must not touch.
func TestEvictionFreesTheSlotAndDoesNotDoubleDecrement(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)
	l := tb.lookup("acc@x", nil)

	// Two connections from .1, so eviction takes both and two stale releases are
	// left pending.
	victim1 := dial(t, tb, "acc@x", "198.51.100.1")
	victim2 := dial(t, tb, "acc@x", "198.51.100.1")
	time.Sleep(2 * time.Millisecond)
	dial(t, tb, "acc@x", "198.51.100.2")
	dial(t, tb, "acc@x", "198.51.100.3") // evicts .1

	// The slot frees at eviction, not when the victim notices.
	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses after an eviction, want K=2", got)
	}
	if holdsIP(l, "198.51.100.1") {
		t.Fatal("the evicted address kept its slot")
	}

	// The victim's address comes straight back, taking .2's slot. It is a new
	// entry, and the old connections' releases have still not run.
	dialCtx(t, tb, "acc@x", "198.51.100.1")
	if !holdsIP(l, "198.51.100.1") || holdsIP(l, "198.51.100.2") {
		t.Fatal("the returning address did not evict the oldest incumbent")
	}

	victim1()
	victim2()
	time.Sleep(50 * time.Millisecond) // let both stale releases run

	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses, want 2: a stale release freed a live slot", got)
	}
	if got := refcount(l, "198.51.100.1"); got != 1 {
		t.Fatalf(".1's new connection has refcount %d, want 1: an evicted connection decremented it", got)
	}
	if got := refcount(l, "198.51.100.3"); got != 1 {
		t.Fatalf(".3 has refcount %d, want 1", got)
	}
}

// TestEvictionSparesOthers: the kill is per connection, so it must take exactly
// one address of one account.
func TestEvictionSparesOthers(t *testing.T) {
	tb, _ := newTestTable(t, acceptSample)
	acc := tb.lookup("acc@x", nil)
	other := tb.lookup("other@x", nil)

	victimCtx, _ := dialCtx(t, tb, "acc@x", "198.51.100.1")
	time.Sleep(2 * time.Millisecond)
	// The same address, on another account, and a second address on this one.
	otherCtx, _ := dialCtx(t, tb, "other@x", "198.51.100.1")
	keepCtx, _ := dialCtx(t, tb, "acc@x", "198.51.100.2")

	dialCtx(t, tb, "acc@x", "198.51.100.3") // evicts acc@x's .1 only

	if !killed(victimCtx) {
		t.Fatal("the victim was not killed")
	}
	if killed(otherCtx) {
		t.Fatal("evicting one account killed another account's connection from the same address")
	}
	if killed(keepCtx) {
		t.Fatal("evicting one address killed the account's other address")
	}
	if got := ipCount(other); got != 1 || !holdsIP(other, "198.51.100.1") {
		t.Fatal("the other account's tally was disturbed")
	}
	if got := ipCount(acc); got != 2 {
		t.Fatalf("holding %d addresses, want K=2", got)
	}
}

// TestStrategyRejectIsUnchanged pins that only the exact word "accept" evicts.
// Anything else is a refusal, which is what every document written before the
// field existed meant and the stricter of the two readings.
func TestStrategyRejectIsUnchanged(t *testing.T) {
	for _, c := range []struct {
		name string
		json string
	}{
		{"absent", `{"email":"r@x","ipLimit":1,"ips":[]}`},
		{"empty", `{"email":"r@x","ipLimit":1,"strategy":"","ips":[]}`},
		{"reject", `{"email":"r@x","ipLimit":1,"strategy":"reject","ips":[]}`},
		{"unknown word", `{"email":"r@x","ipLimit":1,"strategy":"evict","ips":[]}`},
		// The panel emits the words in lower case; a near miss is not an accept.
		{"wrong case", `{"email":"r@x","ipLimit":1,"strategy":"Accept","ips":[]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			tb, _ := newTestTable(t, `{"users":[`+c.json+`]}`)
			l := tb.lookup("r@x", nil)
			if l == nil {
				t.Fatal("the document failed to load")
			}
			if l.evictOldest {
				t.Fatal("this strategy must be reject")
			}

			incumbentCtx, _ := dialCtx(t, tb, "r@x", "198.51.100.1")
			refused(t, tb, "r@x", "198.51.100.2")

			if killed(incumbentCtx) {
				t.Fatal("reject killed the incumbent")
			}
			if got := ipCount(l); got != 1 || !holdsIP(l, "198.51.100.1") {
				t.Fatal("reject disturbed the incumbent's slot")
			}
		})
	}
}

// TestStrategyChangesOnReload: the strategy lives on the same object as K, so an
// operator's edit reaches connections that are already open.
func TestStrategyChangesOnReload(t *testing.T) {
	tb, path := newTestTable(t, `{"users":[{"email":"s@x","ipLimit":1,"ips":[]}]}`)
	l := tb.lookup("s@x", nil)

	dial(t, tb, "s@x", "198.51.100.1")
	refused(t, tb, "s@x", "198.51.100.2")

	write(t, path, `{"users":[{"email":"s@x","ipLimit":1,"strategy":"accept","ips":[]}]}`, time.Second)
	tb.reloadIfChanged()

	if tb.lookup("s@x", nil) != l {
		t.Fatal("Limits was replaced; the live tally would have been lost")
	}
	dial(t, tb, "s@x", "198.51.100.2") // now evicts instead of being refused
	if holdsIP(l, "198.51.100.1") {
		t.Fatal("the strategy change did not take effect")
	}

	write(t, path, `{"users":[{"email":"s@x","ipLimit":1,"strategy":"reject","ips":[]}]}`, 2*time.Second)
	tb.reloadIfChanged()
	refused(t, tb, "s@x", "198.51.100.3")
}

// TestConcurrentAdmitAndEvict races admissions, evictions and the io wrappers'
// reads of the kill flag, which is the one piece of state a foreign goroutine
// writes while a connection is using it.
func TestConcurrentAdmitAndEvict(t *testing.T) {
	tb, _ := newTestTable(t, `{"users":[{"email":"a@x","ipLimit":2,"strategy":"accept","ips":[]}]}`)
	l := tb.lookup("a@x", nil)

	const goroutines = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	var cancels []context.CancelFunc

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every address is new, so at K every admission evicts somebody: the
			// worst case, and the one where a kill can race its own admission.
			ctx, cancel := dialCtx(t, tb, "a@x", fmt.Sprintf("198.51.100.%d", i+1))
			mu.Lock()
			cancels = append(cancels, cancel)
			mu.Unlock()

			// Drive traffic through the wrappers, so the flag is read while other
			// goroutines are writing it.
			w := NewWriter(ctx, &countingWriter{}, l.Down)
			r := NewReader(ctx, &idleReader{}, l.Up)
			for j := 0; j < 8; j++ {
				if err := w.WriteMultiBuffer(makeMB(t, 64)); err != nil {
					break
				}
				if _, err := r.ReadMultiBuffer(); err != nil {
					break
				}
			}
		}(i)
	}
	wg.Wait()

	// accept never refuses, so the account never exceeds K.
	if got := ipCount(l); got != 2 {
		t.Fatalf("holding %d addresses, want K=2", got)
	}
	for _, c := range cancels {
		c()
	}
	// Every connection is gone, including every evicted one, so the tally must
	// drain to empty. A leak here is the lockout bug.
	waitForIPCount(t, l, 0)
}

// TestConcurrentAdmitDuringReload races admission against reloads, which take
// the table lock and the per-account lock on different goroutines.
func TestConcurrentAdmitDuringReload(t *testing.T) {
	tb, path := newTestTable(t, ipSample)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			body := fmt.Sprintf(`{"users":[{"email":"k2@x","ipLimit":%d,"ips":["10.0.0.5/32"]}]}`, 1+i%4)
			write(t, path, body, time.Duration(i+1)*time.Second)
			tb.reloadIfChanged()
		}
	}()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctx, cancel := newInboundCtx("k2@x", fmt.Sprintf("198.51.100.%d", i%4))
				tb.admit(ctx)
				cancel()
			}
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Whatever the interleaving, every connection is gone, so the tally must drain
	// to empty. A leak here is the lockout bug.
	if l := tb.lookup("k2@x", nil); l != nil {
		waitForIPCount(t, l, 0)
	}
}
