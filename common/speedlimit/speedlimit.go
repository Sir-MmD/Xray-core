// Package speedlimit implements per-account bandwidth shaping and per-account
// concurrent source-IP limiting for the dispatcher.
//
// The two features share this package because they share everything that is
// expensive: the sidecar file, its hot reload, the email resolution, and the
// per-account object. Only the enforcement differs, so splitting them would
// duplicate all of that to separate forty lines of admission control.
//
// This is a fork addition, not part of upstream Xray, so it is built to be cheap
// to rebase: one self-contained package plus a handful of lines in
// app/dispatcher/default.go.
//
// Limits arrive out of band, through a JSON sidecar file named by the
// XRAY_SPEEDLIMIT_FILE environment variable, rather than through the Xray config.
// Two reasons. The panel re-arms an account's limit as quota thresholds are
// crossed, which happens continuously; carrying limits in the config would mean
// rewriting it and restarting the core on every crossing, dropping every
// connection on the box, which is the exact thing this feature exists to avoid.
// And an environment variable touches nothing in infra/conf, whose app configs
// are protobuf Any values that a non-protobuf side channel would drag codegen
// into.
//
// With XRAY_SPEEDLIMIT_FILE unset the limiter is permanently disabled: every
// lookup returns nil, nothing is allocated, and no goroutine is started, so an
// unpatched deployment behaves exactly as stock Xray.
package speedlimit

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/time/rate"
)

// EnvPath names the environment variable holding the sidecar file's path.
const EnvPath = "XRAY_SPEEDLIMIT_FILE"

// pollInterval is how often the sidecar's path is stat()ed for changes.
const pollInterval = 2 * time.Second

const (
	// minBurst is the floor for a bucket's depth.
	//
	// rate.Limiter.WaitN reports an error, rather than blocking and draining, when
	// a single request exceeds the burst. Xray hands whole buf.MultiBuffers to the
	// writers, so a shallow bucket would fail every write on a slow account instead
	// of pacing it. This floor keeps buckets deeper than any realistic MultiBuffer;
	// wait() in io.go independently chunks its token requests, so correctness never
	// rests on the floor alone.
	minBurst = 512 * 1024

	// maxBurst caps bucket depth so that converting a rate to an int burst cannot
	// overflow on 32-bit builds.
	maxBurst = 1 << 30
)

// Limits is one account's enforcement state: its two token buckets and its
// concurrent source-IP tally.
//
// The directions are separate limiters on purpose: a single shared bucket can
// only express a combined up+down ceiling, never "5 Mbit down, 2 Mbit up". Both
// fields are non-nil for any account present in the sidecar. An unlimited
// direction is rate.Inf rather than a nil limiter, so that a reload can re-rate
// it in place for connections already holding a reference.
//
// The IP state hangs off the same object for the same reason: a reload reuses
// the *Limits, so K changes in place and the live refcounts survive it. Its
// mutex is never held together with the table's, so the two cannot deadlock.
type Limits struct {
	Up   *rate.Limiter
	Down *rate.Limiter

	ipMu sync.Mutex
	// ipLimit is K, the cap on concurrent distinct source IPs. 0 is unlimited.
	ipLimit int
	// evictOldest is the "accept" strategy: at K, a new address takes the oldest
	// address's slot instead of being refused. False is "reject".
	evictOldest bool
	// ips holds the LIVE dispatches per source address, so an address frees the
	// instant its last connection ends. It is nil until the account first admits
	// something under a limit.
	ips map[netip.Addr]*ipEntry
}

// sidecarFile is the on-disk format. Rates are BYTES per second; 0 means that
// direction is unlimited, and an account that is entirely unlimited is simply
// absent from the file.
type sidecarFile struct {
	Users []sidecarUser `json:"users"`
}

// sidecarUser mirrors one entry of the file. Every field is optional: a document
// written before ipLimit existed still parses, and its accounts come out
// IP-unlimited, which is what they were.
//
// Strategy is what to do at K: "accept" evicts the account's oldest address,
// anything else refuses the new one. It is not validated, because there is no
// safe way to fail here: rejecting the document over one unrecognised word would
// freeze EVERY account's limits at their last good value, so an unknown strategy
// falls back to "reject", which is both the stricter reading and what an absent
// field has always meant.
type sidecarUser struct {
	Email    string   `json:"email"`
	DownBps  int64    `json:"downBps"`
	UpBps    int64    `json:"upBps"`
	IPLimit  int      `json:"ipLimit"`
	Strategy string   `json:"strategy"`
	IPs      []string `json:"ips"`
}

// index is an immutable snapshot. It is replaced wholesale on reload, but the
// *Limits it points at are reused and re-rated so that in-flight connections
// pick up rate changes.
//
// The IP lookup is an exact-address map plus a slice of the remaining prefixes
// sorted longest-first, not a trie. Nearly every account owns individual /32s,
// one per device, which the map answers in O(1). Real CIDRs only come from
// ikev2 psk/eap-tls and wg-c, which bind a whole block to a single account, so
// the linear scan covers a handful of entries. A trie would be more code than
// the workload justifies.
type index struct {
	byEmail  map[string]*Limits
	exact    map[netip.Addr]string
	prefixes []prefixEntry
}

type prefixEntry struct {
	prefix netip.Prefix
	email  string
}

type table struct {
	path string

	mu  sync.RWMutex
	idx *index

	// Touched only by the loading goroutine (and, before it starts, by init).
	mtime   time.Time
	size    int64
	lastErr string
}

// defaultTable is nil when XRAY_SPEEDLIMIT_FILE is unset, which is the disabled
// case. It is written in init, before any lookup can run, and never again.
var defaultTable *table

func init() {
	path := os.Getenv(EnvPath)
	if path == "" {
		return
	}
	t := &table{path: path}
	// Load synchronously so that limits are in force for the first connection
	// rather than up to one poll interval later. A missing file is not fatal: the
	// panel may not have written it yet, and until it appears everyone is
	// unlimited.
	t.reloadIfChanged()
	go t.watch(pollInterval)
	defaultTable = t
}

// LookupSession resolves the limiters for a dispatcher session, returning nil
// when the limiter is disabled or the account is unlimited.
//
// Email is the key for every protocol, so an account's devices share one bucket.
// The source address is only a fallback lookup step, needed because
// dokodemo-door allocates a MemoryUser with an EMPTY email
// (proxy/dokodemo/dokodemo.go), which is how all of the VPN tunnel protocols
// arrive.
//
// The resolved email is used here and NEVER written back onto user.Email.
// Assigning it would switch on Xray's per-user traffic counters for accounts the
// panel already meters through nft/RADIUS, double counting their quota, and would
// make routing "user" rules start matching VPN clients.
func LookupSession(user *protocol.MemoryUser, inbound *session.Inbound) *Limits {
	if defaultTable == nil {
		return nil
	}
	return defaultTable.lookupSession(user, inbound)
}

func (t *table) lookupSession(user *protocol.MemoryUser, inbound *session.Inbound) *Limits {
	var email string
	if user != nil {
		email = user.Email
	}
	var ip net.IP
	// Address.IP() panics on a domain address, hence the family check.
	if email == "" && inbound != nil && inbound.Source.Address != nil && inbound.Source.Address.Family().IsIP() {
		ip = inbound.Source.Address.IP()
	}
	return t.lookup(email, ip)
}

func (t *table) lookup(email string, ip net.IP) *Limits {
	t.mu.RLock()
	idx := t.idx
	t.mu.RUnlock()

	if idx == nil {
		return nil
	}
	if email != "" {
		// A miss is an unlimited account, which is the common case and costs one
		// map lookup and no allocation.
		return idx.byEmail[email]
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	// net.IP holds IPv4 in 16-byte v4-in-v6 form as often as not, while a sidecar
	// entry of "10.0.0.5/32" parses as a 32-bit prefix. netip.Prefix.Contains
	// refuses to compare across address families, so unmap before matching.
	addr = addr.Unmap()
	if e, ok := idx.exact[addr]; ok {
		return idx.byEmail[e]
	}
	for _, pe := range idx.prefixes {
		if pe.prefix.Contains(addr) {
			return idx.byEmail[pe.email]
		}
	}
	return nil
}

func (t *table) watch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		t.reloadIfChanged()
	}
}

// reloadIfChanged polls the sidecar's PATH. This is deliberate, and it is why
// there is no fsnotify dependency here.
//
// The panel rewrites the file with the temp-file-plus-rename idiom, so its
// contents never change in place. An inotify watch would fire IN_MOVED_TO rather
// than IN_MODIFY, and a watch installed on the file itself would follow the old
// unlinked inode and then silently never fire again. stat() on the path cannot
// miss a rename.
//
// Change detection is mtime plus size. On a filesystem with coarse (1s) mtime
// granularity, two writes of identical size within the same second could be
// missed; on ext4's nanosecond timestamps this does not arise.
func (t *table) reloadIfChanged() {
	fi, err := os.Stat(t.path)
	if err != nil {
		t.logOnce("speedlimit: cannot stat " + t.path)
		return
	}
	if fi.ModTime().Equal(t.mtime) && fi.Size() == t.size {
		return
	}
	t.mtime, t.size = fi.ModTime(), fi.Size()

	idx, err := t.load()
	if err != nil {
		// Keep the last good state. Dropping to unlimited because someone wrote a
		// truncated file would be worse than serving a slightly stale limit, and a
		// half-written file is exactly what a crashed writer leaves behind.
		t.logOnce("speedlimit: keeping previous limits, cannot load " + t.path + ": " + err.Error())
		return
	}
	t.mu.Lock()
	t.idx = idx
	t.mu.Unlock()
	t.lastErr = ""
	errors.LogInfo(context.Background(), "speedlimit: loaded ", len(idx.byEmail), " limited account(s) from ", t.path)
}

// logOnce suppresses repeats so that a persistent fault does not emit a line
// every poll interval.
func (t *table) logOnce(msg string) {
	if t.lastErr == msg {
		return
	}
	t.lastErr = msg
	errors.LogWarning(context.Background(), msg)
}

func (t *table) load() (*index, error) {
	data, err := os.ReadFile(t.path)
	if err != nil {
		return nil, err
	}
	var f sidecarFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	t.mu.RLock()
	prev := t.idx
	t.mu.RUnlock()

	return buildIndex(prev, &f)
}

type parsedUser struct {
	user     sidecarUser
	prefixes []netip.Prefix
}

func buildIndex(prev *index, f *sidecarFile) (*index, error) {
	// Phase 1: parse and validate the whole file before touching anything shared.
	//
	// Re-rating below mutates limiters that open connections already hold, so it
	// is not undoable. Were the two phases interleaved, a file that turned out to
	// be bad half way through would leave the accounts it had already reached
	// moved to the new rates while the index was discarded, quietly breaking the
	// promise that a malformed file changes nothing.
	users := make([]parsedUser, 0, len(f.Users))
	seen := make(map[string]bool, len(f.Users))
	for _, u := range f.Users {
		if u.Email == "" {
			return nil, errors.New("speedlimit: entry with empty email")
		}
		if seen[u.Email] {
			// Email is the enforcement key, so a duplicate would silently merge two
			// accounts into one bucket.
			return nil, errors.New("speedlimit: duplicate email ", u.Email)
		}
		seen[u.Email] = true

		p := parsedUser{user: u}
		for _, s := range u.IPs {
			pfx, err := parsePrefix(s)
			if err != nil {
				return nil, errors.New("speedlimit: bad ip ", s, " for ", u.Email).Base(err)
			}
			p.prefixes = append(p.prefixes, pfx)
		}
		users = append(users, p)
	}

	// Phase 2: commit. Nothing beyond this point may fail.
	idx := &index{
		byEmail: make(map[string]*Limits, len(users)),
		exact:   make(map[netip.Addr]string),
	}
	for _, p := range users {
		u := p.user

		var l *Limits
		if prev != nil {
			l = prev.byEmail[u.Email]
		}
		if l == nil {
			l = &Limits{
				Up:   rate.NewLimiter(rateOf(u.UpBps), burstFor(u.UpBps)),
				Down: rate.NewLimiter(rateOf(u.DownBps), burstFor(u.DownBps)),
			}
		} else {
			// Re-rate the EXISTING limiters. Connections that are already open hold
			// a reference to them, and replacing the limiters would pin in-flight
			// traffic to the old rate until it ends.
			setRate(l.Up, u.UpBps)
			setRate(l.Down, u.DownBps)
		}
		// Reusing the *Limits is what makes K change in place: the live refcounts
		// are on it, so lowering K cannot disturb connections already admitted.
		l.setIPLimit(u.IPLimit, u.Strategy)
		idx.byEmail[u.Email] = l

		for _, pfx := range p.prefixes {
			if pfx.Bits() == pfx.Addr().BitLen() {
				idx.exact[pfx.Addr()] = u.Email
				continue
			}
			idx.prefixes = append(idx.prefixes, prefixEntry{prefix: pfx, email: u.Email})
		}
	}

	// Longest prefix first, so the most specific entry wins the linear scan.
	sort.SliceStable(idx.prefixes, func(i, j int) bool {
		return idx.prefixes[i].prefix.Bits() > idx.prefixes[j].prefix.Bits()
	})

	// An account that vanished from the file is unlimited from now on. Its open
	// connections still hold the old *Limits, so the buckets must be opened up
	// rather than merely dropped from the index.
	if prev != nil {
		for email, l := range prev.byEmail {
			if _, ok := idx.byEmail[email]; !ok {
				setRate(l.Up, 0)
				setRate(l.Down, 0)
				// The IP tally needs no such rescue. It is only ever reached through
				// the index, which no longer holds this account, so admission can
				// never consult it again; the limiters are different because an open
				// connection captured them in its io wrappers at dispatch time.
			}
		}
	}
	return idx, nil
}

// parsePrefix turns a sidecar ips entry into a prefix.
//
// The panel writer always emits CIDR, widening the bare addresses that the
// ppp-family paths produce to /32 or /128 before writing, so the fallback to a
// bare address here is tolerance for a hand-edited file rather than part of the
// contract. It is worth its few lines: a single bare address would otherwise
// invalidate the whole document and silently freeze every account's limit at its
// last good value.
//
// Prefix matching, not exact match, is required because ikev2 psk/eap-tls and
// wg-c map one account onto a whole block.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// rateOf maps the sidecar's "0 means this direction is unlimited" onto rate.Inf.
func rateOf(bps int64) rate.Limit {
	if bps <= 0 {
		return rate.Inf
	}
	return rate.Limit(bps)
}

// burstFor sizes a bucket at one second of traffic, floored at minBurst, so that
// an idle account may burst briefly to its nominal rate before being paced.
func burstFor(bps int64) int {
	if bps > maxBurst {
		return maxBurst
	}
	if bps < minBurst {
		return minBurst
	}
	return int(bps)
}

func setRate(l *rate.Limiter, bps int64) {
	l.SetLimit(rateOf(bps))
	l.SetBurst(burstFor(bps))
}
