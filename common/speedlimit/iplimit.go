package speedlimit

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
)

// strategyAccept is the sidecar's word for evict-oldest; every other value,
// including the absent field of a document written before the field existed, is
// "reject".
//
// The two words are the VPN User Limit's existing vocabulary, spelled the same
// here on purpose: the panel has one strategy setting per account and it must
// not mean one thing on l2tp and another on vless.
const strategyAccept = "accept"

// errEvicted is what an evicted connection's next read or write returns.
//
// One shared value, built once: it carries no per-connection detail, and the
// kill sets a flag rather than formatting anything, so that evicting an address
// with many connections open costs nothing per connection.
var errEvicted = errors.New("speedlimit: connection evicted, a newer address took the account's IP slot")

// conn is one dispatch's kill state, and the whole of what makes a connection
// evictable.
//
// It is per CONNECTION, not per account: eviction takes ONE address's
// connections and must leave the account's other addresses untouched.
//
// killed is written by whichever goroutine admits the evicting connection and
// read by this connection's io wrappers, so it is atomic rather than guarded by
// ipMu. The wrappers see every buffer, and taking an account-wide lock on each
// of them would funnel the account's entire throughput through the admission
// lock.
type conn struct {
	killed atomic.Bool

	// mu guards links, which the io wrappers append to as the dispatcher builds
	// this connection's chain while another goroutine may be evicting it. It
	// cannot be folded into the atomic above, and it is never held while ipMu is
	// taken, only the other way round (see evictOldestIP).
	mu sync.Mutex
	// links are the objects this connection's io wrappers pace, which at both
	// dispatcher seams are its pipes. kill interrupts them.
	links []any
}

// track records an object an io wrapper is about to pace, so that kill can
// interrupt it. See kill for why the flag alone is not enough.
func (c *conn) track(o any) {
	c.mu.Lock()
	c.links = append(c.links, o)
	c.mu.Unlock()
}

// kill evicts this connection: it flags it AND interrupts everything it has
// open.
//
// The interrupt is not belt-and-braces, it is the eviction. Flagging alone was
// the original bug: a wrapper only tests the flag BETWEEN buffers, but a writer
// whose downstream pipe is full parks INSIDE pipe.WriteMultiBuffer waiting for
// the reader to drain it, and never returns to the test. That is not a corner
// case, it is the steady state of every connection whose client is slower than
// its origin, which is precisely the connection an operator wants evicted. The
// kill was therefore deferred by roughly (pipe depth / client drain rate), which
// measured 25s against a 60KB/s client and 3s against a 300KB/s one, and is
// unbounded for a client that stops reading altogether.
//
// Interrupting is how upstream already tears a link down (the outbound handler
// does it on every error), and it does the two things the flag cannot: it
// unblocks the parked writer at once, and it DISCARDS the bytes already sitting
// in the pipe, which the flag would otherwise let drain to the very client being
// evicted.
//
// The flag is kept for two reasons. It is what makes the wrapper report
// errEvicted rather than an anonymous io.ErrClosedPipe, and the outbound handler
// turns that error into the Interrupt (not Close) branch, so the rest of the
// chain is torn down rather than drained. And it alone covers a wrapper built
// after this point: track then appends to a list nothing will read again, but
// such a wrapper has not blocked yet and its first buffer tests the flag.
func (c *conn) kill() {
	c.killed.Store(true)

	c.mu.Lock()
	links := c.links
	c.links = nil
	c.mu.Unlock()

	// Interrupted outside c.mu: these run foreign code (pipe.Interrupt takes the
	// pipe's own lock), and nothing downstream of a pipe reaches back into this
	// package, so ipMu -> pipe lock cannot cycle.
	for _, o := range links {
		common.Interrupt(o)
	}
}

// connKey types the context value carrying the eviction token.
type connKey struct{}

// connFromContext returns the token Admit put on the dispatch context, or nil
// when the connection is not evictable: no IP limit, or a caller that never went
// through Admit at all, such as the VLESS reverse-proxy mux, which reaches
// WrapLink directly (proxy/vless/inbound/inbound.go).
func connFromContext(ctx context.Context) *conn {
	c, _ := ctx.Value(connKey{}).(*conn)
	return c
}

// ipEntry is one live source address of one account.
//
// The set of connections IS the refcount: len(conns). Holding the connections
// themselves rather than a bare counter is what makes "accept" possible, since
// evicting an address means killing exactly the connections that address has
// open, and it is also what lets a release tell its own entry from a later one
// (see releaseIP).
//
// firstSeen is stamped when the address takes its slot and is never refreshed,
// so "oldest" means the address that has held its slot longest, not the least
// recently used one. That is the reference implementation's rule
// (web/service/ssh_server.go admit) and it is the predictable one: a device's
// slot cannot be taken back by its own idleness.
type ipEntry struct {
	firstSeen time.Time
	conns     map[*conn]struct{}
}

// Admit applies an account's limit on concurrent distinct source IPs, reserving
// a slot for this dispatch and releasing it when ctx is done.
//
// It returns a context carrying this connection's eviction token, which the io
// wrappers read back out in NewWriter/NewReader. That is the whole of the
// plumbing for the "accept" strategy: getLink and WrapLink are already called
// with this context, so nothing in app/dispatcher has to learn that the token
// exists. The returned context is the argument itself for every connection that
// reserved nothing, so an unlimited account allocates nothing here.
//
// At K, "reject" refuses by returning an error, which the inbound proxy turns
// into a closed client connection: nothing has been allocated yet and no byte
// has flowed. "accept" instead evicts the account's oldest address and admits
// the newcomer.
//
// The slot is released through context.AfterFunc, exactly as trackOnlineIP does
// in the dispatcher, and that release is the whole safety argument. All three
// inbound workers cancel the dispatch context as soon as the proxy stops
// handling the connection (app/proxyman/inbound/worker.go: tcpWorker.callback
// cancels after Process returns, dsWorker.callback likewise, and udpWorker hands
// its cancel to udpConn.Close). So a slot cannot outlive the connection holding
// it, which is the one failure mode that would matter: a leaked refcount would
// lock the account out of its own service, indistinguishable from the fail2ban
// behaviour this replaces.
//
// Errors are only ever returned for a real refusal. Anything the limiter cannot
// evaluate (no session, no source IP) is admitted, because failing open costs an
// unenforced limit while failing closed costs the account its service.
//
// Both dispatcher entry points must call this. Gating only one would miss half
// the protocols: Dispatch carries vmess, trojan, shadowsocks and every mux
// sub-stream, while DispatchLink carries vless, socks, dokodemo, http and the
// rest.
//
// Mux is the one case where the context is coarser than a connection.
// mux.ServerWorker dispatches each sub-stream on a context derived from the
// whole muxed connection's (common/mux/server.go handleStatusNew, whose
// SubContextFromMuxInbound only adds values), so a sub-stream's refcount is not
// released when that sub-stream ends, only when the muxed connection does. That
// is correct for an IP limit rather than merely tolerable: the sub-streams share
// one source address, so they are one entry with a high refcount, and the entry
// is freed when the connection that owns the address really is gone. It does
// mean the refcount is not a connection count, and that a long-lived muxed
// connection accumulates one pending AfterFunc per sub-stream, exactly as
// upstream's trackOnlineIP already does.
func Admit(ctx context.Context) (context.Context, error) {
	// The disabled case: no sidecar path, no table, no work. An unpatched
	// deployment pays one nil compare per dispatch.
	if defaultTable == nil {
		return ctx, nil
	}
	return defaultTable.admit(ctx)
}

func (t *table) admit(ctx context.Context) (context.Context, error) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return ctx, nil
	}
	// Same resolution as the rate limiter: the email if the protocol carries one,
	// otherwise the account that owns the source address. Read, never written back
	// onto user.Email.
	l := t.lookupSession(inbound.User, inbound)
	if l == nil {
		// Not in the sidecar at all, so unlimited. This is the common case and it
		// costs one map miss and no allocation.
		return ctx, nil
	}
	c, release, err := l.admitIP(inbound)
	if err != nil {
		return ctx, err
	}
	// A nil release means no slot was reserved, so there is nothing to release and
	// nothing that could be evicted. Only release what was allocated: neither a
	// refused dispatch nor an IP-unlimited one may decrement anything.
	if release == nil {
		return ctx, nil
	}
	context.AfterFunc(ctx, release)
	return context.WithValue(ctx, connKey{}, c), nil
}

// sourceAddr canonicalises the client's source address into a map key.
//
// The port is deliberately dropped: the unit being limited is the address, not
// the connection.
func sourceAddr(inbound *session.Inbound) (netip.Addr, bool) {
	// Address.IP() panics on a domain address, hence the family check.
	if inbound.Source.Address == nil || !inbound.Source.Address.Family().IsIP() {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(inbound.Source.Address.IP())
	if !ok {
		return netip.Addr{}, false
	}
	// net.IP carries IPv4 in 16-byte v4-in-v6 form as often as not, and the two
	// forms are different netip.Addr values. Without the unmap one device could key
	// two entries and burn two of its K slots.
	return addr.Unmap(), true
}

// admitIP reserves a slot for the connection's source address and returns its
// kill flag and the release to run when it ends. A nil release with a nil error
// means no slot was reserved and nothing must be released.
//
// The results are deliberately unnamed. The release closure captures the kill
// flag, and a captured NAMED result is declared at function entry, so naming it
// would heap-allocate its cell on every call, including the early returns that
// an account with no IP limit takes on every single dispatch.
func (l *Limits) admitIP(inbound *session.Inbound) (*conn, func(), error) {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()

	if l.ipLimit <= 0 {
		return nil, nil, nil
	}
	// Resolved inside the lock, after the K check, and not before it: Address.IP()
	// allocates, because common/net's ipv4Address is an array whose slice escapes.
	// An account with only a rate limit must not pay that on every dispatch.
	addr, valid := sourceAddr(inbound)
	if !valid {
		// No source address to count. There is nothing to enforce, and refusing
		// would break the account on a transport that presents none.
		return nil, nil, nil
	}
	e := l.ips[addr]
	switch {
	case e != nil:
		// A known IP is ALWAYS admitted, no matter how many slots are taken. One
		// device routinely opens dozens of concurrent connections, so refusing its
		// 50th would break ordinary browsing while protecting nothing: the slot is
		// the address, and this address already holds one.
	case len(l.ips) < l.ipLimit:
		if l.ips == nil {
			l.ips = make(map[netip.Addr]*ipEntry, l.ipLimit)
		}
	case l.evictOldest:
		// Exactly one address is evicted per admission, never a sweep down to K.
		// Only a reload that lowers K on a live account can leave the tally above
		// K, and evicting the excess in one go would kill several of the account's
		// devices for an operator's edit; letting it drain by attrition, one
		// address per newcomer, mirrors the reference implementation.
		l.evictOldestIP()
	default:
		// Formatting here costs an allocation, but only on the refusal path, which
		// is rare by construction and is the one place an operator needs to be told
		// what happened: with the access log off by default, this line is all they
		// get.
		return nil, nil, errors.New("speedlimit: refusing ", addr.String(), ": account is at its limit of ", l.ipLimit, " concurrent IPs")
	}
	if e == nil {
		e = &ipEntry{firstSeen: time.Now(), conns: make(map[*conn]struct{}, 1)}
		l.ips[addr] = e
	}
	c := &conn{}
	e.conns[c] = struct{}{}
	return c, func() { l.releaseIP(addr, c) }, nil
}

// evictOldestIP frees the slot held by the account's earliest-seen address and
// kills every connection that address has open. ipMu is held.
//
// The kill is immediate rather than advisory: conn.kill interrupts the victim's
// pipes instead of merely asking its io wrappers to notice a flag next time they
// pass one. Nothing here owns the victim's connection or its context (the
// inbound worker does, and it cancels only once the proxy has already finished
// with it), so interrupting what it reads and writes is the whole of the reach
// this side has, and it is enough: the proxies' copy loops take the error and
// unwind the connection from both ends.
func (l *Limits) evictOldestIP() {
	var oldestAddr netip.Addr
	var oldest *ipEntry
	for addr, e := range l.ips {
		// The address breaks ties so that the choice is deterministic. Map iteration
		// order is not, and two addresses admitted in the same clock tick would
		// otherwise evict a different one on every run.
		if oldest == nil || e.firstSeen.Before(oldest.firstSeen) ||
			(e.firstSeen.Equal(oldest.firstSeen) && addr.Compare(oldestAddr) < 0) {
			oldestAddr, oldest = addr, e
		}
	}
	if oldest == nil {
		return
	}
	// The slot frees HERE, not when the victims notice: the newcomer is admitted
	// in the same critical section and must find room. The victims' releases are
	// already registered and will fire when their contexts are cancelled; they
	// find their entry gone and decrement nothing (see releaseIP).
	delete(l.ips, oldestAddr)
	for c := range oldest.conns {
		c.kill()
	}
	errors.LogInfo(context.Background(), "speedlimit: evicting ", oldestAddr.String(), " and its ", len(oldest.conns),
		" connection(s): the account is at its limit of ", l.ipLimit, " concurrent IPs and strategy is accept")
}

func (l *Limits) releaseIP(addr netip.Addr, c *conn) {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()

	e := l.ips[addr]
	if e == nil {
		return
	}
	// Identity, not a bare refcount. An evicted connection's entry is gone, and by
	// the time its context is cancelled the same address may have dialled back in
	// and built a NEW entry; decrementing that one would charge a live address for
	// a connection that was never its own, and two evicted connections would free
	// its slot outright.
	if _, ok := e.conns[c]; !ok {
		return
	}
	delete(e.conns, c)
	if len(e.conns) == 0 {
		// The address frees the instant its last connection ends. That exactness is
		// the entire point of refcounting here: there is no staleness window, so
		// there is no idle guess to get wrong and no way to ban an address that is
		// still in use.
		delete(l.ips, addr)
	}
}

// setIPLimit changes K and the strategy in place, on the same object open
// connections already hold, so a reload never disturbs them.
//
// Lowering K below the number of addresses already live evicts nobody at reload
// time: they keep their slots, because a known IP is always admitted. Under
// "reject" the account simply takes on no new address until it falls back under
// K; under "accept" each new address evicts one incumbent, so the tally drains
// toward K rather than being cut down to it in one edit.
//
// The tally is deliberately not cleared, for two reasons. Releases for
// connections admitted under the old K are still pending and must still find
// their entries. And while an account is unlimited nothing is recorded, so a
// limit that is removed and later restored resumes with a tally that can only
// UNDER-count the live addresses. That direction is the safe one: it admits an
// address it might have refused, and self-heals as connections cycle, whereas
// over-counting would refuse a device that is not there.
func (l *Limits) setIPLimit(k int, strategy string) {
	l.ipMu.Lock()
	l.ipLimit = k
	l.evictOldest = strategy == strategyAccept
	l.ipMu.Unlock()
}
