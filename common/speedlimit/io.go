package speedlimit

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// wait blocks until n bytes' worth of tokens are available.
//
// It asks for tokens in chunks no larger than the bucket's depth because
// rate.Limiter.WaitN REPORTS AN ERROR, rather than blocking and draining, when a
// single request exceeds the burst (rate.go: "n > burst && limit != Inf"). Xray
// hands whole buf.MultiBuffers to the writers, so an unchunked WaitN would fail
// every write on a slow account rather than pace it. Chunking the token requests
// rather than the payload keeps the write itself atomic while the pacing still
// accounts for every byte.
//
// ctx is the dispatch context, so a closed connection aborts the wait instead of
// parking a goroutine on a bucket nobody is draining.
//
// Both TCP and UDP are paced by blocking. For UDP that trades loss for latency,
// since a token bucket delays rather than drops; an over-limit UDP flow queues
// instead of shedding. That is a deliberate first cut: blocking is what makes TCP
// back-pressure work, and the dispatcher does not cheaply separate the two paths.
// Revisit with AllowN-and-drop on the UDP path if latency proves worse than loss.
func wait(ctx context.Context, l *rate.Limiter, n int) error {
	for n > 0 {
		c := l.Burst()
		// Burst is only ever below n on a misconfigured bucket; hand the request
		// over whole and let WaitN report it rather than spin here.
		if c <= 0 || c > n {
			c = n
		}
		if err := l.WaitN(ctx, c); err != nil {
			return err
		}
		n -= c
	}
	return nil
}

// Writer paces a buf.Writer against one direction of an account's bucket, and
// carries the eviction token that lets the IP limiter stop it.
//
// Shaping counts payload bytes only. Encryption overhead, padding and transport
// headers are added below this layer and are invisible here, so a limit measures
// a few percent under true wire rate.
type Writer struct {
	ctx     context.Context
	writer  buf.Writer
	limiter *rate.Limiter
	conn    *conn
}

// NewWriter wraps writer so that its throughput is paced by limiter and an
// eviction stops it.
//
// The token is taken from ctx rather than passed in, because ctx is what the
// dispatcher already hands to both seams; see Admit.
//
// The writer is returned untouched only when there is NEITHER a limiter nor a
// token, so an unlimited direction on a connection that cannot be evicted still
// costs nothing. A limiter is kept even at rate.Inf, since a reload can re-rate
// it under a connection that is already open. A token is kept even with no
// limiter at all, which is the account that has an ipLimit and no speed limit:
// without this wrapper its eviction would set a flag nothing ever reads.
func NewWriter(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	c := connFromContext(ctx)
	if limiter == nil && c == nil {
		return writer
	}
	if c != nil {
		// Handed to the token so an eviction can interrupt this writer where it
		// parks, rather than wait for it to come back and test the flag. A full
		// pipe blocks inside the write below for as long as the client takes to
		// drain it, which is forever for a client that has stopped reading.
		c.track(writer)
	}
	return &Writer{ctx: ctx, writer: writer, limiter: limiter, conn: c}
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// Checked before the write, so an evicted connection cannot push one more
	// buffer. This is where "accept" lands: the proxy's copy loop takes the error,
	// closes the connection, the inbound worker cancels its context, and the
	// release Admit registered frees whatever is left.
	if w.conn != nil && w.conn.killed.Load() {
		buf.ReleaseMulti(mb)
		return errEvicted
	}
	if n := int(mb.Len()); n > 0 && w.limiter != nil {
		if err := wait(w.ctx, w.limiter, n); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return w.writer.WriteMultiBuffer(mb)
}

// Close and Interrupt forward to the wrapped writer. Xray tears a link down
// through these, so swallowing them here would leak the pipe. SizeStatWriter,
// which sits in the same position in the chain, does the same.
func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) Interrupt() {
	common.Interrupt(w.writer)
}

// Reader paces a buf.Reader against one direction of an account's bucket.
//
// It must sit INSIDE buf.TimeoutWrapperReader, never outside it: the dispatcher
// type-asserts link.Reader to *buf.TimeoutWrapperReader to attach the uplink
// stats counter, and DispatchLink asserts it to buf.TimeoutReader before
// sniffing. Wrapping from the outside would panic both.
type Reader struct {
	ctx     context.Context
	reader  buf.Reader
	limiter *rate.Limiter
	conn    *conn
}

// NewReader wraps reader so that its throughput is paced by limiter and an
// eviction stops it. See NewWriter for when the wrapper is skipped.
func NewReader(ctx context.Context, reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	c := connFromContext(ctx)
	if limiter == nil && c == nil {
		return reader
	}
	if c != nil {
		// See NewWriter: a read parks on a client that may never speak again.
		c.track(reader)
	}
	return &Reader{ctx: ctx, reader: reader, limiter: limiter, conn: c}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// Checked before the read, not after it: an evicted connection must not go
	// back to waiting on a client that may never send another byte.
	if r.conn != nil && r.conn.killed.Load() {
		return nil, errEvicted
	}
	mb, err := r.reader.ReadMultiBuffer()
	// Pace after the read: the bytes have already arrived, so it is delaying their
	// hand-off upstream that pushes back on the sender's window.
	if n := int(mb.Len()); n > 0 && r.limiter != nil {
		if werr := wait(r.ctx, r.limiter, n); werr != nil {
			buf.ReleaseMulti(mb)
			return nil, werr
		}
	}
	return mb, err
}

func (r *Reader) Close() error {
	return common.Close(r.reader)
}

func (r *Reader) Interrupt() {
	common.Interrupt(r.reader)
}
