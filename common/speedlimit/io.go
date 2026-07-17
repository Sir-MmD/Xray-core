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

// Writer paces a buf.Writer against one direction of an account's bucket.
//
// Shaping counts payload bytes only. Encryption overhead, padding and transport
// headers are added below this layer and are invisible here, so a limit measures
// a few percent under true wire rate.
type Writer struct {
	ctx     context.Context
	writer  buf.Writer
	limiter *rate.Limiter
}

// NewWriter wraps writer so its throughput is paced by limiter. A nil limiter
// returns writer untouched, so an unlimited direction costs nothing.
func NewWriter(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	if limiter == nil {
		return writer
	}
	return &Writer{ctx: ctx, writer: writer, limiter: limiter}
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 {
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
}

// NewReader wraps reader so its throughput is paced by limiter. A nil limiter
// returns reader untouched.
func NewReader(ctx context.Context, reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	if limiter == nil {
		return reader
	}
	return &Reader{ctx: ctx, reader: reader, limiter: limiter}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	// Pace after the read: the bytes have already arrived, so it is delaying their
	// hand-off upstream that pushes back on the sender's window.
	if n := int(mb.Len()); n > 0 {
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
