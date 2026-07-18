package speedlimit

import (
	"testing"

	"github.com/xtls/xray-core/common/session"
)

// A limited session must never take the splice path. Pacing lives in the buf
// Reader/Writer wrappers; splice (proxy.CopyRawConnIfExist -> tc.ReadFrom) moves bytes
// kernel-to-kernel and never touches them, so a spliced connection is silently
// unlimited. That is the shape every dokodemo-based VPN protocol arrives in, which is
// how the limiter came to do nothing at all for them.
func TestDisableSpliceMarksSessionIneligible(t *testing.T) {
	in := &session.Inbound{CanSpliceCopy: 1} // what dokodemo-door sets
	DisableSplice(in)
	if in.CanSpliceCopy != 3 {
		t.Fatalf("CanSpliceCopy = %d, want 3 (cannot splice); a limited session would be paced only on paper", in.CanSpliceCopy)
	}
}

// The dispatcher calls this on every limited session, including ones where the inbound
// is absent, so it must not panic.
func TestDisableSpliceNilSafe(t *testing.T) {
	DisableSplice(nil)
}

// Already-ineligible sessions stay ineligible (3 is terminal, not toggled).
func TestDisableSpliceIdempotent(t *testing.T) {
	in := &session.Inbound{CanSpliceCopy: 3}
	DisableSplice(in)
	if in.CanSpliceCopy != 3 {
		t.Fatalf("CanSpliceCopy = %d, want 3", in.CanSpliceCopy)
	}
}
