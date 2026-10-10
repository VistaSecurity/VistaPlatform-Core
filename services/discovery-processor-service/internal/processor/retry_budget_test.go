package processor

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The ladder: base honoured, doubling, capped. Mutations that turn it red:
// reintroduce a floor above the base, drop the cap, or ignore the base.
func TestRetryPolicy_BackoffLadder(t *testing.T) {
	def := DefaultRetryPolicy()
	if def.MaxAttempts < 6 {
		t.Fatalf("default MaxAttempts = %d, want at least 6", def.MaxAttempts)
	}
	var total time.Duration
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		if got := def.Backoff(i); got != w {
			t.Errorf("default Backoff(%d) = %v, want %v", i, got, w)
		}
		if i < def.MaxAttempts-1 {
			total += def.Backoff(i)
		}
	}
	if total < 15*time.Minute {
		t.Errorf("default ladder waits %v in total, want it to cover a rolling restart (>= 15m)", total)
	}

	// The base knob is honoured exactly, below any old 5s floor, and the cap holds.
	p := RetryPolicy{MaxAttempts: 8, BackoffBase: time.Second, BackoffCap: 10 * time.Second}
	for i, w := range []time.Duration{1, 2, 4, 8, 10, 10, 10, 10} {
		if got := p.Backoff(i); got != w*time.Second {
			t.Errorf("base=1s Backoff(%d) = %v, want %v", i, got, w*time.Second)
		}
	}
	if got := p.Backoff(1000); got != 10*time.Second {
		t.Errorf("Backoff(1000) = %v, want the cap", got)
	}
	ms := p.ladderMillis()
	if len(ms) != 8 || ms[0] != 1000 || ms[7] != 10000 {
		t.Errorf("ladderMillis = %v", ms)
	}

	// SetRetryPolicy keeps a small base and never lets the cap undercut it.
	var bp BatchProcessor
	bp.SetRetryPolicy(RetryPolicy{BackoffBase: 2 * time.Second})
	if got := bp.retryPolicy().Backoff(0); got != 2*time.Second {
		t.Errorf("configured base 2s gave first backoff %v", got)
	}
	bp.SetRetryPolicy(RetryPolicy{BackoffBase: 20 * time.Minute})
	if got := bp.retryPolicy().Backoff(3); got != 20*time.Minute {
		t.Errorf("base above the default cap gave %v, want the base", got)
	}
}

func TestTruncateError_StripsNULAndStaysValidUTF8(t *testing.T) {
	got := truncateError(errString("bad\x00 body \x00x"))
	if strings.ContainsRune(got, 0) || got != "bad body x" {
		t.Fatalf("truncateError = %q, want NUL bytes removed", got)
	}
	// NUL at the truncation boundary, and a multibyte rune cut by it.
	long := strings.Repeat("a", maxProcessErrorLen-1) + "\x00" + "tail"
	if g := truncateError(errString(long)); strings.ContainsRune(g, 0) {
		t.Fatalf("NUL survived truncation")
	}
	multi := strings.Repeat("a", maxProcessErrorLen-1) + "é" // 2-byte rune straddles the cut
	g := truncateError(errString(multi))
	if !utf8.ValidString(g) || len(g) > maxProcessErrorLen {
		t.Fatalf("truncated error invalid (valid=%v len=%d)", utf8.ValidString(g), len(g))
	}
}

type errString string

func (e errString) Error() string { return string(e) }
