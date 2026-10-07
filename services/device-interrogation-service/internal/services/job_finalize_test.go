package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// emptyError is legal Go: an error whose message is "".
type emptyError struct{}

func (emptyError) Error() string { return "" }

func TestWithCause_NamesAnErrorThatSaysNothing(t *testing.T) {
	got := withCause(emptyError{})
	if !errors.Is(got, emptyError{}) {
		t.Fatalf("withCause dropped the error it wraps: %v", got)
	}
	if !strings.Contains(got.Error(), "services.emptyError") {
		t.Errorf("message %q does not name the failing error's type", got.Error())
	}
	// The stored text must not end where the cause should begin.
	stored := "failed to interrogate device: failed to mark job completed: " + got.Error()
	if strings.HasSuffix(strings.TrimSpace(stored), "completed:") {
		t.Errorf("stored text %q ends before its cause", stored)
	}

	plain := errors.New("pq: deadlock detected")
	if withCause(plain) != plain {
		t.Error("withCause rewrote an error that already has a message")
	}
	if withCause(nil) != nil {
		t.Error("withCause(nil) must stay nil")
	}
}

func TestBoundedErrorMessage_KeepsTheCauseAtTheTail(t *testing.T) {
	short := "failed to interrogate device: failed to mark job completed: context deadline exceeded"
	if got := boundedErrorMessage(short); got != short {
		t.Fatalf("a message under the cap was changed: %q", got)
	}

	head := "failed to interrogate device: failed to mark job completed: "
	cause := "pq: the real cause, which is last"
	long := head + strings.Repeat("é", 5000) + cause
	got := boundedErrorMessage(long)

	if n := utf8.RuneCountInString(got); n > maxJobErrorRunes {
		t.Errorf("bounded message is %d runes, cap is %d", n, maxJobErrorRunes)
	}
	if !utf8.ValidString(got) {
		t.Error("bounded message is not valid UTF-8 (a character was split)")
	}
	if !strings.HasPrefix(got, head) {
		t.Errorf("the step that failed was dropped: %.80q", got)
	}
	if !strings.HasSuffix(got, cause) {
		t.Errorf("the real cause was dropped: %q", got[len(got)-80:])
	}
	if !strings.Contains(got, "…") {
		t.Error("an elided message carries no ellipsis")
	}
}

func TestFinalizeContext_OutlivesTheJobsDeadline(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "v"), time.Millisecond)
	defer cancel()
	<-parent.Done()

	ctx, done := finalizeContext(parent, time.Minute)
	defer done()
	if err := ctx.Err(); err != nil {
		t.Fatalf("finalize context inherited the spent deadline: %v", err)
	}
	if ctx.Value(key{}) != "v" {
		t.Error("finalize context lost the parent's values")
	}
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > time.Minute {
		t.Errorf("finalize context is not bounded by its own budget (deadline %v, ok %v)", dl, ok)
	}
}
