package services

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// How a job gets finished, and what it says when it fails.
//
// A platform job runs under ONE deadline (processNextJob's five minutes) that
// the slow part — talking to the device — is free to spend entirely. Everything
// after that, writing the findings, stamping the discovery job completed,
// handing it to the device job, ran on the same context. A run that used its
// budget collecting therefore failed at the very last step with
// "failed to mark job completed: context deadline exceeded": the device had
// answered, the results were in hand, and the job was reported failed for want
// of one UPDATE. A pod shutdown cancelling the worker's context ended the same
// way. [finalizeContext] is the answer: the work AFTER the device call gets its
// own bounded budget, derived from the job's context for its values but not its
// deadline or cancellation.

// finalizeBudget bounds the persistence and bookkeeping that follow a device
// interrogation. Generous against a handful of indexed writes; bounded so a
// wedged database cannot hold a worker forever.
const finalizeBudget = 2 * time.Minute

// failureStampBudget bounds the single UPDATE that annotates a failed job.
const failureStampBudget = 30 * time.Second

// finalizeContext returns a context that keeps ctx's values but not its
// deadline or cancellation, bounded by budget.
func finalizeContext(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), budget)
}

// withCause returns err unchanged unless its message is empty, in which case it
// names the error's type so the stored job text still says what failed. An
// error with no message is legal Go and renders as "failed to do X: " — a
// failure with its reason cut off, which is what a job row would otherwise
// carry.
func withCause(err error) error {
	if err == nil || strings.TrimSpace(err.Error()) != "" {
		return err
	}
	return fmt.Errorf("%T with no message: %w", err, err)
}

const (
	// maxJobErrorRunes caps a stored job-level error message.
	maxJobErrorRunes = 2000
	// jobErrorHeadRunes is how much of the START survives a cap: the context
	// that says which step failed.
	jobErrorHeadRunes = 300
)

// boundedErrorMessage caps msg at maxJobErrorRunes, never splitting a
// character. What gets elided is the MIDDLE: these strings are wrapped
// outermost-first ("failed to interrogate device: failed to mark job
// completed: <cause>"), so the step that failed is at the head and the real
// cause is at the tail, and a plain head-keeping cut drops exactly the part an
// operator needs.
func boundedErrorMessage(msg string) string {
	if utf8.RuneCountInString(msg) <= maxJobErrorRunes {
		return msg
	}
	const ellipsis = " … "
	runes := []rune(msg)
	tail := maxJobErrorRunes - jobErrorHeadRunes - utf8.RuneCountInString(ellipsis)
	return string(runes[:jobErrorHeadRunes]) + ellipsis + string(runes[len(runes)-tail:])
}

// storedErrorMessage is the form a job-level error takes in the database:
// secret material masked, then bounded.
func storedErrorMessage(msg string) string {
	return boundedErrorMessage(redactErrorMessage(msg))
}
