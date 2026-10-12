package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
)

// SubmitStatusError is a result submission the platform answered with a
// non-success status. It is typed so the retry policy can tell a transient
// answer (5xx, 429) from one that will never succeed (a 4xx rejecting the
// payload), instead of retrying both for two minutes.
type SubmitStatusError struct {
	StatusCode int
	Body       string
}

func (e *SubmitStatusError) Error() string {
	return fmt.Sprintf("failed to submit result: %s (status: %d)", e.Body, e.StatusCode)
}

// Retryable reports whether the same request may succeed later.
func (e *SubmitStatusError) Retryable() bool {
	switch e.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return e.StatusCode >= 500
}

// RetryPolicy bounds how hard a finished job's result is pushed to the
// platform. By the time a result exists the credentials are already cleared and
// the device was already interrogated, so a single network blip would otherwise
// throw the whole interrogation away.
type RetryPolicy struct {
	// Attempts is the total number of tries, including the first.
	Attempts int
	// Backoff is the wait before the second try; it doubles each time.
	Backoff time.Duration
	// Sleep waits d, or returns early when ctx is done. Nil means a real timer.
	Sleep func(ctx context.Context, d time.Duration)
}

// DefaultSubmitRetry is 5 attempts with 8s, 16s, 32s, 64s between them: about
// two minutes in all. There is deliberately no on-disk spool behind it — a
// result still undelivered after that is lost, which is a follow-up.
var DefaultSubmitRetry = RetryPolicy{Attempts: 5, Backoff: 8 * time.Second}

// SubmitWithRetry calls submit until it succeeds, fails permanently, runs out of
// attempts, or ctx is cancelled during a wait.
func SubmitWithRetry(ctx context.Context, p RetryPolicy, submit func() error) error {
	if p.Attempts < 1 {
		p.Attempts = 1
	}
	sleep := p.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		}
	}
	wait := p.Backoff
	var err error
	for attempt := 1; attempt <= p.Attempts; attempt++ {
		if err = submit(); err == nil {
			return nil
		}
		var status *SubmitStatusError
		if errors.As(err, &status) && !status.Retryable() {
			return err
		}
		if attempt == p.Attempts || ctx.Err() != nil {
			break
		}
		log.Printf("⚠️  Result submission failed (attempt %d of %d), retrying in %v: %v", attempt, p.Attempts, wait, err)
		sleep(ctx, wait)
		if ctx.Err() != nil {
			break
		}
		wait *= 2
	}
	return err
}

// RetryingSubmitter posts job results through SubmitWithRetry.
type RetryingSubmitter struct {
	Client interface {
		SubmitResult(*models.JobResult) error
	}
	Policy RetryPolicy
}

// SubmitResult submits result, retrying transient failures.
func (r *RetryingSubmitter) SubmitResult(result *models.JobResult) error {
	// Not tied to the agent's shutdown context: a result in flight at SIGTERM
	// is exactly the one worth delivering. The shutdown wait bounds it.
	return SubmitWithRetry(context.Background(), r.Policy, func() error { return r.Client.SubmitResult(result) })
}
