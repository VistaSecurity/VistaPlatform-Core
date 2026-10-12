package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
)

var noWait = RetryPolicy{Attempts: 5, Backoff: time.Millisecond, Sleep: func(context.Context, time.Duration) {}}

func TestSubmitWithRetry_RecoversFromTransientFailure(t *testing.T) {
	calls := 0
	err := SubmitWithRetry(context.Background(), noWait, func() error {
		calls++
		if calls < 3 {
			return errors.New("connection reset")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d; want success on the third try", err, calls)
	}
}

func TestSubmitWithRetry_GivesUpAfterTheBound(t *testing.T) {
	calls := 0
	err := SubmitWithRetry(context.Background(), noWait, func() error { calls++; return errors.New("down") })
	if err == nil || calls != 5 {
		t.Fatalf("err=%v calls=%d; want 5 attempts then the error", err, calls)
	}
}

func TestSubmitWithRetry_DoesNotRetryAPermanentRejection(t *testing.T) {
	calls := 0
	err := SubmitWithRetry(context.Background(), noWait, func() error {
		calls++
		return &SubmitStatusError{StatusCode: http.StatusBadRequest, Body: "bad"}
	})
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d; a 400 must not be retried", err, calls)
	}
}

// Through the REAL client: a platform that answers 503 twice and then 200 gets
// the result exactly once more.
//
// Mutation: make RetryingSubmitter.SubmitResult call r.Client.SubmitResult
// directly (single shot) and this fails with the first 503.
func TestRetryingSubmitter_DeliversThroughRealClientAfterBlips(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String(), DataPath: t.TempDir()})
	rs := &RetryingSubmitter{Client: c, Policy: noWait}
	if err := rs.SubmitResult(&models.JobResult{JobID: uuid.New(), Success: true}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3", hits.Load())
	}
}
