package jobs

// Job-execution logging for the stale-asset detector.
//
// Two things are pinned here:
//
//  1. The cycle ALWAYS logs over the HTTP JobLogger. It used to publish to the
//     NATS subject audit.job-execution first and skip the HTTP logger whenever
//     that publish succeeded — which it always did, since the AUDIT stream
//     matches audit.> and the client falls back to core NATS. Nothing has ever
//     subscribed to that subject, so the only transport that reaches
//     audit.job_execution_logs was disabled precisely when the dead one worked
//     and no row was ever written for stale_asset_detection.
//
//  2. Every exit emits a completion. The tenant-query error and the
//     zero-tenants case both used to return after logging a start, leaving an
//     execution that reads as still running forever.
//
// No database and no audit-service: the cycle's two seams (listTenants,
// newJobLogger) are substituted, which is why both early returns are reachable
// at all — on a shared Postgres "no tenants have assets" is not reproducible.

import (
	"context"
	"errors"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
)

// recordingJobLog captures what a cycle logged.
type recordingJobLog struct {
	starts      int
	progress    int
	completions []completionCall
}

type completionCall struct {
	status    string
	processed int
	succeeded int
	failed    int
	errMsg    *string
	metadata  map[string]interface{}
}

func (r *recordingJobLog) LogStart(context.Context, map[string]interface{}) (uuid.UUID, error) {
	r.starts++
	return uuid.New(), nil
}

func (r *recordingJobLog) LogProgress(context.Context, int, int, int) error {
	r.progress++
	return nil
}

func (r *recordingJobLog) LogCompletion(_ context.Context, status string, processed, succeeded, failed int, errMsg *string, metadata map[string]interface{}) error {
	r.completions = append(r.completions, completionCall{status, processed, succeeded, failed, errMsg, metadata})
	return nil
}

// newLoggingDetector builds a detector whose only wired behaviour is job
// logging: no DB handles, so any path that reaches per-tenant work would panic
// rather than pass silently.
func newLoggingDetector(t *testing.T, tenants []uuid.UUID, listErr error) (*StaleAssetDetector, *recordingJobLog) {
	t.Helper()
	rec := &recordingJobLog{}
	d := &StaleAssetDetector{
		logger:       log.New(log.Writer(), "[test] ", 0),
		interval:     time.Hour,
		newJobLogger: func(uuid.UUID) jobExecutionLog { return rec },
		listTenants:  func() ([]uuid.UUID, error) { return tenants, listErr },
	}
	return d, rec
}

func TestStaleAssetDetector_TenantQueryError_LogsFailedCompletion(t *testing.T) {
	d, rec := newLoggingDetector(t, nil, errors.New("enumerate boom"))

	d.detectStaleAssets(context.Background())

	if rec.starts != 1 {
		t.Fatalf("expected exactly one job start over HTTP, got %d", rec.starts)
	}
	if len(rec.completions) != 1 {
		t.Fatalf("a start with no completion reads as still running: got %d completions", len(rec.completions))
	}
	got := rec.completions[0]
	if got.status != "failed" {
		t.Errorf("status = %q, want %q", got.status, "failed")
	}
	if got.errMsg == nil || *got.errMsg != "enumerate boom" {
		t.Errorf("completion must carry the enumerator error, got %v", got.errMsg)
	}
}

func TestStaleAssetDetector_ZeroTenants_LogsCompletedCompletion(t *testing.T) {
	d, rec := newLoggingDetector(t, nil, nil)

	d.detectStaleAssets(context.Background())

	if rec.starts != 1 {
		t.Fatalf("expected exactly one job start over HTTP, got %d", rec.starts)
	}
	if len(rec.completions) != 1 {
		t.Fatalf("a start with no completion reads as still running: got %d completions", len(rec.completions))
	}
	got := rec.completions[0]
	if got.status != "completed" {
		t.Errorf("status = %q, want %q", got.status, "completed")
	}
	if got.errMsg != nil {
		t.Errorf("nothing failed, so the completion must carry no error: %v", *got.errMsg)
	}
	if got.processed != 0 {
		t.Errorf("processed = %d, want 0", got.processed)
	}
	if n, ok := got.metadata["tenants_processed"]; !ok || n != 0 {
		t.Errorf("metadata tenants_processed = %v (present=%v), want 0", n, ok)
	}
}

// The real constructor must wire the HTTP JobLogger unconditionally — there is
// no NATS branch left that could replace it.
func TestStaleAssetDetector_AlwaysWiresHTTPJobLogger(t *testing.T) {
	d := NewStaleAssetDetector(nil, nil, nil)
	if d.newJobLogger == nil {
		t.Fatal("newJobLogger must be wired by the constructor")
	}
	if d.newJobLogger(uuid.New()) == nil {
		t.Fatal("constructor must produce a real job logger")
	}
	if d.listTenants == nil {
		t.Fatal("listTenants must be wired by the constructor")
	}
}
