package backups

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

type forRunOut struct {
	res ForRunResult
	err error
}

// startForRun runs TakeForRun in the background and returns the backup row it
// created once its Job exists.
func startForRun(t *testing.T, bh *backupsHarness, runID uuid.UUID) (Backup, chan forRunOut) {
	t.Helper()
	old := forRunPoll
	forRunPoll = 5 * time.Millisecond
	t.Cleanup(func() { forRunPoll = old })
	out := make(chan forRunOut, 1)
	go func() {
		res, err := bh.svc.TakeForRun(context.Background(), runID)
		out <- forRunOut{res, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := bh.store.GetByRun(context.Background(), runID); err == nil {
			if _, err := bh.client.BatchV1().Jobs(backupsTestNS).Get(context.Background(), JobName(b.ID), metav1.GetOptions{}); err == nil {
				return b, out
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("TakeForRun never created its Job")
	return Backup{}, nil
}

func TestTakeForRun_DatabaseOnlyBackupUnderTheCallingRun(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	runID := uuid.New()
	b, out := startForRun(t, bh, runID)
	job, _ := bh.client.BatchV1().Jobs(backupsTestNS).Get(context.Background(), JobName(b.ID), metav1.GetOptions{})
	if job.Labels[runs.LabelRunID] != runID.String() || job.Spec.Template.Labels[runs.LabelRunID] != runID.String() {
		t.Fatalf("job labels %v", job.Labels)
	}
	if b.Contents.Secrets || b.Encrypted || b.RunID == nil || *b.RunID != runID {
		t.Fatalf("backup row %+v", b)
	}
	bh.completeJob(b, dumpBytes(t, 500))
	r := <-out
	if r.err != nil {
		t.Fatal(r.err)
	}
	got, _ := bh.store.Get(context.Background(), b.ID)
	if got.Status != StatusReady || got.Manifest == nil || got.Encrypted || filepath.Ext(got.FilePath) != ".tar" {
		t.Fatalf("stored %+v", got)
	}
	if r.res.Backup.Status != StatusReady || r.res.Backup.SizeBytes == nil {
		t.Fatalf("result %+v", r.res.Backup)
	}
	if _, err := bh.client.BatchV1().Jobs(backupsTestNS).Get(context.Background(), JobName(b.ID), metav1.GetOptions{}); err == nil {
		t.Fatal("the backup Job was not deleted")
	}
	// No run of its own: the caller's run is the only one.
	if list, _ := bh.runs.List(context.Background(), 10); len(list) != 0 {
		t.Fatalf("TakeForRun opened %d run(s)", len(list))
	}
	if rb, _ := bh.svc.RecentReady(context.Background(), time.Now().Add(-time.Hour)); rb == nil || rb.ID != b.ID {
		t.Fatalf("RecentReady = %+v", rb)
	}
	if rb, _ := bh.svc.RecentReady(context.Background(), time.Now().Add(time.Hour)); rb != nil {
		t.Fatalf("RecentReady in the future = %+v", rb)
	}
}

func TestTakeForRun_JobFailureFailsTheBackup(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	b, out := startForRun(t, bh, uuid.New())
	dir := filepath.Join(bh.root, b.ID.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bh.setJob(JobName(b.ID), batchv1.JobFailed)
	r := <-out
	if !errors.Is(r.err, ErrForRunFailed) {
		t.Fatalf("err = %v", r.err)
	}
	if got, _ := bh.store.Get(context.Background(), b.ID); got.Status != StatusFailed {
		t.Fatalf("status %s", got.Status)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the failed backup's files were left on the volume")
	}
}

func TestTakeForRun_UnavailableAndFailRunning(t *testing.T) {
	off := NewService(Config{}, nil, nil, nil, nil)
	if _, err := off.TakeForRun(context.Background(), uuid.New()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	bh := newBackupsHarness(t, 5)
	runID := uuid.New()
	id := uuid.New()
	if err := bh.store.Insert(context.Background(), Backup{ID: id, RunID: &runID, Status: StatusRunning, CreatedAt: time.Now(), FilePath: id.String()}); err != nil {
		t.Fatal(err)
	}
	bh.svc.FailRunningForRun(context.Background(), runID)
	if got, _ := bh.store.Get(context.Background(), id); got.Status != StatusFailed {
		t.Fatalf("status %s", got.Status)
	}
}
