package runs

import (
	"context"
	"errors"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var startTestSteps = []StepDef{
	{Name: "backup", Executor: ExecutorService},
	{Name: "upgrade", Executor: ExecutorJob},
	{Name: "package", Executor: ExecutorService},
}

func TestStart_PrepareThenLaunch(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t)
	ctx := context.Background()
	run, err := r.Begin(ctx, KindBackup, nil, "", "", startTestSteps)
	if err != nil {
		t.Fatal(err)
	}
	r.Start(run, func(_ context.Context, p *Progress) (*batchv1.Job, error) {
		p.Start("backup")
		p.Note("backup", "skipped_by_operator", "a note")
		p.Succeed("backup")
		return runsJob("prepared-1"), nil
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := client.BatchV1().Jobs(runsTestNS).Get(ctx, "prepared-1", metav1.GetOptions{}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the prepared Job was never launched")
		}
		time.Sleep(5 * time.Millisecond)
	}
	runsSetJobCondition(t, client, "prepared-1", batchv1.JobComplete, "", "")
	got := runsWaitStatus(t, store, run.ID)
	r.Wait()
	if got.Status != StatusSucceeded || got.JobName != "prepared-1" {
		t.Fatalf("got %s job %q", got.Status, got.JobName)
	}
	// The prepared step's outcome and note survive into the followed run.
	if b := stepByName(got, "backup"); b.Status != StepSucceeded || b.Detail != "skipped_by_operator" || b.LogTail != "a note" {
		t.Fatalf("backup step %+v", b)
	}
	if len(f.outcomes()) != 1 {
		t.Fatalf("finalizer calls %d", len(f.outcomes()))
	}
}

func TestStart_PrepareFailureSettlesWithoutAJob(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t)
	ctx := context.Background()
	run, _ := r.Begin(ctx, KindBackup, nil, "", "", startTestSteps)
	r.Start(run, func(_ context.Context, p *Progress) (*batchv1.Job, error) {
		p.Start("backup")
		err := errors.New("pg_dump failed")
		p.Fail("backup", err)
		return nil, err
	})
	got := runsWaitStatus(t, store, run.ID)
	r.Wait()
	if got.Status != StatusFailed || got.Error != "pg_dump failed" || got.FailedStep() != "backup" {
		t.Fatalf("got %s %q %q", got.Status, got.Error, got.FailedStep())
	}
	// The Job step is skipped, not blamed.
	if s := stepByName(got, "upgrade"); s.Status != StepSkipped {
		t.Fatalf("upgrade step %+v", s)
	}
	if jobs, _ := client.BatchV1().Jobs(runsTestNS).List(ctx, metav1.ListOptions{}); len(jobs.Items) != 0 {
		t.Fatal("a Job was created")
	}
	if o := f.outcomes(); len(o) != 1 || o[0].Succeeded {
		t.Fatalf("finalizer outcomes %+v", o)
	}
}

func TestStart_StopDuringPrepareLeavesTheRunForReconcile(t *testing.T) {
	r, store, _, _ := newRunsTestRunner(t)
	run, _ := r.Begin(context.Background(), KindBackup, nil, "", "", startTestSteps)
	entered := make(chan struct{})
	r.Start(run, func(ctx context.Context, _ *Progress) (*batchv1.Job, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	<-entered
	r.Stop()
	if got, _ := store.Get(context.Background(), run.ID); got.Status != StatusRunning {
		t.Fatalf("a stopping Runner settled the run: %s", got.Status)
	}
}
