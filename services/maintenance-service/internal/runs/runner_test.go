package runs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const runsTestNS = "vista-test"

// runsRecordingFinalizer records what it was called with and runs one
// service step.
type runsRecordingFinalizer struct {
	mu       sync.Mutex
	calls    []JobOutcome
	failWith error
}

func (f *runsRecordingFinalizer) Finalize(_ context.Context, _ Run, o JobOutcome, p *Progress) error {
	f.mu.Lock()
	f.calls = append(f.calls, o)
	f.mu.Unlock()
	if !o.Succeeded {
		return nil
	}
	p.Start("package")
	if f.failWith != nil {
		p.Fail("package", f.failWith)
		return f.failWith
	}
	p.Succeed("package")
	return nil
}

func (f *runsRecordingFinalizer) outcomes() []JobOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]JobOutcome(nil), f.calls...)
}

var runsTestSteps = []StepDef{{Name: "dump", Executor: ExecutorJob}, {Name: "package", Executor: ExecutorService}}

func newRunsTestRunner(t *testing.T, objects ...runtime.Object) (*Runner, *MemoryStore, *fake.Clientset, *runsRecordingFinalizer) {
	t.Helper()
	client := fake.NewClientset(objects...)
	store := NewMemoryStore()
	logger, _ := test.NewNullLogger()
	r := NewRunner(store, client, Config{Namespace: runsTestNS, PollInterval: 5 * time.Millisecond}, logger)
	f := &runsRecordingFinalizer{}
	r.Register(KindBackup, f)
	t.Cleanup(r.Stop)
	return r, store, client, f
}

func runsJob(name string) *batchv1.Job {
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func runsSetJobCondition(t *testing.T, client *fake.Clientset, name string, cond batchv1.JobConditionType, reason, msg string) {
	t.Helper()
	ctx := context.Background()
	j, err := client.BatchV1().Jobs(runsTestNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	j.Status.Conditions = append(j.Status.Conditions, batchv1.JobCondition{Type: cond, Status: corev1.ConditionTrue, Reason: reason, Message: msg})
	if _, err := client.BatchV1().Jobs(runsTestNS).UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func runsWaitStatus(t *testing.T, store *MemoryStore, id uuid.UUID) Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := store.Get(context.Background(), id)
		if r.Status != StatusRunning {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %s never settled", id)
	return Run{}
}

func stepByName(r Run, name string) Step {
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	return Step{}
}

func TestRunner_LaunchFollowAndSettleSuccess(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t)
	ctx := context.Background()
	user := uuid.New()
	run, err := r.Begin(ctx, KindBackup, &user, "", "", runsTestSteps)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Launch(ctx, run, runsJob("backup-1")); err != nil {
		t.Fatal(err)
	}
	job, err := client.BatchV1().Jobs(runsTestNS).Get(ctx, "backup-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if job.Labels[LabelRunID] != run.ID.String() || job.Spec.Template.Labels[LabelRunID] != run.ID.String() {
		t.Fatalf("Job not labelled with its run: %v / %v", job.Labels, job.Spec.Template.Labels)
	}
	// The Job's pod, so the log tail has somewhere to come from.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "backup-1-abcde", Namespace: runsTestNS, Labels: map[string]string{"job-name": "backup-1"}}}
	if _, err := client.CoreV1().Pods(runsTestNS).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if got, _ := store.Get(ctx, run.ID); got.Status != StatusRunning || stepByName(got, "dump").LogTail == "" {
		t.Fatalf("while the Job runs: status %s, dump tail %q", got.Status, stepByName(got, "dump").LogTail)
	}

	runsSetJobCondition(t, client, "backup-1", batchv1.JobComplete, "", "")
	got := runsWaitStatus(t, store, run.ID)
	r.Wait()
	if got.Status != StatusSucceeded || got.FinishedAt == nil || got.Error != "" {
		t.Fatalf("settled %+v", got)
	}
	if s := stepByName(got, "dump"); s.Status != StepSucceeded {
		t.Fatalf("dump step %+v", s)
	}
	if s := stepByName(got, "package"); s.Status != StepSucceeded {
		t.Fatalf("package step %+v", s)
	}
	if o := f.outcomes(); len(o) != 1 || !o[0].Succeeded || o[0].Reconciled {
		t.Fatalf("finalizer outcomes %+v", o)
	}
	if _, err := client.BatchV1().Jobs(runsTestNS).Get(ctx, "backup-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("settled Job not deleted: %v", err)
	}
}

func TestRunner_JobFailure(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t)
	ctx := context.Background()
	run, _ := r.Begin(ctx, KindBackup, nil, "", "", runsTestSteps)
	if err := r.Launch(ctx, run, runsJob("backup-2")); err != nil {
		t.Fatal(err)
	}
	runsSetJobCondition(t, client, "backup-2", batchv1.JobFailed, "BackoffLimitExceeded", "Job has reached the specified backoff limit")
	got := runsWaitStatus(t, store, run.ID)
	if got.Status != StatusFailed || !strings.Contains(got.Error, "BackoffLimitExceeded") {
		t.Fatalf("settled %+v", got)
	}
	if s := stepByName(got, "dump"); s.Status != StepFailed || !strings.Contains(s.Error, "backoff limit") {
		t.Fatalf("dump step %+v", s)
	}
	if s := stepByName(got, "package"); s.Status != StepSkipped {
		t.Fatalf("package step %+v, want skipped", s)
	}
	if got.FailedStep() != "dump" {
		t.Fatalf("FailedStep = %q", got.FailedStep())
	}
	if o := f.outcomes(); len(o) != 1 || o[0].Succeeded {
		t.Fatalf("finalizer outcomes %+v", o)
	}
}

func TestRunner_FinalizerFailureFailsTheRun(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t)
	f.failWith = errors.New("disk full")
	ctx := context.Background()
	run, _ := r.Begin(ctx, KindBackup, nil, "", "", runsTestSteps)
	_ = r.Launch(ctx, run, runsJob("backup-3"))
	runsSetJobCondition(t, client, "backup-3", batchv1.JobComplete, "", "")
	got := runsWaitStatus(t, store, run.ID)
	if got.Status != StatusFailed || got.Error != "disk full" || got.FailedStep() != "package" {
		t.Fatalf("settled %+v", got)
	}
}

func TestRunner_OneRunAtATime(t *testing.T) {
	r, _, _, _ := newRunsTestRunner(t)
	ctx := context.Background()
	if _, err := r.Begin(ctx, KindBackup, nil, "", "", runsTestSteps); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Begin(ctx, KindUpdate, nil, "4.5.0", "4.6.0", nil); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("second Begin: %v, want ErrRunInProgress", err)
	}
}

func TestRunner_LaunchFailureSettlesTheRun(t *testing.T) {
	r, store, _, f := newRunsTestRunner(t)
	ctx := context.Background()
	run, _ := r.Begin(ctx, KindBackup, nil, "", "", runsTestSteps)
	_ = r.Launch(ctx, run, &batchv1.Job{})
	got, _ := store.Get(ctx, run.ID)
	if got.Status != StatusFailed || !strings.Contains(got.Error, "no name") {
		t.Fatalf("unnamed Job: %+v", got)
	}
	if o := f.outcomes(); len(o) != 1 || o[0].Succeeded {
		t.Fatalf("finalizer not told of the failed launch: %+v", o)
	}
}

// --- reconcile-on-start: the service was down while the Job ran ---

// runsSeedRunning puts a running run in the store as the previous process
// left it, and a Job in the cluster in the state it reached meanwhile.
func runsSeedRunning(t *testing.T, store *MemoryStore, jobName string) Run {
	t.Helper()
	run, err := store.Create(context.Background(), Run{ID: uuid.New(), Kind: KindBackup, JobName: jobName,
		Steps: []Step{{Name: "dump", Executor: ExecutorJob, Status: StepRunning}, {Name: "package", Executor: ExecutorService, Status: StepPending}}})
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func runsJobWithCondition(name string, cond batchv1.JobConditionType, reason string) *batchv1.Job {
	j := runsJob(name)
	j.Namespace = runsTestNS
	j.Status.Conditions = []batchv1.JobCondition{{Type: cond, Status: corev1.ConditionTrue, Reason: reason}}
	return j
}

func TestReconcile_JobSucceededWhileDown(t *testing.T) {
	r, store, client, f := newRunsTestRunner(t, runsJobWithCondition("backup-done", batchv1.JobComplete, ""))
	run := runsSeedRunning(t, store, "backup-done")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := runsWaitStatus(t, store, run.ID)
	r.Wait()
	if got.Status != StatusSucceeded {
		t.Fatalf("reconciled %+v", got)
	}
	if o := f.outcomes(); len(o) != 1 || !o[0].Succeeded || !o[0].Reconciled {
		t.Fatalf("finalizer outcomes %+v, want one reconciled success", o)
	}
	if _, err := client.BatchV1().Jobs(runsTestNS).Get(context.Background(), "backup-done", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("reconciled Job not deleted: %v", err)
	}
}

func TestReconcile_JobFailedWhileDown(t *testing.T) {
	r, store, _, f := newRunsTestRunner(t, runsJobWithCondition("backup-broke", batchv1.JobFailed, "DeadlineExceeded"))
	run := runsSeedRunning(t, store, "backup-broke")
	_ = r.Reconcile(context.Background())
	got := runsWaitStatus(t, store, run.ID)
	r.Wait()
	if got.Status != StatusFailed || !strings.Contains(got.Error, "DeadlineExceeded") || got.FailedStep() != "dump" {
		t.Fatalf("reconciled %+v", got)
	}
	if o := f.outcomes(); len(o) != 1 || o[0].Succeeded || !o[0].Reconciled {
		t.Fatalf("finalizer outcomes %+v", o)
	}
}

func TestReconcile_JobStillRunningIsFollowed(t *testing.T) {
	running := runsJob("backup-busy")
	running.Namespace = runsTestNS
	r, store, client, _ := newRunsTestRunner(t, running)
	run := runsSeedRunning(t, store, "backup-busy")
	_ = r.Reconcile(context.Background())
	time.Sleep(30 * time.Millisecond)
	if got, _ := store.Get(context.Background(), run.ID); got.Status != StatusRunning {
		t.Fatalf("settled a run whose Job still runs: %+v", got)
	}
	runsSetJobCondition(t, client, "backup-busy", batchv1.JobComplete, "", "")
	if got := runsWaitStatus(t, store, run.ID); got.Status != StatusSucceeded {
		t.Fatalf("followed run settled %+v", got)
	}
}

func TestReconcile_JobGoneOrNeverCreated(t *testing.T) {
	r, store, _, _ := newRunsTestRunner(t)
	gone := runsSeedRunning(t, store, "backup-vanished")
	_ = r.Reconcile(context.Background())
	got := runsWaitStatus(t, store, gone.ID)
	if got.Status != StatusFailed || !strings.Contains(got.Error, "no longer exists") {
		t.Fatalf("missing Job: %+v", got)
	}

	never, err := store.Create(context.Background(), Run{ID: uuid.New(), Kind: KindBackup})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Reconcile(context.Background())
	got, _ = store.Get(context.Background(), never.ID)
	if got.Status != StatusFailed || !strings.Contains(got.Error, "before this run's Job was created") {
		t.Fatalf("no Job name: %+v", got)
	}
}

func TestApplyLog(t *testing.T) {
	now := time.Date(2026, 10, 14, 3, 12, 0, 0, time.UTC)
	run := Run{Steps: []Step{
		{Name: "backup", Executor: ExecutorJob, Status: StepPending},
		{Name: "upgrade", Executor: ExecutorJob, Status: StepPending},
		{Name: "smoke", Executor: ExecutorService, Status: StepPending},
	}}
	log := "starting\nVISTA_STEP backup running\ndumping\nVISTA_STEP backup succeeded\nVISTA_STEP upgrade running\nhelm upgrade ...\nVISTA_STEP smoke running\n"
	if !applyLog(&run, log, 1024, now) {
		t.Fatal("no change reported")
	}
	if run.Steps[0].Status != StepSucceeded || run.Steps[1].Status != StepRunning {
		t.Fatalf("statuses %+v", run.Steps)
	}
	if run.Steps[2].Status != StepPending {
		t.Fatal("a Job marker moved a service step")
	}
	if !strings.Contains(run.Steps[1].LogTail, "helm upgrade") || strings.Contains(run.Steps[1].LogTail, StepMarker) {
		t.Fatalf("tail on the running step = %q", run.Steps[1].LogTail)
	}
	// A later read whose tail no longer holds the early markers cannot move
	// a step backwards.
	applyLog(&run, "VISTA_STEP backup running\n", 1024, now)
	if run.Steps[0].Status != StepSucceeded {
		t.Fatal("a stale marker moved a step backwards")
	}
	if got := boundTail(strings.Repeat("0123456789\n", 100), 35); len(got) > 35 || strings.HasPrefix(got, "\n") {
		t.Fatalf("boundTail = %q", got)
	}
}
