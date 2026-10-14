package upgrade

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

func TestUpdate_HappyPath(t *testing.T) {
	h := newHarness(t)
	user := uuid.New()
	run, res, err := h.svc.StartUpdate(context.Background(), &user, "4.6.0", false)
	if err != nil {
		t.Fatalf("start: %v (%+v)", err, res)
	}
	if run.Kind != runs.KindUpdate || run.FromVersion != "4.5.0" || run.ToVersion != "4.6.0" {
		t.Fatalf("run = %+v", run)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	job := h.waitJob(name)

	// The Job carries everything it needs from creation: action + version,
	// the updater account, and the run label the Runner follows it by.
	env := envOf(job)
	if env[EnvAction] != ActionUpgrade || env[EnvVersion] != "4.6.0" || env[EnvRevision] != "" {
		t.Fatalf("job env = %v", env)
	}
	if job.Spec.Template.Spec.ServiceAccountName != UpdaterServiceAccount || job.Labels[runs.LabelRunID] != run.ID.String() {
		t.Fatalf("job SA/labels = %s %v", job.Spec.Template.Spec.ServiceAccountName, job.Labels)
	}
	// Backup first (D4), then the signature, both before the Job existed.
	if h.backups.tookCount() != 1 {
		t.Fatalf("backup taken %d times, want 1", h.backups.tookCount())
	}
	if got := h.verifier.calls(); !reflect.DeepEqual(got, []string{"ghcr.io/vistasecurity/vistaplatform:4.6.0"}) {
		t.Fatalf("verified %v", got)
	}

	h.addJobPod(name)
	h.setJob(name, "Complete", "", "")
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusSucceeded {
		t.Fatalf("status %s error %q steps %+v", got.Status, got.Error, got.Steps)
	}
	for _, s := range []string{StepBackup, StepVerify, StepUpgrade, StepSmoke} {
		if st := step(got, s); st.Status != runs.StepSucceeded {
			t.Errorf("step %s = %s (%s)", s, st.Status, st.Error)
		}
	}
	if !strings.Contains(step(got, StepBackup).LogTail, "database only") {
		t.Errorf("backup step log = %q", step(got, StepBackup).LogTail)
	}
	if !reflect.DeepEqual(h.smoke.calls(), []string{"4.6.0"}) {
		t.Fatalf("smoke calls %v", h.smoke.calls())
	}
	if _, err := h.client.BatchV1().Jobs(upgradeTestNS).Get(context.Background(), name, metav1.GetOptions{}); err == nil {
		t.Fatal("the finished Job was not reaped")
	}
	if want := []string{EventUpdateStarted + ":started", EventUpdateSucceeded + ":finished"}; !reflect.DeepEqual(h.audit.types(), want) {
		t.Fatalf("audit = %v, want %v", h.audit.types(), want)
	}
}

func TestUpdate_FailedHelmStepCapturesLogTail(t *testing.T) {
	h := newHarness(t)
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	h.waitJob(name)
	h.addJobPod(name)
	h.setJob(name, "Failed", "BackoffLimitExceeded", "Job has reached the specified backoff limit")
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusFailed || got.FailedStep() != StepUpgrade {
		t.Fatalf("status %s failed step %q", got.Status, got.FailedStep())
	}
	up := step(got, StepUpgrade)
	// The fake clientset serves "fake logs" for every pod log read: that it
	// is on the step proves the tail was read from the Job's pod and stored.
	if up.LogTail != "fake logs" {
		t.Fatalf("upgrade log tail = %q", up.LogTail)
	}
	if !strings.Contains(up.Error, "BackoffLimitExceeded") || !strings.Contains(got.Error, "BackoffLimitExceeded") {
		t.Fatalf("errors: step %q run %q", up.Error, got.Error)
	}
	if st := step(got, StepSmoke); st.Status != runs.StepSkipped {
		t.Fatalf("smoke = %s, want skipped", st.Status)
	}
	if len(h.smoke.calls()) != 0 {
		t.Fatal("smoke ran after a failed helm step")
	}
	if want := []string{EventUpdateStarted + ":started", EventUpdateFailed + ":finished:fail"}; !reflect.DeepEqual(h.audit.types(), want) {
		t.Fatalf("audit = %v", h.audit.types())
	}
}

func TestUpdate_SmokeFailureFailsTheRun(t *testing.T) {
	h := newHarness(t)
	h.smoke.err = errors.New("not every service runs 4.6.0: auth-service on 4.5.0")
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	h.waitJob(name)
	h.setJob(name, "Complete", "", "")
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusFailed || got.FailedStep() != StepSmoke || !strings.Contains(got.Error, "auth-service on 4.5.0") {
		t.Fatalf("got %s / %s / %q", got.Status, got.FailedStep(), got.Error)
	}
	if st := step(got, StepUpgrade); st.Status != runs.StepSucceeded {
		t.Fatalf("upgrade = %s", st.Status)
	}
}

func TestUpdate_SkipBackupIsRecordedAndNoBackupTaken(t *testing.T) {
	h := newHarness(t)
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", true)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	h.waitJob(name)
	h.setJob(name, "Complete", "", "")
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	b := step(got, StepBackup)
	if b.Status != runs.StepSkipped || b.Detail != DetailSkippedByOperator {
		t.Fatalf("backup step = %+v", b)
	}
	if h.backups.tookCount() != 0 {
		t.Fatal("a backup was taken although the operator skipped it")
	}
	if got.Status != runs.StatusSucceeded {
		t.Fatalf("status %s", got.Status)
	}
}

func TestUpdate_BackupFailureChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.backups.takeErr = errors.New("backups: the backup failed: the backup Job failed: DeadlineExceeded")
	h.backups.takeTail = "pg_dump: error: connection refused"
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusFailed || got.FailedStep() != StepBackup {
		t.Fatalf("status %s failed %q", got.Status, got.FailedStep())
	}
	if !strings.Contains(step(got, StepBackup).LogTail, "connection refused") {
		t.Fatalf("backup tail %q", step(got, StepBackup).LogTail)
	}
	for _, s := range []string{StepVerify, StepUpgrade, StepSmoke} {
		if st := step(got, s); st.Status == runs.StepSucceeded || st.Status == runs.StepRunning {
			t.Fatalf("step %s = %s after the backup failed", s, st.Status)
		}
	}
	if len(h.verifier.calls()) != 0 {
		t.Fatal("verified after a failed backup")
	}
	jobs, _ := h.client.BatchV1().Jobs(upgradeTestNS).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatalf("a helm Job was created after the backup failed: %d", len(jobs.Items))
	}
}

func TestUpdate_SignatureFailureChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.verifier.err = errors.New("cosign verify of ghcr.io/vistasecurity/vistaplatform:4.6.0 failed: no matching signatures")
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusFailed || got.FailedStep() != StepVerify || !strings.Contains(got.Error, "no matching signatures") {
		t.Fatalf("got %s %q %q", got.Status, got.FailedStep(), got.Error)
	}
	jobs, _ := h.client.BatchV1().Jobs(upgradeTestNS).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatal("a helm Job was created after the signature failed")
	}
}

func TestUpdate_SkipSignatureByConfiguration(t *testing.T) {
	h := newHarness(t, func(h *harness) { h.cfg.SkipSignature = true })
	run, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	h.waitJob(name)
	got, _ := h.store.Get(context.Background(), run.ID)
	if v := step(got, StepVerify); v.Status != runs.StepSkipped || v.Detail != DetailSkippedByConfiguration {
		t.Fatalf("verify step %+v", v)
	}
	if len(h.verifier.calls()) != 0 {
		t.Fatal("verified although verification is off")
	}
}

func TestUpdate_PreflightFailureIs422Shape(t *testing.T) {
	h := newHarness(t)
	_, res, err := h.svc.StartUpdate(context.Background(), nil, "9.9.9", false)
	var pf *PreflightFailedError
	if !errors.As(err, &pf) {
		t.Fatalf("err = %v, want PreflightFailedError", err)
	}
	if res.OK || !reflect.DeepEqual(pf.Result.Failed(), []string{CheckVersion}) {
		t.Fatalf("failed = %v", pf.Result.Failed())
	}
	if list, _ := h.store.List(context.Background(), 10); len(list) != 0 {
		t.Fatal("a run was recorded for a failed pre-flight")
	}
}

func TestUpdate_RunInProgressIs409(t *testing.T) {
	h := newHarness(t)
	if _, err := h.runner.Begin(context.Background(), runs.KindBackup, nil, "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false); !errors.Is(err, runs.ErrRunInProgress) {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.svc.StartRollback(context.Background(), nil, 1); !errors.Is(err, runs.ErrRunInProgress) {
		t.Fatalf("rollback err = %v", err)
	}
}

func TestUpdate_NoBackupStorageNeedsTheOperatorsBackup(t *testing.T) {
	h := newHarness(t)
	h.backups.available = false
	if _, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", false); !errors.Is(err, ErrBackupUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := h.svc.StartUpdate(context.Background(), nil, "4.6.0", true); err != nil {
		t.Fatalf("with skip_backup: %v", err)
	}
}

// The service is replaced by the upgrade it starts: the Job finishes while
// no process watches it, and the NEW process settles the run on start and
// runs the smoke step.
func TestUpdate_ReconcileOnStartSettlesAFinishedJobThenSmokes(t *testing.T) {
	old := newHarness(t)
	run, _, err := old.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	old.waitJob(name)
	old.runner.Stop() // the old pod is terminated by the rollout

	old.setJob(name, "Complete", "", "")
	if r, _ := old.store.Get(context.Background(), run.ID); r.Status != runs.StatusRunning {
		t.Fatalf("settled with no process watching: %s", r.Status)
	}

	// The new pod: same database and cluster, a fresh Runner and Service.
	next := restart(t, old)
	if err := next.runner.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := next.waitSettled(run.ID)
	next.runner.Wait()
	if got.Status != runs.StatusSucceeded || step(got, StepSmoke).Status != runs.StepSucceeded {
		t.Fatalf("status %s smoke %+v err %q", got.Status, step(got, StepSmoke), got.Error)
	}
	if !reflect.DeepEqual(next.smoke.calls(), []string{"4.6.0"}) {
		t.Fatalf("smoke calls %v", next.smoke.calls())
	}
	// Steps finished before the restart survive it.
	if step(got, StepBackup).Status != runs.StepSucceeded || step(got, StepVerify).Status != runs.StepSucceeded {
		t.Fatalf("pre-restart steps lost: %+v", got.Steps)
	}
}

// The new pod comes up while helm is still waiting for the rest of the
// rollout: it resumes watching, and settles when the Job ends.
func TestUpdate_ReconcileResumesARunningJob(t *testing.T) {
	old := newHarness(t)
	run, _, err := old.svc.StartUpdate(context.Background(), nil, "4.6.0", false)
	if err != nil {
		t.Fatal(err)
	}
	name := UpdateJobName(ActionUpgrade, run.ID)
	old.waitJob(name)
	old.runner.Stop()

	next := restart(t, old)
	if err := next.runner.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, _ := next.store.Get(context.Background(), run.ID); r.Status != runs.StatusRunning {
		t.Fatalf("settled a Job that is still running: %s", r.Status)
	}
	next.setJob(name, "Complete", "", "")
	got := next.waitSettled(run.ID)
	next.runner.Wait()
	if got.Status != runs.StatusSucceeded || len(next.smoke.calls()) != 1 {
		t.Fatalf("status %s smoke %v", got.Status, next.smoke.calls())
	}
}

// A restart during the backup step (before the Job existed) fails the run on
// the next start, and the in-flight backup row is failed too.
func TestUpdate_RestartBeforeTheJobFailsTheRunAndItsBackup(t *testing.T) {
	store := runs.NewMemoryStore()
	run, err := store.Create(context.Background(), runs.Run{ID: uuid.New(), Kind: runs.KindUpdate, ToVersion: "4.6.0",
		Steps: []runs.Step{{Name: StepBackup, Executor: runs.ExecutorService, Status: runs.StepRunning}, {Name: StepVerify, Executor: runs.ExecutorService, Status: runs.StepPending},
			{Name: StepUpgrade, Executor: runs.ExecutorJob, Status: runs.StepPending}, {Name: StepSmoke, Executor: runs.ExecutorService, Status: runs.StepPending}}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWith(t, store)
	if err := h.runner.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusFailed || !strings.Contains(got.Error, "restarted") {
		t.Fatalf("got %s %q", got.Status, got.Error)
	}
	if len(h.backups.failed) != 1 || h.backups.failed[0] != run.ID {
		t.Fatalf("in-flight backup not failed: %v", h.backups.failed)
	}
	if len(h.smoke.calls()) != 0 {
		t.Fatal("smoke ran for a run that never upgraded")
	}
}

// restart builds the next process over the same store and cluster.
func restart(t *testing.T, old *harness) *harness {
	t.Helper()
	logger, _ := test.NewNullLogger()
	next := *old
	next.smoke = &fakeSmoke{}
	next.audit = &fakeAuditor{}
	next.runner = runs.NewRunner(old.store, old.client, runs.Config{Namespace: upgradeTestNS, PollInterval: 5 * time.Millisecond}, logger)
	t.Cleanup(next.runner.Stop)
	next.svc = NewService(old.cfg, Deps{Runner: next.runner, RunStore: old.store, Preflight: old.pf, Backups: old.backups,
		Verifier: old.verifier, Releases: old.svc.releases, Smoke: next.smoke, Audit: next.audit, Log: logger})
	return &next
}

func TestRollback_LaunchesHelmRollbackAndSmokesThePreviousVersion(t *testing.T) {
	h := newHarness(t)
	user := uuid.New()
	run, err := h.svc.StartRollback(context.Background(), &user, 1)
	if err != nil {
		t.Fatal(err)
	}
	if run.Kind != runs.KindRollback || run.ToVersion != "4.4.0" {
		t.Fatalf("run %+v", run)
	}
	name := UpdateJobName(ActionRollback, run.ID)
	job := h.waitJob(name)
	if env := envOf(job); env[EnvAction] != ActionRollback || env[EnvRevision] != "1" || env[EnvVersion] != "" {
		t.Fatalf("env %v", env)
	}
	h.setJob(name, "Complete", "", "")
	got := h.waitSettled(run.ID)
	h.runner.Wait()
	if got.Status != runs.StatusSucceeded || !reflect.DeepEqual(h.smoke.calls(), []string{"4.4.0"}) {
		t.Fatalf("status %s smoke %v", got.Status, h.smoke.calls())
	}
	if want := []string{EventRolledBack + ":started", EventRolledBack + ":finished"}; !reflect.DeepEqual(h.audit.types(), want) {
		t.Fatalf("audit %v", h.audit.types())
	}
	if h.backups.tookCount() != 0 {
		t.Fatal("a rollback took a backup")
	}
}

func TestRollback_RefusesRevisionsItCannotRollBackTo(t *testing.T) {
	h := newHarness(t, func(h *harness) {
		h.client = fake.NewClientset(
			releaseSecret(t, 1, "4.4.0", HelmSuperseded, nil, ""),
			releaseSecret(t, 2, "4.4.1", HelmFailed, nil, ""),
			releaseSecret(t, 3, "4.5.0", HelmDeployed, nil, ""),
		)
	})
	for _, rev := range []int{3, 2, 9} {
		if _, err := h.svc.StartRollback(context.Background(), nil, rev); !errors.Is(err, ErrInvalidRevision) {
			t.Errorf("revision %d: err = %v, want ErrInvalidRevision", rev, err)
		}
	}
	h.pf.Capabilities = fakeDetector{caps: capabilitiesGitOps()}
	if _, err := h.svc.StartRollback(context.Background(), nil, 1); !errors.Is(err, ErrNotUpdatable) {
		t.Errorf("gitops: err = %v", err)
	}
}
