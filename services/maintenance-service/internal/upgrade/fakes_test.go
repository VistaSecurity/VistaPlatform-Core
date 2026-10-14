package upgrade

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

const (
	upgradeTestNS      = "vista-test"
	upgradeTestRelease = "vista"
	upgradeTestSource  = "oci://ghcr.io/vistasecurity/vistaplatform"
)

type fakeDetector struct{ caps capabilities.Capabilities }

func (f fakeDetector) Detect(context.Context) capabilities.Capabilities { return f.caps }

var helmManaged = capabilities.Capabilities{HelmManaged: true, Updates: true, Backups: true}

type fakeTags struct {
	tags []string
	err  error
}

func (f fakeTags) ListTags(context.Context) ([]string, error) { return f.tags, f.err }

type fakeVerifier struct {
	mu   sync.Mutex
	err  error
	refs []string
}

func (f *fakeVerifier) Verify(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs = append(f.refs, ref)
	return f.err
}

func (f *fakeVerifier) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.refs...)
}

type fakeReleases struct {
	hist []Release
	err  error
}

func (f fakeReleases) History(context.Context) ([]Release, error) { return f.hist, f.err }

type fakeSchema struct {
	v   string
	err error
}

func (f fakeSchema) LatestChartVersion(context.Context) (string, error) { return f.v, f.err }

type fakeRunning struct {
	list []runs.Run
	err  error
}

func (f fakeRunning) ListRunning(context.Context) ([]runs.Run, error) { return f.list, f.err }

type fakeBackups struct {
	mu        sync.Mutex
	available bool
	recent    *backups.Backup
	listErr   error
	takeErr   error
	takeTail  string
	took      []uuid.UUID
	failed    []uuid.UUID
}

func (f *fakeBackups) Available() bool { return f.available }
func (f *fakeBackups) RecentReady(context.Context, time.Time) (*backups.Backup, error) {
	return f.recent, f.listErr
}
func (f *fakeBackups) TakeForRun(_ context.Context, runID uuid.UUID) (backups.ForRunResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.took = append(f.took, runID)
	if f.takeErr != nil {
		return backups.ForRunResult{LogTail: f.takeTail}, f.takeErr
	}
	size := int64(1234)
	return backups.ForRunResult{Backup: backups.Backup{ID: uuid.New(), RunID: &runID, Status: backups.StatusReady, SizeBytes: &size}}, nil
}
func (f *fakeBackups) FailRunningForRun(_ context.Context, runID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, runID)
}
func (f *fakeBackups) tookCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.took) }

type fakeSmoke struct {
	mu       sync.Mutex
	err      error
	versions []string
}

func (f *fakeSmoke) Smoke(_ context.Context, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions = append(f.versions, v)
	return f.err
}
func (f *fakeSmoke) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.versions...)
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []RunEvent
}

func (f *fakeAuditor) RecordRun(_ context.Context, ev RunEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeAuditor) types() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		s := e.EventType + ":" + e.Phase
		if !e.Success {
			s += ":fail"
		}
		out = append(out, s)
	}
	return out
}

// encodeRelease builds a Helm 3 release Secret payload exactly as Helm
// stores it: JSON -> gzip -> base64 (the API adds the outer base64 layer of
// Secret data, which client-go has already removed from Secret.Data).
func encodeRelease(t *testing.T, rel map[string]any) []byte {
	t.Helper()
	js, err := json.Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(js); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func helmReleaseJSON(rev int, chart, status string, config map[string]any, manifest string) map[string]any {
	return map[string]any{
		"name":      upgradeTestRelease,
		"namespace": upgradeTestNS,
		"version":   rev,
		"config":    config,
		"manifest":  manifest,
		"info": map[string]any{
			"first_deployed": "2026-10-01T10:00:00Z",
			"last_deployed":  time.Date(2026, 10, rev, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
			"status":         status,
			"description":    "Upgrade complete",
		},
		"chart": map[string]any{"metadata": map[string]any{"name": "vistaplatform", "version": chart, "appVersion": chart}},
	}
}

func releaseSecret(t *testing.T, rev int, chart, status string, config map[string]any, manifest string) *corev1.Secret {
	t.Helper()
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sh.helm.release.v1." + upgradeTestRelease + ".v" + itoa(rev),
			Namespace: upgradeTestNS,
			Labels:    map[string]string{"owner": "helm", "name": upgradeTestRelease, "status": status, "version": itoa(rev)},
		},
		Type: "helm.sh/release.v1",
		Data: map[string][]byte{"release": encodeRelease(t, helmReleaseJSON(rev, chart, status, config, manifest))},
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// updateJobTemplate is a minimal stand-in for the chart-rendered template.
const updateJobTemplate = `apiVersion: batch/v1
kind: Job
metadata:
  labels:
    app.kubernetes.io/component: maintenance-updater
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 2400
  template:
    metadata:
      labels:
        app.kubernetes.io/component: maintenance-updater
    spec:
      serviceAccountName: vistaplatform-updater
      automountServiceAccountToken: true
      restartPolicy: Never
      containers:
        - name: helm
          image: docker.io/vistasecurity/maintenance-service:4.5.0
          env:
            - name: MAINTENANCE_ACTION
              value: ""
            - name: TARGET_VERSION
              value: ""
            - name: ROLLBACK_REVISION
              value: ""
            - name: HELM_RELEASE_NAME
              value: vista
`

type harness struct {
	t        *testing.T
	client   *fake.Clientset
	store    *runs.MemoryStore
	runner   *runs.Runner
	svc      *Service
	pf       *Preflight
	verifier *fakeVerifier
	backups  *fakeBackups
	smoke    *fakeSmoke
	audit    *fakeAuditor
	cfg      Config
}

type harnessOpt func(*harness)

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	return newHarnessWith(t, runs.NewMemoryStore(), opts...)
}

func newHarnessWith(t *testing.T, store *runs.MemoryStore, opts ...harnessOpt) *harness {
	t.Helper()
	tmplDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmplDir, UpdateJobTemplateFile), []byte(updateJobTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t:        t,
		store:    store,
		verifier: &fakeVerifier{},
		backups:  &fakeBackups{available: true},
		smoke:    &fakeSmoke{},
		audit:    &fakeAuditor{},
		cfg: Config{Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease, ChartSource: upgradeTestSource,
			RunningChart: "4.5.0", JobTemplateDir: tmplDir, JobTemplateName: "vista-maintenance-update-job"},
	}
	h.client = fake.NewClientset(
		releaseSecret(t, 1, "4.4.0", HelmSuperseded, map[string]any{}, ""),
		releaseSecret(t, 2, "4.5.0", HelmDeployed, map[string]any{"tls": map[string]any{"dnsName": "vista.example.com"}}, ""),
	)
	for _, o := range opts {
		o(h)
	}
	logger, _ := test.NewNullLogger()
	h.runner = runs.NewRunner(h.store, h.client, runs.Config{Namespace: upgradeTestNS, PollInterval: 5 * time.Millisecond}, logger)
	t.Cleanup(h.runner.Stop)
	releases := SecretReleases{Client: h.client, Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease}
	h.pf = &Preflight{
		Capabilities: fakeDetector{caps: helmManaged},
		Tags:         fakeTags{tags: []string{"4.4.0", "4.5.0", "4.6.0", "4.7.0-rc.1"}},
		ChartSource:  upgradeTestSource,
		RunningChart: "4.5.0",
		Verifier:     h.verifier,
		Releases:     releases,
		Schema:       fakeSchema{v: "4.5.0"},
		Runs:         h.store,
		Backups:      h.backups,
	}
	h.svc = NewService(h.cfg, Deps{Runner: h.runner, RunStore: h.store, Preflight: h.pf, Backups: h.backups,
		Verifier: h.verifier, Releases: releases, Smoke: h.smoke, Audit: h.audit, Log: logger})
	return h
}

// waitJob waits for the run's Job to be created (the prepare steps ran).
func (h *harness) waitJob(name string) *batchv1.Job {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := h.client.BatchV1().Jobs(upgradeTestNS).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("Job %s was never created", name)
	return nil
}

// addJobPod gives the Job a pod, so the Runner reads its log.
func (h *harness) addJobPod(job string) {
	h.t.Helper()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job + "-abcde", Namespace: upgradeTestNS, Labels: map[string]string{"job-name": job}}}
	if _, err := h.client.CoreV1().Pods(upgradeTestNS).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) setJob(name string, cond batchv1.JobConditionType, reason, msg string) {
	h.t.Helper()
	setJobCondition(h.t, h.client, name, cond, reason, msg)
}

func setJobCondition(t *testing.T, client *fake.Clientset, name string, cond batchv1.JobConditionType, reason, msg string) {
	t.Helper()
	ctx := context.Background()
	j, err := client.BatchV1().Jobs(upgradeTestNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	j.Status.Conditions = append(j.Status.Conditions, batchv1.JobCondition{Type: cond, Status: corev1.ConditionTrue, Reason: reason, Message: msg})
	if _, err := client.BatchV1().Jobs(upgradeTestNS).UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) waitSettled(id uuid.UUID) runs.Run {
	h.t.Helper()
	return waitSettled(h.t, h.store, id)
}

func waitSettled(t *testing.T, store *runs.MemoryStore, id uuid.UUID) runs.Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := store.Get(context.Background(), id)
		if r.Status != runs.StatusRunning {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %s never settled", id)
	return runs.Run{}
}

func step(r runs.Run, name string) runs.Step {
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	return runs.Step{}
}

func envOf(job *batchv1.Job) map[string]string {
	out := map[string]string{}
	for _, e := range job.Spec.Template.Spec.Containers[0].Env {
		out[e.Name] = e.Value
	}
	return out
}

func capabilitiesGitOps() capabilities.Capabilities {
	return capabilities.Capabilities{HelmManaged: true, GitOps: true, Reason: capabilities.ReasonGitOps}
}
