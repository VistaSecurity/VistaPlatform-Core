package backups

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus/hooks/test"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/bundlecrypt"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

const backupsTestNS = "vista-test"

// backupsMemStore is an in-memory Store.
type backupsMemStore struct {
	mu sync.Mutex
	m  map[uuid.UUID]Backup
}

func newBackupsMemStore() *backupsMemStore { return &backupsMemStore{m: map[uuid.UUID]Backup{}} }

func (s *backupsMemStore) Insert(_ context.Context, b Backup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[b.ID] = b
	return nil
}
func (s *backupsMemStore) Get(_ context.Context, id uuid.UUID) (Backup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[id]
	if !ok {
		return Backup{}, ErrNotFound
	}
	return b, nil
}
func (s *backupsMemStore) GetByRun(_ context.Context, runID uuid.UUID) (Backup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.m {
		if b.RunID != nil && *b.RunID == runID {
			return b, nil
		}
	}
	return Backup{}, ErrNotFound
}
func (s *backupsMemStore) sorted(filter func(Backup) bool) []Backup {
	out := []Backup{}
	for _, b := range s.m {
		if filter(b) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[j].CreatedAt.Before(out[i].CreatedAt) })
	return out
}
func (s *backupsMemStore) List(context.Context) ([]Backup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sorted(func(b Backup) bool { return b.Status != StatusDeleted }), nil
}
func (s *backupsMemStore) set(id uuid.UUID, f func(*Backup)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.m[id]
	f(&b)
	s.m[id] = b
}
func (s *backupsMemStore) MarkReady(_ context.Context, id uuid.UUID, size int64, m Manifest, p string) error {
	s.set(id, func(b *Backup) {
		b.Status, b.SizeBytes, b.Manifest, b.FilePath, b.Contents = StatusReady, &size, &m, p, m.Contents
	})
	return nil
}
func (s *backupsMemStore) MarkFailed(_ context.Context, id uuid.UUID) error {
	s.set(id, func(b *Backup) { b.Status = StatusFailed })
	return nil
}
func (s *backupsMemStore) MarkDeleted(_ context.Context, id uuid.UUID) error {
	now := time.Now()
	s.set(id, func(b *Backup) { b.Status, b.DeletedAt = StatusDeleted, &now })
	return nil
}
func (s *backupsMemStore) ReadyBeyond(_ context.Context, keep int) ([]Backup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ready := s.sorted(func(b Backup) bool { return b.Status == StatusReady })
	if len(ready) <= keep {
		return nil, nil
	}
	old := ready[keep:]
	sort.Slice(old, func(i, j int) bool { return old[i].CreatedAt.Before(old[j].CreatedAt) })
	return old, nil
}

// backupsJobTemplate is a minimal stand-in for the chart-rendered template.
const backupsJobTemplate = `apiVersion: batch/v1
kind: Job
metadata:
  labels:
    app.kubernetes.io/component: maintenance-backup
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: pg-dump
          image: postgres:17-alpine
          env:
            - name: BACKUP_ID
              value: ""
            - name: BACKUP_ROOT
              value: /backups
`

type backupsHarness struct {
	t      *testing.T
	root   string
	store  *backupsMemStore
	runs   *runs.MemoryStore
	runner *runs.Runner
	client *fake.Clientset
	svc    *Service
	h      *Handlers
}

// testParams keep Argon2id cheap in tests.
var backupsTestParams = bundlecrypt.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, ChunkSize: 4096}

func newBackupsHarness(t *testing.T, retention int, objects ...runtime.Object) *backupsHarness {
	t.Helper()
	root := t.TempDir()
	tmplDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmplDir, JobTemplateFile), []byte(backupsJobTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset(objects...)
	logger, _ := test.NewNullLogger()
	rs := runs.NewMemoryStore()
	runner := runs.NewRunner(rs, client, runs.Config{Namespace: backupsTestNS, PollInterval: 5 * time.Millisecond}, logger)
	t.Cleanup(runner.Stop)
	store := newBackupsMemStore()
	cfg := Config{
		Enabled: true, Root: root, Retention: retention, JobTemplateDir: tmplDir,
		Namespace: backupsTestNS, ReleaseName: "vista", AppVersion: "4.6.0", ChartVersion: "4.6.0",
		ChartSource: "oci://ghcr.io/vistasecurity/vistaplatform",
		Secrets:     SecretNames{Install: "vista-install", Platform: "vista-platform", JWTSigning: "vista-jwt-signing", Generated: "vista-generated"},
		DB:          ManifestDB{CredentialSecret: "vista-generated", CredentialKey: "postgres-password"},
		Params:      backupsTestParams,
	}
	svc := NewService(cfg, store, runner, client, logger)
	return &backupsHarness{t: t, root: root, store: store, runs: rs, runner: runner, client: client, svc: svc, h: NewHandlers(svc, nil, logger)}
}

// dumpBytes stands in for a pg_dump -Fc archive.
func dumpBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	copy(b, pgDumpMagic)
	return b
}

// completeJob plays the backup Job: writes what the chart's script writes,
// then marks the Job complete.
func (bh *backupsHarness) completeJob(b Backup, dump []byte) {
	t := bh.t
	t.Helper()
	dir := filepath.Join(bh.root, b.ID.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if dump != nil {
		mustWrite(t, filepath.Join(dir, FileDump), dump)
	}
	mustWrite(t, filepath.Join(dir, FilePgDumpVersion), []byte("pg_dump (PostgreSQL) 17.6\n"))
	mustWrite(t, filepath.Join(dir, FileSchema), []byte(`{"schema_hash":"abc123","app_version":"4.6.0","chart_version":"4.6.0","applied_at":"2026-10-14T03:00:00Z"}`))
	bh.setJob(JobName(b.ID), batchv1.JobComplete)
}

func (bh *backupsHarness) setJob(name string, cond batchv1.JobConditionType) {
	t := bh.t
	t.Helper()
	ctx := context.Background()
	j, err := bh.client.BatchV1().Jobs(backupsTestNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	j.Status.Conditions = append(j.Status.Conditions, batchv1.JobCondition{Type: cond, Status: corev1.ConditionTrue, Reason: "Test"})
	if _, err := bh.client.BatchV1().Jobs(backupsTestNS).UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (bh *backupsHarness) waitRun(id uuid.UUID) runs.Run {
	t := bh.t
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := bh.runs.Get(context.Background(), id)
		if r.Status != runs.StatusRunning {
			bh.runner.Wait()
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %s never settled", id)
	return runs.Run{}
}

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// untar reads a tar into name -> content.
func untar(t *testing.T, r io.Reader) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(r)
	var order []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = b
		order = append(order, h.Name)
	}
	if len(order) == 0 || order[0] != FileManifest {
		t.Fatalf("tar order %v, want manifest.json first", order)
	}
	return out
}

func backupsSecret(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: backupsTestNS, ResourceVersion: "42", UID: "uid-1",
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "Helm"},
			Annotations: map[string]string{"meta.helm.sh/release-name": "vista", "meta.helm.sh/release-namespace": backupsTestNS, "kubectl.kubernetes.io/last-applied-configuration": "{}"}},
		Type: corev1.SecretTypeOpaque, Data: map[string][]byte{},
	}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

func TestBackup_DatabaseOnly(t *testing.T) {
	bh := newBackupsHarness(t, 5, backupsSecret("vista-install", map[string]string{"install-id": "11111111-2222-3333-4444-555555555555", "signing-key.pem": "PRIVATE"}))
	ctx := context.Background()
	user := uuid.New()
	b, run, err := bh.svc.Create(ctx, &user, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := bh.client.BatchV1().Jobs(backupsTestNS).Get(ctx, JobName(b.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Job not created: %v", err)
	}
	env := map[string]string{}
	for _, e := range job.Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env[EnvBackupID] != b.ID.String() || env["BACKUP_ROOT"] != "/backups" {
		t.Fatalf("Job env %v: want BACKUP_ID set and the template's env kept", env)
	}
	dump := dumpBytes(t, 10_000)
	bh.completeJob(b, dump)
	settled := bh.waitRun(run.ID)
	if settled.Status != runs.StatusSucceeded {
		t.Fatalf("run %+v", settled)
	}
	got, _ := bh.store.Get(ctx, b.ID)
	if got.Status != StatusReady || got.Encrypted || got.SizeBytes == nil || got.FilePath != filepath.Join(b.ID.String(), FileBundleTar) {
		t.Fatalf("backup %+v", got)
	}
	m := got.Manifest
	if m == nil || m.AppVersion != "4.6.0" || m.Edition != "core" || m.InstallID != "11111111-2222-3333-4444-555555555555" ||
		m.PgDumpVersion != "pg_dump (PostgreSQL) 17.6" || !strings.Contains(string(m.Schema), "abc123") || m.Contents.Secrets || len(m.Secrets) != 0 {
		t.Fatalf("manifest %+v", m)
	}
	for _, f := range []string{FileDump, FilePgDumpVersion, FileSchema} {
		if _, err := os.Stat(filepath.Join(bh.root, b.ID.String(), f)); err == nil {
			t.Fatalf("%s left beside the bundle", f)
		}
	}
	f, err := os.Open(filepath.Join(bh.root, got.FilePath))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	files := untar(t, f)
	if !bytes.Equal(files[FileDump], dump) {
		t.Fatal("dump in the tar differs")
	}
	if _, ok := files[FileSecrets]; ok {
		t.Fatal("a database-only backup carries secrets.yaml")
	}
	var tm Manifest
	if err := json.Unmarshal(files[FileManifest], &tm); err != nil || tm.BackupID != b.ID.String() {
		t.Fatalf("manifest.json %s: %v", files[FileManifest], err)
	}
	if strings.Contains(string(files[FileManifest]), "PRIVATE") {
		t.Fatal("the manifest carries the install signing key")
	}
}

func TestBackup_WithSecretsIsEncryptedAndNeverPlaintextOnDisk(t *testing.T) {
	const masterKey = "MASTER-KEY-VALUE-do-not-leak"
	bh := newBackupsHarness(t, 5,
		backupsSecret("vista-install", map[string]string{"install-id": "iid", "signing-key.pem": "INSTALL-SIGNING"}),
		backupsSecret("vista-platform", map[string]string{"encryption-master-key": masterKey}),
		backupsSecret("vista-generated", map[string]string{"postgres-password": "pgpw"}),
		// vista-jwt-signing absent: jwtSigning.enabled=false.
		backupsSecret("unrelated", map[string]string{"x": "must not be included"}),
	)
	ctx := context.Background()
	pass := "a long enough passphrase"
	b, run, err := bh.svc.Create(ctx, nil, CreateOptions{IncludeSecrets: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	bh.completeJob(b, dumpBytes(t, 20_000))
	if s := bh.waitRun(run.ID); s.Status != runs.StatusSucceeded {
		t.Fatalf("run %+v", s)
	}
	got, _ := bh.store.Get(ctx, b.ID)
	if got.Status != StatusReady || !got.Encrypted || !strings.HasSuffix(got.FilePath, FileBundleEnc) {
		t.Fatalf("backup %+v", got)
	}
	if want := []string{"vista-generated", "vista-install", "vista-platform"}; strings.Join(got.Manifest.Secrets, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest secrets %v, want %v", got.Manifest.Secrets, want)
	}
	// MAINTENANCE_SECRET_CBOM_SIGNING unset (the chart does not render that
	// Secret): skipped, recorded as absent, not an error.
	if got.Manifest.Contents.CBOMSigningKey || got.Contents.CBOMSigningKey {
		t.Fatal("cbom_signing_key recorded as included without MAINTENANCE_SECRET_CBOM_SIGNING")
	}
	// Nothing in the backup's directory holds the key in the clear.
	entries, _ := os.ReadDir(filepath.Join(bh.root, b.ID.String()))
	if len(entries) != 1 || entries[0].Name() != FileBundleEnc {
		t.Fatalf("directory holds %v, want only bundle.enc", entries)
	}
	raw, _ := os.ReadFile(filepath.Join(bh.root, got.FilePath))
	if bytes.Contains(raw, []byte(masterKey)) || bytes.Contains(raw, []byte(pgDumpMagic)) {
		t.Fatal("plaintext visible in bundle.enc")
	}
	r, err := bundlecrypt.NewReader(bytes.NewReader(raw), []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	files := untar(t, r)
	var list secretsList
	if err := yaml.Unmarshal(files[FileSecrets], &list); err != nil {
		t.Fatal(err)
	}
	if list.Kind != "List" || len(list.Items) != 3 {
		t.Fatalf("secrets.yaml: kind %s, %d items", list.Kind, len(list.Items))
	}
	for _, s := range list.Items {
		if s.Namespace != "" || s.ResourceVersion != "" || s.UID != "" {
			t.Fatalf("%s keeps server identity: ns=%q rv=%q uid=%q", s.Name, s.Namespace, s.ResourceVersion, s.UID)
		}
		if s.Annotations["meta.helm.sh/release-name"] != "vista" || s.Labels["app.kubernetes.io/managed-by"] != "Helm" {
			t.Fatalf("%s lost the Helm ownership metadata a restore needs", s.Name)
		}
		if _, ok := s.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
			t.Fatalf("%s keeps last-applied-configuration", s.Name)
		}
		if s.Name == "vista-platform" && string(s.Data["encryption-master-key"]) != masterKey {
			t.Fatal("the master key did not survive the round trip")
		}
	}
	if _, err := bundlecrypt.NewReader(bytes.NewReader(raw), []byte("not the passphrase")); !errors.Is(err, bundlecrypt.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

func TestBackup_Validation(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	for _, tc := range []struct {
		opts CreateOptions
		want error
	}{
		{CreateOptions{IncludeSecrets: true}, ErrPassphraseRequired},
		{CreateOptions{IncludeSecrets: true, Passphrase: "short"}, ErrPassphraseTooShort},
		{CreateOptions{Passphrase: "a passphrase with no secrets"}, ErrPassphraseWithoutSecrets},
	} {
		if _, _, err := bh.svc.Create(context.Background(), nil, tc.opts); !errors.Is(err, tc.want) {
			t.Errorf("%+v: %v, want %v", tc.opts, err, tc.want)
		}
	}
	if l, _ := bh.runs.ListRunning(context.Background()); len(l) != 0 {
		t.Fatal("a refused request began a run")
	}
}

func TestBackup_OneRunAtATime(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	if _, _, err := bh.svc.Create(context.Background(), nil, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bh.svc.Create(context.Background(), nil, CreateOptions{}); !errors.Is(err, runs.ErrRunInProgress) {
		t.Fatalf("second backup: %v, want ErrRunInProgress", err)
	}
}

func TestBackup_JobFailureMarksFailedAndCleansUp(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	b, run, err := bh.svc.Create(context.Background(), nil, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(bh.root, b.ID.String())
	_ = os.MkdirAll(dir, 0o700)
	mustWrite(t, filepath.Join(dir, FileDump+".partial"), []byte("PGDMP half"))
	bh.setJob(JobName(b.ID), batchv1.JobFailed)
	if s := bh.waitRun(run.ID); s.Status != runs.StatusFailed || s.FailedStep() != StepDump {
		t.Fatalf("run %+v", s)
	}
	if got, _ := bh.store.Get(context.Background(), b.ID); got.Status != StatusFailed {
		t.Fatalf("backup %+v", got)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed backup's partial dump was left on the volume")
	}
}

// A Job that "succeeded" without a real dump must not become a ready backup.
func TestBackup_MissingOrBogusDumpFails(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	b, run, _ := bh.svc.Create(context.Background(), nil, CreateOptions{})
	bh.completeJob(b, []byte("not a pg_dump archive"))
	s := bh.waitRun(run.ID)
	if s.Status != runs.StatusFailed || s.FailedStep() != StepPackage || !strings.Contains(s.Error, "custom-format") {
		t.Fatalf("run %+v", s)
	}
}

func TestBackup_RetentionPrunesOldest(t *testing.T) {
	bh := newBackupsHarness(t, 2)
	ctx := context.Background()
	var old []Backup
	for i := 0; i < 3; i++ {
		ob := Backup{ID: uuid.New(), CreatedAt: time.Now().Add(-time.Duration(10-i) * time.Hour), Contents: Contents{Database: true}, Status: StatusReady}
		ob.FilePath = filepath.Join(ob.ID.String(), FileBundleTar)
		_ = os.MkdirAll(filepath.Join(bh.root, ob.ID.String()), 0o700)
		mustWrite(t, filepath.Join(bh.root, ob.FilePath), []byte("old"))
		_ = bh.store.Insert(ctx, ob)
		old = append(old, ob)
	}
	b, run, _ := bh.svc.Create(ctx, nil, CreateOptions{})
	bh.completeJob(b, dumpBytes(t, 100))
	if s := bh.waitRun(run.ID); s.Status != runs.StatusSucceeded {
		t.Fatalf("run %+v", s)
	}
	// Retention 2 keeps the new backup and the newest old one.
	for i, ob := range old {
		got, _ := bh.store.Get(ctx, ob.ID)
		_, statErr := os.Stat(filepath.Join(bh.root, ob.ID.String()))
		if i < 2 && (got.Status != StatusDeleted || statErr == nil) {
			t.Errorf("old backup %d: status %s, files present %v; want pruned", i, got.Status, statErr == nil)
		}
		if i == 2 && (got.Status != StatusReady || statErr != nil) {
			t.Errorf("newest old backup pruned: %s", got.Status)
		}
	}
	list, _ := bh.svc.List(ctx)
	if len(list) != 2 || list[0].ID != b.ID {
		t.Fatalf("list after pruning: %d backups", len(list))
	}
}

// The passphrase lives only in memory: a backup with secrets whose service
// restarted mid-run fails with that reason, and one without secrets completes.
func TestBackup_ReconcileAfterRestart(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	ctx := context.Background()
	withSecrets, run1, err := bh.svc.Create(ctx, nil, CreateOptions{IncludeSecrets: true, Passphrase: "a long enough passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	bh.runner.Stop() // the process goes away; the run stays running

	// The next process: a fresh Runner and Service over the same state.
	logger, _ := test.NewNullLogger()
	runner2 := runs.NewRunner(bh.runs, bh.client, runs.Config{Namespace: backupsTestNS, PollInterval: 5 * time.Millisecond}, logger)
	t.Cleanup(runner2.Stop)
	svc2 := NewService(bh.svc.cfg, bh.store, runner2, bh.client, logger)
	bh.runner, bh.svc = runner2, svc2
	bh.completeJob(withSecrets, dumpBytes(t, 100))
	if err := runner2.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	s := bh.waitRun(run1.ID)
	if s.Status != runs.StatusFailed || !strings.Contains(s.Error, "restarted") {
		t.Fatalf("secrets backup after restart: %+v", s)
	}

	plain, run2, err := svc2.Create(ctx, nil, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runner2.Stop()
	runner3 := runs.NewRunner(bh.runs, bh.client, runs.Config{Namespace: backupsTestNS, PollInterval: 5 * time.Millisecond}, logger)
	t.Cleanup(runner3.Stop)
	NewService(bh.svc.cfg, bh.store, runner3, bh.client, logger)
	bh.runner = runner3
	bh.completeJob(plain, dumpBytes(t, 100))
	_ = runner3.Reconcile(ctx)
	if s := bh.waitRun(run2.ID); s.Status != runs.StatusSucceeded {
		t.Fatalf("database-only backup after restart: %+v", s)
	}
	if got, _ := bh.store.Get(ctx, plain.ID); got.Status != StatusReady {
		t.Fatalf("backup %+v", got)
	}
}

func TestBackup_DeleteAndPathContainment(t *testing.T) {
	bh := newBackupsHarness(t, 5)
	ctx := context.Background()
	running, _, _ := bh.svc.Create(ctx, nil, CreateOptions{})
	if _, err := bh.svc.Delete(ctx, running.ID); !errors.Is(err, ErrBackupRunning) {
		t.Fatalf("delete running: %v", err)
	}
	if _, err := bh.svc.Delete(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	evil := Backup{ID: uuid.New(), Status: StatusReady, FilePath: "../../etc/passwd", CreatedAt: time.Now()}
	_ = bh.store.Insert(ctx, evil)
	if _, err := bh.svc.Open(ctx, evil.ID); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("Open followed a path out of the volume: %v", err)
	}
}

func TestDownloadFilename(t *testing.T) {
	at := time.Date(2026, 10, 14, 3, 12, 0, 0, time.UTC)
	b := Backup{CreatedAt: at, Manifest: &Manifest{AppVersion: "4.6.0"}, FilePath: "x/bundle.tar"}
	if got := DownloadFilename(b); got != "vista-platform-backup-20261014-031200-4.6.0.tar" {
		t.Fatal(got)
	}
	b.Encrypted, b.Manifest.AppVersion = true, `4.6.0"; rm -rf /`
	if got := DownloadFilename(b); got != "vista-platform-backup-20261014-031200-4.6.0_rm_-rf.enc" {
		t.Fatal(got)
	}
}

func TestEditionFromChartSource(t *testing.T) {
	for src, want := range map[string]string{
		"oci://ghcr.io/vistasecurity/vistaplatform":   "core",
		"oci://docker.io/vistasecurity/vistaplatform": "commercial",
		"oci://mirror.example/charts/vistaplatform":   "unknown",
	} {
		if got := EditionFromChartSource(src); got != want {
			t.Errorf("%s: %s, want %s", src, got, want)
		}
	}
}

// With MAINTENANCE_SECRET_CBOM_SIGNING set, a secrets-included backup carries
// the CBOM signing key (so restored artifacts still verify) and says so in
// contents; a database-only backup never does.
func TestBackup_CBOMSigningKey(t *testing.T) {
	const cbomKey = "CBOM-SIGNING-PRIVATE-KEY"
	bh := newBackupsHarness(t, 5,
		backupsSecret("vista-install", map[string]string{"install-id": "iid"}),
		backupsSecret("vista-platform", map[string]string{"encryption-master-key": "mk"}),
		backupsSecret("vista-cbom-signing", map[string]string{"signing-key.pem": cbomKey}),
	)
	bh.svc.cfg.Secrets.CBOMSigning = "vista-cbom-signing"
	ctx := context.Background()
	pass := "a long enough passphrase"
	b, run, err := bh.svc.Create(ctx, nil, CreateOptions{IncludeSecrets: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	bh.completeJob(b, dumpBytes(t, 1000))
	if s := bh.waitRun(run.ID); s.Status != runs.StatusSucceeded {
		t.Fatalf("run %+v", s)
	}
	got, _ := bh.store.Get(ctx, b.ID)
	if !got.Manifest.Contents.CBOMSigningKey || !got.Contents.CBOMSigningKey {
		t.Fatalf("contents %+v / manifest contents %+v: want cbom_signing_key true", got.Contents, got.Manifest.Contents)
	}
	if !strings.Contains(strings.Join(got.Manifest.Secrets, ","), "vista-cbom-signing") {
		t.Fatalf("manifest secrets %v", got.Manifest.Secrets)
	}
	raw, _ := os.ReadFile(filepath.Join(bh.root, got.FilePath))
	if bytes.Contains(raw, []byte(cbomKey)) {
		t.Fatal("the CBOM key is visible in bundle.enc")
	}
	r, err := bundlecrypt.NewReader(bytes.NewReader(raw), []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	var list secretsList
	if err := yaml.Unmarshal(untar(t, r)[FileSecrets], &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list.Items {
		if s.Name == "vista-cbom-signing" && string(s.Data["signing-key.pem"]) == cbomKey {
			found = true
		}
	}
	if !found {
		t.Fatal("secrets.yaml lacks the CBOM signing Secret")
	}

	// Env set but the Secret is not there: skipped, absent, not an error.
	bh2 := newBackupsHarness(t, 5, backupsSecret("vista-platform", map[string]string{"encryption-master-key": "mk"}))
	bh2.svc.cfg.Secrets.CBOMSigning = "vista-cbom-signing"
	b2, run2, err := bh2.svc.Create(ctx, nil, CreateOptions{IncludeSecrets: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	bh2.completeJob(b2, dumpBytes(t, 1000))
	if s := bh2.waitRun(run2.ID); s.Status != runs.StatusSucceeded {
		t.Fatalf("missing CBOM Secret failed the backup: %+v", s)
	}
	if got2, _ := bh2.store.Get(ctx, b2.ID); got2.Contents.CBOMSigningKey {
		t.Fatal("cbom_signing_key true with the Secret absent")
	}

	// Database only: never.
	b3, run3, err := bh.svc.Create(ctx, nil, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bh.completeJob(b3, dumpBytes(t, 1000))
	bh.waitRun(run3.ID)
	if got3, _ := bh.store.Get(ctx, b3.ID); got3.Contents.CBOMSigningKey || got3.Contents.Secrets {
		t.Fatalf("database-only backup contents %+v", got3.Contents)
	}
}
