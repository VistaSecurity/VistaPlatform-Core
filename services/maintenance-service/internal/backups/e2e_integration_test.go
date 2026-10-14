package backups

// The real-bundle check (WP3): the chart's backup Job SCRIPT runs `pg_dump
// -Fc` in postgres:17-alpine against a real Postgres, then the REAL service —
// SQL stores, Runner, Finalizer — writes the manifest and the encrypted
// bundle. scripts/test-maintenance-backup-e2e.sh drives it (it renders the
// script from the chart, starts Postgres, and afterwards decrypts the bundle
// with cmd/bundle-decrypt and pg_restores it), so the bundle format is proven
// end to end rather than only unit-tested.
//
// Skips unless TEST_DATABASE_URL and the MAINTENANCE_E2E_* variables are set.

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// backupsLockMaintenanceTables is runs' advisory lock (same key): the
// one-running index is global, so tests that create running rows serialise.
func backupsLockMaintenanceTables(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(2524)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(2524)`)
		_ = conn.Close()
	})
	if _, err := db.ExecContext(ctx, `UPDATE public.platform_maintenance_runs SET status = 'cancelled', finished_at = now() WHERE status = 'running'`); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_BackupE2E_RealPgDump(t *testing.T) {
	db := testdb.Connect(t)
	script := os.Getenv("MAINTENANCE_E2E_JOB_SCRIPT")
	// The chart-rendered Job template (the ConfigMap's backup-job.yaml): the
	// service must parse exactly what the chart renders.
	tmplDir := os.Getenv("MAINTENANCE_E2E_JOB_TEMPLATE_DIR")
	out := os.Getenv("MAINTENANCE_E2E_OUT")
	network := os.Getenv("MAINTENANCE_E2E_DOCKER_NETWORK")
	if script == "" || out == "" || network == "" || tmplDir == "" {
		t.Skip("MAINTENANCE_E2E_* not set — run scripts/test-maintenance-backup-e2e.sh")
	}
	testdb.ApplySchema(t, db)
	backupsLockMaintenanceTables(t, db)
	ctx := context.Background()

	root := filepath.Join(out, "volume")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	client := fake.NewClientset(
		backupsSecret("vista-install", map[string]string{"install-id": "e2e-install-id", "signing-key.pem": "E2E-SIGNING-KEY"}),
		backupsSecret("vista-platform", map[string]string{"encryption-master-key": "E2E-MASTER-KEY"}),
		backupsSecret("vista-generated", map[string]string{"postgres-password": "e2e"}),
	)
	logger, _ := test.NewNullLogger()
	runStore := runs.SQLStore{DB: db}
	runner := runs.NewRunner(runStore, client, runs.Config{Namespace: backupsTestNS, PollInterval: 20 * time.Millisecond}, logger)
	t.Cleanup(runner.Stop)
	store := SQLStore{DB: db}
	svc := NewService(Config{
		Enabled: true, Root: root, Retention: 5, JobTemplateDir: tmplDir,
		Namespace: backupsTestNS, ReleaseName: "vista", AppVersion: "4.6.0-e2e", ChartVersion: "4.6.0-e2e",
		ChartSource: "oci://ghcr.io/vistasecurity/vistaplatform",
		Secrets:     SecretNames{Install: "vista-install", Platform: "vista-platform", JWTSigning: "vista-jwt-signing", Generated: "vista-generated"},
	}, store, runner, client, logger)

	pass := os.Getenv("MAINTENANCE_E2E_PASSPHRASE")
	b, run, err := svc.Create(ctx, nil, CreateOptions{IncludeSecrets: true, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.platform_backups WHERE id = $1`, b.ID)
		_, _ = db.Exec(`DELETE FROM public.platform_maintenance_runs WHERE id = $1`, run.ID)
	})

	// Play the Job: the chart's script, in the chart's image, with the plain
	// env the service put on the Job (BACKUP_ID among it). The cluster-only
	// values — PGHOST "postgres", the Secret-backed PGPASSWORD — are replaced
	// by the e2e Postgres's (later -e flags win).
	job, err := client.BatchV1().Jobs(backupsTestNS).Get(ctx, JobName(b.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The Job and the service run as ONE uid in the chart (both take
	// podSecurityContext), and the Job writes with umask 077 — so the e2e runs
	// the Job as this test process's uid, which plays the service.
	user := os.Getenv("MAINTENANCE_E2E_USER")
	if user == "" {
		user = "1001:1001"
	}
	args := []string{"run", "--rm", "--network", network, "--user", user, "-v", root + ":/backups"}
	for _, e := range job.Spec.Template.Spec.Containers[0].Env {
		if e.Value != "" {
			args = append(args, "-e", e.Name+"="+e.Value)
		}
	}
	for _, k := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"} {
		args = append(args, "-e", k+"="+os.Getenv("MAINTENANCE_E2E_"+k))
	}
	args = append(args, "-v", script+":/job.sh:ro", "postgres:17-alpine", "sh", "/job.sh")
	cmd := exec.Command("docker", args...)
	logOut, err := cmd.CombinedOutput()
	t.Logf("backup Job log:\n%s", logOut)
	if err != nil {
		t.Fatalf("the backup Job script failed: %v", err)
	}
	if !strings.Contains(string(logOut), "VISTA_STEP dump succeeded") {
		t.Fatal("the Job did not report its step")
	}

	j := job.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	if _, err := client.BatchV1().Jobs(backupsTestNS).UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	var settled runs.Run
	for time.Now().Before(deadline) {
		settled, _ = runStore.Get(ctx, run.ID)
		if settled.Status != runs.StatusRunning {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if settled.Status != runs.StatusSucceeded {
		t.Fatalf("run %+v", settled)
	}
	got, err := store.Get(ctx, b.ID)
	if err != nil || got.Status != StatusReady || !got.Encrypted || got.Manifest == nil {
		t.Fatalf("backup %+v, %v", got, err)
	}
	m := got.Manifest
	if !strings.HasPrefix(m.PgDumpVersion, "pg_dump (PostgreSQL) 17") || !strings.Contains(string(m.Schema), "schema_hash") || m.InstallID != "e2e-install-id" {
		t.Fatalf("manifest from the real Job: %+v (schema %s)", m, m.Schema)
	}
	if err := os.Rename(filepath.Join(root, got.FilePath), filepath.Join(out, "bundle.enc")); err != nil {
		t.Fatal(err)
	}
	t.Logf("bundle.enc: %d bytes, manifest pg_dump %q, schema %s", *got.SizeBytes, m.PgDumpVersion, m.Schema)
}
