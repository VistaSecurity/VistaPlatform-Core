package handlers

// The job-lifecycle routes driven through the real handlers against a real
// Postgres ( H2/H3): progress comes from the job's target rows, and a
// cancel cannot rewrite a job that has already ended.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func setJobStatus(t *testing.T, db *sqlx.DB, jobID, status string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE discovery_jobs SET status = $2 WHERE id = $1`, jobID, status); err != nil {
		t.Fatalf("set job status: %v", err)
	}
}

func addTargets(t *testing.T, db *sqlx.DB, tenant uuid.UUID, jobID string, statuses ...string) {
	t.Helper()
	for i, status := range statuses {
		if _, err := db.Exec(`
			INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status)
			VALUES ($1, $2, $3, ARRAY['TLS'], ARRAY[443], $4)`,
			jobID, tenant, "10.44.0."+string(rune('1'+i)), status); err != nil {
			t.Fatalf("insert target: %v", err)
		}
	}
}

func lifecycleHandler(t *testing.T) (*DiscoveryHandler, *sqlx.DB, uuid.UUID) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := sqlx.NewDb(testdb.Connect(t), "postgres")
	return NewDiscoveryHandler(services.NewDiscoveryService(db, db), nil, nil, nil), db, testdb.NewTenant(t, db.DB)
}

// H3. A running job's progress is the share of its targets that are finished
// — not 50 because it is running. 1 of 3 is 33; nothing finished is 0.
func TestIntegration_DiscoveryHandler_ProgressComesFromTargets(t *testing.T) {
	h, db, tenant := lifecycleHandler(t)

	cases := []struct {
		name         string
		status       string
		targets      []string
		wantProgress int
	}{
		{"one of three finished", "running", []string{"completed", "running", "pending"}, 33},
		{"running, nothing finished", "running", []string{"running", "pending"}, 0},
		{"a refused target counts as finished", "running", []string{"failed", "completed", "pending", "pending"}, 50},
		{"all finished", "completed", []string{"completed", "failed"}, 100},
		{"no targets, completed", "completed", nil, 100},
		{"no targets, queued", "queued", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobID := seedDiscoveryJob(t, db, tenant)
			setJobStatus(t, db, jobID, tc.status)
			addTargets(t, db, tenant, jobID, tc.targets...)

			c, w := newTestContext(tenant, jobID)
			h.GetJobStatus(c)
			if w.Code != http.StatusOK {
				t.Fatalf("GetJobStatus = %d", w.Code)
			}
			var status models.DiscoveryJobStatusResponse
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if status.Progress != tc.wantProgress {
				t.Errorf("status progress = %d, want %d", status.Progress, tc.wantProgress)
			}
			if status.TargetCounts == nil || status.TargetCounts.Total != len(tc.targets) {
				t.Errorf("status target_counts = %+v, want total %d", status.TargetCounts, len(tc.targets))
			}

			// The job read the Jobs page polls carries the same numbers.
			c, w = newTestContext(tenant, jobID)
			h.GetJob(c)
			var job models.DiscoveryJob
			if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
				t.Fatal(err)
			}
			if job.Progress != tc.wantProgress || job.TargetCounts == nil || *job.TargetCounts != *status.TargetCounts {
				t.Errorf("GetJob progress = %d / %+v, want %d / %+v", job.Progress, job.TargetCounts, tc.wantProgress, status.TargetCounts)
			}
		})
	}
}

// H2. Cancel ends a live job, is idempotent on a cancelled one, and is refused
// — 409, nothing written — on a job that already completed or failed.
func TestIntegration_DiscoveryHandler_CancelRespectsEndedJobs(t *testing.T) {
	h, db, tenant := lifecycleHandler(t)

	cancel := func(jobID string) int {
		c, w := newTestContext(tenant, jobID)
		h.CancelJob(c)
		return w.Code
	}
	statusOf := func(jobID string) string {
		var s string
		if err := db.Get(&s, `SELECT status FROM discovery_jobs WHERE id = $1`, jobID); err != nil {
			t.Fatal(err)
		}
		return s
	}

	running := seedDiscoveryJob(t, db, tenant)
	setJobStatus(t, db, running, "running")
	addTargets(t, db, tenant, running, "completed", "pending")
	if code := cancel(running); code != http.StatusOK {
		t.Fatalf("cancel running job = %d, want 200", code)
	}
	if s := statusOf(running); s != "cancelled" {
		t.Fatalf("status = %q, want cancelled", s)
	}
	var states []string
	if err := db.Select(&states, `SELECT status FROM discovery_targets WHERE job_id = $1 ORDER BY status`, running); err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0] != "cancelled" || states[1] != "completed" {
		t.Errorf("target states = %v, want the finished target kept and the unstarted one cancelled", states)
	}
	if code := cancel(running); code != http.StatusOK {
		t.Errorf("cancel of a cancelled job = %d, want 200 (idempotent)", code)
	}

	for _, ended := range []string{"completed", "failed"} {
		jobID := seedDiscoveryJob(t, db, tenant)
		setJobStatus(t, db, jobID, ended)
		if code := cancel(jobID); code != http.StatusConflict {
			t.Errorf("cancel of a %s job = %d, want 409", ended, code)
		}
		if s := statusOf(jobID); s != ended {
			t.Errorf("a refused cancel changed a %s job to %q", ended, s)
		}
	}
}
