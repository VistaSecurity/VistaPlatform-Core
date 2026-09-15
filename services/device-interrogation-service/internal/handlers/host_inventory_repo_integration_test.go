package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The intake repository, driven, against a real Postgres (asset-inventory 2.11a).
//
// This test lives HERE rather than in internal/services because that is where
// hostInventoryRepository lives, and the point is to run the INSERT the handler
// actually issues. The previous version was in the services package and could
// not reach the unexported repository, so it re-typed the INSERT statement — a
// copy, which is exactly the wiring gap CLAUDE.md's "test the WIRING, not just
// the helper" rule is about. A column added to, renamed in or dropped from
// RecordHostInventory would have left that copy green.
//
// Every column the real INSERT names is read back and asserted below, so
// dropping any one of them fails this.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// seedIntakeAgent creates the device_agents row a host_inventory row must
// reference — the widened valid_job_assignment CHECK requires agent_id for this
// job type, so a row without one cannot be written at all.
func seedIntakeAgent(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO device_agents (id, tenant_id, name, registration_key, platform, version)
		 VALUES ($1, $2, 'host-inventory-intake-test-agent', $3, 'linux', '0.0.0-test')`,
		id, tenantID, "regkey-"+id.String()); err != nil {
		t.Fatalf("seed device_agent: %v", err)
	}
	return id
}

func TestIntegration_HostInventoryIntake_WritesACompletedJobRow(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedIntakeAgent(t, owner, tenantID)

	// The REAL repository the handler is built over, not a re-typed INSERT.
	repo := &hostInventoryRepository{db: appDB, bypassDB: owner}

	params := []byte(`{"mode":"local","platform":"linux","origin":"agent","agent_version":"1.2.3"}`)
	results := []byte(`{"success":true,"report":{"platform":"linux"},"observations":{"facts":[]}}`)

	before := time.Now().Add(-time.Minute)
	jobID, err := repo.RecordHostInventory(ctx, tenantID, agentID, params, results)
	if err != nil {
		t.Fatalf("RecordHostInventory: %v", err)
	}
	if jobID == uuid.Nil {
		t.Fatal("RecordHostInventory returned the nil UUID; the caller has no row to report")
	}

	// Read back EVERY column the INSERT names. Dropping one from the statement
	// has to fail here, which is the whole reason this test moved packages.
	var (
		gotTenant, gotAgent                                    uuid.UUID
		jobType, status                                        string
		gotParams, gotResults                                  []byte
		createdAt, assignedAt, startedAt, completedAt, updated time.Time
	)
	if err := owner.QueryRow(`
		SELECT tenant_id, agent_id, job_type, status, parameters, results,
		       created_at, assigned_at, started_at, completed_at, updated_at
		  FROM device_jobs WHERE id = $1`, jobID,
	).Scan(&gotTenant, &gotAgent, &jobType, &status, &gotParams, &gotResults,
		&createdAt, &assignedAt, &startedAt, &completedAt, &updated); err != nil {
		t.Fatalf("read back the row: %v", err)
	}

	if gotTenant != tenantID {
		t.Errorf("tenant_id = %s, want %s — the row would be invisible to its owner under RLS", gotTenant, tenantID)
	}
	// The agent id is mandatory: valid_job_assignment requires it for this job
	// type, and a row without one could not be attributed to anything.
	if gotAgent != agentID {
		t.Errorf("agent_id = %s, want %s", gotAgent, agentID)
	}
	if jobType != string(models.JobTypeHostInventory) {
		t.Errorf("job_type = %q, want %q", jobType, models.JobTypeHostInventory)
	}
	// A local collection is already finished when it arrives — there is no
	// queued phase for it, so a row in any other status would sit in the job
	// list as work nobody is going to do.
	if status != "completed" {
		t.Errorf("status = %q, want \"completed\"", status)
	}

	// The payload has to survive intact: it is the whole of what 2.11b will
	// materialise, and a truncated or re-encoded copy is not replayable.
	var storedParams, storedResults map[string]any
	if err := json.Unmarshal(gotParams, &storedParams); err != nil {
		t.Fatalf("parameters did not round-trip as JSON: %v", err)
	}
	if err := json.Unmarshal(gotResults, &storedResults); err != nil {
		t.Fatalf("results did not round-trip as JSON: %v", err)
	}
	if storedParams["mode"] != "local" || storedParams["agent_version"] != "1.2.3" {
		t.Errorf("parameters lost fields: %v", storedParams)
	}
	if storedResults["success"] != true || storedResults["report"] == nil || storedResults["observations"] == nil {
		t.Errorf("results lost fields: %v", storedResults)
	}

	// Every timestamp column the INSERT sets must actually be set. A NULL
	// completed_at on a row marked completed is the kind of thing that reads as
	// a stuck job forever.
	for name, ts := range map[string]time.Time{
		"created_at":   createdAt,
		"assigned_at":  assignedAt,
		"started_at":   startedAt,
		"completed_at": completedAt,
		"updated_at":   updated,
	} {
		if ts.IsZero() || ts.Before(before) {
			t.Errorf("%s = %v; the INSERT did not set it", name, ts)
		}
	}
}

// A repository with no database must say so rather than returning a nil UUID
// and no error — the handler turns that into a 500 the agent can act on.
func TestIntegration_HostInventoryIntake_NoDatabaseIsAnError(t *testing.T) {
	testdb.Connect(t) // keeps this with its siblings under the same gate
	repo := &hostInventoryRepository{}
	if _, err := repo.RecordHostInventory(context.Background(), uuid.New(), uuid.New(), nil, nil); err == nil {
		t.Fatal("a repository with no database reported success")
	}
}
