package services

// Dropped ops observations must show up on the device job.
//
// ObservationSink.Persist does not fail an interrogation — the crypto assets
// have landed — so its error used to go to stdout and nowhere else. A UniFi run
// that lost 139 of 143 facts and every edge still persisted
// `errors: [], fully_materialized: true`. These drive the REAL ProcessJobResults
// so the wiring, not just the ProcessingLog helper, is what is pinned.
//
// MUTATION: delete either steps.observationsFailed call in ProcessJobResults and
// the matching subtest fails.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type storedObservationProcessing struct {
	ObservationsFailed int  `json:"observations_failed"`
	FullyMaterialized  bool `json:"fully_materialized"`
	Errors             []struct {
		Stage   string `json:"stage"`
		Message string `json:"message"`
		Count   int    `json:"count"`
	} `json:"errors"`
}

func TestIntegration_ProcessJobResults_DroppedObservationsReachProcessingBlock(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	processor := NewResultProcessor(app, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := func(t *testing.T, result *models.JobResult) storedObservationProcessing {
		t.Helper()
		asset := subjectAsset(t, owner, tenant, "gateway-"+uuid.NewString()[:8])
		agent := insertDeviceAgent(t, owner, tenant)
		result.JobID = uuid.New()
		if _, err := owner.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
			VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, result.JobID, tenant, agent, asset); err != nil {
			t.Fatalf("seed device_job: %v", err)
		}
		if err := processor.ProcessJobResults(ctx, result.JobID, result); err != nil {
			t.Fatalf("ProcessJobResults: %v", err)
		}
		var body []byte
		if err := owner.QueryRow(`SELECT results->'processing' FROM device_jobs WHERE id=$1`, result.JobID).Scan(&body); err != nil {
			t.Fatalf("read processing block: %v", err)
		}
		var p storedObservationProcessing
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("decode processing block %s: %v", body, err)
		}
		return p
	}
	assertSurfaced := func(t *testing.T, p storedObservationProcessing, wantFailed int, wantMessage string) {
		t.Helper()
		if p.ObservationsFailed != wantFailed {
			t.Errorf("observations_failed = %d, want %d", p.ObservationsFailed, wantFailed)
		}
		if p.FullyMaterialized {
			t.Error("fully_materialized = true for a run that dropped observations")
		}
		found := false
		for _, e := range p.Errors {
			if e.Stage == StageObservations && strings.Contains(e.Message, wantMessage) {
				found = true
			}
		}
		if !found {
			t.Errorf("no %q error mentioning %q in %+v", StageObservations, wantMessage, p.Errors)
		}
	}

	// The agent path: the processor persists the observations itself, and a
	// fact key nothing registered is a real rejection from the fact writer.
	t.Run("agent result", func(t *testing.T) {
		p := run(t, &models.JobResult{
			Success:     true,
			CompletedAt: time.Now().UTC(),
			Facts:       []di.FactObservation{{Key: "test.never_registered", Value: "x", Confidence: 1}},
		})
		assertSurfaced(t, p, 1, "not registered")
	})

	// The in-cluster path: the executor persisted them and hands over what it
	// could not write. One step per dropped observation.
	t.Run("in-cluster result", func(t *testing.T) {
		p := run(t, &models.JobResult{
			Success:     true,
			CompletedAt: time.Now().UTC(),
			ObservationsErr: errors.Join(
				errors.New("fact hw.model: resolving subject: boom"),
				errors.New("edge connects_to: resolving subject: boom"),
			),
		})
		assertSurfaced(t, p, 2, "resolving subject")
	})

	// And a run that dropped nothing still reads clean.
	t.Run("clean result", func(t *testing.T) {
		p := run(t, &models.JobResult{
			Success:     true,
			CompletedAt: time.Now().UTC(),
			Facts:       []di.FactObservation{{Key: "hw.model", Value: "Gateway", Confidence: 1}},
		})
		if p.ObservationsFailed != 0 || !p.FullyMaterialized || len(p.Errors) != 0 {
			t.Errorf("clean run reported %+v", p)
		}
	})
}
