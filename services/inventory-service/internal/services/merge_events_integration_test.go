package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type mergeDeliveryProbe struct {
	deliver func(invevents.Envelope) error
}

func (p *mergeDeliveryProbe) Publish(context.Context, string, uuid.UUID, string, interface{}) error {
	return errors.New("non-durable publication used")
}
func (p *mergeDeliveryProbe) PublishDurable(_ context.Context, event invevents.Envelope) error {
	return p.deliver(event)
}

func TestIntegration_MergeEvents_DurableRetryAndTenantIsolation(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)
	survivor := seedAsset(t, db, tenant, "event-survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "event-source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	svc := NewMergeProposalService(db)
	calls := []invevents.Envelope{}
	probe := &mergeDeliveryProbe{deliver: func(event invevents.Envelope) error {
		var status string
		if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, source).Scan(&status); err != nil || status != "archived" {
			t.Fatalf("event published before committed merge: %s %v", status, err)
		}
		calls = append(calls, event)
		return errors.New("temporary bus outage")
	}}
	svc.SetEventPublisher(&EventPublisherService{lifecycle: probe})
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	req := MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Operator verified device identity"}
	result, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, seedUser(t, db, tenant), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("initial attempts=%d", len(calls))
	}
	var count int
	if err := db.QueryRow(`SELECT jsonb_array_length(pending_events) FROM asset_merge_audits WHERE tenant_id=$1 AND id=$2 AND events_published_at IS NULL`, tenant, result.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("lost pending envelope: %d %v", count, err)
	}
	if n, err := svc.PublishPendingMergeEvents(t.Context(), other); err != nil || n != 0 {
		t.Fatalf("other tenant: %d %v", n, err)
	}
	if n, err := svc.PublishPendingMergeEvents(t.Context(), tenant); err != nil || n != 0 {
		t.Fatalf("retry ignored backoff: %d %v", n, err)
	}
	if _, err := db.Exec(`UPDATE asset_merge_audits SET events_next_attempt_at=now()-interval '1 minute' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	probe.deliver = func(event invevents.Envelope) error { calls = append(calls, event); return nil }
	// Recreate the service to prove retry does not depend on process memory.
	restarted := NewMergeProposalService(db)
	restarted.SetEventPublisher(&EventPublisherService{lifecycle: probe})
	if n, err := restarted.PublishPendingMergeEvents(t.Context(), tenant); err != nil || n != 1 {
		t.Fatalf("retry failed: %d %v", n, err)
	}
	first, _ := json.Marshal(calls[0])
	second, _ := json.Marshal(calls[1])
	if string(first) != string(second) {
		t.Fatalf("replay changed stable envelope")
	}
	if calls[0].EventID != uuid.NewSHA1(result.ID, []byte(source.String())) {
		t.Fatal("event is not keyed by merge and source")
	}
	if err := db.QueryRow(`SELECT jsonb_array_length(pending_events) FROM asset_merge_audits WHERE tenant_id=$1 AND id=$2 AND events_published_at IS NOT NULL`, tenant, result.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("delivery not acknowledged: %d %v", count, err)
	}
	if replay, err := restarted.ExecuteMerge(t.Context(), tenant, uuid.Nil, uuid.Nil, req); err != nil || !replay.Replayed {
		t.Fatalf("merge replay failed: %+v %v", replay, err)
	}
	if len(calls) != 2 {
		t.Fatalf("acknowledged envelope republished: %d", len(calls))
	}
}
