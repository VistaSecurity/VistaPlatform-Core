package services

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"strings"
	"testing"
	"time"
)

func TestIntegration_MergePreservesSensitivePolicyAndQueuedProbeDenial(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	foreign := testdb.NewTenant(t, raw)
	source := seedAsset(t, db, tenant, "source.test", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, db, tenant, "survivor.test", "server", "hardware.computer.server", "production", 0, 0)
	actor := seedUser(t, db, tenant)
	sensitive := []uuid.UUID{source}
	for len(sensitive) < 256 {
		sensitive = append(sensitive, uuid.New())
	}
	list, _ := json.Marshal(sensitive)
	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,jsonb_build_object('private_unrelated',jsonb_build_object('secret','never-project'),'discovery_auto_scan',jsonb_build_object('rescan_interval_hours',12),'identity_admission',jsonb_build_object('mode','enforce'),'identity_enrichment',jsonb_build_object('enabled',true,'future_flag',true,'sensitive_asset_ids',$2::jsonb))) ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant, string(list)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"untouched":true}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, foreign); err != nil {
		t.Fatal(err)
	}
	observation := uuid.New()
	if _, err := raw.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,state,asset_id,first_seen_at,last_seen_at) VALUES($1,$2::uuid,$2::text,'measured','sensor:test','{}','linked',$3,now(),now())`, tenant, observation, source); err != nil {
		t.Fatal(err)
	}
	svc := NewMergeProposalService(db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"hostname": survivor, "display_name": survivor}}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(preview)
	if strings.Contains(string(public), "never-project") {
		t.Fatal("private settings leaked to preview")
	}
	request := MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Verified same protected appliance"}
	result, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, actor, request)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	var data []byte
	var version int
	if err := raw.QueryRow(`SELECT config,version FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&data, &version); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	ids := config["identity_enrichment"].(map[string]any)["sensitive_asset_ids"].([]any)
	if len(ids) != 256 || version != 2 {
		t.Fatalf("limit/version changed %d %d", len(ids), version)
	}
	found := false
	for _, id := range ids {
		if id == source.String() {
			t.Fatal("archived source retained instead of survivor")
		}
		found = found || id == survivor.String()
	}
	if !found {
		t.Fatal("survivor protection lost")
	}
	if config["private_unrelated"].(map[string]any)["secret"] != "never-project" || config["identity_enrichment"].(map[string]any)["future_flag"] != true {
		t.Fatal("unrelated settings clobbered")
	}
	var auditedActor uuid.UUID
	var reason string
	if err := raw.QueryRow(`SELECT changed_by,change_reason FROM tenant_admin_settings_audit WHERE tenant_id=$1 AND version_before=1 AND version_after=2`, tenant).Scan(&auditedActor, &reason); err != nil || auditedActor != actor || reason != request.Reason {
		t.Fatalf("audit %v %q %v", auditedActor, reason, err)
	}
	var audit string
	if err := raw.QueryRow(`SELECT audit::text FROM asset_merge_audits WHERE tenant_id=$1 AND id=$2`, tenant, result.ID).Scan(&audit); err != nil || strings.Contains(audit, "never-project") {
		t.Fatalf("merge audit leaked private config: %v", err)
	}
	if err := raw.QueryRow(`SELECT config::text FROM tenant_admin_settings WHERE tenant_id=$1`, foreign).Scan(&audit); err != nil || audit != "{\"untouched\": true}" {
		t.Fatalf("foreign policy changed %v", err)
	}
	tx, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = dispatchguard.AuthorizeProbe(tx, sensordispatch.Payload{TenantID: tenant.String(), Protocols: []string{"TLS"}, Ports: []int{443}, Options: map[string]interface{}{"identity_enrichment_request_id": uuid.NewString(), "identity_observation_id": observation.String(), "identity_network_scope": uuid.NewString()}}, uuid.New())
	_ = tx.Rollback()
	if !errors.Is(err, dispatchguard.ErrDenied) || !strings.Contains(err.Error(), "sensitive asset") {
		t.Fatalf("queued probe did not retain sensitivity: %v", err)
	}
	if replay, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, actor, request); err != nil || !replay.Replayed {
		t.Fatalf("replay %v %v", replay, err)
	}
	if err := raw.QueryRow(`SELECT version FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&version); err != nil || version != 2 {
		t.Fatalf("replay changed policy version %d %v", version, err)
	}
}

func TestIntegration_MergePolicyChangesInvalidatePreviewBeforeAssetLocks(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	source := seedAsset(t, db, tenant, "source.test", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, db, tenant, "survivor.test", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{}') ON CONFLICT(tenant_id) DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	svc := NewMergeProposalService(db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	var version int
	if err := blocker.QueryRow(`SELECT version FROM tenant_admin_settings WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&version); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, uuid.Nil, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Review current policy"})
		finished <- err
	}()
	// Wait for the merge's policy row wait, rather than assuming a scheduler delay.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := raw.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT version FROM tenant_admin_settings%' AND pid<>pg_backend_pid())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("merge never waited for policy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := blocker.Exec(`SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT`, tenant, source); err != nil {
		t.Fatalf("merge acquired asset row before policy: %v", err)
	}
	if _, err := blocker.Exec(`UPDATE tenant_admin_settings SET version=version+1,config=jsonb_build_object('identity_enrichment',jsonb_build_object('sensitive_asset_ids',jsonb_build_array($2::text))) WHERE tenant_id=$1`, tenant, source); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, ErrMergePreviewChanged) {
		t.Fatalf("changed policy accepted: %v", err)
	}
	var status string
	if err := raw.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, source).Scan(&status); err != nil || status == "archived" {
		t.Fatalf("stale merge archived source %s %v", status, err)
	}
}
