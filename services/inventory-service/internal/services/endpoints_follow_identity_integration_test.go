package services

// Endpoints follow the identity decision (owner decision 2 on, platform
// ADR-0003 D2). Matched / Created attach a sighting's sockets inside the
// engine's transaction; Supporting leaves them on the observation until an
// operator's Link or Confirm materialises them — unless ( D4) the
// evidence is a direct measurement of a single live owner, when the engine
// attaches the sockets and holds only the identifiers; existing endpoint rows
// are not deleted, they just stop being refreshed by held evidence.
//
// These tests drive the REAL intake (IngestFindingsReport + the retained-
// evidence worker + DecideIdentityObservation) over the intake matrix's
// gateway fixture, so deleting any one wiring line goes red — see the
// mutation notes on each subtest.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/intakematrix"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// scanAt is the matrix's three-port TLS scan, at any address.
func (m *invMatrix) scanAt(addr string) []IngestFinding {
	out := make([]IngestFinding, 0, len(intakematrix.Ports))
	for i, port := range intakematrix.Ports {
		addr, sensor, port := addr, m.sensor.String(), port
		suite, version := "TLS_AES_128_GCM_SHA256", "TLS 1.3"
		out = append(out, IngestFinding{
			IPAddress: &addr, Port: &port, Protocol: "TLS", AssetType: "server",
			CipherSuite: &suite, ProtocolVersion: &version, SourceSensorID: &sensor,
			RawData: map[string]interface{}{
				"source":       "sensor_discovery",
				"observed_at":  m.Now.Add(-time.Minute).Format(time.RFC3339Nano),
				"discovery_id": fmt.Sprintf("efi-%s-%d", addr, i),
			},
		})
	}
	return out
}

func (m *invMatrix) countRows(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := m.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (m *invMatrix) actor(t *testing.T) uuid.UUID {
	t.Helper()
	actor := uuid.New()
	if _, err := m.DB.Exec(`INSERT INTO users(id,tenant_id,email,is_active) VALUES($1,$2,$3,true)`, actor, m.Tenant, "efi-"+actor.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	return actor
}

func (m *invMatrix) observationIDs(t *testing.T, where string) []uuid.UUID {
	t.Helper()
	rows, err := m.DB.Query(`SELECT id FROM identity_observations WHERE tenant_id=$1 AND `+where+` ORDER BY id`, m.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestIntegration_EndpointsFollowIdentity(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	ctx := context.Background()

	// A match writes the sockets INSIDE the engine's transaction: with service
	// identification unwired and the worker never run, the ports are still
	// there. Mutation: delete the UpsertEndpoints call in the engine's
	// applyToAsset (shared/identity/engine.go) → red.
	t.Run("matched_scan_endpoints_come_from_the_engine", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		m.svc.SetEnrichmentServices(NewNetworkSegmentService(m.svc.db, NewLocationService(m.svc.db)), nil)
		report, err := m.svc.IngestFindingsReport(m.Tenant, m.scanAt(intakematrix.StaticAddr), identity.StatusPendingApproval)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Results {
			if r.Outcome != string(identity.OutcomeMatched) {
				t.Fatalf("outcome %s, want matched", r.Outcome)
			}
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 3 {
			t.Errorf("%d endpoints on the gateway after a matched scan, want 3 written by the engine", n)
		}
	})

	// The lookup never creates. Mutation: restore the UpsertEndpoints call in
	// resolveEndpointForFinding → red.
	t.Run("resolveEndpointForFinding_is_lookup_only", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		f := m.scanAt(intakematrix.TenantAddr)[0]
		id, err := m.svc.resolveEndpointForFinding(ctx, m.Tenant, m.Asset, f)
		if !errors.Is(err, errEndpointNotAttached) || id != uuid.Nil {
			t.Errorf("resolveEndpointForFinding = %s, %v; want uuid.Nil, errEndpointNotAttached", id, err)
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 0 {
			t.Errorf("the lookup wrote %d endpoints", n)
		}
	})

	// D4: a supporting finding that is a direct measurement (a completed
	// TLS exchange, l3_probe) for ONE owner attaches its sockets to that owner,
	// inside the engine's transaction — the engine is the only writer, so this
	// holds with service identification unwired and the worker never run. The
	// identifiers stay held. Mutation: make identity's
	// supportingEndpointsAttach return false → 0 endpoints.
	t.Run("supporting_direct_finding_attaches_its_endpoints_to_the_single_owner", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		m.svc.SetEnrichmentServices(NewNetworkSegmentService(m.svc.db, NewLocationService(m.svc.db)), nil)
		report, err := m.svc.IngestFindingsReport(m.Tenant, m.scanAt(intakematrix.TenantAddr), identity.StatusPendingApproval)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Results {
			if r.Outcome != string(identity.OutcomeSupporting) || r.AssetID != m.Asset.String() {
				t.Fatalf("result %+v, want supporting on the gateway", r)
			}
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 3 {
			t.Errorf("%d endpoints on the gateway, want the 3 the engine attached", n)
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND changes_json->>'supporting'='true' AND jsonb_array_length(changes_json->'endpoints')=1`, m.Tenant, m.Asset); n == 0 {
			t.Error("no supporting history row names the attached endpoints")
		}
		if n := m.countRows(t, `SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND state='linked' AND resolution_outcome='supporting'`, m.Tenant); n != 3 {
			t.Errorf("%d observations recorded as linked supporting evidence, want 3", n)
		}
	})

	// The other polarity: the same scan whose identifiers name TWO owners — the
	// gateway's address and another asset's SSH host key — is contested, and
	// contested evidence attaches no socket to either.
	t.Run("contested_finding_attaches_no_endpoint", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		const otherKey = "SHA256:hostinvOtherAssetKeyAAAAAAAAAAAAAAAAAAAAAAAA"
		other, err := pgidentity.New(raw).CreateAsset(ctx, m.Tenant.String(), identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceDeclared, ClassConfidence: 1,
			DisplayName: "other-host", Status: identity.StatusMonitoring, IdentityStatus: string(identity.IdentityEstablished),
			FirstSeenAt: m.Now, LastSeenAt: m.Now,
			Identifiers: []identity.Identifier{{Kind: identity.KindSSHHostKeyFingerprint, Value: otherKey, Confidence: 1,
				Source: identity.Source{Kind: identity.SourceMeasured, Ref: "scan"}, SeenAt: m.Now}},
		})
		if err != nil {
			t.Fatal(err)
		}
		findings := m.scanAt(intakematrix.TenantAddr)
		for i := range findings {
			findings[i].RawData["ssh_host_key_fingerprint"] = otherKey
		}
		report, err := m.svc.IngestFindingsReport(m.Tenant, findings, identity.StatusPendingApproval)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Results {
			if r.Outcome == string(identity.OutcomeSupporting) || r.Outcome == string(identity.OutcomeMatched) {
				t.Fatalf("outcome %s, want contested evidence for two owners", r.Outcome)
			}
		}
		for _, asset := range []string{m.Asset.String(), other.ID} {
			if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, asset); n != 0 {
				t.Errorf("contested evidence wrote %d endpoints on %s", n, asset)
			}
		}
	})

	// Supporting evidence that is NOT a direct measurement (traffic only, no
	// completed exchange) attaches no socket and refreshes none the asset
	// already has: the gateway's existing :443 keeps its service name and gets
	// no crypto configuration; :8443 and :9443 do not appear. Mutations, each
	// red on its own: drop the `evidenceHeld` skip in IngestFindings (service
	// name refreshed); drop the Direct check in identity's
	// supportingEndpointsAttach (three endpoints).
	t.Run("supporting_indirect_finding_attaches_nothing_and_refreshes_nothing", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		existing := uuid.New()
		if _, err := m.DB.Exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport,service_name,service_confidence,first_seen_at,last_seen_at)
			VALUES($1,$2,$3,$4::inet,443,'tcp','legacy-name','reported',now()-interval '10 days',now()-interval '10 days')`, existing, m.Tenant, m.Asset, intakematrix.TenantAddr); err != nil {
			t.Fatal(err)
		}
		findings := m.scanAt(intakematrix.TenantAddr)
		for i := range findings {
			findings[i].CipherSuite = nil
		}
		report, err := m.svc.IngestFindingsReport(m.Tenant, findings, identity.StatusPendingApproval)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.svc.SweepIdentityEvidence(ctx, m.Tenant); err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Results {
			if r.Outcome != string(identity.OutcomeSupporting) {
				t.Fatalf("outcome %s, want supporting", r.Outcome)
			}
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 1 {
			t.Errorf("%d endpoints on the gateway, want only the pre-existing :443", n)
		}
		var service string
		var fresh bool
		if err := m.DB.QueryRow(`SELECT COALESCE(service_name,''),last_seen_at > now()-interval '1 day' FROM asset_endpoints WHERE tenant_id=$1 AND id=$2`, m.Tenant, existing).Scan(&service, &fresh); err != nil {
			t.Fatal(err)
		}
		if service != "legacy-name" || fresh {
			t.Errorf("existing :443 refreshed by supporting evidence: service %q, last_seen refreshed=%v", service, fresh)
		}
		if n := m.countRows(t, `SELECT count(*) FROM crypto_implementations_partitioned WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 0 {
			t.Errorf("%d crypto configurations materialised from supporting evidence", n)
		}
		if n := m.countRows(t, `SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND state='linked' AND resolution_outcome='supporting'`, m.Tenant); n != 3 {
			t.Errorf("%d observations recorded as linked supporting evidence, want 3", n)
		}
		if n := m.countRows(t, `SELECT count(*) FROM deferred_crypto_findings WHERE tenant_id=$1 AND observation_id IS NOT NULL AND replayed_at IS NULL`, m.Tenant); n != 3 {
			t.Errorf("%d unreplayed held findings, want the 3 held ones", n)
		}
	})

	// Link materialises what supporting evidence held: the three sockets, then
	// (via the worker) the crypto on each. Mutation: drop the
	// attachObservationEndpoints call in DecideIdentityObservation → red.
	t.Run("link_materialises_held_supporting_evidence", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		if _, err := m.svc.IngestFindingsReport(m.Tenant, m.scanAt(intakematrix.TenantAddr), identity.StatusPendingApproval); err != nil {
			t.Fatal(err)
		}
		// Since D4 this direct scan's sockets are attached at ingest.
		// Supporting observations HELD before D4 shipped have none: remove
		// them, so the Link below is what has to write them.
		if _, err := m.DB.Exec(`DELETE FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); err != nil {
			t.Fatal(err)
		}
		actor := m.actor(t)
		ids := m.observationIDs(t, `state='linked' AND resolution_outcome='supporting'`)
		if len(ids) != 3 {
			t.Fatalf("%d supporting observations, want 3", len(ids))
		}
		for _, id := range ids {
			asset := m.Asset
			res, err := m.svc.DecideIdentityObservation(ctx, m.Tenant, id, actor, "linked", ObservationDecisionInput{Reason: "these are the gateway's services", AssetID: &asset})
			if err != nil {
				t.Fatalf("link %s: %v", id, err)
			}
			if res.AssetID != m.Asset.String() {
				t.Errorf("linked to %s, want the gateway", res.AssetID)
			}
		}
		// The decision itself writes the sockets — before the worker runs.
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, m.Tenant, m.Asset); n != 3 {
			t.Errorf("%d endpoints after Link, want 3 written by the decision", n)
		}
		if _, err := m.svc.SweepIdentityEvidence(ctx, m.Tenant); err != nil {
			t.Fatal(err)
		}
		if n := m.countRows(t, `SELECT count(*) FROM crypto_implementations_partitioned WHERE tenant_id=$1 AND asset_id=$2 AND endpoint_id IS NOT NULL`, m.Tenant, m.Asset); n != 3 {
			t.Errorf("%d crypto configurations on endpoints after Link, want 3", n)
		}
		if n := m.countRows(t, `SELECT count(*) FROM deferred_crypto_findings WHERE tenant_id=$1 AND replayed_at IS NULL`, m.Tenant); n != 0 {
			t.Errorf("%d held findings still unreplayed after Link", n)
		}
	})

	// The issue's unverified suspicion: confirming several same-address
	// observations (443, 8443, 9443) of a host nobody owns. It must be ONE
	// asset with three endpoints, not three assets. Mutation: drop the
	// sibling-confirmation join in DecideIdentityObservation → red.
	t.Run("confirm_same_address_three_ports_is_one_asset", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		const host = "10.20.1.50"
		if _, err := m.svc.IngestFindingsReport(m.Tenant, m.scanAt(host), identity.StatusPendingApproval); err != nil {
			t.Fatal(err)
		}
		ids := m.observationIDs(t, `state='unresolved' AND asset_id IS NULL`)
		if len(ids) != 3 {
			t.Fatalf("%d unresolved observations at %s, want 3", len(ids), host)
		}
		actor := m.actor(t)
		assets := map[string]bool{}
		for _, id := range ids {
			res, err := m.svc.DecideIdentityObservation(ctx, m.Tenant, id, actor, "confirmed", ObservationDecisionInput{Reason: "a real host"})
			if err != nil {
				t.Fatalf("confirm %s: %v", id, err)
			}
			assets[res.AssetID] = true
		}
		if len(assets) != 1 {
			t.Fatalf("confirming three observations of %s produced %d assets, want 1", host, len(assets))
		}
		var asset string
		for a := range assets {
			asset = a
		}
		if n := m.countRows(t, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND address=$3::inet`, m.Tenant, asset, host); n != 3 {
			t.Errorf("%d endpoints on the confirmed asset, want 3 written by the decisions", n)
		}
		if _, err := m.svc.SweepIdentityEvidence(ctx, m.Tenant); err != nil {
			t.Fatal(err)
		}
		if n := m.countRows(t, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND id<>$2 AND deleted_at IS NULL`, m.Tenant, m.Asset); n != 1 {
			t.Errorf("%d assets besides the gateway, want 1", n)
		}
	})
}
