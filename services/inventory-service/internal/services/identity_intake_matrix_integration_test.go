package services

// The identity intake characterization matrix, inventory-service half.
//
// Every intake path in this service that turns device evidence into identity
// is driven with the SAME evidence — one gateway's address on ports
// 443/8443/9443, with and without its MAC, with and without its SSH host key —
// at three places: inside a segment a controller measured as DHCP, inside a
// static segment, and inside no segment. The fixture's established asset
// already owns every identifier sent (shared/identity/identitytest/intakematrix).
//
// Each row records what the path did: its outcome, the observation its adapter
// handed the engine (scope, dynamic scopes, admission flags, the decision's
// reasons), the identifiers and endpoint rows it wrote, assets it created and
// proposals it opened. The expectation is TODAY's behaviour, read off the code
// by running it — not a statement that it is right. Rows the identity-intake
// issue lists as divergences say which item they belong to, so the PR that
// fixes an item knows which expectations it may flip and that nothing else
// should move. shared/identity/identitytest/intakematrix/README.md says how
// to read and update a row.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/intakematrix"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// invMatrix is one row's world: a fresh tenant, the gateway fixture, and an
// AssetService wired the way cmd/main.go wires it (segment and service
// identification enrichment, external-connections routing).
type invMatrix struct {
	*intakematrix.Fixture
	svc    *AssetService
	sensor uuid.UUID
}

func newInvMatrix(t *testing.T, raw *sql.DB) *invMatrix {
	t.Helper()
	tenant := testdb.NewTenant(t, raw)
	f := intakematrix.Setup(t, raw, tenant)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	svc.SetEnrichmentServices(NewNetworkSegmentService(db, NewLocationService(db)), NewServiceIdentificationService(db))
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))
	m := &invMatrix{Fixture: f, svc: svc, sensor: uuid.New()}
	if _, err := raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat)
		VALUES($1,$2,'matrix-sensor','linux','test-v1','datacenter_host','active',now())`, m.sensor, tenant); err != nil {
		t.Fatal(err)
	}
	return m
}

// scanFindings is the active scan of the gateway as discovery-processor hands
// it over: one TLS finding per port, `source` overwritten to sensor_discovery
// by the converter (so it is filed as a passive sensor observation — issue
// item 10), and a negotiated cipher suite, which is what makes the finding
// Direct. The MAC and host key ride in raw_data, where discoveryObservation
// reads them.
func (m *invMatrix) scanFindings(p intakematrix.Place, s intakematrix.Shape, extra map[string]interface{}) []IngestFinding {
	out := make([]IngestFinding, 0, len(intakematrix.Ports))
	for i, port := range intakematrix.Ports {
		addr, sensor, port := p.Addr(), m.sensor.String(), port
		suite, version := "TLS_AES_128_GCM_SHA256", "TLS 1.3"
		raw := map[string]interface{}{
			"source":       "sensor_discovery",
			"observed_at":  m.Now.Add(-time.Minute).Format(time.RFC3339Nano),
			"discovery_id": fmt.Sprintf("matrix-%d", i),
		}
		if s.MAC {
			raw["mac_address"] = intakematrix.MAC
		}
		if s.SSHKey {
			raw["ssh_host_key_fingerprint"] = intakematrix.SSHHostKey
		}
		for k, v := range extra {
			raw[k] = v
		}
		out = append(out, IngestFinding{
			IPAddress: &addr, Port: &port, Protocol: "TLS", AssetType: "server",
			CipherSuite: &suite, ProtocolVersion: &version, SourceSensorID: &sensor, RawData: raw,
		})
	}
	return out
}

// ingest runs findings through IngestFindingsReport and then the enforce-mode
// retained-evidence worker, which is the second writer of endpoints.
func (m *invMatrix) ingest(t *testing.T, findings []IngestFinding) string {
	t.Helper()
	report, err := m.svc.IngestFindingsReport(m.Tenant, findings, identity.StatusPendingApproval)
	if err != nil {
		return "error"
	}
	if _, err := m.svc.SweepIdentityEvidence(context.Background(), m.Tenant); err != nil {
		t.Fatalf("sweep retained evidence: %v", err)
	}
	outs := make([]string, 0, len(report.Results))
	for _, r := range report.Results {
		outs = append(outs, r.Outcome)
	}
	return foldOutcomes(outs)
}

// foldOutcomes spells a batch's outcomes as `supporting*3` or
// `matched*2+rejected`, sorted, so the row does not depend on port order.
func foldOutcomes(outs []string) string {
	counts := map[string]int{}
	for _, o := range outs {
		counts[o]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if counts[k] == 1 {
			parts = append(parts, k)
		} else {
			parts = append(parts, fmt.Sprintf("%s*%d", k, counts[k]))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
}

func errOutcome(err error) string {
	var conflict *IdentifierConflictError
	var retained *identity.RetainedObservation
	switch {
	case err == nil:
		return ""
	case errors.As(err, &conflict):
		return "refused_conflict:" + conflict.Kind
	case errors.As(err, &retained):
		return "retained:" + retained.Result.Outcome
	case errors.Is(err, ErrObservationChanged):
		return "refused_changed"
	}
	return "error"
}

// invPath is one intake path. shapes lists the evidence shapes the path's
// input can carry at all; a path that cannot carry a MAC has no +mac rows.
type invPath struct {
	name   string
	shapes []intakematrix.Shape
	// places defaults to every place.
	places []intakematrix.Place
	drive  func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect
}

var (
	allShapes  = intakematrix.Shapes
	macShapes  = []intakematrix.Shape{{}, {MAC: true}}
	bareShapes = []intakematrix.Shape{{}}
	// dynOnly is for the review-table decisions: only the dynamic segment
	// leaves unresolved observations to decide (the other places match or
	// support on the scan itself — see the ingest_scan rows).
	dynOnly       = []intakematrix.Place{intakematrix.InDynamicSegment}
	noSegmentOnly = []intakematrix.Place{intakematrix.InNoSegment}
)

func invPaths() []invPath {
	return []invPath{
		{
			// IngestFindings → discoveryObservation: platform scan, tenant
			// sensor, cluster-sensor, pcap. Endpoints are written by the
			// engine, by resolveEndpointForFinding after it (service
			// identification), and by the retained-evidence worker.
			name: "ingest_scan", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				before := m.Take(t)
				return m.Effect(t, before, m.ingest(t, m.scanFindings(p, s, nil)))
			},
		},
		{
			// The host-observation path (ARP when a MAC is present, mDNS-style
			// address-only otherwise). It carries no ports and no host key.
			name: "host_observation", shapes: macShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				ho := &hostobs.HostObservation{Source: hostobs.SourceMDNS, ObservedAt: m.Now.Add(-time.Minute),
					Addresses: []netip.Addr{netip.MustParseAddr(p.Addr())}}
				if s.MAC {
					ho.Source, ho.MAC = hostobs.SourceARP, intakematrix.MAC
				}
				f := hostObsFinding(t, ho, map[string]interface{}{"observed_at": m.Now.Add(-time.Minute).Format(time.RFC3339Nano), "discovery_id": "matrix-host"})
				sensor := m.sensor.String()
				f.SourceSensorID = &sensor
				before := m.Take(t)
				return m.Effect(t, before, m.ingest(t, []IngestFinding{f}))
			},
		},
		{
			// One host observation carrying TWO of the gateway's addresses,
			// the no-segment one first and the dynamic-LAN one second, so
			// the row shows how this path scopes a multi-address device:
			// each address on its own segment.
			name: "host_observation_two_addresses", shapes: macShapes, places: noSegmentOnly,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				ho := &hostobs.HostObservation{Source: hostobs.SourceMDNS, ObservedAt: m.Now.Add(-time.Minute),
					Addresses: []netip.Addr{netip.MustParseAddr(intakematrix.TenantAddr), netip.MustParseAddr(intakematrix.DynamicAddr)}}
				if s.MAC {
					ho.Source, ho.MAC = hostobs.SourceARP, intakematrix.MAC
				}
				f := hostObsFinding(t, ho, map[string]interface{}{"observed_at": m.Now.Add(-time.Minute).Format(time.RFC3339Nano), "discovery_id": "matrix-host"})
				sensor := m.sensor.String()
				f.SourceSensorID = &sensor
				before := m.Take(t)
				return m.Effect(t, before, m.ingest(t, []IngestFinding{f}))
			},
		},
		{
			// Interrogation-owned findings: a finding the platform
			// interrogation sensor wrote, claiming the gateway through a
			// completed device job. No engine at all.
			name: "interrogation_owned", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				var platform string
				if err := m.DB.QueryRow(`SELECT id::text FROM sensors WHERE tenant_id=$1 AND profile='device_interrogation' AND platform_managed AND deleted_at IS NULL`, m.Tenant).Scan(&platform); err != nil {
					t.Fatalf("platform interrogation sensor: %v", err)
				}
				job := uuid.New()
				if _, err := m.DB.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, asset_id, status) VALUES ($1,$2,'device_interrogation',$3,'completed')`, job, m.Tenant, m.Asset); err != nil {
					t.Fatal(err)
				}
				findings := m.scanFindings(p, s, map[string]interface{}{
					"discovery_method": "device_interrogation", "source_asset_id": m.Asset.String(),
					"source_device_id": m.Asset.String(), "device_job_id": job.String(),
				})
				for i := range findings {
					findings[i].SourceSensorID = &platform
				}
				before := m.Take(t)
				return m.Effect(t, before, m.ingest(t, findings))
			},
		},
		{
			// Manual create (POST /assets): manualObservation, source declared.
			name: "manual_create", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				// CreateAsset's own body, so the row can name the engine's
				// outcome (CreateAsset returns only the asset).
				in := m.declaredInput(p, s)
				before := m.Take(t)
				_, outcome, err := m.svc.createAssetResolved(m.Tenant, in,
					identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
					m.svc.evaluateAssetApproval(m.Tenant, in.IPAddress, in.Hostname))
				out := errOutcome(err)
				if out == "" {
					out = string(outcome)
				}
				return m.Effect(t, before, out)
			},
		},
		{
			// A connector import (NetBox / CMDB): manualObservation with an
			// imported connection source, which is Authoritative.
			name: "source_import", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				before := m.Take(t)
				_, outcome, err := m.svc.CreateAssetFromSource(m.Tenant, m.declaredInput(p, s),
					identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()})
				out := errOutcome(err)
				if out == "" {
					out = string(outcome)
				}
				return m.Effect(t, before, out)
			},
		},
		{
			// Manual identifier edit of the gateway ITSELF: the operator
			// declares the address (and MAC / host key) it already holds.
			name: "identifier_edit_self", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				in := m.editInput(p, s)
				if p != intakematrix.InStaticSegment {
					// Keep the declared static address in the list, or the
					// edit retires it (only declared identifiers retire).
					scope := m.Scope(intakematrix.InStaticSegment)
					in.Identifiers = append(in.Identifiers, models.AssetIdentifierInput{Kind: string(identity.KindIPAddress), Value: intakematrix.StaticAddr, Scope: &scope})
				}
				before := m.Take(t)
				_, _, err := m.svc.UpdateAsset(m.Tenant, m.Asset, in, uuid.Nil)
				out := errOutcome(err)
				if out == "" {
					out = "ok"
				}
				return m.Effect(t, before, out)
			},
		},
		{
			// Manual identifier edit of ANOTHER asset that declares the
			// gateway's address (and MAC / host key).
			name: "identifier_edit_other", shapes: allShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				// Written directly: in enforce admission a manual create of a
				// bare hostname is retained as evidence, not created.
				name := "matrix-other"
				ref, err := pgidentity.New(m.DB).CreateAsset(context.Background(), m.Tenant.String(), identity.NewAsset{
					ClassKey: string(assetclass.KeyServer), DisplayName: name, Hostname: name, Status: identity.StatusMonitoring,
					Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: name, Scope: identity.ScopeTenantDefault, Confidence: 1,
						Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}}},
				})
				if err != nil {
					t.Fatalf("create the other asset: %v", err)
				}
				in := m.editInput(p, s)
				in.Hostname = &name
				before := m.Take(t)
				_, _, err = m.svc.UpdateAsset(m.Tenant, uuid.MustParse(ref.ID), in, uuid.Nil)
				out := errOutcome(err)
				if out == "" {
					out = "ok"
				}
				return m.Effect(t, before, out)
			},
		},
		{
			// Source link (AttachLinks): a connector attaching a link
			// identifier to an asset it already resolved. It takes
			// cmdb_sys_id only, so the device evidence cannot travel it at
			// all; the row records that the address is refused.
			name: "source_link", shapes: bareShapes,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				src := NewSourceImportService(&database.DB{DB: sqlx.NewDb(m.DB, "postgres")}, m.svc)
				before := m.Take(t)
				res, err := src.AttachLinks(context.Background(), m.Tenant, identity.Source{Kind: identity.SourceImported, Ref: "cmdb:matrix"},
					[]SourceLink{{AssetID: m.Asset, Kind: string(identity.KindIPAddress), Value: p.Addr(), Scope: m.Scope(p)}})
				if err != nil {
					t.Fatal(err)
				}
				out := string(res[0].Outcome)
				if strings.Contains(res[0].Error, "is not a source link") {
					out += ":kind_not_a_source_link"
				}
				return m.Effect(t, before, out)
			},
		},
		{
			// Confirm on the observations the scan left behind (Observations
			// review table). Confirm resolves a declaration through the
			// engine; the worker runs after it.
			name: "confirm_after_scan", shapes: allShapes, places: dynOnly,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.decideAfterScan(t, p, s, "confirmed")
			},
		},
		{
			// Link to the gateway on the observations the scan left behind.
			name: "link_after_scan", shapes: allShapes, places: dynOnly,
			drive: func(t *testing.T, m *invMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.decideAfterScan(t, p, s, "linked")
			},
		},
	}
}

// declaredInput is the gateway as a person or an importer states it.
func (m *invMatrix) declaredInput(p intakematrix.Place, s intakematrix.Shape) models.AssetInput {
	addr := p.Addr()
	in := models.AssetInput{ClassKey: string(assetclass.KeyRouter), IPAddress: &addr}
	for _, port := range intakematrix.Ports {
		port := port
		in.Endpoints = append(in.Endpoints, models.AssetEndpointInput{Address: &addr, Port: &port, Transport: "tcp"})
	}
	in.Identifiers = m.bindingIdentifiers(s)
	return in
}

// editInput is the identifier edit form's body: the address in the address
// field, the device-binding identifiers in the identifiers array.
func (m *invMatrix) editInput(p intakematrix.Place, s intakematrix.Shape) models.AssetInput {
	addr := p.Addr()
	in := models.AssetInput{IPAddress: &addr, Identifiers: m.bindingIdentifiers(s)}
	if in.Identifiers == nil {
		in.Identifiers = []models.AssetIdentifierInput{}
	}
	return in
}

func (m *invMatrix) bindingIdentifiers(s intakematrix.Shape) []models.AssetIdentifierInput {
	var out []models.AssetIdentifierInput
	if s.MAC {
		out = append(out, models.AssetIdentifierInput{Kind: string(identity.KindMACAddress), Value: intakematrix.MAC})
	}
	if s.SSHKey {
		out = append(out, models.AssetIdentifierInput{Kind: string(identity.KindSSHHostKeyFingerprint), Value: intakematrix.SSHHostKey})
	}
	return out
}

// decideAfterScan runs the scan, then the operator's decision on every
// observation the scan left unlinked, then the worker. The row records the
// DECISION's footprint only.
func (m *invMatrix) decideAfterScan(t *testing.T, p intakematrix.Place, s intakematrix.Shape, action string) intakematrix.Effect {
	t.Helper()
	m.ingest(t, m.scanFindings(p, s, nil))
	rows, err := m.DB.Query(`SELECT id FROM identity_observations WHERE tenant_id=$1 AND state='unresolved' AND asset_id IS NULL ORDER BY id`, m.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	actor := uuid.New()
	if _, err := m.DB.Exec(`INSERT INTO users(id,tenant_id,email,is_active) VALUES($1,$2,$3,true)`, actor, m.Tenant, "matrix-"+actor.String()[:8]+"@example.test"); err != nil {
		t.Fatal(err)
	}
	before := m.Take(t)
	outs := []string{}
	for _, id := range ids {
		in := ObservationDecisionInput{Reason: "intake matrix"}
		if action == "linked" {
			asset := m.Asset
			in.AssetID = &asset
		}
		res, err := m.svc.DecideIdentityObservation(context.Background(), m.Tenant, id, actor, action, in)
		if e := errOutcome(err); e != "" {
			outs = append(outs, e)
			continue
		}
		outs = append(outs, res.Outcome)
	}
	if _, err := m.svc.SweepIdentityEvidence(context.Background(), m.Tenant); err != nil {
		t.Fatalf("sweep retained evidence: %v", err)
	}
	if len(ids) == 0 {
		outs = append(outs, "nothing_to_decide")
	}
	return m.Effect(t, before, foldOutcomes(outs))
}

func TestIntegration_IdentityIntakeMatrix_InventoryService(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	seen := map[string]bool{}
	for _, path := range invPaths() {
		t.Run(path.name, func(t *testing.T) {
			places := path.places
			if places == nil {
				places = intakematrix.Places
			}
			for _, place := range places {
				t.Run(place.String(), func(t *testing.T) {
					for _, shape := range path.shapes {
						t.Run(shape.String(), func(t *testing.T) {
							key := path.name + "/" + place.String() + "/" + shape.String()
							seen[key] = true
							want, ok := invMatrixWant[key]
							m := newInvMatrix(t, raw)
							got := path.drive(t, m, place, shape)
							if !ok {
								t.Errorf("no expectation for this row; today it is:\n\t%q: %q,", key, got.String())
								return
							}
							intakematrix.Check(t, got, want)
						})
					}
				})
			}
		})
	}
	if !t.Failed() {
		for key := range invMatrixWant {
			if !seen[key] {
				t.Errorf("expectation %q names no row; remove it", key)
			}
		}
	}
}

// invMatrixWant is TODAY's behaviour, one line per row. Comments name the
// identity-intake issue's divergence items (1–10) a row demonstrates; only a
// PR that changes that item's rule should flip those rows.
var invMatrixWant = map[string]string{
	// IngestFindings → discoveryObservation. Every row is filed
	// measured/sensor/passive although it is an active scan: the converter's
	// `source=sensor_discovery` overwrite (issue item 10). Admission is Direct
	// on every row (port + cipher suite). Ports land on the gateway when the
	// engine matched; on `supporting` they stay on the observation (issue item
	// 1, owner decision 2 / platform ADR-0003 D2 — flipped by's
	// endpoints-follow-identity change).
	// Headline row 2 (issue items 2 and decision 1): three unresolved observations, no endpoints.
	"ingest_scan/dyn_segment/ip":     "outcome=unresolved*3 obs=[3x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[direct] reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/dyn_segment/ip+mac": "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Issue item 1: a host key is not a device binding for admission and the engine answers supporting. Decision 2: no ports are written.
	"ingest_scan/dyn_segment/ip+ssh":        "outcome=supporting*3 obs=[3x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=[ssh] adm=[direct] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/dyn_segment/ip+mac+ssh":    "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac,ssh] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/static_segment/ip":         "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=- adm=[direct] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/static_segment/ip+mac":     "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/static_segment/ip+ssh":     "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[ssh] adm=[direct] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/static_segment/ip+mac+ssh": "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[mac,ssh] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Headline row 1 (issue items 1 and 2): the tenant-scope address is never dynamic; supporting, and (decision 2) the ports stay on the observations.
	"ingest_scan/no_segment/ip":     "outcome=supporting*3 obs=[3x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=- adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/no_segment/ip+mac": "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Issue item 1 and decision 2, as above.
	"ingest_scan/no_segment/ip+ssh":     "outcome=supporting*3 obs=[3x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=[ssh] adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"ingest_scan/no_segment/ip+mac+ssh": "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=[mac,ssh] adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Host observations: mDNS for the address-only shape (not Direct), ARP
	// when a MAC is present (Direct). No ports, so never an endpoint.
	"host_observation/dyn_segment/ip":        "outcome=unresolved obs=[1x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=- reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation/dyn_segment/ip+mac":    "outcome=matched obs=[1x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation/static_segment/ip":     "outcome=supporting obs=[1x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=- adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation/static_segment/ip+mac": "outcome=matched obs=[1x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation/no_segment/ip":         "outcome=supporting obs=[1x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=- adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation/no_segment/ip+mac":     "outcome=matched obs=[1x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// One host observation with the no-segment and the dynamic-LAN address:
	// each address keeps ITS OWN scope (ip=[dyn,tenant]); the observation's
	// network scope is the dynamic segment (issue item 5 — contrast the
	// device-interrogation host inventory rows).
	"host_observation_two_addresses/no_segment/ip":     "outcome=supporting obs=[1x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=- adm=- reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_observation_two_addresses/no_segment/ip+mac": "outcome=matched obs=[1x{src=measured/sensor/passive scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Interrogation-owned findings (issue item 4: no engine, no admission).
	// At the dynamic and no-segment addresses the claim checks out and the
	// findings land on the gateway with no observation at all. At the static
	// address it does NOT: isDeviceOwnAddress counts only MEASURED
	// ip_address rows (and primary_address), and the static one is declared,
	// so those findings fall through to the ordinary engine path.
	"interrogation_owned/dyn_segment/ip":            "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/dyn_segment/ip+mac":        "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/dyn_segment/ip+ssh":        "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/dyn_segment/ip+mac+ssh":    "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/static_segment/ip":         "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=- adm=[direct] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/static_segment/ip+mac":     "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/static_segment/ip+ssh":     "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[ssh] adm=[direct] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/static_segment/ip+mac+ssh": "outcome=matched*3 obs=[3x{src=measured/sensor/passive scope=static dyn=- ip=[static] kinds=[mac,ssh] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/no_segment/ip":             "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/no_segment/ip+mac":         "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/no_segment/ip+ssh":         "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"interrogation_owned/no_segment/ip+mac+ssh":     "outcome=matched*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Manual create: manualObservation, source declared, never Direct. The
	// declared endpoints are NOT written when the engine answers supporting
	// (the issue's table says "from in.Endpoints" — true only for created or
	// matched). In the dynamic segment the declared address alone is
	// retained as unresolved (issue item 2 / decision 1: a declaration does
	// not let an address match in a dynamic segment).
	"manual_create/dyn_segment/ip":            "outcome=retained:unresolved obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=- reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/dyn_segment/ip+mac":        "outcome=supporting obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/dyn_segment/ip+ssh":        "outcome=supporting obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[ssh] adm=- reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/dyn_segment/ip+mac+ssh":    "outcome=supporting obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac,ssh] adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/static_segment/ip":         "outcome=supporting obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=- adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/static_segment/ip+mac":     "outcome=supporting obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=[mac] adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/static_segment/ip+ssh":     "outcome=supporting obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=[ssh] adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/static_segment/ip+mac+ssh": "outcome=supporting obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=[mac,ssh] adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/no_segment/ip":             "outcome=supporting obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=- adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/no_segment/ip+mac":         "outcome=supporting obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/no_segment/ip+ssh":         "outcome=supporting obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=[ssh] adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"manual_create/no_segment/ip+mac+ssh":     "outcome=supporting obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=[mac,ssh] adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Connector import: as manual create, plus Authoritative for a
	// connection source — which does not change the outcome here.
	"source_import/dyn_segment/ip":            "outcome=retained:unresolved obs=[1x{src=imported/netbox/- scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[auth] reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/dyn_segment/ip+mac":        "outcome=supporting obs=[1x{src=imported/netbox/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/dyn_segment/ip+ssh":        "outcome=supporting obs=[1x{src=imported/netbox/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[ssh] adm=[auth] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/dyn_segment/ip+mac+ssh":    "outcome=supporting obs=[1x{src=imported/netbox/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac,ssh] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/static_segment/ip":         "outcome=supporting obs=[1x{src=imported/netbox/- scope=static dyn=- ip=[static] kinds=- adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/static_segment/ip+mac":     "outcome=supporting obs=[1x{src=imported/netbox/- scope=static dyn=- ip=[static] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/static_segment/ip+ssh":     "outcome=supporting obs=[1x{src=imported/netbox/- scope=static dyn=- ip=[static] kinds=[ssh] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/static_segment/ip+mac+ssh": "outcome=supporting obs=[1x{src=imported/netbox/- scope=static dyn=- ip=[static] kinds=[mac,ssh] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/no_segment/ip":             "outcome=supporting obs=[1x{src=imported/netbox/- scope=tenant dyn=- ip=[tenant] kinds=- adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/no_segment/ip+mac":         "outcome=supporting obs=[1x{src=imported/netbox/- scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/no_segment/ip+ssh":         "outcome=supporting obs=[1x{src=imported/netbox/- scope=tenant dyn=- ip=[tenant] kinds=[ssh] adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_import/no_segment/ip+mac+ssh":     "outcome=supporting obs=[1x{src=imported/netbox/- scope=tenant dyn=- ip=[tenant] kinds=[mac,ssh] adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Identifier edit of the gateway itself: no engine (issue item 4). Every
	// identifier sent is already held, so nothing is written — and the
	// operator declaring the dynamic-LAN address does NOT re-source its
	// measured row (resourced=-): the edit skips held addresses and the
	// upsert only upgrades from inferred. Decision 1 flips these.
	"identifier_edit_self/dyn_segment/ip":            "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/dyn_segment/ip+mac":        "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/dyn_segment/ip+ssh":        "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/dyn_segment/ip+mac+ssh":    "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/static_segment/ip":         "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/static_segment/ip+mac":     "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/static_segment/ip+ssh":     "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/static_segment/ip+mac+ssh": "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/no_segment/ip":             "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/no_segment/ip+mac":         "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/no_segment/ip+ssh":         "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"identifier_edit_self/no_segment/ip+mac+ssh":     "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Identifier edit of another asset declaring the gateway's identifiers:
	// a hard conflict and a merge proposal at EVERY place, including the
	// dynamic segment where the engine would only record the address
	// (issue item 4).
	"identifier_edit_other/dyn_segment/ip":            "outcome=refused_conflict:ip_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/dyn_segment/ip+mac":        "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/dyn_segment/ip+ssh":        "outcome=refused_conflict:ssh_host_key_fingerprint obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/dyn_segment/ip+mac+ssh":    "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/static_segment/ip":         "outcome=refused_conflict:ip_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/static_segment/ip+mac":     "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/static_segment/ip+ssh":     "outcome=refused_conflict:ssh_host_key_fingerprint obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/static_segment/ip+mac+ssh": "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/no_segment/ip":             "outcome=refused_conflict:ip_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/no_segment/ip+mac":         "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/no_segment/ip+ssh":         "outcome=refused_conflict:ssh_host_key_fingerprint obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	"identifier_edit_other/no_segment/ip+mac+ssh":     "outcome=refused_conflict:mac_address obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",

	// Source link (AttachLinks) takes cmdb_sys_id only, so device evidence
	// cannot travel it at all: the address is refused before any write. The
	// issue lists it with the engine-less address paths; it is not one.
	"source_link/dyn_segment/ip":    "outcome=error:kind_not_a_source_link obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_link/static_segment/ip": "outcome=error:kind_not_a_source_link obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"source_link/no_segment/ip":     "outcome=error:kind_not_a_source_link obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Confirm on what the dynamic-segment scan left unresolved. Every
	// confirm is refused because the address has an owner (issue item 9: the
	// review table offers it as ready_to_confirm). With a MAC or a host key
	// the scan already landed on the gateway, so there is nothing to decide.
	"confirm_after_scan/dyn_segment/ip":         "outcome=refused_changed*3 obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"confirm_after_scan/dyn_segment/ip+mac":     "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"confirm_after_scan/dyn_segment/ip+ssh":     "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"confirm_after_scan/dyn_segment/ip+mac+ssh": "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",

	// Link to the gateway: accepted, and the decision writes the ports from
	// the observations' evidence (decision 2's "Link materialises"); the
	// retained-evidence worker then materialises the payloads onto them.
	"link_after_scan/dyn_segment/ip":         "outcome=linked*3 obs=- ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"link_after_scan/dyn_segment/ip+mac":     "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"link_after_scan/dyn_segment/ip+ssh":     "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"link_after_scan/dyn_segment/ip+mac+ssh": "outcome=nothing_to_decide obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
}

// TestIntegration_IdentityIntakeMatrix_HeadlineRows spells out the two rows
// the identity-intake issue opened with. The first asked WHICH writer put the
// scan's ports on the asset when the engine said `supporting` and attached
// nothing: two did — service identification's resolveEndpointForFinding
// upsert and the enforce-mode retained-evidence worker — each on its own.
// Owner decision 2 (platform ADR-0003 D2) closed both: each writer is switched
// on alone, and then together, and none of them lands a port.
func TestIntegration_IdentityIntakeMatrix_HeadlineRows(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)

	t.Run("no_segment_scan_lands_no_endpoints_when_the_engine_declined", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			serviceID   bool // resolveEndpointForFinding after the engine (asset_service.go, service identification)
			sweep       bool // the enforce-mode retained-evidence worker (identity_observation_retention.go)
			wantOutcome string
			wantPorts   string
		}{
			{name: "neither_writer", wantOutcome: "supporting*3", wantPorts: "-"},
			// Decision 2: was [443,8443,9443] before.
			{name: "service_identification_only", serviceID: true, wantOutcome: "supporting*3", wantPorts: "-"},
			// Decision 2: was [443,8443,9443] before.
			{name: "worker_only", sweep: true, wantOutcome: "supporting*3", wantPorts: "-"},
			{name: "both_writers", serviceID: true, sweep: true, wantOutcome: "supporting*3", wantPorts: "-"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				m := newInvMatrix(t, raw)
				if !tc.serviceID {
					m.svc.SetEnrichmentServices(NewNetworkSegmentService(m.svc.db, NewLocationService(m.svc.db)), nil)
				}
				before := m.Take(t)
				report, err := m.svc.IngestFindingsReport(m.Tenant, m.scanFindings(intakematrix.InNoSegment, intakematrix.Shape{}, nil), identity.StatusPendingApproval)
				if err != nil {
					t.Fatal(err)
				}
				if tc.sweep {
					if _, err := m.svc.SweepIdentityEvidence(context.Background(), m.Tenant); err != nil {
						t.Fatal(err)
					}
				}
				outs := []string{}
				for _, r := range report.Results {
					outs = append(outs, r.Outcome)
					if r.AssetID != m.Asset.String() {
						t.Errorf("resolution names asset %q, want the gateway %s", r.AssetID, m.Asset)
					}
				}
				got := m.Effect(t, before, foldOutcomes(outs))
				if got.Outcome != tc.wantOutcome {
					t.Errorf("outcome %s, want %s", got.Outcome, tc.wantOutcome)
				}
				if listOrDash(got.Ports) != tc.wantPorts {
					t.Errorf("ports on the gateway %s, want %s", listOrDash(got.Ports), tc.wantPorts)
				}
				if len(got.IDs) != 0 || got.NewAssets != 0 {
					t.Errorf("supporting evidence wrote identifiers %v / assets %d; the engine attaches nothing on supporting", got.IDs, got.NewAssets)
				}
			})
		}
	})

	t.Run("dynamic_segment_scan_is_three_unresolved_observations", func(t *testing.T) {
		m := newInvMatrix(t, raw)
		before := m.Take(t)
		got := m.Effect(t, before, m.ingest(t, m.scanFindings(intakematrix.InDynamicSegment, intakematrix.Shape{}, nil)))
		if got.Outcome != "unresolved*3" {
			t.Errorf("outcome %s, want unresolved*3", got.Outcome)
		}
		if len(got.Observations) != 3 {
			t.Fatalf("%d observations, want 3", len(got.Observations))
		}
		for _, o := range got.Observations {
			if o.State != "unresolved" || o.OnAsset != "-" || listOrDash(o.Reasons) != "[dynamic_address_without_device_binding]" {
				t.Errorf("observation %s, want unresolved, on no asset, reason dynamic_address_without_device_binding", o)
			}
		}
		if len(got.Ports) != 0 || got.OtherPorts != 0 {
			t.Errorf("endpoints written: gateway %v, others %d; want none", got.Ports, got.OtherPorts)
		}
	})
}

func listOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return "[" + strings.Join(v, ",") + "]"
}
