package services

// One prefix read per import request ( F4; DCIM row 1.6).
//
// Every finding used to re-read the tenant's networks several times —
// classification, enrichment — plus a separate identity-intake snapshot. These
// drive the REAL IngestFindingsReport and IngestSightings paths and count both
// reads: the inventory prefix set (loadPrefixSet, through
// AssetService.prefixSetIn) and the intake's snapshot (identity.Intake.Snapshot,
// through a counting repository). Each must happen once for the whole request.
//
// They also check the reads were USED — every asset landed in the prefix, every
// sighting was scoped to it — so a build that stopped consulting prefixes at
// all cannot pass on a count of zero.
//
// Mutation: put back a per-finding read (a nil segs into classifyFindingIn or
// discoveryObservationIn) and the counts go red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// snapshotCountingRepo counts the intake's prefix snapshot reads.
type snapshotCountingRepo struct {
	*pgidentity.Repository
	snapshots atomic.Int32
}

func (r *snapshotCountingRepo) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	r.snapshots.Add(1)
	return r.Repository.SegmentSnapshot(ctx, tenantID)
}

// segmentReadFixture is a tenant with one prefix over 198.51.100.0/24 and an
// AssetService whose two prefix reads are counted.
type segmentReadFixture struct {
	raw      *sqlx.DB
	tenant   uuid.UUID
	svc      *AssetService
	prefix   uuid.UUID
	setLoads *atomic.Int32
	counting *snapshotCountingRepo
}

func newSegmentReadFixture(t *testing.T) segmentReadFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	setLoads := &atomic.Int32{}

	svc := NewAssetService(db)
	svc.onLoadPrefixSet = func(uuid.UUID) { setLoads.Add(1) }
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))
	if _, err := svc.identityEngine(); err != nil {
		t.Fatalf("identity engine: %v", err)
	}
	counting := &snapshotCountingRepo{Repository: svc.identityRepo}
	svc.intakeOnce.Do(func() {
		svc.intakeVal, svc.intakeErr = identity.NewIntake(counting, identity.WithIntakeGenericNames(svc.genericNames()))
	})

	out, err := NewIPAMService(raw).Create(ipamTestCtx(), tenant, "prefixes",
		[]byte(`{"prefix":"198.51.100.0/24","description":"Branch LAN","network_type":"private","environment":"production"}`))
	if err != nil {
		t.Fatalf("create prefix: %v", err)
	}
	var row struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatal(err)
	}
	setLoads.Store(0)
	counting.snapshots.Store(0)
	return segmentReadFixture{raw: db.DB, tenant: tenant, svc: svc, prefix: row.ID, setLoads: setLoads, counting: counting}
}

func TestIntegration_ImportReadsPrefixesOncePerRequest(t *testing.T) {
	fx := newSegmentReadFixture(t)

	const n = 50
	findings := make([]IngestFinding, 0, n)
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+10)
		host := fmt.Sprintf("host-%02d.branch.example", i)
		port := 443
		version := "TLS 1.2"
		cipher := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		findings = append(findings, IngestFinding{
			Hostname:        &host,
			IPAddress:       &ip,
			Port:            &port,
			Protocol:        "TLS",
			ProtocolVersion: &version,
			CipherSuite:     &cipher,
			RawData:         map[string]interface{}{"source": "sensor_discovery", "discovery_method": "passive"},
		})
	}

	report, err := fx.svc.IngestFindingsReport(fx.tenant, findings, "monitoring")
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}
	if report.Imported != n {
		t.Fatalf("imported %d of %d findings", report.Imported, n)
	}

	if got := fx.setLoads.Load(); got != 1 {
		t.Errorf("the tenant's prefix set was read %d times for a %d-finding import, want 1", got, n)
	}
	if got := fx.counting.snapshots.Load(); got != 1 {
		t.Errorf("the intake's prefix snapshot was read %d times for a %d-finding import, want 1", got, n)
	}

	// The one read answered every finding: each asset is in the prefix, with
	// its environment. Without this a build that read nothing would pass the
	// counts.
	var inPrefix, placed int
	if err := fx.raw.QueryRow(`SELECT count(*) FILTER (WHERE prefix_id = $2),
	                                  count(*) FILTER (WHERE environment = 'production')
	                           FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, fx.tenant, fx.prefix).Scan(&inPrefix, &placed); err != nil {
		t.Fatalf("read assets: %v", err)
	}
	if inPrefix != n || placed != n {
		t.Fatalf("%d assets in the prefix and %d with its environment, want %d each", inPrefix, placed, n)
	}
}

func TestIntegration_SightingsBatchReadsPrefixesOnce(t *testing.T) {
	fx := newSegmentReadFixture(t)

	const n = 20
	items := make([]SightingItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, SightingItem{Sighting: identity.Sighting{
			// An interrogation source, so the prefix auto-approval question is
			// asked too (interrogationSightingApproved).
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + "device-under-test", Mode: identity.ModeActive},
			Channel:    identity.ChannelAuthenticatedSession,
			ObservedAt: time.Now().UTC(),
			ReceiptID:  fmt.Sprintf("receipt-%02d", i),
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindIPAddress, Value: fmt.Sprintf("198.51.100.%d", i+100)},
				{Kind: identity.KindHostname, Value: fmt.Sprintf("sighted-%02d", i), Address: fmt.Sprintf("198.51.100.%d", i+100)},
			},
		}})
	}
	results, err := fx.svc.IngestSightings(context.Background(), fx.tenant, items)
	if err != nil {
		t.Fatalf("IngestSightings: %v", err)
	}
	for i, r := range results {
		if r.AssetID == "" {
			t.Fatalf("sighting %d resolved to no asset: %+v", i, r)
		}
	}
	if got := fx.counting.snapshots.Load(); got != 1 {
		t.Errorf("the intake's prefix snapshot was read %d times for a %d-sighting batch, want 1", got, n)
	}
	if got := fx.setLoads.Load(); got != 1 {
		t.Errorf("the tenant's prefix set was read %d times for a %d-sighting batch, want 1", got, n)
	}
	// Used, not merely read: every sighted address was filed under the prefix.
	var scoped int
	if err := fx.raw.QueryRow(`SELECT count(*) FROM (`+identifiersql.All+`) ident_rows
	                           WHERE tenant_id = $1 AND kind = 'ip_address' AND scope = $2`, fx.tenant, fx.prefix.String()).Scan(&scoped); err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	if scoped != n {
		t.Fatalf("%d ip identifiers scoped to the prefix, want %d", scoped, n)
	}
}
