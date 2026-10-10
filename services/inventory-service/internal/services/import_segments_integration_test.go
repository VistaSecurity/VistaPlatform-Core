package services

// One segment read per import request ( F4).
//
// Every finding used to re-read every network segment of the tenant several
// times — classification, tags, enrichment — plus a separate identity-intake
// snapshot. These drive the REAL IngestFindingsReport and IngestSightings
// paths and count both reads: the inventory segment set
// (NetworkSegmentService.LoadSegmentSet) and the intake's snapshot
// (identity.Intake.Snapshot, through a counting repository). Each must happen
// once for the whole request.
//
// They also check the reads were USED — every asset landed in the segment with
// its tags, every sighting was scoped to it — so a build that stopped
// consulting segments at all cannot pass on a count of zero.
//
// Mutation: put back a per-finding read (classifyAsset instead of
// classifyAssetIn, or a nil segs into discoveryObservationIn) and the counts
// go red (51 set reads and 50 snapshots for fifty findings).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// snapshotCountingRepo counts the intake's segment snapshot reads.
type snapshotCountingRepo struct {
	*pgidentity.Repository
	snapshots atomic.Int32
}

func (r *snapshotCountingRepo) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	r.snapshots.Add(1)
	return r.Repository.SegmentSnapshot(ctx, tenantID)
}

// segmentReadFixture is a tenant with one tagged segment over 198.51.100.0/24
// and an AssetService whose two segment reads are counted.
type segmentReadFixture struct {
	raw      *sqlx.DB
	tenant   uuid.UUID
	svc      *AssetService
	segment  *models.NetworkSegment
	setLoads *atomic.Int32
	counting *snapshotCountingRepo
}

func newSegmentReadFixture(t *testing.T) segmentReadFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	segSvc := NewNetworkSegmentService(db, NewLocationService(db))
	setLoads := &atomic.Int32{}
	segSvc.onLoadSegmentSet = func(uuid.UUID) { setLoads.Add(1) }

	svc := NewAssetService(db)
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))
	svc.SetEnrichmentServices(segSvc, nil)
	if _, err := svc.identityEngine(); err != nil {
		t.Fatalf("identity engine: %v", err)
	}
	counting := &snapshotCountingRepo{Repository: svc.identityRepo}
	svc.intakeOnce.Do(func() {
		svc.intakeVal, svc.intakeErr = identity.NewIntake(counting, identity.WithIntakeGenericNames(svc.genericNames()))
	})

	isActive := true
	seg, err := segSvc.Create(tenant, models.NetworkSegmentInput{
		Name:        "Branch LAN",
		SegmentType: "cidr",
		Value:       "198.51.100.0/24",
		NetworkType: "private",
		Environment: "production",
		IsActive:    &isActive,
		Tags:        map[string]interface{}{"site": "branch"},
	})
	if err != nil {
		t.Fatalf("create segment: %v", err)
	}
	setLoads.Store(0)
	counting.snapshots.Store(0)
	return segmentReadFixture{raw: db.DB, tenant: tenant, svc: svc, segment: seg, setLoads: setLoads, counting: counting}
}

func TestIntegration_ImportReadsSegmentsOncePerRequest(t *testing.T) {
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
		t.Errorf("the tenant's segment set was read %d times for a %d-finding import, want 1", got, n)
	}
	if got := fx.counting.snapshots.Load(); got != 1 {
		t.Errorf("the intake's segment snapshot was read %d times for a %d-finding import, want 1", got, n)
	}

	// The one read answered every finding: each asset is in the segment, with
	// its tags. Without this a build that read nothing would pass the counts.
	var inSegment, tagged int
	if err := fx.raw.QueryRow(`SELECT count(*) FILTER (WHERE network_segment_id = $2),
	                                  count(*) FILTER (WHERE tags->>'site' = 'branch')
	                           FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, fx.tenant, fx.segment.ID).Scan(&inSegment, &tagged); err != nil {
		t.Fatalf("read assets: %v", err)
	}
	if inSegment != n || tagged != n {
		t.Fatalf("%d assets in the segment and %d tagged, want %d each", inSegment, tagged, n)
	}
}

func TestIntegration_SightingsBatchReadsSegmentsOnce(t *testing.T) {
	fx := newSegmentReadFixture(t)

	const n = 20
	items := make([]SightingItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, SightingItem{Sighting: identity.Sighting{
			// An interrogation source, so the segment auto-approval question is
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
		t.Errorf("the intake's segment snapshot was read %d times for a %d-sighting batch, want 1", got, n)
	}
	if got := fx.setLoads.Load(); got != 1 {
		t.Errorf("the tenant's segment set was read %d times for a %d-sighting batch, want 1", got, n)
	}
	// Used, not merely read: every sighted address was filed under the segment.
	var scoped int
	if err := fx.raw.QueryRow(`SELECT count(*) FROM asset_identifiers
	                           WHERE tenant_id = $1 AND kind = 'ip_address' AND scope = $2`, fx.tenant, fx.segment.ID.String()).Scan(&scoped); err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	if scoped != n {
		t.Fatalf("%d ip identifiers scoped to the segment, want %d", scoped, n)
	}
}
