package services

// The network map against a real Postgres.
//
// Each test seeds the awkward row first and asserts what happens to it: the
// other tenant's asset, the archived/denied/deleted ones, the closed endpoint,
// the soft-deleted configuration, the offered-only component. Every one of them
// is a WHERE clause whose absence produces a plausible, wrong map.
//
// Catalogue rows are the SEEDED ones, read and never written: `algorithms` is a
// global table, and a test that inserted or updated rows there would leak into
// every other suite sharing the database.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type mapAssetSpec struct {
	displayName *string
	hostname    *string
	address     *string
	site        *string
	segment     *uuid.UUID
	status      string
	risk        int
	assessedBy  []string
	deleted     bool
}

func seedMapAsset(t *testing.T, db *database.DB, tenant uuid.UUID, s mapAssetSpec) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if s.assessedBy == nil {
		s.assessedBy = []string{}
	}
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, display_name, hostname, primary_address, class_key, class_path,
		                    asset_status, site, network_segment_id, risk_score, risk_assessed_by,
		                    deleted_at, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5::inet,'server','hardware.computer.server',$6,$7,$8,$9,$10,
		        CASE WHEN $11 THEN NOW() ELSE NULL END, NOW(),NOW(),NOW(),NOW())`,
		id, tenant, s.displayName, s.hostname, s.address, s.status, s.site, s.segment,
		s.risk, pq.Array(s.assessedBy), s.deleted); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

func strp(s string) *string { return &s }

func seedMapEndpoint(t *testing.T, db *database.DB, tenant, asset uuid.UUID, port int, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, status)
		VALUES ($1,$2,$3,'198.51.100.7'::inet,$4,'tcp',$5)`, id, tenant, asset, port, status); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	return id
}

type mapLink struct {
	role, code string
	inferred   bool
}

// seedMapConfig writes one configuration and links SEEDED catalogue rows.
func seedMapConfig(t *testing.T, db *database.DB, tenant, asset uuid.UUID, endpoint, cert *uuid.UUID, deleted bool, links ...mapLink) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, certificate_id, protocol,
		                                    discovery_method, deleted_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'TLS','active', CASE WHEN $6 THEN NOW() ELSE NULL END, NOW(), NOW())`,
		id, tenant, asset, endpoint, cert, deleted); err != nil {
		t.Fatalf("insert configuration: %v", err)
	}
	for _, l := range links {
		if _, err := db.Exec(`
			INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
			SELECT $1, id, $2, $3 FROM algorithms WHERE code = $4 ORDER BY id LIMIT 1`,
			id, l.role, l.inferred, l.code); err != nil {
			t.Fatalf("link %s=%s: %v", l.role, l.code, err)
		}
	}
	return id
}

func seedMapCert(t *testing.T, db *database.DB, tenant uuid.UUID, notAfter string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256, not_before, not_after)
		VALUES ($1,$2,'CN=map.example.test','CN=CA',$3, NOW() - interval '1 year', NOW() + $4::interval)`,
		id, tenant, fmt.Sprintf("%x", sha256.Sum256([]byte(id.String()))), notAfter); err != nil {
		t.Fatalf("insert certificate: %v", err)
	}
	return id
}

// catalogueComponent reads what the SEEDED catalogue says about a code, so the
// assertion is "the map repeats the catalogue", not a copy of today's row.
func catalogueComponent(t *testing.T, db *database.DB, role, code string, observed bool) NetworkMapComponent {
	t.Helper()
	c := NetworkMapComponent{AlgorithmType: role, Observed: observed}
	if err := db.QueryRow(`
		SELECT name, COALESCE(strength::text, ''), COALESCE(is_pqc, false)
		  FROM algorithms WHERE code = $1 ORDER BY id LIMIT 1`, code).Scan(&c.Name, &c.Strength, &c.IsPQC); err != nil {
		t.Fatalf("catalogue lookup %q (is it seeded?): %v", code, err)
	}
	return c
}

func mapAssetByID(m *NetworkMap) map[uuid.UUID]NetworkMapAsset {
	out := map[uuid.UUID]NetworkMapAsset{}
	for _, a := range m.Assets {
		out[a.AssetID] = a
	}
	return out
}

// Population: monitoring and pending are drawn; archived, denied and deleted
// are not; another tenant's asset and segment never appear; an inactive
// segment is not listed. And "unknown is not zero" on the way.
func TestIntegration_NetworkMap_PopulationIsolationAndSegments(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	other := newTopologyOtherTenant(t, db)
	ctx := context.Background()

	core := seedSegment(t, db, tenant, "Core VLAN", "10.0.0.0/16")
	inactive := seedSegment(t, db, tenant, "Retired VLAN", "10.9.0.0/16")
	if _, err := db.Exec(`UPDATE network_segments SET is_active = false WHERE id = $1 AND tenant_id = $2`, inactive, tenant); err != nil {
		t.Fatal(err)
	}
	empty := seedSegment(t, db, tenant, "Empty VLAN", "10.8.0.0/16")
	seedSegment(t, db, other, "Other tenant VLAN", "10.0.0.0/16")

	east := "DC-East"
	monitored := seedMapAsset(t, db, tenant, mapAssetSpec{
		displayName: strp("web-01"), address: strp("10.0.0.5"), site: &east, segment: &core,
		status: "monitoring", risk: 70, assessedBy: []string{"catalogue"},
	})
	// No display name, empty hostname: falls through to the address. Zero
	// risk with nothing in risk_assessed_by: NOT assessed.
	pending := seedMapAsset(t, db, tenant, mapAssetSpec{
		hostname: strp(""), address: strp("10.0.0.6"), status: "pending_approval",
	})
	archived := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("archived"), status: "archived"})
	denied := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("denied"), status: "denied"})
	deleted := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("deleted"), status: "monitoring", deleted: true})
	foreign := seedMapAsset(t, db, other, mapAssetSpec{displayName: strp("foreign"), status: "monitoring", risk: 99})

	m, err := svc.GetNetworkMap(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	by := mapAssetByID(m)
	if _, ok := by[foreign]; ok {
		t.Fatal("another tenant's asset is on this tenant's map")
	}
	for name, id := range map[string]uuid.UUID{"archived": archived, "denied": denied, "deleted": deleted} {
		if _, ok := by[id]; ok {
			t.Errorf("the %s asset is on the map", name)
		}
	}
	if len(m.Assets) != 2 || m.TotalAssets != 2 || m.Truncated || m.AssetCap != NetworkMapAssetCap {
		t.Fatalf("assets=%d total=%d truncated=%v cap=%d, want 2/2/false/%d",
			len(m.Assets), m.TotalAssets, m.Truncated, m.AssetCap, NetworkMapAssetCap)
	}

	w := by[monitored]
	if w.DisplayName != "web-01" || w.Address != "10.0.0.5" || w.Site != "DC-East" ||
		w.SegmentID == nil || *w.SegmentID != core || !w.RiskAssessed || w.RiskScore != 70 {
		t.Errorf("monitored asset = %+v", w)
	}
	p, ok := by[pending]
	if !ok {
		t.Fatal("the pending-approval asset is not on the map (spec D5 draws it)")
	}
	if p.AssetStatus != "pending_approval" || p.DisplayName != "10.0.0.6" || p.Address != "10.0.0.6" ||
		p.SegmentID != nil || p.Site != TopologyUnassignedSite {
		t.Errorf("pending asset = %+v", p)
	}
	if p.RiskAssessed || p.RiskScore != 0 {
		t.Errorf("a 0 score with empty risk_assessed_by must be risk_assessed=false; got %+v", p)
	}
	if p.Crypto.Components == nil || len(p.Crypto.Components) != 0 {
		t.Errorf("an asset with no crypto must carry [] components; got %#v", p.Crypto.Components)
	}

	if len(m.Segments) != 2 {
		t.Fatalf("segments = %+v, want Core VLAN + Empty VLAN only", m.Segments)
	}
	if m.Segments[0].SegmentID != core || m.Segments[0].Name != "Core VLAN" ||
		m.Segments[0].Value != "10.0.0.0/16" || m.Segments[0].SegmentType != "cidr" {
		t.Errorf("segments[0] = %+v", m.Segments[0])
	}
	if m.Segments[1].SegmentID != empty {
		t.Errorf("an active segment with no asset in it must still be listed; got %+v", m.Segments[1])
	}
}

// newTopologyOtherTenant takes a second throwaway tenant on the same database.
func newTopologyOtherTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	return testdb.NewTenant(t, db.DB.DB)
}

// The crypto summary: live endpoints, catalogue components, the PQC
// partition, expiring certificates and the cloud scope.
func TestIntegration_NetworkMap_CryptoSummary(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	ctx := context.Background()

	asset := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("tls-01"), status: "monitoring", risk: 60, assessedBy: []string{"catalogue"}})
	seedFact(t, db, tenant, asset, facts.KeyCloudAccountID, "123456789012", "cloud:aws", 1, "2026-09-20T00:00:00Z")

	eCrypto := seedMapEndpoint(t, db, tenant, asset, 443, "active")
	seedMapEndpoint(t, db, tenant, asset, 22, "stale") // live, no crypto
	eClosed := seedMapEndpoint(t, db, tenant, asset, 8443, "closed")
	eDeletedOnly := seedMapEndpoint(t, db, tenant, asset, 993, "active")

	soon := seedMapCert(t, db, tenant, "30 days")
	expired := seedMapCert(t, db, tenant, "-1 day")
	far := seedMapCert(t, db, tenant, "1 year")
	onDeleted := seedMapCert(t, db, tenant, "10 days")

	// Hybrid-PQC key exchange + classical signature: the classical signature
	// makes it need migration, whatever the key exchange is.
	seedMapConfig(t, db, tenant, asset, &eCrypto, &soon, false,
		mapLink{"key_exchange", "X25519MLKEM768", false},
		mapLink{"signature", "ECDSA", false},
		mapLink{"protocol_version", "TLS1.3", true}, // offered/derived only
	)
	// Same leaf certificate on a second config: counted once.
	seedMapConfig(t, db, tenant, asset, &eCrypto, &soon, false, mapLink{"symmetric", "AES256", false})
	// Endpoint-less (at rest): symmetric only, expired cert.
	seedMapConfig(t, db, tenant, asset, nil, &expired, false, mapLink{"symmetric", "AES256", false})
	// PQC only.
	seedMapConfig(t, db, tenant, asset, nil, &far, false, mapLink{"key_exchange", "ML-KEM-768", false})
	// Nothing resolved: unclassified.
	seedMapConfig(t, db, tenant, asset, nil, nil, false)
	// On a CLOSED endpoint: live config, so it counts toward the summary, but
	// the endpoint is not a live service.
	seedMapConfig(t, db, tenant, asset, &eClosed, nil, false, mapLink{"hash", "SHA256", false})
	// Soft-deleted: nothing about it may reach the map.
	seedMapConfig(t, db, tenant, asset, &eDeletedOnly, &onDeleted, true, mapLink{"key_exchange", "RSA-2048", false})

	m, err := svc.GetNetworkMap(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(m.Assets))
	}
	a := m.Assets[0]

	if a.ServiceCount != 3 {
		t.Errorf("service_count = %d, want 3 (active + stale + active; closed excluded)", a.ServiceCount)
	}
	// :443, plus ONE for the live configurations no live endpoint accounts
	// for (the endpoint-less ones and the one on closed :8443). The deleted
	// config must not make :993 a crypto service.
	if a.CryptoServiceCount != 2 {
		t.Errorf("crypto_service_count = %d, want 2", a.CryptoServiceCount)
	}
	if a.Crypto.CertsExpiring90d != 2 {
		t.Errorf("certs_expiring_90d = %d, want 2 (soon, once; expired; not far, not the deleted config's)", a.Crypto.CertsExpiring90d)
	}
	wantPQC := NetworkMapPQC{NeedsMigration: 1, PQCReady: 1, SymmetricSafe: 3, Unclassified: 1}
	if a.Crypto.PQC != wantPQC {
		t.Errorf("pqc = %+v, want %+v", a.Crypto.PQC, wantPQC)
	}
	if a.CloudAccount != "123456789012" || a.CloudRegion != "" {
		t.Errorf("cloud scope = %q/%q", a.CloudAccount, a.CloudRegion)
	}

	want := sortNetworkMapComponents([]NetworkMapComponent{
		catalogueComponent(t, db, "hash", "SHA256", true),
		catalogueComponent(t, db, "key_exchange", "ML-KEM-768", true),
		catalogueComponent(t, db, "key_exchange", "X25519MLKEM768", true),
		catalogueComponent(t, db, "protocol_version", "TLS1.3", false),
		catalogueComponent(t, db, "signature", "ECDSA", true),
		catalogueComponent(t, db, "symmetric", "AES256", true),
	})
	if len(a.Crypto.Components) != len(want) {
		t.Fatalf("components = %+v\nwant %+v", a.Crypto.Components, want)
	}
	for i := range want {
		if a.Crypto.Components[i] != want[i] {
			t.Errorf("components[%d] = %+v, want %+v", i, a.Crypto.Components[i], want[i])
		}
	}
}

// `observed` is bool_or over the links: offered-only in one configuration and
// used in another is observed.
func TestIntegration_NetworkMap_ObservedIsAnyUse(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	asset := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("mixed"), status: "monitoring"})
	seedMapConfig(t, db, tenant, asset, nil, nil, false, mapLink{"protocol_version", "TLS1.3", true})
	seedMapConfig(t, db, tenant, asset, nil, nil, false, mapLink{"protocol_version", "TLS1.3", false})

	m, err := svc.GetNetworkMap(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Assets[0].Crypto.Components
	if len(c) != 1 || !c[0].Observed {
		t.Errorf("components = %+v, want one TLS1.3 with observed=true", c)
	}
}

// The cap: ordered by risk, then name, then id, and a truncated answer says so
// beside the real total.
func TestIntegration_NetworkMap_CapAndTruncated(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	high := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("zeta"), status: "monitoring", risk: 90, assessedBy: []string{"catalogue"}})
	seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("bravo"), status: "monitoring", risk: 50, assessedBy: []string{"catalogue"}})
	midA := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("alpha"), status: "pending_approval", risk: 50, assessedBy: []string{"catalogue"}})

	m, err := svc.getNetworkMap(context.Background(), tenant, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated || m.TotalAssets != 3 || m.AssetCap != 2 || len(m.Assets) != 2 {
		t.Fatalf("truncated=%v total=%d cap=%d len=%d, want true/3/2/2", m.Truncated, m.TotalAssets, m.AssetCap, len(m.Assets))
	}
	if m.Assets[0].AssetID != high || m.Assets[1].AssetID != midA {
		t.Errorf("order = [%s %s], want [zeta alpha] (risk desc, then name)", m.Assets[0].DisplayName, m.Assets[1].DisplayName)
	}

	full, err := svc.getNetworkMap(context.Background(), tenant, 3)
	if err != nil {
		t.Fatal(err)
	}
	if full.Truncated || len(full.Assets) != 3 {
		t.Errorf("at exactly the cap the answer is complete; truncated=%v len=%d", full.Truncated, len(full.Assets))
	}
}

// An empty estate is an answer: empty arrays, zero total.
func TestIntegration_NetworkMap_EmptyEstate(t *testing.T) {
	svc, _, tenant := newTopologyFixture(t)
	m, err := svc.GetNetworkMap(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if m.Assets == nil || m.Segments == nil || len(m.Assets) != 0 || len(m.Segments) != 0 || m.TotalAssets != 0 || m.Truncated {
		t.Errorf("empty estate = %+v", m)
	}
}

// A device whose ONLY crypto is not tied to a live endpoint (at rest, or on a
// socket since closed) still carries crypto on the map. Counting endpoints
// alone drew it as a device with none.
func TestIntegration_NetworkMap_UnboundCryptoStillCounts(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	asset := seedMapAsset(t, db, tenant, mapAssetSpec{displayName: strp("vault-01"), status: "monitoring"})
	seedMapConfig(t, db, tenant, asset, nil, nil, false, mapLink{"symmetric", "AES256", false})

	m, err := svc.GetNetworkMap(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(m.Assets))
	}
	if got := m.Assets[0]; got.CryptoServiceCount != 1 || got.ServiceCount != 0 {
		t.Errorf("crypto_service_count/service_count = %d/%d, want 1/0", got.CryptoServiceCount, got.ServiceCount)
	}
}
