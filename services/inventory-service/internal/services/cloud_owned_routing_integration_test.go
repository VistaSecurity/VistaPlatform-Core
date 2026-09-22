package services

// Ownership, not addressability, decides where a cloud resource's crypto lands.
//
// A tenant added an AWS account. Its CloudFront distribution serves
// shop.example.com under an ACM certificate. The distribution's discovery row
// has a PUBLIC dest_ip — it is a CDN, that is the whole point — so
// classifyAsset called it third_party and the finding went to
// external_connections: the tenant's own CDN filed as somebody else's endpoint,
// and its certificate with it. Nothing reached `certificates`.
//
// This drives the REAL ingest path end to end and asserts both polarities:
//
//	owned      cloud_api + integration_id → an asset, and the ACM certificate
//	           in `certificates` with its real expiry
//	unowned    the same address, same certificate, discovered by a SENSOR →
//	           still external_connections, because a public endpoint we merely
//	           observed is still not ours
//
// Deleting `isTenantOwnedCloudResource(f)` from the ownership override in
// asset_service.go turns the first case red; widening it to every cloud-shaped
// finding turns the second red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// acmCertificateEntry is the canonical `certificates` array entry the cloud
// collector now emits — the shape mergeProviderCertificates produces in
// device-interrogation-service. Values are the live ones from the demo
// discovery.
func acmCertificateEntry() map[string]interface{} {
	return map[string]interface{}{
		"subject_dn":                "CN=shop.example.com",
		"issuer_dn":                 "Amazon",
		"common_name":               "shop.example.com",
		"serial_number":             "0f1e2d3c",
		"not_before":                "2025-11-19T00:00:00Z",
		"not_after":                 "2026-12-18T23:59:59Z",
		"key_algorithm":             "RSA",
		"key_size":                  float64(2048),
		"signature_alg":             "SHA256WITHRSA",
		"subject_alternative_names": []interface{}{"shop.example.com"},
		"data_source":               "cloud_api",
		"chain_order":               float64(0),
		"acm_metadata": map[string]interface{}{
			"arn":    "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-4000-8000-000000000001",
			"status": "ISSUED",
		},
	}
}

// newCloudRoutingAssetService wires the two services the routing decision needs.
//
// Both matter. Without the NETWORK SEGMENT service, classifyAsset answers
// "unknown" for everything and no finding is ever third_party, so every
// assertion below would hold for a build with the fix removed — the vacuous
// pass that makes a test worthless. Without the EXTERNAL CONNECTIONS service,
// the third-party branch is skipped entirely.
func newCloudRoutingAssetService(db *database.DB) *AssetService {
	svc := NewAssetService(db)
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, NewAlgorithmService(db)))
	svc.SetEnrichmentServices(NewNetworkSegmentService(db, NewLocationService(db)), nil)
	return svc
}

func countExternalConnections(t *testing.T, raw *sql.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM external_connections WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatalf("count external_connections: %v", err)
	}
	return n
}

func TestIntegration_CloudOwnedResource_CertificateLandsOnTheAsset(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)

	hostname := "shop.example.com"
	// A real, routable, PUBLIC address — the thing that used to decide this.
	ip := "203.0.113.55"
	port := 443
	version := "TLS 1.2"
	suite := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

	f := IngestFinding{
		Hostname:        &hostname,
		IPAddress:       &ip,
		Port:            &port,
		AssetType:       "cdn",
		Protocol:        "TLS",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   uuid.NewString(),
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_cloudfront",
			"certificates":     []interface{}{acmCertificateEntry()},
		},
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	if n := countExternalConnections(t, raw, tenant); n != 0 {
		t.Fatalf("the tenant's own CloudFront distribution produced %d external_connections row(s) — "+
			"a resource enumerated through the tenant's own cloud credentials is theirs, whatever its IP", n)
	}

	var assetID uuid.UUID
	if err := raw.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2`, tenant, hostname).Scan(&assetID); err != nil {
		t.Fatalf("the distribution did not become an asset: %v", err)
	}

	// The certificate — the user-visible outcome of this whole slice. It is in
	// `certificates`, so Inventory → Certificates lists it, with the expiry ACM
	// actually stated.
	var commonName, dataSource string
	var notAfter sql.NullTime
	err := raw.QueryRow(`
		SELECT common_name, data_source, not_after
		  FROM certificates
		 WHERE tenant_id = $1 AND common_name = $2`, tenant, "shop.example.com").
		Scan(&commonName, &dataSource, &notAfter)
	if err != nil {
		t.Fatalf("the ACM certificate did not reach `certificates`: %v", err)
	}
	if dataSource != "cloud_api" {
		t.Errorf("data_source = %q, want %q — the Certificates lens badges cloud-managed certificates "+
			"differently from ones observed on the wire", dataSource, "cloud_api")
	}
	if !notAfter.Valid || notAfter.Time.Format("2006-01-02") != "2026-12-18" {
		t.Errorf("not_after = %v, want 2026-12-18 — the expiry ACM stated, which is what puts this "+
			"certificate in an expiry band", notAfter)
	}

	// …and it is attached to the asset, not floating unassigned.
	var deployments int
	if err := raw.QueryRow(`
		SELECT COUNT(*) FROM crypto_implementations ci
		  JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		 WHERE ci.tenant_id = $1 AND ci.asset_id = $2`, tenant, assetID).Scan(&deployments); err != nil {
		t.Fatalf("count certificate deployments: %v", err)
	}
	if deployments == 0 {
		t.Error("the certificate is in the inventory but linked to no crypto configuration on the asset")
	}
}

// The other polarity. Without it, an override that simply stopped routing
// ANYTHING to external_connections would pass the test above.
func TestIntegration_ObservedThirdParty_StillRoutesToExternalConnections(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)

	hostname := "cdn.example.net"
	ip := "203.0.113.56"
	port := 443
	version := "TLS 1.2"

	f := IngestFinding{
		Hostname:        &hostname,
		IPAddress:       &ip,
		Port:            &port,
		Protocol:        "TLS",
		ProtocolVersion: &version,
		RawData: map[string]interface{}{
			// A sensor watched a connection leave for somebody else's CDN.
			// Same public address shape, no cloud credential behind it.
			"source":           "sensor_discovery",
			"discovery_method": "passive",
			"certificates":     []interface{}{acmCertificateEntry()},
		},
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	if n := countExternalConnections(t, raw, tenant); n != 1 {
		t.Fatalf("a third-party endpoint produced %d external_connections row(s), want 1 — "+
			"the ownership override must not swallow genuine third-party traffic", n)
	}
}

// A cloud-API finding with NO integration id is not evidence of ownership. The
// credential is the claim: `discovery_method` alone can be stamped by anything.
func TestIntegration_CloudAPIFindingWithoutCredential_IsNotOwned(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)

	hostname := "unattributed.example.net"
	ip := "203.0.113.57"
	port := 443
	version := "TLS 1.2"

	f := IngestFinding{
		Hostname:        &hostname,
		IPAddress:       &ip,
		Port:            &port,
		Protocol:        "TLS",
		ProtocolVersion: &version,
		RawData: map[string]interface{}{
			"discovery_method": "cloud_api",
			// no integration_id
		},
	}

	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if n := countExternalConnections(t, raw, tenant); n != 1 {
		t.Fatalf("got %d external_connections row(s), want 1 — ownership is claimed by the credential "+
			"the resource was reached through, not by a method label", n)
	}
}

// A certificate array can now carry two different kinds of entry: the chain a
// handshake captured, and a record the provider's API says is configured. They
// are not one chain, and position must stop implying issuance.
//
// Deleting the DN comparison from the issuer link in processDiscoveryCryptoData
// turns this red: the intermediate would be recorded as having been issued by
// the ACM record, which is a fabricated relationship between two unrelated
// certificates.
func TestIntegration_CertificateIssuerLink_FollowsDNsNotPosition(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := newCloudRoutingAssetService(db)

	hostname := "chained.example.com"
	ip := "203.0.113.58"
	port := 443
	version := "TLS 1.2"

	leaf := map[string]interface{}{
		"subject_dn": "CN=chained.example.com", "issuer_dn": "CN=Example Intermediate CA",
		"common_name": "chained.example.com", "fingerprint_sha256": "aa" + strings.Repeat("11", 31),
		"not_after": "2027-01-01T00:00:00Z", "data_source": "discovery", "chain_order": float64(0),
	}
	intermediate := map[string]interface{}{
		"subject_dn": "CN=Example Intermediate CA", "issuer_dn": "CN=Example Root CA",
		"common_name": "Example Intermediate CA", "fingerprint_sha256": "bb" + strings.Repeat("22", 31),
		"not_after": "2030-01-01T00:00:00Z", "data_source": "discovery", "chain_order": float64(1),
	}
	// Configured, not served, and issued by nobody in this array.
	configured := map[string]interface{}{
		"subject_dn": "CN=other.example.com", "issuer_dn": "Amazon",
		"common_name": "other.example.com", "serial_number": "abc123",
		"not_after": "2026-12-18T23:59:59Z", "data_source": "cloud_api", "chain_order": float64(2),
	}

	f := IngestFinding{
		Hostname: &hostname, IPAddress: &ip, Port: &port,
		Protocol: "TLS", ProtocolVersion: &version,
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   uuid.NewString(),
			"certificates":     []interface{}{leaf, intermediate, configured},
		},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{f}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}

	issuerOf := func(commonName string) (uuid.NullUUID, uuid.UUID) {
		t.Helper()
		var id uuid.UUID
		var issuer uuid.NullUUID
		if err := raw.QueryRow(`SELECT id, issuer_certificate_id FROM certificates WHERE tenant_id = $1 AND common_name = $2`,
			tenant, commonName).Scan(&id, &issuer); err != nil {
			t.Fatalf("read certificate %q: %v", commonName, err)
		}
		return issuer, id
	}

	leafIssuer, _ := issuerOf("chained.example.com")
	intermediateIssuer, intermediateID := issuerOf("Example Intermediate CA")
	_, configuredID := issuerOf("other.example.com")

	if !leafIssuer.Valid || leafIssuer.UUID != intermediateID {
		t.Errorf("the leaf's issuer_certificate_id = %v, want the intermediate (%s) — a genuine chain must still link",
			leafIssuer, intermediateID)
	}
	if intermediateIssuer.Valid {
		t.Errorf("the intermediate is recorded as issued by %v (the configured certificate is %s) — "+
			"adjacency in the array is not evidence of issuance", intermediateIssuer.UUID, configuredID)
	}

	// Per-ENTRY provenance, inside a finding that is itself cloud_api. The leaf
	// was captured on the wire and must not be badged as provider-managed just
	// because the discovery carrying it came from a cloud API — that is exactly
	// how CloudFront's default certificate read as cloud-managed.
	source := func(commonName string) string {
		t.Helper()
		var s string
		if err := raw.QueryRow(`SELECT data_source FROM certificates WHERE tenant_id = $1 AND common_name = $2`,
			tenant, commonName).Scan(&s); err != nil {
			t.Fatalf("read data_source for %q: %v", commonName, err)
		}
		return s
	}
	if got := source("chained.example.com"); got != "discovery" {
		t.Errorf("the observed leaf's data_source = %q, want %q — the finding-level label must not "+
			"overrule an entry that says where it actually came from", got, "discovery")
	}
	if got := source("other.example.com"); got != "cloud_api" {
		t.Errorf("the provider-API record's data_source = %q, want %q", got, "cloud_api")
	}
}
