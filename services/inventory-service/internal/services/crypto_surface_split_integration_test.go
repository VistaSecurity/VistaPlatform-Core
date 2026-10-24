package services

// The unscored set, split by whether the asset shows a crypto surface
// (shared/cryptosurface).
//
// On the lab estate that prompted this, 78 of 102 assets read "Not assessed".
// Nearly all were phones, TVs and AWS security groups seen only by ARP, DHCP or
// a cloud listing: nothing cryptographic was ever on record for them, so there
// was nothing for the crypto producer to judge, and "not assessed" said we had
// skipped work that did not exist. The split is only honest if every reader
// draws the same line, so this is an AGREEMENT test: the summary tile, the
// facet rail, the query a click writes and the per-asset flag must all put
// each asset in the same bucket.
//
// Skips without TEST_DATABASE_URL.

import (
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestIntegration_CryptoSurfaceSplit_AgreesAcrossSummaryFacetQueryAndAsset(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	mk := func(name, classKey, classPath string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status,
			                    last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			id, tenant, name, classKey, classPath); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
		return id
	}
	endpoint := func(asset uuid.UUID, port int, protocol, status string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, protocol, status)
			VALUES ($1, $2, '10.0.0.9', $3, 'tcp', $4::protocol_type, $5)`,
			tenant, asset, port, protocol, status); err != nil {
			t.Fatalf("insert endpoint: %v", err)
		}
	}

	// No surface: seen, nothing cryptographic on record.
	arpOnly := mk("arp-only.example.test", "unknown_host", "unknown_host")
	closedSSH := mk("closed-ssh.example.test", "server", "hardware.computer.server")
	endpoint(closedSSH, 22, "SSH", "closed") // a port that WAS open is not a surface now
	plainModbus := mk("plc.example.test", "plc", "hardware.ot_device.plc")
	endpoint(plainModbus, 502, "Modbus", "active") // cleartext: configuration's question, not crypto's

	// A surface, and nobody has judged it.
	withConfig := mk("with-config.example.test", "server", "hardware.computer.server")
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score, created_at, updated_at)
		VALUES ($1, $2, $3, 'TLS', 'passive', 0, NOW(), NOW())`, uuid.New(), tenant, withConfig); err != nil {
		t.Fatalf("insert crypto configuration: %v", err)
	}
	tlsListener := mk("tls-listener.example.test", "server", "hardware.computer.server")
	endpoint(tlsListener, 8443, "TLS", "active")
	keyStore := mk("alias/aws/rds", "key_store", "cloud_resource.key_store")
	atRest := mk("bucket.example.test", "object_storage", "cloud_resource.object_storage")
	if _, err := db.Exec(`
		INSERT INTO crypto_applications (id, tenant_id, asset_id, resource_type, resource_identifier, encryption_context)
		VALUES ($1, $2, $3, 'cloud_storage', 'bucket', 'at_rest')`, uuid.New(), tenant, atRest); err != nil {
		t.Fatalf("insert crypto application: %v", err)
	}

	// Scored: in neither unscored bucket, surface or not.
	scored := mk("scored.example.test", "server", "hardware.computer.server")
	if _, err := db.Exec(`UPDATE assets SET risk_score = 0, risk_assessed_by = ARRAY['configuration'] WHERE id = $1`,
		scored); err != nil {
		t.Fatalf("score: %v", err)
	}

	wantNoCrypto := []uuid.UUID{arpOnly, closedSSH, plainModbus}
	wantNotAssessed := []uuid.UUID{withConfig, tlsListener, keyStore, atRest}

	summary, err := svc.GetRiskSummary(tenant)
	if err != nil {
		t.Fatalf("risk summary: %v", err)
	}
	if summary.NotAssessed != len(wantNotAssessed) || summary.NoCryptoObserved != len(wantNoCrypto) {
		t.Errorf("summary not_assessed=%d no_crypto_observed=%d, want %d and %d",
			summary.NotAssessed, summary.NoCryptoObserved, len(wantNotAssessed), len(wantNoCrypto))
	}
	if summary.UnknownRisk != summary.NotAssessed+summary.NoCryptoObserved {
		t.Errorf("unknown_risk=%d is not not_assessed+no_crypto_observed=%d; the split must partition it",
			summary.UnknownRisk, summary.NotAssessed+summary.NoCryptoObserved)
	}
	if sum := summary.HighRisk + summary.MediumRisk + summary.LowRisk + summary.Informational + summary.UnknownRisk; sum != summary.TotalAssets {
		t.Errorf("bands sum to %d, want total_assets %d", sum, summary.TotalAssets)
	}

	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "risk", 50)
	if err != nil {
		t.Fatalf("risk facets: %v", err)
	}
	facet := map[string]int{}
	for _, b := range buckets {
		facet[b.Key] = b.Count
	}
	if facet["not_assessed"] != summary.NotAssessed || facet["no_crypto_observed"] != summary.NoCryptoObserved {
		t.Errorf("facet not_assessed=%d no_crypto_observed=%d disagree with the summary's %d and %d",
			facet["not_assessed"], facet["no_crypto_observed"], summary.NotAssessed, summary.NoCryptoObserved)
	}

	// The list a click lands on, and the flag each row carries.
	// surface is the flag every row must carry, or nil for a query that spans both.
	list := func(query string, surface *bool) []uuid.UUID {
		t.Helper()
		assets, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: query, Page: 1, PageSize: 100})
		if err != nil {
			t.Fatalf("GetAssets(%q): %v", query, err)
		}
		var ids []uuid.UUID
		for _, a := range assets {
			ids = append(ids, a.ID)
			if a.CryptoSurface == nil {
				t.Errorf("%v: the list did not project crypto_surface", a.ID)
				continue
			}
			if surface != nil && *a.CryptoSurface != *surface {
				t.Errorf("asset %v in %q carries crypto_surface=%v", a.ID, query, *a.CryptoSurface)
			}
		}
		return ids
	}
	yes, no := true, false
	assertUUIDSet(t, "risk:not_assessed", list("risk:not_assessed", &yes), wantNotAssessed)
	assertUUIDSet(t, "risk:no_crypto_observed", list("risk:no_crypto_observed", &no), wantNoCrypto)
	assertUUIDSet(t, "either pseudo-band", list("risk:not_assessed or risk:no_crypto_observed", nil),
		append(append([]uuid.UUID{}, wantNotAssessed...), wantNoCrypto...))

	one, err := svc.GetAssetByID(tenant, keyStore)
	if err != nil {
		t.Fatalf("GetAssetByID: %v", err)
	}
	if one.CryptoSurface == nil || !*one.CryptoSurface {
		t.Errorf("a key store must carry crypto_surface=true on the detail read, got %v", one.CryptoSurface)
	}
}

func assertUUIDSet(t *testing.T, what string, got, want []uuid.UUID) {
	t.Helper()
	s := func(ids []uuid.UUID) []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = id.String()
		}
		sort.Strings(out)
		return out
	}
	g, w := s(got), s(want)
	if len(g) != len(w) {
		t.Errorf("%s: got %d assets, want %d", what, len(g), len(w))
		return
	}
	for i := range g {
		if g[i] != w[i] {
			t.Errorf("%s: got %v, want %v", what, g, w)
			return
		}
	}
}
