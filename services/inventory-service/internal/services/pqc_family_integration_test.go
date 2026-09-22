package services

// Guards for the per-family PQC worklist (`/pqc/progress` → by_family).
//
// The bug these pin: the family query grouped by `primitive` as well as family,
// then dropped the primitive on the floor — PQCFamilyStats has no field for it.
// Any family spanning two primitives therefore emitted two rows identical in
// every exposed field (live on: `AES` at 18 and again at 5, `SHA-2`
// at 11 and again at 7), each carrying a COUNT(DISTINCT implementation) taken
// WITHIN its group — so summing them over-counted a configuration that used one
// family twice, and a family with one safe and one unsafe primitive would have
// been reported safe AND unsafe at the same time.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// familyRows returns the by_family rows for one family, in response order.
func familyRows(t *testing.T, p *models.PQCProgress, family string) []models.PQCFamilyStats {
	t.Helper()
	var out []models.PQCFamilyStats
	for _, f := range p.ByFamily {
		if f.Family == family {
			out = append(out, f)
		}
	}
	return out
}

func progressFor(t *testing.T, f pqcFixture) *models.PQCProgress {
	t.Helper()
	got, err := (&AlgorithmService{db: f.db}).GetPQCProgress(f.tenant)
	if err != nil {
		t.Fatalf("GetPQCProgress: %v", err)
	}
	return got
}

// ONE configuration, ONE family, TWO primitives — one row, count 1.
//
// AES128 is primitive 'block-cipher' and DNP3-SA-AES-GMAC-12 is primitive
// 'mac'; both are algorithm_family 'AES' in the shipped catalogue. Under the old
// grouping this produced two AES rows of 1 each, which a consumer summing them
// (the dashboard does) reads as two configurations. There is one.
func TestIntegration_PQC_FamilyAppearsOnceWhenItSpansPrimitives(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"symmetric": "AES128", "hash": "DNP3-SA-AES-GMAC-12"})

	rows := familyRows(t, progressFor(t, f), "AES")
	if len(rows) != 1 {
		t.Fatalf("AES appears %d times in by_family, want exactly 1: %+v — a family spanning "+
			"two primitives must not emit two rows that nothing in the payload can tell apart", len(rows), rows)
	}
	if rows[0].Count != 1 {
		t.Errorf("AES count = %d, want 1 — the same configuration linked under two of the "+
			"family's primitives is still ONE configuration", rows[0].Count)
	}
	if !rows[0].QuantumSafe {
		t.Errorf("AES quantum_safe = false, want true (block-cipher and mac are both on the " +
			"family allowlist; Grover weakens symmetric crypto, Shor does not break it)")
	}
	if rows[0].IsPQC {
		t.Error("AES is_pqc = true, want false")
	}
}

// Two configurations reaching the same family through DIFFERENT primitives are
// still counted once each — the distinct count is over the whole family now, not
// within a primitive group.
func TestIntegration_PQC_FamilyCountIsDistinctAcrossPrimitives(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"symmetric": "AES128"})                                // block-cipher
	f.addImpl(t, map[string]string{"symmetric": "aes256-gcm@openssh.com"})                // ae
	f.addImpl(t, map[string]string{"symmetric": "AES256", "hash": "DNP3-SA-AES-GMAC-12"}) // block-cipher + mac

	rows := familyRows(t, progressFor(t, f), "AES")
	if len(rows) != 1 {
		t.Fatalf("AES appears %d times, want 1: %+v", len(rows), rows)
	}
	if rows[0].Count != 3 {
		t.Errorf("AES count = %d, want 3 distinct configurations", rows[0].Count)
	}
}

// A family holding one quantum-safe primitive and one Shor-breakable one is
// reported ONCE, and unsafe.
//
// This is the flaw that was latent rather than observed: no shipped family mixes
// the two (AES spans ae/block-cipher/mac, SHA-2 hash/mac, SHA-3 hash/xof, RSA
// pke/signature — each entirely inside or entirely outside the allowlist), so
// the old code's per-primitive `quantum_safe` never actually split a family
// across both of the dashboard's lists. The catalogue is what kept it hidden,
// not the query, so the guard builds the mixed family itself.
//
// Conservative is the only defensible answer: one Shor-breakable member is
// enough, which is the same precedence the per-implementation classifier uses
// (any classical asymmetric component makes the whole configuration vulnerable).
func TestIntegration_PQC_MixedSafetyFamilyIsOneUnsafeRow(t *testing.T) {
	f := newPQCFixture(t)

	// Scratch catalogue rows. The catalogue is platform-scoped (no tenant_id),
	// so they are removed again — a leftover row would answer another suite's
	// family lookup. The family name is unique to this test for the same reason.
	const family = "PQCMixedSafetyGuard"
	for _, a := range []struct {
		code      string
		category  string
		primitive string
	}{
		{"pqc-guard-digest", "hash", "hash"},     // on the family allowlist
		{"pqc-guard-kem", "key_exchange", "kem"}, // classical KEM: Shor-breakable
	} {
		id := uuid.New()
		if _, err := f.db.Exec(`
			INSERT INTO algorithms (id, code, name, category, strength, deprecation_status,
			                        risk_score, is_pqc, primitive, algorithm_family)
			VALUES ($1, $2, $2, $3, 'acceptable', 'current', 10, false, $4, $5)`,
			id, a.code, a.category, a.primitive, family); err != nil {
			t.Fatalf("insert scratch algorithm %s: %v", a.code, err)
		}
		t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM algorithms WHERE id = $1`, id) })
	}

	f.addImpl(t, map[string]string{"hash": "pqc-guard-digest", "key_exchange": "pqc-guard-kem"})

	rows := familyRows(t, progressFor(t, f), family)
	if len(rows) != 1 {
		t.Fatalf("%s appears %d times in by_family, want 1: %+v — a family with one safe and "+
			"one vulnerable primitive used to emit both a safe row and an unsafe row, which the "+
			"dashboard renders under 'Already quantum-safe' AND 'Replace these' at once",
			family, len(rows), rows)
	}
	if rows[0].QuantumSafe {
		t.Errorf("%s quantum_safe = true, want false — one Shor-breakable member is enough to "+
			"put the family on the worklist", family)
	}
}

// by_family counts the same population as the headline: configurations on a
// live, monitoring asset.
//
// The family query used to read every non-deleted crypto_implementations row
// with no assets join at all, so the worklist counted configurations that
// total_implementations — on the same response — excludes. That is the M-1
// divergence (see MonitoredConfigurationsSQL), one endpoint further in.
func TestIntegration_PQC_FamilyExcludesPendingApprovalAssets(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"signature": "RSA-2048"}) // on the fixture's monitoring asset

	pending := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'pqc-pending.example.test', 'server', 'hardware.computer.server', 'pending_approval', NOW(), NOW(), NOW(), NOW())`,
		pending, f.tenant); err != nil {
		t.Fatalf("insert pending asset: %v", err)
	}
	implID := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`, implID, f.tenant, pending); err != nil {
		t.Fatalf("insert implementation on pending asset: %v", err)
	}
	var algID uuid.UUID
	if err := f.db.QueryRow(`SELECT id FROM algorithms WHERE code = 'RSA-4096'`).Scan(&algID); err != nil {
		t.Fatalf("catalogue lookup RSA-4096: %v", err)
	}
	if _, err := f.db.Exec(`
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		VALUES ($1,$2,'signature',false)`, implID, algID); err != nil {
		t.Fatalf("link RSA to the pending asset's implementation: %v", err)
	}

	got := progressFor(t, f)
	rows := familyRows(t, got, "RSA")
	if len(rows) != 1 {
		t.Fatalf("RSA appears %d times, want 1: %+v", len(rows), rows)
	}
	if rows[0].Count != 1 {
		t.Errorf("RSA count = %d, want 1 — the pending-approval asset's configuration is not in "+
			"total_implementations (%d), so it must not be in the family worklist either",
			rows[0].Count, got.TotalImplementations)
	}
	if rows[0].MigrateTo != "ML-KEM" {
		t.Errorf("RSA migrate_to = %q, want ML-KEM", rows[0].MigrateTo)
	}
}

// No family may appear twice, whatever the tenant's crypto looks like. The
// blanket form of the first guard: a consumer keying by family name is entitled
// to assume the name identifies the row.
func TestIntegration_PQC_EveryFamilyAppearsAtMostOnce(t *testing.T) {
	f := newPQCFixture(t)
	f.addImpl(t, map[string]string{"key_exchange": "ECDHE", "symmetric": "AES256", "hash": "SHA256"})
	f.addImpl(t, map[string]string{"signature": "RSA-2048", "symmetric": "AES128"})
	f.addImpl(t, map[string]string{"key_exchange": "ML-KEM-768", "hash": "SHA384"})
	f.addImpl(t, map[string]string{"symmetric": "aes128-gcm@openssh.com", "hash": "hmac-sha2-256"})

	got := progressFor(t, f)
	if len(got.ByFamily) == 0 {
		t.Fatal("by_family is empty — this guard would pass vacuously")
	}
	seen := map[string]int{}
	for _, row := range got.ByFamily {
		seen[row.Family]++
	}
	for family, n := range seen {
		if n > 1 {
			t.Errorf("family %q appears %d times in by_family, want 1", family, n)
		}
	}

	// And a family cannot be on both of the dashboard's lists, which is what
	// "at most once" buys: the page filters on quantum_safe before folding.
	safe, unsafe := map[string]bool{}, map[string]bool{}
	for _, row := range got.ByFamily {
		if row.QuantumSafe {
			safe[row.Family] = true
		} else {
			unsafe[row.Family] = true
		}
	}
	for family := range safe {
		if unsafe[family] {
			t.Errorf("family %q is reported both quantum-safe and not", family)
		}
	}
}
