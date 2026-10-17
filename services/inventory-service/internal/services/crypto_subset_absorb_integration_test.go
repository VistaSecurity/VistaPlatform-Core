package services

// Integration proof, against a real Postgres with the real schema and seed,
// of SUBSET ABSORPTION in crypto configuration materialization (see the
// package doc on cryptoImplementationKey in crypto_dedup.go).
//
// The defect these pin, verified in an observed deployment: a passive sensor wrote a
// crypto configuration with protocol='TLS' and every other component NULL; the
// active probe that followed measured the full handshake and, because six key
// columns now differed, INSERTED a second row for the same endpoint that never
// superseded the first. 2 of 247 endpoints carried exactly that pair, and the
// automatic active scan on first observation makes it the steady state for
// every passive-first endpoint. The asset page showed two rows under one
// endpoint, total_crypto counted both, and the CBOM shipped an empty component
// beside the real one.
//
// Four branches, and every one of them is asserted in BOTH polarities:
//
//   - partial then complete  → ONE row, enriched in place, same score and
//     junction a fresh insert would get, first-seen kept, both methods recorded
//   - complete then partial  → ONE row, components untouched, score untouched
//   - CONFLICTING components → TWO rows (a real second configuration)
//   - exact re-observation   → ONE row, method recorded once
//
// plus the POST-MIGRATIONS reconcile of pairs written before the fix.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type absorbFixture struct {
	svc    *AssetService
	db     *database.DB
	tenant uuid.UUID
}

// newAbsorbFixture drives the REAL ingest entry point with the algorithm
// catalogue and the certificate service wired, so configurations are
// classified, scored and certificate-linked the way production ones are.
func newAbsorbFixture(t *testing.T) absorbFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return absorbFixture{
		svc: &AssetService{
			db:                 db,
			algorithmService:   NewAlgorithmService(db),
			certificateService: &CertificateService{db: db},
		},
		db:     db,
		tenant: testdb.NewTenant(t, raw),
	}
}

func (f absorbFixture) newAsset(t *testing.T, host string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, id, f.tenant, host); err != nil {
		t.Fatalf("insert asset %s: %v", host, err)
	}
	return id
}

func (f absorbFixture) ingest(t *testing.T, asset uuid.UUID, finding IngestFinding) {
	t.Helper()
	if err := materializeForTest(f.svc, f.tenant, asset, finding, nil, nil, nil); err != nil {
		t.Fatalf("ingest %s: %v", derefStr(finding.ProtocolVersion), err)
	}
}

// passiveGlimpse is what a passive sensor writes when it sees a TLS handshake
// it cannot decode: the protocol, the socket, and nothing else. This is the
// exact shape of the partial rows in that deployment.
func passiveGlimpse(host, ip string) IngestFinding {
	port := 443
	return IngestFinding{
		Hostname:  &host,
		IPAddress: &ip,
		Port:      &port,
		AssetType: "server",
		Protocol:  "TLS",
		RawData: map[string]interface{}{
			"source":           "sensor",
			"discovery_method": "passive",
			"observed_at":      time.Now().Format(time.RFC3339Nano),
		},
	}
}

// activeHandshake is what the active probe measures on the same socket: the
// full negotiated handshake. TLS 1.3 / TLS_AES_128_GCM_SHA256 is the observed
// pair's complete half.
func activeHandshake(host, ip string) IngestFinding {
	port := 443
	return IngestFinding{
		Hostname:        &host,
		IPAddress:       &ip,
		Port:            &port,
		AssetType:       "server",
		Protocol:        "TLS",
		ProtocolVersion: strPtr("TLS 1.3"),
		CipherSuite:     strPtr("TLS_AES_128_GCM_SHA256"),
		RawData: map[string]interface{}{
			"source":           "sensor",
			"discovery_method": "active",
			"tls_versions":     []interface{}{"TLS 1.3"},
			"probed_at":        time.Now().Format(time.RFC3339Nano),
		},
	}
}

// withLeafCert attaches a leaf certificate in the canonical "certificates"
// array (CLAUDE.md, "Single certificate format").
func withLeafCert(f IngestFinding, cn, fingerprint string) IngestFinding {
	raw := map[string]interface{}{}
	for k, v := range f.RawData {
		raw[k] = v
	}
	raw["certificates"] = []interface{}{
		map[string]interface{}{
			"subject_dn":           "CN=" + cn,
			"issuer_dn":            "CN=Absorb Test CA",
			"fingerprint_sha256":   fingerprint,
			"not_before":           time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
			"not_after":            time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
			"public_key_algorithm": "RSA",
			"public_key_size":      float64(2048),
			"signature_algorithm":  "SHA256-RSA",
		},
	}
	f.RawData = raw
	return f
}

type implRow struct {
	ID                uuid.UUID      `db:"id"`
	ProtocolVersion   *string        `db:"protocol_version"`
	CipherSuite       *string        `db:"cipher_suite"`
	KeyExchange       *string        `db:"key_exchange_algorithm"`
	Signature         *string        `db:"signature_algorithm"`
	Symmetric         *string        `db:"symmetric_encryption"`
	Hash              *string        `db:"hash_algorithm"`
	KeySize           *int           `db:"key_size"`
	DiscoveryMethod   string         `db:"discovery_method"`
	DiscoveryMethods  pq.StringArray `db:"discovery_methods"`
	RiskScore         *int           `db:"risk_score"`
	CertificateID     *uuid.UUID     `db:"certificate_id"`
	FirstDiscoveredAt time.Time      `db:"first_discovered_at"`
	LastVerifiedAt    time.Time      `db:"last_verified_at"`
	RawData           []byte         `db:"raw_data"`
}

func (f absorbFixture) liveRows(t *testing.T, asset uuid.UUID) []implRow {
	t.Helper()
	var rows []implRow
	if err := f.db.Select(&rows, `
		SELECT id, protocol_version, cipher_suite, key_exchange_algorithm, signature_algorithm,
		       symmetric_encryption, hash_algorithm, key_size, discovery_method, discovery_methods,
		       risk_score, certificate_id, first_discovered_at, last_verified_at, raw_data
		  FROM crypto_implementations
		 WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL
		 ORDER BY first_discovered_at, id`, f.tenant, asset); err != nil {
		t.Fatalf("read crypto implementations: %v", err)
	}
	return rows
}

func (f absorbFixture) oneLiveRow(t *testing.T, asset uuid.UUID, label string) implRow {
	t.Helper()
	rows := f.liveRows(t, asset)
	if len(rows) != 1 {
		t.Fatalf("%s: asset has %d live crypto configurations, want exactly 1 — %s", label, len(rows), describeRows(rows))
	}
	return rows[0]
}

func describeRows(rows []implRow) string {
	out := ""
	for _, r := range rows {
		out += "[" + derefStr(r.ProtocolVersion) + "/" + derefStr(r.CipherSuite) + " method=" + r.DiscoveryMethod + "] "
	}
	return out
}

// junction is the configuration's catalogue links as "role:code", sorted, so
// two configurations can be compared for identical linking.
func (f absorbFixture) junction(t *testing.T, impl uuid.UUID) []string {
	t.Helper()
	var links []string
	if err := f.db.Select(&links, `
		SELECT cia.algorithm_type || ':' || a.code
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE cia.crypto_implementation_id = $1`, impl); err != nil {
		t.Fatalf("read junction: %v", err)
	}
	sort.Strings(links)
	return links
}

func (f absorbFixture) leafLinked(t *testing.T, impl uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := f.db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM crypto_implementation_certificates
		                WHERE crypto_implementation_id = $1 AND certificate_role = 'leaf')`, impl).Scan(&ok); err != nil {
		t.Fatalf("read leaf link: %v", err)
	}
	return ok
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIntegration_CryptoAbsorb_PartialThenCompleteEnrichesInPlace is the
// headline: the observed pair, ingested in the order it happened, is ONE row.
func TestIntegration_CryptoAbsorb_PartialThenCompleteEnrichesInPlace(t *testing.T) {
	f := newAbsorbFixture(t)
	asset := f.newAsset(t, "absorb-partial-first.example.test")
	fp := hexFingerprint(uuid.NewString())

	// The passive glimpse carries the leaf certificate — the sensor sees the
	// chain even when it cannot decode the negotiated parameters.
	f.ingest(t, asset, withLeafCert(passiveGlimpse("absorb-partial-first.example.test", "192.0.2.10"), "absorb-partial-first.example.test", fp))
	partial := f.oneLiveRow(t, asset, "after the passive glimpse")
	if partial.ProtocolVersion != nil || partial.CipherSuite != nil {
		t.Fatalf("fixture: the passive glimpse should have written a partial row, got %s", describeRows([]implRow{partial}))
	}
	if partial.CertificateID == nil || !f.leafLinked(t, partial.ID) {
		t.Fatalf("fixture: the passive glimpse should have linked its leaf certificate")
	}

	time.Sleep(10 * time.Millisecond)
	f.ingest(t, asset, activeHandshake("absorb-partial-first.example.test", "192.0.2.10"))

	got := f.oneLiveRow(t, asset, "after the active probe")
	if got.ID != partial.ID {
		t.Fatalf("the active probe replaced the partial row (%s → %s) instead of completing it", partial.ID, got.ID)
	}
	if derefStr(got.ProtocolVersion) != "TLS 1.3" || derefStr(got.CipherSuite) != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("components not filled: version=%q suite=%q", derefStr(got.ProtocolVersion), derefStr(got.CipherSuite))
	}
	if got.Symmetric == nil || got.Hash == nil {
		t.Errorf("derived components not filled: symmetric=%v hash=%v", got.Symmetric, got.Hash)
	}
	if !got.FirstDiscoveredAt.Equal(partial.FirstDiscoveredAt) {
		t.Errorf("first_discovered_at moved from %s to %s — completing the picture is not a new discovery", partial.FirstDiscoveredAt, got.FirstDiscoveredAt)
	}
	if !got.LastVerifiedAt.After(partial.LastVerifiedAt) {
		t.Errorf("last_verified_at did not advance (%s → %s)", partial.LastVerifiedAt, got.LastVerifiedAt)
	}
	if got.DiscoveryMethod != "passive" {
		t.Errorf("primary discovery_method = %q, want the FIRST observer, passive", got.DiscoveryMethod)
	}
	if !sameStrings(got.DiscoveryMethods, []string{"passive", "active"}) {
		t.Errorf("discovery_methods = %v, want [passive active]", []string(got.DiscoveryMethods))
	}
	if got.CertificateID == nil || *got.CertificateID != *partial.CertificateID {
		t.Errorf("certificate_id changed or was dropped across enrichment: %v → %v", partial.CertificateID, got.CertificateID)
	}
	if !f.leafLinked(t, got.ID) {
		t.Errorf("the leaf certificate junction row did not survive enrichment")
	}

	// The enriched row must end exactly where a fresh insert of the same
	// observation ends — same score, same junction — or the two paths have two
	// opinions about one configuration.
	other := f.newAsset(t, "absorb-fresh-insert.example.test")
	f.ingest(t, other, activeHandshake("absorb-fresh-insert.example.test", "192.0.2.11"))
	fresh := f.oneLiveRow(t, other, "fresh insert of the complete observation")
	if fresh.RiskScore == nil || got.RiskScore == nil {
		t.Fatalf("risk_score must be assessed on both paths: fresh=%v enriched=%v", fresh.RiskScore, got.RiskScore)
	}
	if *fresh.RiskScore != *got.RiskScore {
		t.Errorf("enriched row scored %d, a fresh insert of the same observation scores %d — the enrich path must re-score like an insert",
			*got.RiskScore, *fresh.RiskScore)
	}
	if fj, gj := f.junction(t, fresh.ID), f.junction(t, got.ID); !sameStrings(fj, gj) {
		t.Errorf("enriched row's junction %v differs from a fresh insert's %v", gj, fj)
	}
	if len(f.junction(t, got.ID)) == 0 {
		t.Errorf("enriched row has no catalogue links — it would read as NOT ASSESSED")
	}
}

// TestIntegration_CryptoAbsorb_CompleteThenPartialReobserves is the converse:
// a passive glimpse of a configuration the probe already measured in full is a
// re-observation, and it must change nothing the probe established.
func TestIntegration_CryptoAbsorb_CompleteThenPartialReobserves(t *testing.T) {
	f := newAbsorbFixture(t)
	asset := f.newAsset(t, "absorb-complete-first.example.test")

	f.ingest(t, asset, activeHandshake("absorb-complete-first.example.test", "192.0.2.20"))
	complete := f.oneLiveRow(t, asset, "after the active probe")
	if complete.RiskScore == nil {
		t.Fatalf("fixture: the complete observation should have been scored")
	}
	completeJunction := f.junction(t, complete.ID)

	time.Sleep(10 * time.Millisecond)
	f.ingest(t, asset, passiveGlimpse("absorb-complete-first.example.test", "192.0.2.20"))

	got := f.oneLiveRow(t, asset, "after the passive glimpse")
	if got.ID != complete.ID {
		t.Fatalf("the passive glimpse became a new row (%s ≠ %s) beside the complete one", got.ID, complete.ID)
	}
	if derefStr(got.ProtocolVersion) != "TLS 1.3" || derefStr(got.CipherSuite) != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("a less complete observation altered the components: version=%q suite=%q", derefStr(got.ProtocolVersion), derefStr(got.CipherSuite))
	}
	if got.RiskScore == nil || *got.RiskScore != *complete.RiskScore {
		t.Errorf("risk_score moved from %v to %v on a partial re-observation that measured nothing new", complete.RiskScore, got.RiskScore)
	}
	if !sameStrings(f.junction(t, got.ID), completeJunction) {
		t.Errorf("junction changed on a partial re-observation: %v → %v", completeJunction, f.junction(t, got.ID))
	}
	if !sameStrings(got.DiscoveryMethods, []string{"active", "passive"}) {
		t.Errorf("discovery_methods = %v, want [active passive]", []string(got.DiscoveryMethods))
	}
	if got.DiscoveryMethod != "active" {
		t.Errorf("primary discovery_method = %q, want active (the first observer)", got.DiscoveryMethod)
	}
	if !got.LastVerifiedAt.After(complete.LastVerifiedAt) {
		t.Errorf("last_verified_at did not advance on re-observation")
	}
	// The probe's evidence survives: raw_data is merged, not replaced, so the
	// enumerated accepted-version list a passive glimpse never carries is
	// still there for AnalyzeCryptoRisk.
	if !containsKey(got.RawData, "tls_versions") {
		t.Errorf("raw_data lost the active probe's tls_versions evidence on a passive re-observation: %s", string(got.RawData))
	}
}

func containsKey(raw []byte, key string) bool {
	return strings.Contains(string(raw), `"`+key+`"`)
}

// TestIntegration_CryptoAbsorb_PartialReobservationCannotLowerScore pins WHY
// a partial re-observation is not scored. The weak-crypto detector judges the
// finding it is handed, and key SIZE is the one thing only the detector can
// see (the catalogue is per-algorithm). A probe that measured a 1024-bit RSA
// key scored the row above anything the catalogue says; a passive glimpse
// that measured no key must not be allowed to re-run the detector on nothing
// and write the lower number back.
//
// The measured key is a 160-bit EC key (below cryptoparse.MinECCKeySizeBits)
// rather than a short RSA one: the catalogue's bare RSA row is itself rated
// weak/deprecated, so an RSA fixture cannot tell the detector's verdict from
// the catalogue's. ECDHE is rated strong, so here only the detector can raise
// the score, and the premise check below proves it did.
func TestIntegration_CryptoAbsorb_PartialReobservationCannotLowerScore(t *testing.T) {
	f := newAbsorbFixture(t)
	f.svc.weakCryptoDetector = NewWeakCryptoDetector(nil)

	weakKey := func(host, ip string) IngestFinding {
		obs := activeHandshake(host, ip)
		obs.ProtocolVersion = strPtr("TLS 1.2")
		obs.CipherSuite = strPtr("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		// The detector applies a bit-length floor only to a NAMED family
		// (cryptoparse.WeakKeySizeSeverity answers "" for an unknown one), so
		// the probe reports the key exchange it measured.
		obs.KeyExchangeAlgorithm = strPtr("ECDHE")
		size := 160
		obs.KeySize = &size
		return obs
	}

	// Premise check: the detector really does raise this above the
	// catalogue's verdict for the same suite without a key size.
	baseline := f.newAsset(t, "absorb-floor-baseline.example.test")
	noKey := weakKey("absorb-floor-baseline.example.test", "192.0.2.70")
	noKey.KeySize = nil
	f.ingest(t, baseline, noKey)
	catalogueOnly := f.oneLiveRow(t, baseline, "catalogue-only baseline")

	asset := f.newAsset(t, "absorb-floor.example.test")
	f.ingest(t, asset, weakKey("absorb-floor.example.test", "192.0.2.71"))
	measured := f.oneLiveRow(t, asset, "after the probe that measured the key")
	if measured.RiskScore == nil || catalogueOnly.RiskScore == nil || *measured.RiskScore <= *catalogueOnly.RiskScore {
		t.Fatalf("premise: a 160-bit EC key should score above the catalogue-only %s, got %s", derefInt(catalogueOnly.RiskScore), derefInt(measured.RiskScore))
	}

	f.ingest(t, asset, passiveGlimpse("absorb-floor.example.test", "192.0.2.71"))
	after := f.oneLiveRow(t, asset, "after the passive glimpse")
	if after.ID != measured.ID {
		t.Fatalf("the glimpse became a second row")
	}
	if after.RiskScore == nil || *after.RiskScore != *measured.RiskScore {
		t.Errorf("a passive glimpse that measured no key lowered the score from %s to %s", derefInt(measured.RiskScore), derefInt(after.RiskScore))
	}
}

// TestIntegration_CryptoAbsorb_ConflictingComponentsStayTwoRows is the
// over-absorb guard. A component both observations measured DIFFERENTLY is a
// second configuration — the server changed between observations, or offers
// both — and must not be folded into one.
func TestIntegration_CryptoAbsorb_ConflictingComponentsStayTwoRows(t *testing.T) {
	f := newAbsorbFixture(t)
	asset := f.newAsset(t, "absorb-conflict.example.test")

	// Passive decoded the version this time — and saw TLS 1.2.
	glimpse := passiveGlimpse("absorb-conflict.example.test", "192.0.2.30")
	glimpse.ProtocolVersion = strPtr("TLS 1.2")
	f.ingest(t, asset, glimpse)
	// Active negotiated TLS 1.3.
	f.ingest(t, asset, activeHandshake("absorb-conflict.example.test", "192.0.2.30"))

	rows := f.liveRows(t, asset)
	if len(rows) != 2 {
		t.Fatalf("TLS 1.2 (passive) beside TLS 1.3 (active) produced %d rows, want 2 — a conflicting pair is a real second configuration: %s",
			len(rows), describeRows(rows))
	}
	for _, r := range rows {
		if len(r.DiscoveryMethods) != 1 {
			t.Errorf("a conflicting row gained provenance it did not earn: %v", []string(r.DiscoveryMethods))
		}
	}

	// The same conflict in the OTHER order — the complete row exists, then a
	// glimpse that decoded a DIFFERENT version arrives — goes through the
	// superset lookup rather than the partial one, and must not be treated as
	// a re-observation of a configuration it contradicts.
	reversed := f.newAsset(t, "absorb-conflict-reversed.example.test")
	f.ingest(t, reversed, activeHandshake("absorb-conflict-reversed.example.test", "192.0.2.32"))
	lateGlimpse := passiveGlimpse("absorb-conflict-reversed.example.test", "192.0.2.32")
	lateGlimpse.ProtocolVersion = strPtr("TLS 1.2")
	f.ingest(t, reversed, lateGlimpse)
	if rows := f.liveRows(t, reversed); len(rows) != 2 {
		t.Fatalf("TLS 1.3 (active, first) then TLS 1.2 (passive) produced %d rows, want 2 — a glimpse that contradicts the held row is not a re-observation of it: %s",
			len(rows), describeRows(rows))
	}

	// And the equal-fingerprint, different-method case stays two rows too —
	// the attribution argument on cryptoImplementationKey is unchanged.
	other := f.newAsset(t, "absorb-equal-fp.example.test")
	f.ingest(t, other, activeHandshake("absorb-equal-fp.example.test", "192.0.2.31"))
	asPassive := activeHandshake("absorb-equal-fp.example.test", "192.0.2.31")
	asPassive.RawData = map[string]interface{}{"source": "sensor", "discovery_method": "passive"}
	f.ingest(t, other, asPassive)
	if n := len(f.liveRows(t, other)); n != 2 {
		t.Fatalf("equal fingerprints under two methods produced %d rows, want 2 — discovery_method is still in the key", n)
	}
}

// TestIntegration_CryptoAbsorb_EnrichedRowAbsorbsLaterObservations pins the
// steady state after enrichment: the daily active probe and the hourly
// passive glimpse both keep landing on the ONE row. Without the provenance
// array in the exact-key predicate, the very next active probe would insert
// a duplicate — the defect re-created one observation later.
func TestIntegration_CryptoAbsorb_EnrichedRowAbsorbsLaterObservations(t *testing.T) {
	f := newAbsorbFixture(t)
	asset := f.newAsset(t, "absorb-steady.example.test")

	f.ingest(t, asset, passiveGlimpse("absorb-steady.example.test", "192.0.2.40"))
	f.ingest(t, asset, activeHandshake("absorb-steady.example.test", "192.0.2.40"))
	enriched := f.oneLiveRow(t, asset, "after enrichment")

	for i := 0; i < 3; i++ {
		f.ingest(t, asset, activeHandshake("absorb-steady.example.test", "192.0.2.40"))
		f.ingest(t, asset, passiveGlimpse("absorb-steady.example.test", "192.0.2.40"))
	}
	got := f.oneLiveRow(t, asset, "after three more probe+glimpse cycles")
	if got.ID != enriched.ID {
		t.Fatalf("the enriched row was replaced (%s → %s)", enriched.ID, got.ID)
	}
	if !sameStrings(got.DiscoveryMethods, []string{"passive", "active"}) {
		t.Errorf("discovery_methods grew or reordered on repeat observations: %v", []string(got.DiscoveryMethods))
	}
	if got.RiskScore == nil || enriched.RiskScore == nil || *got.RiskScore != *enriched.RiskScore {
		t.Errorf("risk_score drifted across repeat observations: %v → %v", enriched.RiskScore, got.RiskScore)
	}
}

// TestIntegration_CryptoAbsorb_ExactReobservationRecordsMethodOnce: the
// provenance array is a set.
func TestIntegration_CryptoAbsorb_ExactReobservationRecordsMethodOnce(t *testing.T) {
	f := newAbsorbFixture(t)
	asset := f.newAsset(t, "absorb-exact.example.test")
	for i := 0; i < 4; i++ {
		f.ingest(t, asset, activeHandshake("absorb-exact.example.test", "192.0.2.50"))
	}
	got := f.oneLiveRow(t, asset, "after four identical observations")
	if !sameStrings(got.DiscoveryMethods, []string{"active"}) {
		t.Errorf("discovery_methods = %v after four identical active observations, want [active]", []string(got.DiscoveryMethods))
	}
}
