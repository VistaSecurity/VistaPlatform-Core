package services

// End-to-end proof, against a real Postgres with the real schema and seed, that
// an SSH discovery finding now produces a scored crypto configuration.
//
// Before this, SSH data was collected in full (banner, KEXINIT name-lists, host
// key type) and mapped nowhere: the ingest adapter promoted only TLS-shaped
// fields, so an SSH configuration linked ZERO rows in
// crypto_implementation_algorithms, catalogueRiskForImplementation returned
// ok=false, and the implementation kept risk_score 0 — "not assessed". Every
// SSH asset scored identically no matter how it was configured.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newSSHIngestFixture(t *testing.T, hostname string) (*AssetService, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	asset := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,$3,'server','monitoring',NOW(),NOW(),NOW(),NOW())`, asset, tenant, hostname); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return &AssetService{db: db, algorithmService: NewAlgorithmService(db)}, tenant, asset
}

// ingestSSH runs the materialisation step and fails the test if it errors.
//
// The error return is a real signal here, not ceremony: every assertion below
// is about rows ingest was supposed to write, so a silently-failed ingest would
// surface as "expected 5 junction rows, got 0" and send the next reader hunting
// through the mapping code for a bug that is actually in the fixture.
func ingestSSH(t *testing.T, svc *AssetService, tenant, asset uuid.UUID, f IngestFinding) {
	t.Helper()
	if err := svc.processDiscoveryCryptoData(tenant, asset, f, nil, nil, nil); err != nil {
		t.Fatalf("ingest returned error: %v", err)
	}
}

// modernSSHFinding is an OpenSSH 9.x server offering only current algorithms.
func modernSSHFinding() IngestFinding {
	return IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner":        "SSH-2.0-OpenSSH_9.6p1",
			"ssh_host_key_type": "ssh-ed25519",
			"ssh_kex_algorithms_client": []interface{}{
				"curve25519-sha256", "ecdh-sha2-nistp256",
			},
			"ssh_kex_algorithms_server": []interface{}{
				"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
			},
			"ssh_encryption_algs_c2s_client": []interface{}{"aes256-gcm@openssh.com", "aes256-ctr"},
			"ssh_encryption_algs_c2s_server": []interface{}{"aes256-gcm@openssh.com", "aes256-ctr"},
			"ssh_encryption_algs_s2c_server": []interface{}{"aes256-gcm@openssh.com", "aes256-ctr"},
			"ssh_mac_algs_c2s_client":        []interface{}{"hmac-sha2-256-etm@openssh.com"},
			"ssh_mac_algs_c2s_server":        []interface{}{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
		},
	}
}

// legacySSHFinding is a long-unpatched server: SHA-1 host key, 1024-bit MODP
// key exchange, 3DES-CBC and HMAC-MD5.
func legacySSHFinding() IngestFinding {
	return IngestFinding{
		Protocol: "SSH",
		RawData: map[string]interface{}{
			"ssh_banner":        "SSH-2.0-OpenSSH_5.3",
			"ssh_host_key_type": "ssh-rsa",
			"ssh_kex_algorithms_client": []interface{}{
				"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
			},
			"ssh_kex_algorithms_server": []interface{}{
				"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
			},
			"ssh_encryption_algs_c2s_client": []interface{}{"3des-cbc", "aes128-cbc"},
			"ssh_encryption_algs_c2s_server": []interface{}{"3des-cbc", "aes128-cbc"},
			"ssh_encryption_algs_s2c_server": []interface{}{"3des-cbc", "aes128-cbc"},
			"ssh_mac_algs_c2s_client":        []interface{}{"hmac-md5", "hmac-sha1"},
			"ssh_mac_algs_c2s_server":        []interface{}{"hmac-md5", "hmac-sha1"},
		},
	}
}

func sshImplRiskScore(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) int {
	t.Helper()
	var score int
	if err := svc.db.QueryRow(`
		SELECT COALESCE(risk_score, 0) FROM crypto_implementations
		 WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
		tenant, asset).Scan(&score); err != nil {
		t.Fatalf("read back risk score: %v", err)
	}
	return score
}

// sshLinkedCodes returns every catalogue code linked to the tenant's single SSH
// implementation, mapped to its is_inferred flag.
func sshLinkedCodes(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) map[string]bool {
	t.Helper()
	rows, err := svc.db.Query(`
		SELECT a.code, cia.is_inferred
		  FROM crypto_implementations ci
		  JOIN crypto_implementation_algorithms cia ON cia.crypto_implementation_id = ci.id
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE ci.tenant_id = $1 AND ci.asset_id = $2`, tenant, asset)
	if err != nil {
		t.Fatalf("read back links: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]bool{}
	for rows.Next() {
		var code string
		var inferred bool
		if err := rows.Scan(&code, &inferred); err != nil {
			t.Fatalf("scan link: %v", err)
		}
		out[code] = inferred
	}
	return out
}

// The headline defect: an SSH configuration used to link nothing and therefore
// score 0 ("not assessed"). It must now resolve components and carry a real
// score, with the negotiated ones marked measured and the merely-offered ones
// marked inferred.
func TestIntegration_SSHIngest_LinksComponentsAndScores(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "ssh-modern.example.test")
	ingestSSH(t, svc, tenant, asset, modernSSHFinding())

	links := sshLinkedCodes(t, svc, tenant, asset)
	if len(links) == 0 {
		t.Fatal("no algorithms linked to the SSH configuration — this is the original defect")
	}

	// Measured (is_inferred = false).
	for _, code := range []string{"SSH-2.0", "ssh-ed25519", "curve25519-sha256", "aes256-gcm@openssh.com"} {
		inferred, ok := links[code]
		if !ok {
			t.Errorf("%s not linked", code)
			continue
		}
		if inferred {
			t.Errorf("%s linked as inferred, want measured", code)
		}
	}
	// Offered-only (is_inferred = true). curve25519-sha256@libssh.org and
	// aes256-ctr are on the server's list but were not the negotiated choice.
	for _, code := range []string{"curve25519-sha256@libssh.org", "aes256-ctr", "hmac-sha2-256"} {
		inferred, ok := links[code]
		if !ok {
			t.Errorf("%s not linked", code)
			continue
		}
		if !inferred {
			t.Errorf("%s linked as measured, want inferred — the server offers it but did not use it", code)
		}
	}

	// An AEAD cipher was negotiated, so no MAC was: hmac-sha2-256-etm is on the
	// offer list and must be inferred, never measured.
	if inferred, ok := links["hmac-sha2-256-etm@openssh.com"]; ok && !inferred {
		t.Error("a MAC was recorded as negotiated alongside an AEAD cipher — no MAC is negotiated in that case")
	}

	// Component columns record what was USED.
	var kex, sig, sym, hash, protoVer *string
	if err := svc.db.QueryRow(`
		SELECT key_exchange_algorithm, signature_algorithm, symmetric_encryption, hash_algorithm, protocol_version
		  FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, asset).Scan(&kex, &sig, &sym, &hash, &protoVer); err != nil {
		t.Fatalf("read back component columns: %v", err)
	}
	deref := func(p *string) string {
		if p == nil {
			return "<NULL>"
		}
		return *p
	}
	if deref(protoVer) != "SSH-2.0" {
		t.Errorf("protocol_version = %s, want SSH-2.0 (derived from the banner)", deref(protoVer))
	}
	if deref(kex) != "curve25519-sha256" {
		t.Errorf("key_exchange_algorithm = %s", deref(kex))
	}
	if deref(sig) != "ssh-ed25519" {
		t.Errorf("signature_algorithm = %s", deref(sig))
	}
	if deref(sym) != "aes256-gcm@openssh.com" {
		t.Errorf("symmetric_encryption = %s", deref(sym))
	}
	if hash != nil {
		t.Errorf("hash_algorithm = %s, want NULL — an AEAD cipher negotiates no MAC", deref(hash))
	}

	if got := sshImplRiskScore(t, svc, tenant, asset); got == 0 {
		t.Fatal("risk_score is still 0 — the product reads 0 as NOT ASSESSED, which is the defect")
	}
}

// A modern SSH server must band Low; a legacy one must band High. Both numbers
// come from the catalogue, so this also pins that the seeded SSH rows resolve.
func TestIntegration_SSHIngest_ModernScoresLowLegacyScoresHigh(t *testing.T) {
	modernSvc, modernTenant, modernAsset := newSSHIngestFixture(t, "ssh-low.example.test")
	ingestSSH(t, modernSvc, modernTenant, modernAsset, modernSSHFinding())
	modernScore := sshImplRiskScore(t, modernSvc, modernTenant, modernAsset)

	legacySvc, legacyTenant, legacyAsset := newSSHIngestFixture(t, "ssh-high.example.test")
	ingestSSH(t, legacySvc, legacyTenant, legacyAsset, legacySSHFinding())
	legacyScore := sshImplRiskScore(t, legacySvc, legacyTenant, legacyAsset)

	if band := models.GetRiskLevel(modernScore); band != "Low" {
		t.Errorf("modern SSH server scored %d (band %q), want the low band", modernScore, band)
	}
	if band := models.GetRiskLevel(legacyScore); band != "High" && band != "Critical" {
		t.Errorf("legacy SSH server scored %d (band %q), want high or above", legacyScore, band)
	}
	if legacyScore <= modernScore {
		t.Errorf("legacy score %d is not worse than modern score %d", legacyScore, modernScore)
	}

	// The legacy score must trace to a catalogue row, not to a hardcoded rule.
	links := sshLinkedCodes(t, legacySvc, legacyTenant, legacyAsset)
	for _, code := range []string{"ssh-rsa", "diffie-hellman-group1-sha1", "3des-cbc", "hmac-md5"} {
		if _, ok := links[code]; !ok {
			t.Errorf("%s did not resolve against the catalogue", code)
		}
	}
}

// A server that offers a weak algorithm it did not negotiate is still exposed:
// any client can ask for it. Worst-component-wins deliberately counts inferred
// (offered) links, and this pins that reading.
func TestIntegration_SSHIngest_OfferedWeakAlgorithmRaisesRisk(t *testing.T) {
	cleanSvc, cleanTenant, cleanAsset := newSSHIngestFixture(t, "ssh-clean.example.test")
	ingestSSH(t, cleanSvc, cleanTenant, cleanAsset, modernSSHFinding())
	clean := sshImplRiskScore(t, cleanSvc, cleanTenant, cleanAsset)

	// Same negotiated outcome, but 3des-cbc left on the server's cipher list.
	f := modernSSHFinding()
	f.RawData["ssh_encryption_algs_c2s_server"] = []interface{}{"aes256-gcm@openssh.com", "aes256-ctr", "3des-cbc"}
	dirtySvc, dirtyTenant, dirtyAsset := newSSHIngestFixture(t, "ssh-legacy-offer.example.test")
	ingestSSH(t, dirtySvc, dirtyTenant, dirtyAsset, f)
	dirty := sshImplRiskScore(t, dirtySvc, dirtyTenant, dirtyAsset)

	if dirty <= clean {
		t.Errorf("offering 3des-cbc did not raise risk (%d vs %d) — an offered weak cipher is reachable by any client", dirty, clean)
	}
	links := sshLinkedCodes(t, dirtySvc, dirtyTenant, dirtyAsset)
	if inferred, ok := links["3des-cbc"]; !ok || !inferred {
		t.Errorf("3des-cbc link: present=%v inferred=%v, want present and inferred", ok, inferred)
	}
	// It must NOT be written to the component column: it was not used.
	var sym *string
	if err := svc0Query(dirtySvc, dirtyTenant, dirtyAsset, &sym); err != nil {
		t.Fatalf("read back symmetric column: %v", err)
	}
	if sym == nil || *sym != "aes256-gcm@openssh.com" {
		t.Errorf("symmetric_encryption = %v, want the negotiated aes256-gcm@openssh.com", sym)
	}
}

func svc0Query(svc *AssetService, tenant, asset uuid.UUID, dst **string) error {
	return svc.db.QueryRow(`
		SELECT symmetric_encryption FROM crypto_implementations
		 WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset).Scan(dst)
}

// Every SSH wire name the sensors actually emit must resolve to the row that
// carries its assessment — an exact code match, not the ambiguous-substring
// fallback that once turned "RSA" into RSA-MD5.
func TestIntegration_SSHCatalogue_WireNamesResolveExactly(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAlgorithmService(db)

	cases := []struct{ observed, category, want string }{
		{"SSH-2.0", "protocol_version", "SSH-2.0"},
		{"SSH-1.99", "protocol_version", "SSH-1.99"},
		{"curve25519-sha256", "key_exchange", "curve25519-sha256"},
		{"curve25519-sha256@libssh.org", "key_exchange", "curve25519-sha256@libssh.org"},
		{"ecdh-sha2-nistp256", "key_exchange", "ecdh-sha2-nistp256"},
		{"diffie-hellman-group14-sha256", "key_exchange", "diffie-hellman-group14-sha256"},
		{"diffie-hellman-group14-sha1", "key_exchange", "diffie-hellman-group14-sha1"},
		{"diffie-hellman-group1-sha1", "key_exchange", "diffie-hellman-group1-sha1"},
		{"diffie-hellman-group-exchange-sha1", "key_exchange", "diffie-hellman-group-exchange-sha1"},
		{"sntrup761x25519-sha512@openssh.com", "key_exchange", "sntrup761x25519-sha512@openssh.com"},
		{"mlkem768x25519-sha256", "key_exchange", "mlkem768x25519-sha256"},
		{"aes256-gcm@openssh.com", "symmetric", "aes256-gcm@openssh.com"},
		{"chacha20-poly1305@openssh.com", "symmetric", "chacha20-poly1305@openssh.com"},
		{"aes256-ctr", "symmetric", "aes256-ctr"},
		{"aes128-cbc", "symmetric", "aes128-cbc"},
		{"3des-cbc", "symmetric", "3des-cbc"},
		{"arcfour256", "symmetric", "arcfour256"},
		{"hmac-sha2-256-etm@openssh.com", "hash", "hmac-sha2-256-etm@openssh.com"},
		{"hmac-sha2-512", "hash", "hmac-sha2-512"},
		{"hmac-sha1", "hash", "hmac-sha1"},
		{"hmac-md5", "hash", "hmac-md5"},
		{"umac-128-etm@openssh.com", "hash", "umac-128-etm@openssh.com"},
		{"ssh-ed25519", "signature", "ssh-ed25519"},
		{"ecdsa-sha2-nistp256", "signature", "ecdsa-sha2-nistp256"},
		{"rsa-sha2-512", "signature", "rsa-sha2-512"},
		{"ssh-rsa", "signature", "ssh-rsa"},
		{"ssh-dss", "signature", "ssh-dss"},

		// The pre-existing TLS/other vocabulary must resolve exactly as before.
		// The SSH rows introduce many new codes containing "aes", "sha" and
		// "ed25519" as substrings; if any of these regress, the substring
		// fallback has started competing with the exact match.
		{"AES256", "symmetric", "AES256"},
		{"AES128", "symmetric", "AES128"},
		{"AES-256-GCM", "symmetric", "AES256"},
		{"CHACHA20", "symmetric", "ChaCha20"},
		{"3DES", "symmetric", "3DES"},
		{"RC4", "symmetric", "RC4"},
		{"SHA256", "hash", "SHA256"},
		{"SHA1", "hash", "SHA1"},
		{"MD5", "hash", "MD5"},
		{"ECDHE", "key_exchange", "ECDHE"},
		{"CURVE25519", "key_exchange", "CURVE25519"},
		{"ML-KEM-768", "key_exchange", "ML-KEM-768"},
		{"RSA-SHA256", "signature", "RSA-SHA256"},
		{"ED25519", "signature", "Ed25519"},
		{"TLS 1.2", "protocol_version", "TLS1.2"},
		{"SSL 3.0", "protocol_version", "SSLv3"},
	}
	for _, tc := range cases {
		alg, err := svc.ClassifyAlgorithm(tc.observed, tc.category)
		if err != nil {
			t.Errorf("ClassifyAlgorithm(%q, %q): %v", tc.observed, tc.category, err)
			continue
		}
		if alg == nil {
			t.Errorf("ClassifyAlgorithm(%q, %q) resolved to nothing, want %s", tc.observed, tc.category, tc.want)
			continue
		}
		if alg.Code != tc.want {
			t.Errorf("ClassifyAlgorithm(%q, %q) = %s, want %s", tc.observed, tc.category, alg.Code, tc.want)
		}
	}
}

// The PQC classifier reads `primitive` off exactly these rows. A modern SSH
// server must land in needs-migration (its Ed25519 host key and X25519 key
// exchange are both Shor-breakable per NIST IR 8547), and a hybrid-PQC key
// exchange must not be mistaken for a classical one. The four categories must
// still partition the population.
func TestIntegration_SSHIngest_PQCClassificationStaysCoherent(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "ssh-pqc.example.test")
	ingestSSH(t, svc, tenant, asset, modernSSHFinding())

	counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if counts.Total != 1 {
		t.Fatalf("Total = %d, want 1", counts.Total)
	}
	if counts.NeedsMigration+counts.PQCReady+counts.SymmetricSafe+counts.Unclassified != counts.Total {
		t.Errorf("categories do not partition the population: %+v", counts)
	}
	if counts.NeedsMigration != 1 {
		t.Errorf("a classical SSH server classified as %+v, want NeedsMigration=1 (Ed25519 and X25519 are Shor-breakable)", counts)
	}

	// A hybrid PQC key exchange is is_pqc, but a classical host key still makes
	// the implementation vulnerable — precedence must not invert.
	f := modernSSHFinding()
	f.RawData["ssh_kex_algorithms_client"] = []interface{}{"mlkem768x25519-sha256"}
	f.RawData["ssh_kex_algorithms_server"] = []interface{}{"mlkem768x25519-sha256"}
	hybridSvc, hybridTenant, hybridAsset := newSSHIngestFixture(t, "ssh-hybrid.example.test")
	ingestSSH(t, hybridSvc, hybridTenant, hybridAsset, f)
	hybrid, err := classifyTenantImplementationsPQC(hybridSvc.db, hybridTenant)
	if err != nil {
		t.Fatalf("classify hybrid: %v", err)
	}
	if hybrid.NeedsMigration != 1 {
		t.Errorf("hybrid-kex server classified as %+v, want NeedsMigration=1 — the ssh-ed25519 host key is still classical", hybrid)
	}
}
