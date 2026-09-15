package services

// THE PARITY GATE for workstream 3.6.
//
// Replacing nineteen hand-written SQL extractors with one registry-driven
// executor is only safe if the two produce the SAME measurements — the same
// subjects, the same values, the same evidence keys, the same omissions. A
// reading of the new code cannot establish that; running both over one fixture
// can, and that is what this file does.
//
// The parity run itself is HISTORY, not a test you can run today: the oracle it
// compared against (measurement_oracle_test.go, the pre-registry extractor kept
// verbatim) was deleted in the commit after it passed, which is the whole point
// of doing it that way. What survives is
// testdata/measurement_parity_golden.json — the 74 measurements that run
// recorded — and …_MatchesGolden below, which holds the executor to them. A
// later change to a shape, a transform or a predicate is therefore still
// measured against what the ORIGINAL extractor produced, not against the
// current code's own opinion.
//
// The fixture is deliberately awkward: a soft-deleted asset, a soft-deleted
// configuration, a certificate with no algorithm at all, a CA certificate, a
// post-quantum key that belongs to neither key-size family, an endpoint with no
// address, and a configuration with no endpoint. Every one of those is a case
// where "reasonable-looking" SQL and the original disagree.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

var updateParityGolden = flag.Bool("update-parity-golden", false,
	"rewrite testdata/measurement_parity_golden.json from the current extractor")

// legacyMeasurementCodes are the nineteen codes the pre-registry extractor
// implemented, and exactly what the parity run compared. The codes that arrive
// with this workstream are covered by the Hygiene and Lifecycle framework
// tests instead: they have no oracle, because they never existed before.
var legacyMeasurementCodes = []string{
	"cert_expiration_days", "cert_algorithm", "cert_pqc_status", "cert_sig_pqc_status",
	"cert_validity_days", "certificate_chain_valid", "key_size", "key_size_ec",
	"tls_version", "key_exchange_algorithm", "symmetric_encryption", "hash_algorithm",
	"cipher_suite_name", "pfs_support", "tls_compression_enabled", "ot_protocol_encryption",
	"config_kex_pqc_status", "config_sig_pqc_status", "config_sym_strength",
}

// parityFixture is the seeded inventory, with a label per row so the golden can
// name subjects without embedding per-run uuids.
type parityFixture struct {
	db     *sqlx.DB
	tenant uuid.UUID
	labels map[uuid.UUID]string
	// now is the instant the fixture was built. Every seeded timestamp is an
	// offset from it, and the golden records timestamps the same way — an
	// absolute instant in a golden file would be correct for exactly one day.
	now time.Time
}

// Timestamps are offset by twelve hours from a whole number of days on purpose.
// Every day count these measurements produce is a floor (or a truncation) of a
// fractional day, so a fixture built exactly N days out would land on the
// boundary and flip between N and N-1 depending on the microsecond the test ran.
// Half a day of margin makes every expected value stable for twelve hours.
const parityHalfDay = 12 * time.Hour

func newParityFixture(t *testing.T) *parityFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	f := &parityFixture{db: db, tenant: tenant, labels: map[uuid.UUID]string{}, now: time.Now().UTC()}

	// ---- assets ---------------------------------------------------------
	web := f.asset(t, "parity-web.example.test", "server", "hardware.computer.server", "192.0.2.10", "monitoring", false)
	edge := f.asset(t, "parity-edge.example.test", "server", "hardware.computer.server", "192.0.2.11", "monitoring", false)
	ot := f.asset(t, "parity-ot.example.test", "server", "hardware.computer.server", "192.0.2.12", "monitoring", false)
	// A soft-deleted asset whose configurations are still present. Extracting
	// it would resurrect its INACTIVE findings on the next reconcile.
	gone := f.asset(t, "parity-gone.example.test", "server", "hardware.computer.server", "192.0.2.13", "monitoring", true)
	// A discovery still waiting in Approvals. The crypto measurements DO see
	// it — they always have — which is why the hygiene measurements filter on
	// status and these do not.
	pending := f.asset(t, "parity-pending.example.test", "server", "hardware.computer.server", "192.0.2.14", "pending_approval", false)

	// ---- endpoints ------------------------------------------------------
	addressed := f.endpoint(t, web, "192.0.2.20", "", 443)
	fqdnOnly := f.endpoint(t, edge, "", "parity-vhost.example.test", 8443)

	// ---- crypto configurations -----------------------------------------
	f.config(t, web, &addressed, cryptoRow{
		protocol: "TLS", version: "TLS1.2",
		cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		kex:         "ECDHE", sig: "RSA", sym: "AES-128-GCM", hash: "SHA256",
		rawData: `{"compression":false,"alpn":["h2"]}`,
	})
	// No endpoint at all: an asset-level observation, which has no port.
	f.config(t, web, nil, cryptoRow{
		protocol: "TLS", version: "TLS1.0",
		cipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		kex:         "RSA", sig: "RSA", sym: "3DES", hash: "SHA1",
	})
	// Post-quantum, on an endpoint identified only by FQDN.
	f.config(t, edge, &fqdnOnly, cryptoRow{
		protocol: "TLS", version: "TLS1.3",
		cipherSuite: "TLS_AES_256_GCM_SHA384",
		kex:         "X25519MLKEM768", sig: "ML-DSA-65", sym: "AES-256-GCM", hash: "SHA384",
	})
	// Plaintext OT and encrypted OT.
	f.config(t, ot, nil, cryptoRow{protocol: "Modbus"})
	f.config(t, ot, nil, cryptoRow{protocol: "BACnet_SC", cipherSuite: "TLS_AES_128_GCM_SHA256", sym: "AES-128-GCM"})
	// On the deleted asset, and a deleted configuration on a live asset.
	f.config(t, gone, nil, cryptoRow{protocol: "TLS", version: "TLS1.1", kex: "DHE", sym: "AES-128-CBC", hash: "SHA1"})
	f.config(t, web, nil, cryptoRow{protocol: "TLS", version: "SSL3.0", kex: "RSA", deleted: true})
	// A pending discovery is in scope for the crypto measurements.
	f.config(t, pending, nil, cryptoRow{protocol: "TLS", version: "TLS1.2", kex: "ECDHE", sym: "AES-256-GCM", hash: "SHA384"})

	// ---- certificates ---------------------------------------------------
	now := f.now
	f.certificate(t, certRow{
		label: "rsa-leaf", commonName: "parity-rsa.example.test",
		issuer: "CN=Parity Test CA", keyAlg: "RSA", sigAlg: "sha256WithRSAEncryption", keySize: 2048,
		notBefore: now.Add(-30*24*time.Hour - parityHalfDay), notAfter: now.Add(45*24*time.Hour + parityHalfDay),
	})
	f.certificate(t, certRow{
		label: "ec-leaf", commonName: "parity-ec.example.test",
		issuer: "CN=parity-ec.example.test", keyAlg: "ecdsa-with-SHA384", sigAlg: "ecdsa-with-SHA384", keySize: 256,
		notBefore: now.Add(-10*24*time.Hour - parityHalfDay), notAfter: now.Add(200*24*time.Hour + parityHalfDay),
		selfSigned: true,
	})
	f.certificate(t, certRow{
		label: "pqc-leaf", commonName: "parity-pqc.example.test",
		issuer: "CN=Parity Test CA", keyAlg: "ML-DSA-65", sigAlg: "ML-DSA-65", keySize: 1952,
		notBefore: now.Add(-1*24*time.Hour - parityHalfDay), notAfter: now.Add(90*24*time.Hour + parityHalfDay),
	})
	// Already expired: the day count counts DOWN past zero.
	f.certificate(t, certRow{
		label: "expired-leaf", commonName: "parity-expired.example.test",
		issuer: "CN=Parity Test CA", keyAlg: "RSA", sigAlg: "sha1WithRSAEncryption", keySize: 1024,
		notBefore: now.Add(-400*24*time.Hour - parityHalfDay), notAfter: now.Add(-10*24*time.Hour - parityHalfDay),
	})
	// Nothing is known about this certificate's key. It must still be
	// classified quantum_vulnerable (absent is not safe) and must be judged by
	// NEITHER key-size measurement.
	f.certificate(t, certRow{
		label: "unknown-key-leaf", commonName: "parity-unknown.example.test",
		issuer:    "CN=Parity Test CA",
		notBefore: now.Add(-5*24*time.Hour - parityHalfDay), notAfter: now.Add(30*24*time.Hour + parityHalfDay),
	})
	// A CA certificate: out of scope for every certificate measurement.
	f.certificate(t, certRow{
		label: "ca", commonName: "Parity Test CA", issuer: "CN=Parity Test CA",
		keyAlg: "RSA", sigAlg: "sha256WithRSAEncryption", keySize: 4096,
		notBefore: now.Add(-1000 * 24 * time.Hour), notAfter: now.Add(1000 * 24 * time.Hour),
		selfSigned: true, isCA: true,
	})
	return f
}

func (f *parityFixture) asset(t *testing.T, hostname, class, classPath, address, status string, deleted bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var deletedAt interface{}
	if deleted {
		deletedAt = time.Now().UTC()
	}
	if err := f.db.QueryRow(`
		INSERT INTO assets (tenant_id, class_key, class_path, hostname, display_name, primary_address, asset_status, deleted_at)
		VALUES ($1, $2, $3, $4, $4, $5::inet, $6, $7)
		RETURNING id`, f.tenant, class, classPath, hostname, address, status, deletedAt).Scan(&id); err != nil {
		t.Fatalf("seed asset %s: %v", hostname, err)
	}
	f.labels[id] = hostname
	return id
}

func (f *parityFixture) endpoint(t *testing.T, asset uuid.UUID, address, fqdn string, port int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var addressArg, fqdnArg interface{}
	if address != "" {
		addressArg = address
	}
	if fqdn != "" {
		fqdnArg = fqdn
	}
	if err := f.db.QueryRow(`
		INSERT INTO asset_endpoints (tenant_id, asset_id, address, fqdn, port, transport, status)
		VALUES ($1, $2, $3::inet, $4, $5, 'tcp', 'active')
		RETURNING id`, f.tenant, asset, addressArg, fqdnArg, port).Scan(&id); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	return id
}

type cryptoRow struct {
	protocol    string
	version     string
	cipherSuite string
	kex         string
	sig         string
	sym         string
	hash        string
	rawData     string
	deleted     bool
}

func (f *parityFixture) config(t *testing.T, asset uuid.UUID, endpoint *uuid.UUID, r cryptoRow) {
	t.Helper()
	var id uuid.UUID
	var endpointArg interface{}
	if endpoint != nil {
		endpointArg = *endpoint
	}
	var deletedAt interface{}
	if r.deleted {
		deletedAt = time.Now().UTC()
	}
	if err := f.db.QueryRow(`
		INSERT INTO crypto_implementations_partitioned
			(tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite,
			 key_exchange_algorithm, signature_algorithm, symmetric_encryption, hash_algorithm,
			 raw_data, discovery_method, last_verified_at, deleted_at)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), NULLIF($7,''), NULLIF($8,''),
		        NULLIF($9,''), NULLIF($10,''), NULLIF($11,'')::jsonb, 'active', NOW(), $12)
		RETURNING id`,
		f.tenant, asset, endpointArg, r.protocol, r.version, r.cipherSuite,
		r.kex, r.sig, r.sym, r.hash, r.rawData, deletedAt).Scan(&id); err != nil {
		t.Fatalf("seed configuration %s/%s: %v", r.protocol, r.version, err)
	}
	f.labels[id] = f.labels[asset] + "/" + r.protocol + r.version
}

// fingerprintFor is a deterministic stand-in for a real certificate
// fingerprint: the column is NOT NULL and unique in practice, and the label is
// what the golden names the row by.
func fingerprintFor(label string) string {
	sum := sha256.Sum256([]byte("parity/" + label))
	return hex.EncodeToString(sum[:])
}

type certRow struct {
	label      string
	commonName string
	issuer     string
	keyAlg     string
	sigAlg     string
	keySize    int
	notBefore  time.Time
	notAfter   time.Time
	selfSigned bool
	isCA       bool
}

func (f *parityFixture) certificate(t *testing.T, r certRow) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var keyAlg, sigAlg interface{}
	var keySize interface{}
	if r.keyAlg != "" {
		keyAlg = r.keyAlg
	}
	if r.sigAlg != "" {
		sigAlg = r.sigAlg
	}
	if r.keySize != 0 {
		keySize = r.keySize
	}
	if err := f.db.QueryRow(`
		INSERT INTO certificates (tenant_id, subject_dn, issuer_dn, common_name, signature_algorithm,
			public_key_algorithm, public_key_size, not_before, not_after, fingerprint_sha256,
			is_self_signed, is_ca_certificate)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id`,
		f.tenant, "CN="+r.commonName, r.issuer, r.commonName, sigAlg, keyAlg, keySize,
		r.notBefore, r.notAfter, fingerprintFor(r.label),
		r.selfSigned, r.isCA).Scan(&id); err != nil {
		t.Fatalf("seed certificate %s: %v", r.label, err)
	}
	f.labels[id] = r.label
	return id
}

// normalized renders one measurement as a comparable line: the subject by its
// fixture label, the value with its Go type (so an int that became a float is a
// difference), and every evidence key sorted.
func (f *parityFixture) normalized(code string, m MeasurementValue) string {
	label, ok := f.labels[m.SubjectID]
	if !ok {
		label = "UNKNOWN:" + m.SubjectID.String()
	}
	keys := make([]string, 0, len(m.Metadata))
	for k := range m.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := m.Metadata[k]
		if ts, isTime := v.(time.Time); isTime {
			// A timestamp in the evidence is a real column (not_after), and the
			// fixture seeded it as an offset from f.now. Render the OFFSET, not
			// the instant: the instant is right for one day and the offset is
			// right forever. Rounded to the hour, because the fixture's offsets
			// are whole hours and seeding itself takes milliseconds.
			parts = append(parts, fmt.Sprintf("%s=%+dh", k, int(ts.UTC().Sub(f.now).Round(time.Hour)/time.Hour)))
			continue
		}
		if ids, isList := v.([]string); isList {
			// crypto_implementation_ids carries per-run row ids. The golden
			// names the configurations the fixture seeded, so the file stays
			// meaningful and stable; a set the executor got wrong still shows.
			labelled := make([]string, 0, len(ids))
			for _, id := range ids {
				parsed, err := uuid.Parse(id)
				if err != nil {
					labelled = append(labelled, id)
					continue
				}
				if label, known := f.labels[parsed]; known {
					labelled = append(labelled, label)
					continue
				}
				labelled = append(labelled, "UNKNOWN:"+id)
			}
			sort.Strings(labelled)
			parts = append(parts, fmt.Sprintf("%s=[%s]", k, strings.Join(labelled, ",")))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v(%T)", k, v, v))
	}
	return fmt.Sprintf("%s | %s | %v(%T) | %s | %s",
		code, label, m.Value, m.Value, m.SubjectType, strings.Join(parts, " "))
}

// TestIntegration_MeasurementParity_MatchesGolden is the parity gate's
// successor. The golden file was recorded by the run above, while the oracle
// still existed; from then on it is what a change to a shape, a transform or a
// predicate is measured against.
//
// Regenerate deliberately, never reflexively:
//
//	TEST_DATABASE_URL=… go test ./internal/services -run MeasurementParity_MatchesGolden -update-parity-golden
//
// and read the diff — every line of it is a behaviour change to a compliance
// measurement that a customer's score depends on.
func TestIntegration_MeasurementParity_MatchesGolden(t *testing.T) {
	f := newParityFixture(t)
	registry := NewMeasurementExtractor(f.db)

	out := map[string][]string{}
	for _, code := range legacyMeasurementCodes {
		values, err := registry.ExtractMeasurements(f.tenant, code)
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		lines := make([]string, 0, len(values))
		for _, v := range values {
			lines = append(lines, f.normalized(code, v))
		}
		sort.Strings(lines)
		out[code] = lines
	}

	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	path := filepath.Join("testdata", "measurement_parity_golden.json")
	if *updateParityGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("parity golden rewritten")
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (record it with -update-parity-golden)", err)
	}
	if string(want) != string(encoded) {
		t.Errorf("measurements differ from the recorded parity golden.\n--- want\n%s\n--- got\n%s",
			string(want), string(encoded))
	}
}
