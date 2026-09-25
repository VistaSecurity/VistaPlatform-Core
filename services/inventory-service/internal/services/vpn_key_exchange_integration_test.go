package services

// End-to-end, as far as one module can reach, for an interrogated VPN tunnel:
// the ingest finding discovery-processor hands over for it must link the
// tunnel's key exchange — every configured DH group, not only the first — to
// the right catalogue rows, and the PQC classifier must then see it.
//
// It could not. The key exchange was dropped between device-interrogation and
// the converter, the DH group was never linked anywhere, and a VPN linking only
// AES and SHA-2 was classified symmetric_safe and counted as quantum-ready.
// The expectations come from cryptoparsetest.VPNKeyExchangeCases, the contract
// the writer's and the converter's tests are held to as well.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse/cryptoparsetest"
)

// vpnFinding builds the ingest finding the pipeline produces for a contract
// case. The key exchange is derived from the collector's DH-group setting with
// the same shared helper the writer uses, so a change to how a group resolves
// shows up here, against the real catalogue, and not only in a unit test.
func vpnFinding(t *testing.T, c cryptoparsetest.VPNKeyExchangeCase) IngestFinding {
	t.Helper()
	kex := c.CollectorKex
	raw := map[string]interface{}{"discovery_method": "device_interrogation"}
	if c.DHGroup != "" || c.PFSGroup != "" {
		ike := cryptoparse.ParseIKEGroups(c.DHGroup)
		codes := cryptoparse.OfferedIKEGroupCodes(ike, cryptoparse.ParseIKEGroups(c.PFSGroup))
		if !reflect.DeepEqual(codes, c.WantOffered) {
			t.Fatalf("dh_group %q / pfs %q resolve to %v, want %v", c.DHGroup, c.PFSGroup, codes, c.WantOffered)
		}
		offered := make([]interface{}, 0, len(codes))
		for _, code := range codes {
			offered = append(offered, code)
		}
		raw["kex_algorithms"] = offered
		if g, ok := cryptoparse.PreferredIKEGroup(ike); ok {
			kex = g.Code
		}
	}
	if kex != c.WantKex {
		t.Fatalf("key exchange = %q, want %q", kex, c.WantKex)
	}
	suite, hash := c.CipherSuite, c.Hash
	f := IngestFinding{
		Protocol:      c.Protocol,
		CipherSuite:   &suite,
		HashAlgorithm: &hash,
		RawData:       raw,
	}
	// Absent stays absent, as the converter hands it over.
	if kex != "" {
		f.KeyExchangeAlgorithm = &kex
	}
	if c.WantKeySize != 0 {
		size := c.WantKeySize
		f.KeySize = &size
	}
	return f
}

func linkedCodes(t *testing.T, svc *AssetService, tenant, asset uuid.UUID, role string) []string {
	t.Helper()
	var codes []string
	if err := svc.db.Select(&codes, `
		SELECT a.code
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		  JOIN crypto_implementations ci ON ci.id = cia.crypto_implementation_id
		 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND cia.algorithm_type = $3
		 ORDER BY a.code`, tenant, asset, role); err != nil {
		t.Fatalf("read %s links: %v", role, err)
	}
	return codes
}

func pqcCategory(t *testing.T, svc *AssetService, tenant uuid.UUID) string {
	t.Helper()
	c, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if c.Total != 1 {
		t.Fatalf("classified %d configurations, want exactly 1: %+v", c.Total, c)
	}
	switch {
	case c.NeedsMigration == 1:
		return cryptoparsetest.PQCNeedsMigration
	case c.PQCReady == 1:
		return cryptoparsetest.PQCReady
	case c.SymmetricSafe == 1:
		return cryptoparsetest.PQCSymmetricSafe
	default:
		return cryptoparsetest.PQCUnclassified
	}
}

func TestIntegration_VPNKeyExchange_LinksEveryGroupAndClassifies(t *testing.T) {
	for _, c := range cryptoparsetest.VPNKeyExchangeCases {
		t.Run(c.Name, func(t *testing.T) {
			svc, tenant, asset := newIngestFixture(t)
			// The production service scores with the weak-crypto detector as
			// well as the catalogue; without it the key-size assertion below
			// could not fail.
			svc.weakCryptoDetector = NewWeakCryptoDetector(nil)
			if err := svc.processDiscoveryCryptoData(tenant, asset, vpnFinding(t, c), nil, nil, nil); err != nil {
				t.Fatalf("processDiscoveryCryptoData: %v", err)
			}

			want := append([]string(nil), c.WantLinkedKex...)
			sort.Strings(want)
			if got := linkedCodes(t, svc, tenant, asset, "key_exchange"); !reflect.DeepEqual(got, want) {
				t.Errorf("key_exchange links = %v, want %v — every configured group must be scored", got, want)
			}
			if got := pqcCategory(t, svc, tenant); got != c.WantPQC {
				t.Errorf("PQC category = %s, want %s", got, c.WantPQC)
			}

			// The stored score is the catalogue's worst linked component and
			// nothing more. In particular the key-size rule must not fire:
			// key_size is the group's key size, so a 2048-bit MODP group is not
			// read as a 256-bit finite-field key (Critical).
			var stored, catalogueWorst int
			if err := svc.db.QueryRow(`
				SELECT COALESCE(ci.risk_score, 0),
				       COALESCE((SELECT MAX(a.risk_score)
				                   FROM crypto_implementation_algorithms cia
				                   JOIN algorithms a ON a.id = cia.algorithm_id
				                  WHERE cia.crypto_implementation_id = ci.id), 0)
				  FROM crypto_implementations ci
				 WHERE ci.tenant_id = $1 AND ci.asset_id = $2`, tenant, asset).Scan(&stored, &catalogueWorst); err != nil {
				t.Fatalf("read risk: %v", err)
			}
			if stored != catalogueWorst {
				t.Errorf("risk_score = %d, want the catalogue's worst linked component (%d) — something outside the catalogue raised it", stored, catalogueWorst)
			}
		})
	}
}

// The bug, reproduced: the same tunnel with its key exchange dropped — what the
// converter used to hand over — links only symmetric components and is
// classified symmetric_safe. If this ever stops holding, the case above no
// longer proves anything about the key exchange.
func TestIntegration_VPNKeyExchange_WithoutItTheTunnelLooksQuantumSafe(t *testing.T) {
	c := cryptoparsetest.VPNKeyExchangeCases[0]
	svc, tenant, asset := newIngestFixture(t)
	f := vpnFinding(t, c)
	f.KeyExchangeAlgorithm = nil
	f.RawData = map[string]interface{}{"discovery_method": "device_interrogation"}
	if err := svc.processDiscoveryCryptoData(tenant, asset, f, nil, nil, nil); err != nil {
		t.Fatalf("processDiscoveryCryptoData: %v", err)
	}
	if got := linkedCodes(t, svc, tenant, asset, "key_exchange"); len(got) != 0 {
		t.Fatalf("control links a key exchange %v; it must not", got)
	}
	if got := pqcCategory(t, svc, tenant); got != cryptoparsetest.PQCSymmetricSafe {
		t.Errorf("control PQC category = %s, want %s (the mis-classification being fixed)", got, cryptoparsetest.PQCSymmetricSafe)
	}
}

// Every group the shared helper names a catalogue code for must BE in the
// catalogue, as a key exchange the PQC denylist can see. A misspelt code would
// otherwise leave the group silently unlinked — the original bug again.
func TestIntegration_VPNKeyExchange_EveryIKEGroupCodeIsCatalogued(t *testing.T) {
	svc, _, _ := newIngestFixture(t)
	for id := 0; id <= 1024; id++ {
		g, ok := cryptoparse.IKEKeyExchangeMethod(id)
		if !ok || g.Code == "" {
			continue
		}
		var category, primitive string
		var isPQC bool
		var risk *int
		err := svc.db.QueryRow(`
			SELECT category, COALESCE(primitive, ''), is_pqc, risk_score
			  FROM algorithms WHERE code = $1`, g.Code).Scan(&category, &primitive, &isPQC, &risk)
		if err != nil {
			t.Errorf("group %d -> %s: not in the catalogue: %v", id, g.Code, err)
			continue
		}
		if category != "key_exchange" {
			t.Errorf("group %d -> %s: category %s, want key_exchange", id, g.Code, category)
		}
		if risk == nil {
			t.Errorf("group %d -> %s: no risk assessment", id, g.Code)
		}
		wantPrimitive, wantPQC := "key-agree", false
		if cryptoparse.KeyAlgorithmFamily(g.Code) == cryptoparse.KexFamilyPostQuantum {
			wantPrimitive, wantPQC = "kem", true
		}
		if primitive != wantPrimitive || isPQC != wantPQC {
			t.Errorf("group %d -> %s: primitive=%q is_pqc=%v, want %q/%v", id, g.Code, primitive, isPQC, wantPrimitive, wantPQC)
		}
	}
}

// Against the REAL catalogue: a name stating only one half of a hybrid must
// not resolve to the hybrid row. "secp384r1" used to match only
// SecP384r1MLKEM1024 and so resolved to it — a classical P-384 exchange read
// as post-quantum ready.
func TestIntegration_HybridRowsAreNotReachedByOneHalf(t *testing.T) {
	svc, _, _ := newIngestFixture(t)
	for _, in := range []string{"secp384r1", "MLKEM1024", "secp256r1", "SECP256R1"} {
		alg, err := svc.algorithmService.ClassifyAlgorithm(in, "key_exchange")
		if err != nil {
			t.Fatalf("ClassifyAlgorithm(%q): %v", in, err)
		}
		if alg != nil && (alg.IsPQC || isHybridKeyExchangeRow(alg)) {
			t.Errorf("ClassifyAlgorithm(%q) = %s (is_pqc=%v) — one half of a hybrid resolved to a post-quantum row", in, alg.Code, alg.IsPQC)
		}
	}
	alg, err := svc.algorithmService.ClassifyAlgorithm("SecP384r1MLKEM1024", "key_exchange")
	if err != nil || alg == nil || alg.Code != "SecP384r1MLKEM1024" {
		t.Errorf("the full hybrid name no longer resolves: %v (err %v)", alg, err)
	}
}

// The hybrid TLS named groups the active probe can negotiate must each have a
// row, as a post-quantum KEM, or a handshake that negotiated one links nothing
// and the endpoint cannot be classified pqc_ready.
func TestIntegration_HybridTLSGroupsAreCatalogued(t *testing.T) {
	svc, _, _ := newIngestFixture(t)
	for _, code := range []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"} {
		var category, primitive string
		var isPQC bool
		if err := svc.db.QueryRow(`
			SELECT category, COALESCE(primitive, ''), is_pqc FROM algorithms WHERE code = $1`, code).Scan(&category, &primitive, &isPQC); err != nil {
			t.Errorf("%s: not in the catalogue: %v", code, err)
			continue
		}
		if category != "key_exchange" || primitive != "kem" || !isPQC {
			t.Errorf("%s: category=%s primitive=%s is_pqc=%v, want key_exchange/kem/true", code, category, primitive, isPQC)
		}
	}
}
