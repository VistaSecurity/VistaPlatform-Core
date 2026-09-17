package producers

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CryptoProducer_StrengthReassessmentAndRollup(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()
	cfg := f.configuration(t, "TLS 1.3", 90)
	high := f.linkAlgorithm(t, cfg, "protocol_version", "HIGH-"+uuid.NewString(), 90, "other", false)
	low := f.linkAlgorithm(t, cfg, "hash", "LOW-"+uuid.NewString(), 1, "hash", false)
	exec(t, f.owner, `UPDATE algorithms SET strength='recommended' WHERE id=$1`, high)
	// Inferred links participate just like directly resolved and offered components.
	exec(t, f.owner, `UPDATE crypto_implementation_algorithms SET is_inferred=true WHERE algorithm_id=$1`, low)
	var findingID uuid.UUID
	for _, stage := range []struct {
		strength, word string
		active         bool
		score          int
	}{
		{"weak", "uses weak cryptography", true, 90},
		{"acceptable", "uses an algorithm rated acceptable", true, 90},
		{"strong", "", false, 0},
		{"recommended", "", false, 0},
	} {
		exec(t, f.owner, `UPDATE algorithms SET strength=$1 WHERE id=$2`, stage.strength, low)
		f.mustRun(t, ctx)
		testdb.WithSchemaShareLock(t, f.owner, func() {
			err := database.WithTenantTx(ctx, f.app, f.tenant, func(tx *sql.Tx) error { _, err := riskrollup.Recompute(ctx, tx, f.tenant, uuid.Nil); return err })
			if err != nil {
				t.Fatal(err)
			}
		})
		var id uuid.UUID
		var state, summary string
		var score, assetScore int
		var covered bool
		var evidence []byte
		if err := f.owner.QueryRow(`SELECT id,detection_state,summary,score,evidence FROM findings WHERE tenant_id=$1 AND kind='weak_configuration' AND subject_id=$2`, f.tenant, cfg).Scan(&id, &state, &summary, &score, &evidence); err != nil {
			t.Fatal(err)
		}
		if findingID == uuid.Nil {
			findingID = id
		}
		if id != findingID {
			t.Fatal("reassessment replaced finding identity")
		}
		if (state == "ACTIVE") != stage.active || (stage.active && !strings.Contains(summary, stage.word)) {
			t.Fatalf("stage %s: %s / %s", stage.strength, state, summary)
		}
		if stage.active && score != 90 {
			t.Fatalf("score=%d", score)
		}
		if stage.active && strings.Contains(summary, "HIGH-") {
			t.Fatalf("score winner controlled title: %s", summary)
		}
		if stage.active && !strings.Contains(string(evidence), `"is_inferred": true`) {
			t.Fatal("lost inferred role evidence")
		}
		if err := f.owner.QueryRow(`SELECT risk_score, 'crypto'=ANY(risk_assessed_by) FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, f.assetID).Scan(&assetScore, &covered); err != nil {
			t.Fatal(err)
		}
		if assetScore != stage.score || !covered {
			t.Fatalf("rollup=%d covered=%v", assetScore, covered)
		}
	}
	var history int
	if err := f.owner.QueryRow(`SELECT count(*) FROM compliance_finding_history WHERE finding_id=$1`, findingID).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if history != 2 {
		t.Fatalf("history=%d want initial detection and one sweep", history)
	}
	// Configuration numeric rating is preserved even after its false weak finding is swept.
	var stored int
	if err := f.owner.QueryRow(`SELECT risk_score FROM crypto_implementations WHERE id=$1`, cfg).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 90 {
		t.Fatalf("stored score changed to %d", stored)
	}
}

func TestIntegration_CryptoProducer_IncompleteStoredEvidenceRetained(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()
	cfg := f.configuration(t, "TLS 1.3", 90)
	alg := f.linkAlgorithm(t, cfg, "protocol_version", "GAP-"+uuid.NewString(), 10, "other", false)
	f.mustRun(t, ctx) // explicit weak catalogue judgment
	exec(t, f.owner, `UPDATE algorithms SET strength='recommended' WHERE id=$1`, alg)
	f.mustRun(t, ctx) // opaque stored 90 cannot establish a key-size/hash result
	var state, summary string
	var score int
	var evidence []byte
	if err := f.owner.QueryRow(`SELECT detection_state,summary,score,evidence FROM findings WHERE tenant_id=$1 AND kind='weak_configuration' AND subject_id=$2`, f.tenant, cfg).Scan(&state, &summary, &score, &evidence); err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	if err := json.Unmarshal(evidence, &ev); err != nil {
		t.Fatal(err)
	}
	if state != "ACTIVE" || score != 90 || !strings.Contains(summary, "requires cryptographic reassessment") || ev["reassessment_required"] != true {
		t.Fatalf("%s %s %d %s", state, summary, score, evidence)
	}
	// No prior finding: the same opaque score is not proof of weakness.
	cfg2 := f.configuration(t, "TLS 1.3", 90)
	alg2 := f.linkAlgorithm(t, cfg2, "protocol_version", "GAP2-"+uuid.NewString(), 10, "other", false)
	exec(t, f.owner, `UPDATE algorithms SET strength='recommended' WHERE id=$1`, alg2)
	f.mustRun(t, ctx)
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1 AND subject_id=$2`, f.tenant, cfg2).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("invented %d findings from opaque stored score", n)
	}
	// A persisted size failure independently justifies a weak title despite strong catalogue rows.
	exec(t, f.owner, `UPDATE crypto_implementations SET key_exchange_algorithm='RSA',key_size=512,hash_algorithm='SHA-256' WHERE id=$1`, cfg)
	f.mustRun(t, ctx)
	if err := f.owner.QueryRow(`SELECT summary,evidence FROM findings WHERE tenant_id=$1 AND kind='weak_configuration' AND subject_id=$2`, f.tenant, cfg).Scan(&summary, &evidence); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "uses weak cryptography") || !strings.Contains(string(evidence), `"rule": "key_size"`) {
		t.Fatalf("lost size-rule evidence: %s %s", summary, evidence)
	}
}

func TestIntegration_CryptoProducer_CertificateStrengthSweep(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()
	cfg := f.configuration(t, "", 0)
	code := "CERT-" + uuid.NewString()
	alg := f.linkAlgorithm(t, cfg, "signature", code, 0, "signature", false)
	certID := uuid.New()
	exec(t, f.owner, `INSERT INTO certificates(id,tenant_id,subject_dn,issuer_dn,common_name,public_key_algorithm,public_key_size,signature_algorithm,fingerprint_sha256) VALUES($1,$2,'CN=test','CN=CA','test',$3,3072,$3,$4)`, certID, f.tenant, code, fingerprint())
	exec(t, f.owner, `INSERT INTO crypto_implementation_certificates(crypto_implementation_id,certificate_id,certificate_role) VALUES($1,$2,'leaf')`, cfg, certID)
	for _, stage := range []struct{ strength, word, state string }{
		{"weak", "uses weak cryptography", "ACTIVE"},
		{"acceptable", "uses an algorithm rated acceptable", "ACTIVE"},
		{"recommended", "", "INACTIVE"},
	} {
		exec(t, f.owner, `UPDATE algorithms SET strength=$1 WHERE id=$2`, stage.strength, alg)
		f.mustRun(t, ctx)
		var state, summary, severity string
		var score int
		if err := f.owner.QueryRow(`SELECT detection_state,summary,severity,score FROM findings WHERE tenant_id=$1 AND kind='weak_certificate' AND subject_id=$2`, f.tenant, certID).Scan(&state, &summary, &severity, &score); err != nil {
			t.Fatal(err)
		}
		if state != stage.state || !strings.Contains(summary, stage.word) || score != 0 || severity != "info" {
			t.Fatalf("stage %s: %s %s %s %d", stage.strength, state, summary, severity, score)
		}
	}
}
