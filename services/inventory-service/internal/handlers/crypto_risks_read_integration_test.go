package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"context"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/producers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Exercises the HTTP surface used by useCryptoRisks against actual Postgres,
// including all four read endpoints. No producer has populated findings.
func TestIntegration_CryptoRisks_HTTPJudgmentParity(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	asset := func(owner uuid.UUID, status string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,created_at,updated_at) VALUES($1,$2,$3,'server','hardware.computer.server',$4,NOW(),NOW())`, id, owner, "risk-"+id.String(), status)
		return id
	}
	host := asset(tenant, "monitoring")
	add := func(owner, host uuid.UUID, strength string, score *int) uuid.UUID {
		ci, alg := uuid.New(), uuid.New()
		exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,protocol_version,discovery_method,risk_score,created_at,updated_at) VALUES($1,$2,$3,'TLS','TLS1.0','passive',0,NOW(),NOW())`, ci, owner, host)
		exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'read test','symmetric',$3,$4)`, alg, "READ-"+alg.String(), strength, 0)
		exec(`UPDATE algorithms SET risk_score=$2 WHERE id=$1`, alg, score)
		exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'protocol_version')`, ci, alg)
		t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, alg) })
		return ci
	}
	expected := map[uuid.UUID]string{}
	for _, tc := range []struct {
		score int
		band  string
	}{{90, "critical"}, {70, "high"}, {40, "medium"}, {1, "low"}, {0, "info"}} {
		expected[add(tenant, host, "weak", &tc.score)] = tc.band
	}
	zero, ninety := 0, 90
	acceptable := add(tenant, host, "acceptable", &zero)
	expected[acceptable] = "info"
	unknown := add(tenant, asset(tenant, "monitoring"), "weak", nil)
	expected[unknown] = ""
	strong := add(tenant, host, "strong", &ninety)
	recommended := add(tenant, host, "recommended", &ninety)
	pending := add(tenant, asset(tenant, "pending_approval"), "weak", &ninety)
	archived := add(tenant, asset(tenant, "archived"), "weak", &ninety)
	foreign := add(other, asset(other, "monitoring"), "weak", &ninety)
	// Numeric winner is not necessarily the qualitative reason.
	alg := uuid.New()
	exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'weak zero component','hash','weak',0)`, alg, "WEAK-ZERO-"+alg.String())
	exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'hash')`, strong, alg)
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, alg) })
	expected[strong] = "critical"
	mixed := add(tenant, host, "acceptable", &zero)
	exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'hash')`, mixed, alg)
	expected[mixed] = "info"

	// Future expiry is a separate named policy, without a numeric floor.
	cert := uuid.New()
	expiry := time.Now().Add(10 * 24 * time.Hour)
	exec(`INSERT INTO certificates(id,tenant_id,subject_dn,issuer_dn,fingerprint_sha256,not_after) VALUES($1,$2,'CN=lifecycle','CN=lifecycle',$3,$4)`, cert, tenant, strings.ReplaceAll(cert.String(), "-", "")+strings.ReplaceAll(cert.String(), "-", ""), expiry)
	exec(`INSERT INTO crypto_implementation_certificates(crypto_implementation_id,certificate_id,certificate_role) VALUES($1,$2,'leaf')`, recommended, cert)
	expected[recommended] = "medium"
	endpoint := uuid.New()
	exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport) VALUES($1,$2,$3,'192.0.2.4',443,'tcp')`, endpoint, tenant, host)
	exec(`UPDATE crypto_implementations SET endpoint_id=$1 WHERE id=$2`, endpoint, recommended)

	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := services.NewCryptoRisksService(db)
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	h := NewCryptoRisksHandlers(svc)
	engine.GET("/crypto-risks", h.ListRisks)
	engine.GET("/crypto-risks/summary", h.GetSummary)
	engine.GET("/crypto-risks/export", h.ExportRisks)
	engine.GET("/crypto-risks/:id", h.GetRisk)
	get := func(path string, status int) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	schema := loadSpec(t)
	seen := map[uuid.UUID]bool{}
	for page := 1; page <= 5; page++ {
		var response services.CryptoRisksResponse
		body := get(fmt.Sprintf("/crypto-risks?page=%d&page_size=2", page), 200)
		schema.assertConforms(t, "CryptoRisksResponse", body)
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != len(expected) {
			t.Fatalf("total=%d want%d", response.Total, len(expected))
		}
		for _, r := range response.Risks {
			if seen[r.ID] {
				t.Fatalf("duplicate across pages %s", r.ID)
			}
			seen[r.ID] = true
			band, ok := expected[r.ID]
			if !ok {
				t.Fatalf("unexpected row %+v", r)
			}
			if r.ID != r.CryptoImplementationID || r.Severity == nil && band != "" || r.Severity != nil && *r.Severity != band {
				t.Fatalf("row contract %+v band %q", r, band)
			}
			var detail services.CryptoRisk
			if err := json.Unmarshal(get("/crypto-risks/"+r.ID.String(), 200), &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Description != r.Description || detail.IssueType != r.IssueType {
				t.Fatalf("detail/list disagree: %+v %+v", detail, r)
			}
			if r.ID == unknown && (r.RiskScore != nil || len(r.AssessmentLimitations) == 0) {
				t.Fatalf("fabricated unknown: %+v", r)
			}
			if r.ID == mixed && (r.IssueType != "weak_hash" || r.Category != "algorithm") {
				t.Fatalf("acceptable representative hid weakness: %+v", r)
			}
			if r.ID == acceptable && !strings.Contains(r.Description, "rated acceptable") {
				t.Fatalf("dishonest acceptable: %+v", r)
			}
			if r.ID == strong && strings.Contains(r.Description, "READ-") {
				t.Fatalf("numeric winner justified weakness: %+v", r)
			}
			if r.ID == recommended && (r.AssessmentBasis != "certificate_lifecycle" || r.RiskScore == nil || *r.RiskScore != 90) {
				t.Fatalf("lifecycle invented score: %+v", r)
			}
		}
	}
	if len(seen) != len(expected) {
		t.Fatalf("page coverage=%d want%d", len(seen), len(expected))
	}
	for _, id := range []uuid.UUID{pending, archived, foreign, uuid.New()} {
		get("/crypto-risks/"+id.String(), 404)
	}
	for _, filter := range []string{"info", "informational", "low", "unscored"} {
		var response services.CryptoRisksResponse
		_ = json.Unmarshal(get("/crypto-risks?severity="+filter, 200), &response)
		want := 1
		if filter == "info" || filter == "informational" {
			want = 3
		}
		if response.Total != want {
			t.Fatalf("filter %s total=%d want%d", filter, response.Total, want)
		}
	}
	var certificates services.CryptoRisksResponse
	_ = json.Unmarshal(get("/crypto-risks?category=certificate", 200), &certificates)
	if certificates.Total != 1 || certificates.Risks[0].ID != recommended {
		t.Fatalf("certificate facet: %+v", certificates)
	}
	var summary services.CryptoRisksSummary
	_ = json.Unmarshal(get("/crypto-risks/summary", 200), &summary)
	if summary.Critical != 1 || summary.Unscored != 1 || summary.TotalAffected != 2 || summary.High+summary.Medium+summary.Low+summary.Informational != 0 {
		t.Fatalf("asset worst-band summary %+v", summary)
	}
	records, err := csv.NewReader(strings.NewReader(string(get("/crypto-risks/export", 200)))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(expected)+1 {
		t.Fatalf("export rows=%d want%d", len(records), len(expected)+1)
	}
	for _, row := range records[1:] {
		id, err := uuid.Parse(row[0])
		if err != nil {
			t.Fatal(err)
		}
		if id == unknown && (row[13] != "" || row[16] == "") {
			t.Fatalf("CSV dropped null/limitations: %v", row)
		}
		if band, ok := expected[id]; !ok || row[1] != band {
			t.Fatalf("CSV wrong %v", row)
		}
	}
	var giant services.CryptoRisksResponse
	_ = json.Unmarshal(get("/crypto-risks?page=9223372036854775807&page_size=100", 200), &giant)
	if len(giant.Risks) != 0 || giant.Total != len(expected) {
		t.Fatalf("overflow page: %+v", giant)
	}

	var findings int
	if err := raw.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1`, tenant).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 0 {
		t.Fatalf("GET mutated findings: %d", findings)
	}
	// Missing evidence alone cannot invent a row, but an actual active historical
	// finding survives until complete current facts can disprove it.
	retained := add(tenant, host, "strong", &ninety)
	get("/crypto-risks/"+retained.String(), 404)
	exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence)
 VALUES($1,'crypto','weak_configuration','crypto_configuration',$2,'high',70,'historical weak size','{}')`, tenant, retained)
	exec(`UPDATE crypto_implementations SET key_exchange_algorithm='RSA',key_size=NULL WHERE id=$1`, retained)
	var history services.CryptoRisk
	_ = json.Unmarshal(get("/crypto-risks/"+retained.String(), 200), &history)
	if history.AssessmentBasis != "retained_finding" || history.Severity == nil || *history.Severity != "high" || len(history.AssessmentLimitations) == 0 {
		t.Fatalf("historical gap dropped/invented: %+v", history)
	}
	exec(`INSERT INTO crypto_implementation_certificates(crypto_implementation_id,certificate_id,certificate_role) VALUES($1,$2,'leaf')`, retained, cert)
	_ = json.Unmarshal(get("/crypto-risks/"+retained.String(), 200), &history)
	if history.Severity == nil || *history.Severity != "high" || !strings.Contains(history.Description, "lifecycle policy") {
		t.Fatalf("lifecycle hid retained risk: %+v", history)
	}
	exec(`DELETE FROM crypto_implementation_certificates WHERE crypto_implementation_id=$1`, retained)
	exec(`UPDATE crypto_implementations SET key_exchange_algorithm=NULL,key_size=NULL WHERE id=$1`, retained)
	get("/crypto-risks/"+retained.String(), 200)
	producer, err := producers.NewCryptoProducer(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Run(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	get("/crypto-risks/"+retained.String(), 200)
	var state string
	if err := raw.QueryRow(`SELECT detection_state FROM findings WHERE tenant_id=$1 AND subject_id=$2 AND kind='weak_configuration'`, tenant, retained).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ACTIVE" {
		t.Fatalf("producer swept missing historical facts: %s", state)
	}
	// A newly observed weakness cannot erase the older unexplained gap.
	for _, strength := range []string{"weak", "strong"} {
		exec(`UPDATE algorithms SET strength=$2 WHERE id IN (SELECT algorithm_id FROM crypto_implementation_algorithms WHERE crypto_implementation_id=$1)`, retained, strength)
		if _, err := producer.Run(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		get("/crypto-risks/"+retained.String(), 200)
	}
	// Affirmative replacement facts, not deletion, permit reassessment. The
	// catalogue numeric maximum stays 90, higher than the prior stored score 70.
	exec(`UPDATE crypto_implementations SET hash_algorithm='SHA1' WHERE id=$1`, retained)
	if _, err := producer.Run(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"key_exchange", "hash", "signature"} {
		replacement := uuid.New()
		exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'replacement','symmetric','strong',0)`, replacement, "REPLACEMENT-"+replacement.String())
		exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,$3)`, retained, replacement, role)
		t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, replacement) })
	}
	exec(`UPDATE crypto_implementations SET key_exchange_algorithm='RSA',key_size=4096,hash_algorithm=NULL,signature_algorithm='RSA' WHERE id=$1`, retained)
	_ = json.Unmarshal(get("/crypto-risks/"+retained.String(), 200), &history)
	if !strings.Contains(strings.Join(history.AssessmentLimitations, ";"), "prior hash failure") {
		t.Fatalf("new independent hash obligation lost: %+v", history)
	}
	if _, err := producer.Run(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	get("/crypto-risks/"+retained.String(), 200)
	exec(`UPDATE crypto_implementations SET hash_algorithm='SHA256' WHERE id=$1`, retained)
	get("/crypto-risks/"+retained.String(), 404)
	if _, err := producer.Run(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT detection_state FROM findings WHERE tenant_id=$1 AND subject_id=$2 AND kind='weak_configuration'`, tenant, retained).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "INACTIVE" {
		t.Fatalf("producer retained complete replacement facts: %s", state)
	}

	moved := asset(tenant, "monitoring")
	exec(`UPDATE asset_endpoints SET asset_id=$1 WHERE id=$2`, moved, endpoint)
	var movedRisk services.CryptoRisk
	_ = json.Unmarshal(get("/crypto-risks/"+recommended.String(), 200), &movedRisk)
	if movedRisk.AssetID != moved || movedRisk.EndpointID == nil || *movedRisk.EndpointID != endpoint || movedRisk.EndpointAddress == nil || *movedRisk.EndpointAddress != "192.0.2.4" {
		t.Fatalf("stale endpoint owner: %+v", movedRisk)
	}

	// A fresh explicit weak zero cannot downgrade an unrefuted older size rule.
	downgrade := add(tenant, host, "weak", &zero)
	exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence)
 VALUES($1,'crypto','weak_configuration','crypto_configuration',$2,'high',70,'previous RSA size failure','{"rule_failures":[{"rule":"key_size","algorithm":"RSA","bits":1024,"score":70}]}')`, tenant, downgrade)
	for _, complete := range []bool{false, true} {
		want := 70
		if complete {
			want = 0
			key := uuid.New()
			exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'resolved key','key_exchange','strong',0)`, key, "KEY-"+key.String())
			exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,'key_exchange')`, downgrade, key)
			t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, key) })
			exec(`UPDATE crypto_implementations SET key_exchange_algorithm='RSA',key_size=4096 WHERE id=$1`, downgrade)
		}
		var assessed services.CryptoRisk
		_ = json.Unmarshal(get("/crypto-risks/"+downgrade.String(), 200), &assessed)
		if assessed.RiskScore == nil || *assessed.RiskScore != want {
			t.Fatalf("complete=%v GET numeric contribution lost: %+v", complete, assessed)
		}
		if !complete && (assessed.AssessmentBasis != "retained_finding" || !strings.Contains(strings.Join(assessed.ScoreSources, ";"), "retained prior")) {
			t.Fatalf("retained provenance lost: %+v", assessed)
		}
		if _, err := producer.Run(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		var score int
		if err := raw.QueryRow(`SELECT score FROM findings WHERE tenant_id=$1 AND subject_id=$2 AND kind='weak_configuration' AND detection_state='ACTIVE'`, tenant, downgrade).Scan(&score); err != nil {
			t.Fatal(err)
		}
		if score != want {
			t.Fatalf("complete=%v producer score=%d want%d", complete, score, want)
		}
	}

}
