package services

// Coverage guard for the DemoCorp seed dataset.
//
// The seed exists to show the product working. That only holds if the data
// actually reaches every surface — so this ingests the committed findings
// through the real pipeline and asserts each capability has something to show.
// Without it, the dataset silently rots as features land (which is exactly what
// happened to its predecessor: 1 certificate, 0 PQC, and a README claiming
// 80-100 certificates).
//
// Skips without TEST_DATABASE_URL.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_DemoCorpSeed_ShowcasesEveryFeature(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewAssetService(db)
	dir := filepath.Join(testdb.RepoRoot(t), "democorp-seed", "data", "findings")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no findings files under %s (err=%v)", dir, err)
	}

	total := 0
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Findings []IngestFinding `json:"findings"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		if _, err := svc.IngestFindings(tenant, payload.Findings, "monitoring"); err != nil {
			t.Fatalf("%s: ingest: %v", filepath.Base(f), err)
		}
		total += len(payload.Findings)
	}
	t.Logf("submitted %d findings from %d files", total, len(files))

	count := func(q string, args ...interface{}) int {
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}

	type check struct {
		what string
		got  int
		min  int
	}
	checks := []check{
		{"assets", count(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant), 100},
		{"crypto configurations", count(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant), 100},
		{"certificates", count(`SELECT count(*) FROM certificates WHERE tenant_id=$1`, tenant), 50},
		{"cryptographic keys (Keys lens)", count(`SELECT count(*) FROM keys WHERE tenant_id=$1`, tenant), 20},
		{"algorithm links (risk + PQC source)", count(`SELECT count(*) FROM crypto_implementation_algorithms cia JOIN crypto_implementations ci ON ci.id=cia.crypto_implementation_id WHERE ci.tenant_id=$1`, tenant), 200},
		{"expired certificates", count(`SELECT count(*) FROM certificates WHERE tenant_id=$1 AND not_after < NOW()`, tenant), 1},
		{"certs expiring within 60d", count(`SELECT count(*) FROM certificates WHERE tenant_id=$1 AND not_after BETWEEN NOW() AND NOW()+interval '60 days'`, tenant), 1},
		{"self-signed certificates", count(`SELECT count(*) FROM certificates WHERE tenant_id=$1 AND is_self_signed`, tenant), 1},
		{"OT protocol configurations", count(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND protocol IN ('Modbus','DNP3','OPC_UA','S7','EtherNet_IP','BACnet')`, tenant), 10},
	}
	for _, c := range checks {
		if c.got < c.min {
			t.Errorf("%-38s = %d, want >= %d", c.what, c.got, c.min)
		} else {
			t.Logf("%-38s = %d (>= %d)", c.what, c.got, c.min)
		}
	}

	// A shared public key must collapse to ONE key row used by MANY assets.
	var maxDeploy int
	if err := db.QueryRow(`
		SELECT COALESCE(MAX(c),0) FROM (
		  SELECT COUNT(DISTINCT ci.asset_id) c
		  FROM keys k
		  JOIN implementation_keys ik ON ik.key_id = k.id
		  JOIN crypto_implementations ci ON ci.id = ik.implementation_id
		  WHERE k.tenant_id = $1 AND ci.deleted_at IS NULL
		  GROUP BY k.id) s`, tenant).Scan(&maxDeploy); err != nil {
		t.Fatal(err)
	}
	if maxDeploy < 3 {
		t.Errorf("max key deployment_count = %d, want >= 3 — the SPKI-dedup story needs one key on several assets", maxDeploy)
	} else {
		t.Logf("%-38s = %d assets", "busiest key is deployed on", maxDeploy)
	}

	// Risk must be spread, not clustered — otherwise the bands and facets look dead.
	// Use the shared ladder — never hand-write a risk CASE (see models.RiskBands).
	rows, err := db.Query(`
		SELECT `+models.RiskLevelCaseSQL("s")+` AS lvl, count(*)
		FROM (SELECT COALESCE(MAX(ci.risk_score),0) s
		      FROM assets a
		      LEFT JOIN crypto_implementations ci ON ci.asset_id=a.id AND ci.deleted_at IS NULL
		      WHERE a.tenant_id=$1 AND a.deleted_at IS NULL GROUP BY a.id) t
		GROUP BY lvl`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	bands := map[string]int{}
	for rows.Next() {
		var l string
		var n int
		if err := rows.Scan(&l, &n); err != nil {
			t.Fatal(err)
		}
		bands[l] = n
	}
	_ = rows.Close()
	t.Logf("risk distribution: %v", bands)
	for _, want := range []string{"Critical", "High", "Medium", "Low"} {
		if bands[want] == 0 {
			t.Errorf("no assets in the %s risk band — the risk lens/facets would look empty", want)
		}
	}

	// PQC must show all four categories, or the readiness view tells no story.
	c, err := classifyTenantImplementationsPQC(db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PQC: needs=%d ready=%d symmetric=%d unclassified=%d total=%d (%.1f%% ready)",
		c.NeedsMigration, c.PQCReady, c.SymmetricSafe, c.Unclassified, c.Total, c.ReadyPercent())
	if c.PQCReady == 0 {
		t.Error("no PQC-ready configurations — the post-quantum story is invisible")
	}
	if c.NeedsMigration == 0 {
		t.Error("no configurations needing migration — nothing to track")
	}
	if c.ReadyPercent() > 100 {
		t.Errorf("PQC readiness %.1f%% exceeds 100", c.ReadyPercent())
	}

	assertExpiryRunway(t, db, tenant)
}

// expiryWindowDays is the "expiring soon" window the dataset must always have a
// certificate inside — the same 60 days the checks table above counts.
const expiryWindowDays = 60

// minExpiryRunwayDays is how much warning we insist on. The dataset is a
// SNAPSHOT of real X.509 certificates, so its dates cannot be shifted at load
// time and it necessarily decays; the only question is whether we hear about it
// before or after it stops demonstrating the feature.
//
// We heard after, for three weeks: the committed findings stopped having any
// certificate inside the 60-day window on, and the first signal was
// this test going red in the nightly with nothing to say about how to fix it.
const minExpiryRunwayDays = 30

// assertExpiryRunway fails while there is still time to act, rather than on the
// day the dataset stops showing expiring certificates.
//
// Runway is how long the "at least one certificate expires within 60 days"
// property will keep holding as the clock advances: walk the future expiries in
// order, and the property survives exactly as far as the rungs stay within 60
// days of each other. See the certDays ladder in democorp-seed/generator/main.go
// — this is the assertion that ladder exists to satisfy.
func assertExpiryRunway(t *testing.T, db *database.DB, tenant uuid.UUID) {
	t.Helper()
	rows, err := db.Query(`
		SELECT not_after FROM certificates
		WHERE tenant_id = $1 AND not_after >= NOW() ORDER BY not_after`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var future []time.Time
	for rows.Next() {
		var ts time.Time
		if err := rows.Scan(&ts); err != nil {
			t.Fatal(err)
		}
		future = append(future, ts)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	window := time.Duration(expiryWindowDays) * 24 * time.Hour
	now := time.Now()
	reach := now // the property holds for every instant up to `reach`
	for _, e := range future {
		if e.Sub(reach) > window {
			break // gap wider than the window: the story lapses before this rung
		}
		if e.After(reach) {
			reach = e
		}
	}
	runway := reach.Sub(now)

	t.Logf("%-38s = %d days (%d future certificates)",
		"expiring-soon runway", int(runway.Hours()/24), len(future))

	if runway < time.Duration(minExpiryRunwayDays)*24*time.Hour {
		t.Errorf("the dataset stops showing certificates expiring within %dd in %d days "+
			"(want at least %d days of runway) — regenerate it:\n"+
			"    cd democorp-seed/generator && go run . -out ../data/findings\n"+
			"If regenerating does not restore the runway, the certDays ladder in that "+
			"file has developed a gap wider than %dd; see the comment above `profiles`.",
			expiryWindowDays, int(runway.Hours()/24), minExpiryRunwayDays, expiryWindowDays)
	}
}
