package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// judgmentFixture is a varied, deterministic estate: scored and unscored
// catalogue components, key-size and hash rule failures, retained prior
// findings, expiring certificates, endpoints with their own addresses, assets
// that are unnamed, unmonitored or soft-deleted.
type judgmentFixture struct {
	t       *testing.T
	raw     *sql.DB
	svc     *CryptoRisksService
	tenant  uuid.UUID
	configs []uuid.UUID
	algs    []uuid.UUID
	assets  []uuid.UUID
}

func newJudgmentFixture(t *testing.T, n int) *judgmentFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	f := &judgmentFixture{t: t, raw: raw, tenant: tenant, svc: NewCryptoRisksService(db)}
	// The judgement table has no foreign key to the tenant, so clean it by hand.
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM crypto_risk_judgments WHERE tenant_id=$1`, tenant) })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("%v: %s", err, q)
		}
	}
	rng := rand.New(rand.NewSource(2451))

	type asset struct {
		host   any
		addr   any
		status string
		del    bool
	}
	assets := []asset{
		{"Alpha.Example", "10.0.0.1", "monitoring", false}, {"beta.example", "10.0.0.2", "monitoring", false},
		{nil, "10.0.0.3", "monitoring", false}, {"gamma-tls", nil, "monitoring", false},
		{"pending.example", "10.0.0.5", "pending_approval", false}, {"gone.example", "10.0.0.6", "monitoring", true},
		{"Zed_host", "192.0.2.77", "monitoring", false},
	}
	for i := 0; i < 30; i++ {
		assets = append(assets, asset{fmt.Sprintf("bulk-%02d.example", i), fmt.Sprintf("10.9.0.%d", i), "monitoring", false})
	}
	for _, a := range assets {
		id := uuid.New()
		deleted := any(nil)
		if a.del {
			deleted = time.Now()
		}
		exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,deleted_at) VALUES($1,$2,$3,$4,'server','hardware.computer.server',$5,$6)`,
			id, tenant, a.host, a.addr, a.status, deleted)
		f.assets = append(f.assets, id)
	}
	for _, spec := range []struct {
		strength string
		score    int
	}{{"weak", 95}, {"weak", 0}, {"acceptable", 45}, {"strong", 20}, {"recommended", 75}, {"weak", 75}, {"strong", 0}} {
		id := uuid.New()
		exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'fixture','symmetric',$3,$4)`,
			id, "JDG-"+id.String(), spec.strength, spec.score)
		t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, id) })
		f.algs = append(f.algs, id)
	}
	// One catalogue row with no numeric assessment at all.
	nullAlg := uuid.New()
	exec(`INSERT INTO algorithms(id,code,name,category,strength,risk_score) VALUES($1,$2,'fixture','symmetric','weak',1)`, nullAlg, "JDG-"+nullAlg.String())
	exec(`UPDATE algorithms SET risk_score=NULL WHERE id=$1`, nullAlg)
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE id=$1`, nullAlg) })
	f.algs = append(f.algs, nullAlg)

	var certs []uuid.UUID
	for _, days := range []float64{10.5, 61.3, 200.2, -5.2} {
		id := uuid.New()
		exec(`INSERT INTO certificates(id,tenant_id,subject_dn,issuer_dn,fingerprint_sha256,not_after) VALUES($1,$2,'CN=j','CN=j',$3,$4)`,
			id, tenant, strings.Repeat(strings.ReplaceAll(id.String(), "-", ""), 2), time.Now().Add(time.Duration(days*24)*time.Hour))
		certs = append(certs, id)
	}
	protocols := []string{"TLS", "TLS", "TLS", "SSH", "IPSec", "VPN"}
	suites := []string{"TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-SHA", "DES-CBC3-SHA", "RC4-MD5", "", "aes256-ctr"}
	kex := []any{nil, "RSA", "ECDHE", "DH"}
	sizes := []any{nil, 1024, 2048, 256}
	hashes := []any{nil, "MD5", "SHA256", "SHA1"}
	roles := []string{"symmetric", "hash", "key_exchange", "signature", "protocol_version", "cipher_suite"}
	for i := 0; i < n; i++ {
		id := uuid.New()
		asset := f.assets[rng.Intn(len(f.assets))]
		var endpoint any
		if rng.Intn(2) == 0 {
			ep := uuid.New()
			exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port) VALUES($1,$2,$3,$4,$5)`, ep, tenant, asset, fmt.Sprintf("198.51.100.%d", i%250), 443+i%5)
			endpoint = ep
		}
		exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,endpoint_id,protocol,protocol_version,cipher_suite,key_exchange_algorithm,key_size,hash_algorithm,discovery_method,risk_score,created_at)
 VALUES($1,$2,$3,$4,$5::protocol_type,$6,$7,$8,$9,$10,'passive',$11,$12)`,
			id, tenant, asset, endpoint, protocols[rng.Intn(len(protocols))], []any{nil, "1.0", "1.2", "1.3"}[rng.Intn(4)],
			suites[rng.Intn(len(suites))], kex[rng.Intn(len(kex))], sizes[rng.Intn(len(sizes))], hashes[rng.Intn(len(hashes))],
			[]int{0, 0, 50, 85}[rng.Intn(4)], time.Now().Add(-time.Duration(rng.Intn(1000))*time.Minute))
		for _, r := range rng.Perm(len(roles))[:rng.Intn(4)] {
			exec(`INSERT INTO crypto_implementation_algorithms(crypto_implementation_id,algorithm_id,algorithm_type) VALUES($1,$2,$3)`,
				id, f.algs[rng.Intn(len(f.algs))], roles[r])
		}
		if rng.Intn(4) == 0 {
			exec(`INSERT INTO crypto_implementation_certificates(crypto_implementation_id,certificate_id,certificate_role) VALUES($1,$2,'leaf')`, id, certs[rng.Intn(len(certs))])
		}
		if rng.Intn(6) == 0 {
			exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence)
 VALUES($1,'crypto','weak_configuration','crypto_configuration',$2,'high',70,'prior weak size','{}')`, tenant, id)
		}
		if rng.Intn(15) == 0 {
			exec(`UPDATE crypto_implementations SET deleted_at=now() WHERE id=$1`, id)
		}
		f.configs = append(f.configs, id)
	}
	return f
}

func (f *judgmentFixture) ex(q string, args ...any) {
	f.t.Helper()
	if _, err := f.raw.Exec(q, args...); err != nil {
		f.t.Fatalf("%v: %s", err, q)
	}
}

func (f *judgmentFixture) rawDB() *sql.DB { return f.raw }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestIntegration_CryptoRiskJudgments_ReadersEqualTheGoJudge diffs the persisted
// readers against the previous in-memory implementation (the oracle), over every
// sort, filter, search and page shape.
func TestIntegration_CryptoRiskJudgments_ReadersEqualTheGoJudge(t *testing.T) {
	f := newJudgmentFixture(t, 90)
	filters := []CryptoRiskFilters{{}}
	for _, sortBy := range []string{"", "severity", "hostname", "protocol", "detected_at", "bogus"} {
		for _, order := range []string{"", "asc", "DESC"} {
			filters = append(filters, CryptoRiskFilters{SortBy: sortBy, SortOrder: order})
		}
	}
	for _, sev := range [][]string{{"critical"}, {"high", "medium"}, {"low"}, {"informational"}, {"info", "unscored"}, {"unscored"}, {"nonsense"}} {
		filters = append(filters, CryptoRiskFilters{Severity: sev}, CryptoRiskFilters{Severity: sev, SortBy: "hostname", SortOrder: "asc"})
	}
	for _, cat := range [][]string{{"protocol"}, {"algorithm"}, {"KEY_SIZE"}, {"certificate"}, {"protocol", "certificate"}} {
		filters = append(filters, CryptoRiskFilters{Category: cat, PageSize: 7, Page: 2})
	}
	for _, search := range []string{"alpha", "%", "10.0.0", "198.51.100.1", "tls", "ssh", "ipsec", "des-cbc", "zzz-no-match", "_", "gamma"} {
		filters = append(filters, CryptoRiskFilters{Search: search}, CryptoRiskFilters{Search: search, SortBy: "protocol", SortOrder: "asc", PageSize: 5})
	}
	for _, p := range []int{1, 2, 3, 100, 9223372036854775807} {
		for _, size := range []int{0, 7, 500} {
			filters = append(filters, CryptoRiskFilters{Page: p, PageSize: size})
		}
	}
	nonEmpty := 0
	for _, flt := range filters {
		want, err := f.svc.legacyListRisks(f.tenant, flt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.svc.ListRisks(f.tenant, flt)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := mustJSON(t, want), mustJSON(t, got); a != b {
			t.Fatalf("ListRisks(%+v) diverges from the Go judge\nwant %s\n got %s", flt, a, b)
		}
		if len(want.Risks) > 0 {
			nonEmpty++
		}
		wantExport, err := f.svc.legacyExportRisks(f.tenant, flt)
		if err != nil {
			t.Fatal(err)
		}
		gotExport, err := f.svc.ExportRisks(f.tenant, flt)
		if err != nil {
			t.Fatal(err)
		}
		if len(wantExport) == 0 && len(gotExport) == 0 {
			continue
		}
		if a, b := mustJSON(t, wantExport), mustJSON(t, gotExport); a != b {
			t.Fatalf("ExportRisks(%+v) diverges\nwant %s\n got %s", flt, a, b)
		}
	}
	if nonEmpty < 40 {
		t.Fatalf("fixture too thin: only %d of %d filter shapes returned rows", nonEmpty, len(filters))
	}
	wantSummary, err := f.svc.legacyGetSummary(f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	gotSummary, err := f.svc.GetSummary(f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := mustJSON(t, wantSummary), mustJSON(t, gotSummary); a != b {
		t.Fatalf("GetSummary diverges\nwant %s\n got %s", a, b)
	}
	spread := map[string]int{}
	all, _ := f.svc.legacyExportRisks(f.tenant, CryptoRiskFilters{})
	for _, r := range all {
		if r.Severity == nil {
			spread["unscored"]++
		} else {
			spread[*r.Severity]++
		}
	}
	t.Logf("fixture feed severities: %v", spread)
	t.Logf("fixture summary: %+v", wantSummary)
	if wantSummary.TotalAffected < 3 {
		t.Fatalf("summary fixture too thin: %+v", wantSummary)
	}
	// By id: every configuration, visible or not.
	for _, id := range f.configs {
		want, wantErr := f.svc.legacyGetRiskByID(f.tenant, id)
		got, gotErr := f.svc.GetRiskByID(f.tenant, id)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("GetRiskByID(%s) error mismatch: want %v got %v", id, wantErr, gotErr)
		}
		if wantErr == nil && mustJSON(t, want) != mustJSON(t, got) {
			t.Fatalf("GetRiskByID(%s) diverges\nwant %s\n got %s", id, mustJSON(t, want), mustJSON(t, got))
		}
	}
}

// TestIntegration_CryptoRiskJudgments_ReadsJudgeNothingWhenWarm proves the point
// of persisting: after the first read, repeated reads judge zero configurations,
// and a change to one configuration re-judges exactly that one.
func TestIntegration_CryptoRiskJudgments_ReadsJudgeNothingWhenWarm(t *testing.T) {
	f := newJudgmentFixture(t, 40)
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	before := judgedConfigurations.Load()
	for i := 0; i < 3; i++ {
		if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{Page: 2, PageSize: 5, Search: "tls"}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.GetSummary(f.tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.ExportRisks(f.tenant, CryptoRiskFilters{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := judgedConfigurations.Load() - before; n != 0 {
		t.Fatalf("warm reads judged %d configurations; want 0", n)
	}
	f.ex(`UPDATE crypto_implementations SET key_size=512, key_exchange_algorithm='RSA' WHERE id=$1`, f.configs[0])
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	if n := judgedConfigurations.Load() - before; n != 1 {
		t.Fatalf("one changed configuration re-judged %d rows; want 1", n)
	}
	// Touching only observation timestamps invalidates nothing.
	f.ex(`UPDATE crypto_implementations SET last_verified_at=now() WHERE tenant_id=$1`, f.tenant)
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	if n := judgedConfigurations.Load() - before; n != 1 {
		t.Fatalf("last_verified_at churn re-judged rows: %d", n)
	}
}

// TestIntegration_CryptoRiskJudgments_EveryInputInvalidates changes each input
// of the judge in turn and requires the next read to match the Go judge.
func TestIntegration_CryptoRiskJudgments_EveryInputInvalidates(t *testing.T) {
	f := newJudgmentFixture(t, 60)
	check := func(what string) {
		t.Helper()
		got, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{PageSize: 100})
		if err != nil {
			t.Fatal(err)
		}
		want, err := f.svc.legacyListRisks(f.tenant, CryptoRiskFilters{PageSize: 100})
		if err != nil {
			t.Fatal(err)
		}
		if mustJSON(t, got) != mustJSON(t, want) {
			t.Fatalf("after %s the persisted feed is stale:\nwant %s\n got %s", what, mustJSON(t, want), mustJSON(t, got))
		}
		gs, _ := f.svc.GetSummary(f.tenant)
		ws, _ := f.svc.legacyGetSummary(f.tenant)
		if mustJSON(t, gs) != mustJSON(t, ws) {
			t.Fatalf("after %s the summary is stale: want %+v got %+v", what, ws, gs)
		}
	}
	check("the initial read")
	f.ex(`UPDATE algorithms SET risk_score=99, strength='weak' WHERE id=$1`, f.algs[3])
	check("a catalogue row edit")
	f.ex(`UPDATE algorithms SET risk_score=NULL WHERE id=$1`, f.algs[2])
	check("a catalogue score removed")
	f.ex(`DELETE FROM crypto_implementation_algorithms WHERE algorithm_id=$1`, f.algs[0])
	check("junction rows removed")
	f.ex(`UPDATE certificates SET not_after=now()+interval '3 days' WHERE tenant_id=$1`, f.tenant)
	check("certificate expiry moved")
	f.ex(`DELETE FROM crypto_implementation_certificates WHERE crypto_implementation_id IN (SELECT id FROM crypto_implementations WHERE tenant_id=$1)`, f.tenant)
	check("certificate links removed")
	f.ex(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence)
 VALUES($1,'crypto','weak_configuration','crypto_configuration',$2,'high',80,'prior','{}')`, f.tenant, f.configs[1])
	check("a prior finding raised")
	f.ex(`UPDATE findings SET detection_state='INACTIVE' WHERE tenant_id=$1`, f.tenant)
	check("prior findings resolved")
	f.ex(`UPDATE crypto_implementations SET hash_algorithm='MD5', protocol_version='1.0' WHERE tenant_id=$1`, f.tenant)
	check("configuration facts changed")
	f.ex(`UPDATE crypto_implementations SET deleted_at=now() WHERE id=$1`, f.configs[2])
	check("a soft delete")
	f.ex(`UPDATE crypto_implementations SET deleted_at=NULL WHERE id=$1`, f.configs[2])
	check("an undelete")
	f.ex(`DELETE FROM crypto_implementations WHERE id=$1`, f.configs[4])
	check("a hard delete")
	f.ex(`UPDATE assets SET hostname='renamed.example' WHERE id=$1`, f.assets[0])
	check("an asset rename (live join, nothing to invalidate)")
	f.ex(`UPDATE assets SET asset_status='archived' WHERE id=$1`, f.assets[1])
	check("an asset leaving monitoring")
	var leftovers int
	if err := f.rawDB().QueryRow(`SELECT count(*) FROM crypto_risk_judgments WHERE crypto_implementation_id=$1`, f.configs[4]).Scan(&leftovers); err != nil || leftovers != 0 {
		t.Fatalf("hard-deleted configuration keeps its judgement row: %d %v", leftovers, err)
	}
}

// TestIntegration_CryptoRiskJudgments_CertificateClockRejudges: a judgement that
// depends on the clock is re-judged once its valid_until passes.
func TestIntegration_CryptoRiskJudgments_CertificateClockRejudges(t *testing.T) {
	f := newJudgmentFixture(t, 25)
	f.ex(`UPDATE certificates SET not_after=now()+interval '120 days' WHERE tenant_id=$1`, f.tenant)
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	var due int
	db := f.rawDB()
	if err := db.QueryRow(`SELECT count(*) FROM crypto_risk_judgments WHERE tenant_id=$1 AND valid_until IS NOT NULL AND valid_until > now() + interval '29 days' AND valid_until < now() + interval '31 days'`, f.tenant).Scan(&due); err != nil || due == 0 {
		t.Fatalf("a certificate 120 days out must be valid until its 90-day window opens: due=%d err=%v", due, err)
	}
	// The window opens: time passes (the certificates move, which would also
	// invalidate, so only the clock is advanced on the judgement rows).
	f.ex(`UPDATE crypto_risk_judgments SET valid_until=now()-interval '1 minute' WHERE tenant_id=$1 AND valid_until IS NOT NULL`, f.tenant)
	before := judgedConfigurations.Load()
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	if n := judgedConfigurations.Load() - before; n == 0 {
		t.Fatal("rows past valid_until were not re-judged")
	}
	var stillDue int
	if err := db.QueryRow(`SELECT count(*) FROM crypto_risk_judgments WHERE tenant_id=$1 AND (stale OR valid_until <= now())`, f.tenant).Scan(&stillDue); err != nil || stillDue != 0 {
		t.Fatalf("rows left stale/due after a read: %d %v", stillDue, err)
	}
}

// TestIntegration_CryptoRiskJudgments_SweepIsBounded: the background pass judges
// at most its limit per call and finishes the backlog over successive passes.
func TestIntegration_CryptoRiskJudgments_SweepIsBounded(t *testing.T) {
	f := newJudgmentFixture(t, 30)
	var stale int
	db := f.rawDB()
	if err := db.QueryRow(`SELECT count(*) FROM crypto_risk_judgments WHERE tenant_id=$1 AND stale`, f.tenant).Scan(&stale); err != nil || stale < 20 {
		t.Fatalf("new configurations must start stale: %d %v", stale, err)
	}
	n, err := f.svc.SweepJudgments(t.Context(), f.tenant, 10)
	if err != nil || n != 10 {
		t.Fatalf("bounded pass judged %d (err %v), want 10", n, err)
	}
	total := n
	for {
		n, err = f.svc.SweepJudgments(t.Context(), f.tenant, 10)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		total += n
	}
	if total != stale {
		t.Fatalf("sweep judged %d of %d stale rows", total, stale)
	}
}

// TestIntegration_CryptoRiskJudgments_SchemaReappliesOverJudgedRows: the schema
// is re-applied on every upgrade; with judged rows present it must keep them.
// (It used to also re-create a missing row as stale from a backfill INSERT on
// apply; the 5.0.0 baseline has no backfills, asset-inventory ADR-0010 D11, and
// every configuration gets its row from the crypto_risk_judgment triggers.)
func TestIntegration_CryptoRiskJudgments_SchemaReappliesOverJudgedRows(t *testing.T) {
	f := newJudgmentFixture(t, 30)
	if _, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{}); err != nil {
		t.Fatal(err)
	}
	db := f.rawDB()
	var live, judged int
	if err := db.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND deleted_at IS NULL`, f.tenant).Scan(&live); err != nil {
		t.Fatal(err)
	}
	testdb.ForceApplySchema(t, db)
	if err := db.QueryRow(`SELECT count(*) FROM crypto_risk_judgments WHERE tenant_id=$1 AND NOT stale`, f.tenant).Scan(&judged); err != nil {
		t.Fatal(err)
	}
	var missing int
	if err := db.QueryRow(`SELECT count(*) FROM crypto_implementations ci WHERE ci.tenant_id=$1 AND ci.deleted_at IS NULL
 AND NOT EXISTS (SELECT 1 FROM crypto_risk_judgments j WHERE j.crypto_implementation_id=ci.id)`, f.tenant).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != 0 {
		t.Fatalf("after re-applying the schema %d of %d live configurations have no judgement row", missing, live)
	}
	if judged < live-2 {
		t.Fatalf("re-applying the schema discarded judged rows: %d fresh of %d", judged, live)
	}
	want, _ := f.svc.legacyListRisks(f.tenant, CryptoRiskFilters{PageSize: 100})
	got, err := f.svc.ListRisks(f.tenant, CryptoRiskFilters{PageSize: 100})
	if err != nil || mustJSON(t, want) != mustJSON(t, got) {
		t.Fatalf("feed wrong after schema re-apply: %v", err)
	}
}

// TestIntegration_CryptoRiskJudgments_ListIsServedByIndexes pins the shape of
// the SQL: ordering and paging happen in the database (ORDER BY ... LIMIT
// ... OFFSET), the default order walks the feed index, and search touches the
// trigram indexes.
func TestIntegration_CryptoRiskJudgments_ListIsServedByIndexes(t *testing.T) {
	where, _ := feedWhere(CryptoRiskFilters{Search: "x"}, nil)
	for _, want := range []string{"ILIKE", "pg_enum"} {
		if !strings.Contains(where, want) {
			t.Fatalf("search clause lacks %q: %s", want, where)
		}
	}
	if o := feedOrder(CryptoRiskFilters{}); !strings.Contains(o, "severity_rank DESC") {
		t.Fatalf("default order: %s", o)
	}
	f := newJudgmentFixture(t, 10)
	db := f.rawDB()
	// The bulk rows only pad the table so the planner prefers the indexes; they
	// belong to no configuration, which the configuration FK forbids, so the
	// insert runs with FK triggers off (session_replication_role = replica;
	// the test database user is a superuser).
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO crypto_risk_judgments(crypto_implementation_id,tenant_id,stale,emitted,severity,severity_rank)
 SELECT gen_random_uuid(),$1,false,true,'high',4 FROM generate_series(1,5000)`, f.tenant); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ANALYZE crypto_risk_judgments`); err != nil {
		t.Fatal(err)
	}
	explain := func(q string, args ...any) string {
		rows, err := db.Query(`EXPLAIN `+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var sb strings.Builder
		for rows.Next() {
			var line string
			_ = rows.Scan(&line)
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}
	plan := explain(`SELECT j.crypto_implementation_id FROM crypto_risk_judgments j WHERE j.tenant_id=$1 AND j.emitted ORDER BY j.severity_rank DESC, j.crypto_implementation_id LIMIT 20`, f.tenant)
	if !strings.Contains(plan, "idx_crypto_risk_judgments_feed") || strings.Contains(plan, "Sort") {
		t.Fatalf("default page is not an ordered index walk:\n%s", plan)
	}
	plan = explain(`SELECT id FROM assets WHERE hostname ILIKE '%alpha%' OR host(primary_address) ILIKE '%10.0%'`)
	_ = plan // planner choice on a tiny table is not asserted; the indexes' existence is
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE indexname IN ('idx_assets_hostname_trgm','idx_assets_primary_host_trgm','idx_asset_endpoints_address_host_trgm','idx_crypto_impl_cipher_suite_trgm')`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("trigram indexes missing: %d %v", n, err)
	}
}
