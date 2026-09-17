package services

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	cryptostrength "github.com/vistasecurity/vistaplatform/shared/strength"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ExternalStrength_AllComponents(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	tenant := testdb.NewTenant(t, raw)
	testdb.WithSchemaShareLock(t, raw, func() {
		codes := map[string]string{}
		for i, grade := range []string{"weak", "acceptable", "strong", "recommended"} {
			code := "EXTERNAL" + uuid.NewString()
			codes[grade] = code
			if _, err := raw.Exec(`INSERT INTO algorithms(code,name,category,strength,risk_score,is_pqc,pqc_standardization_status) VALUES($1,$1,'hash',$2,$3,$4,$5)`, code, grade, i*30, grade == "recommended", map[bool]string{true: "standardized", false: "none"}[grade == "recommended"]); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE code=$1`, code) }()
		}
		for _, grade := range []string{"weak", "acceptable", "strong", "recommended"} {
			in := models.ExternalConnectionUpsert{KeyExchangeAlgorithm: strPtr(codes[grade])}
			got, pqc, _, _, _ := svc.assessCrypto(in)
			if got != grade || pqc != (grade == "recommended") {
				t.Errorf("grade %s got %s pqc=%v", grade, got, pqc)
			}
			in.SourceIP, in.DestIP, in.Protocol = "192.0.2.17", "198.51.100.17", "TLS"
			rank, _ := cryptostrength.Rank(grade)
			in.DestPort = 440 + rank
			row, err := svc.Upsert(tenant, in)
			if err != nil || stringValue(row.Strength) != grade {
				t.Fatalf("persisted %s: %+v %v", grade, row, err)
			}
			rows, count, err := svc.List(tenant, models.ExternalConnectionFilters{Strength: grade})
			if err != nil || count != 1 || len(rows) != 1 || stringValue(rows[0].Strength) != grade {
				t.Fatalf("filter %s: %+v %d %v", grade, rows, count, err)
			}

		}
		sorted, count, err := svc.List(tenant, models.ExternalConnectionFilters{SortBy: "strength", SortOrder: "asc"})
		if err != nil || count != 4 {
			t.Fatalf("strength sort: %d %v", count, err)
		}
		for i, want := range []string{"weak", "acceptable", "strong", "recommended"} {
			if stringValue(sorted[i].Strength) != want {
				t.Fatalf("strength order[%d]=%s want %s", i, stringValue(sorted[i].Strength), want)
			}
		}
		for _, score := range []int{0, 90} {
			if _, err := raw.Exec(`UPDATE algorithms SET risk_score=$1 WHERE code=$2`, score, codes["weak"]); err != nil {
				t.Fatal(err)
			}
			got, pqc, _, _, _ := svc.assessCrypto(models.ExternalConnectionUpsert{CipherSuite: strPtr(codes["recommended"]), KeyExchangeAlgorithm: strPtr(codes["weak"])})
			if !pqc {
				t.Fatal("weak rating discarded observed PQC suite")
			}
			if got != "weak" {
				t.Fatalf("weak component hidden by recommended suite, score=%d: %q", score, got)
			}
		}
		for _, in := range []models.ExternalConnectionUpsert{{}, {Protocol: "TLS", ProtocolVersion: strPtr("1.3")}, {KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(0)}, {KeyExchangeAlgorithm: strPtr("not-in-catalogue")}, {CipherSuite: strPtr(codes["recommended"]), KeyExchangeAlgorithm: strPtr("not-in-catalogue")}} {
			got, _, _, _, _ := svc.assessCrypto(in)
			if got != "" {
				t.Fatalf("unknown must be null: %q", got)
			}
		}
	})
}

func TestIntegration_ExternalStrength_MergedWriterReadersAndIngest(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	testdb.WithSchemaShareLock(t, raw, func() {
		healthy := models.ExternalConnectionUpsert{SourceIP: "192.0.2.16", DestIP: "198.51.100.16", DestPort: 443, Protocol: "TLS", ProtocolVersion: strPtr("1.3"), CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"), KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(256), SupportedTLSVersions: []string{"TLS 1.3"}, CertPublicKeyAlgorithm: strPtr("RSA"), CertPublicKeySize: intPtr(4096), CertSignatureAlgorithm: strPtr("SHA384")}
		weak := healthy
		weak.CertPublicKeySize = intPtr(1024)
		weak.CertSignatureAlgorithm = strPtr("SHA1")
		weak.SupportedTLSVersions = []string{"TLS 1.0", "TLS 1.3"}
		first, err := svc.Upsert(tenant, weak)
		if err != nil {
			t.Fatal(err)
		}
		if stringValue(first.Strength) != "weak" {
			t.Fatalf("initial grade %v", first.Strength)
		}
		fragment := models.ExternalConnectionUpsert{SourceIP: healthy.SourceIP, DestIP: healthy.DestIP, DestPort: 443, Protocol: "TLS", CipherSuite: healthy.CipherSuite, KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(256)}
		for _, incoming := range []models.ExternalConnectionUpsert{fragment, {SourceIP: healthy.SourceIP, DestIP: healthy.DestIP, DestPort: 443, Protocol: "TLS", CertPublicKeyAlgorithm: strPtr("ECDSA")}, {SourceIP: healthy.SourceIP, DestIP: healthy.DestIP, DestPort: 443, Protocol: "TLS", KeySize: intPtr(0), CertPublicKeySize: intPtr(0), CertSignatureAlgorithm: strPtr("")}} {
			got, e := svc.Upsert(tenant, incoming)
			if e != nil {
				t.Fatal(e)
			}
			if stringValue(got.Strength) != "weak" || !containsSubstr(got.WeakReasons, "1024") || !containsSubstr(got.WeakReasons, "SHA-1") || len(got.SupportedTLSVersions) != 2 {
				t.Fatalf("partial writer lost evidence: %+v", got)
			}
		}
		assetSvc := NewAssetService(db)
		assetSvc.SetExternalConnectionsService(svc)
		if e := assetSvc.routeToExternalConnection(tenant, IngestFinding{IPAddress: &healthy.DestIP, Port: &healthy.DestPort, Protocol: "TLS", CipherSuite: healthy.CipherSuite, RawData: map[string]interface{}{"source_ip": healthy.SourceIP}}); e != nil {
			t.Fatal(e)
		}
		got, e := svc.GetByID(tenant, first.ID)
		if e != nil || stringValue(got.Strength) != "weak" {
			t.Fatalf("discovery ingest lost weakness: %+v %v", got, e)
		}
		rows, n, e := svc.List(tenant, models.ExternalConnectionFilters{Strength: "weak"})
		if e != nil || n != 1 || len(rows) != 1 {
			t.Fatalf("weak filter %d %v", n, e)
		}
		if _, n, e = svc.List(other, models.ExternalConnectionFilters{Strength: "weak"}); e != nil || n != 0 {
			t.Fatalf("tenant leak %d %v", n, e)
		}
		summary, e := svc.GetSummary(tenant)
		if e != nil || summary.WeakCrypto != 1 {
			t.Fatalf("weak summary %+v %v", summary, e)
		}
		corrected, e := svc.Upsert(tenant, healthy)
		if e != nil {
			t.Fatal(e)
		}
		if stringValue(corrected.Strength) != "strong" || len(corrected.WeakReasons) != 0 {
			t.Fatalf("complete corrected observation should clear weakness: %+v", corrected)
		}
		hist, n, e := svc.GetHistory(tenant, first.ID, 1, 100)
		if e != nil || n != 2 {
			t.Fatalf("history count %d %v", n, e)
		}
		if hist[0].StrengthVocabularyVersion != 2 || stringValue(hist[0].PreviousStrength) != "weak" || stringValue(hist[0].NewStrength) != "strong" {
			t.Fatalf("history %+v", hist[0])
		}
		if _, e := raw.Exec(`UPDATE external_connections SET crypto_strength=NULL,weak_reasons=ARRAY['Historical key-size evidence unavailable'] WHERE id=$1`, first.ID); e != nil {
			t.Fatal(e)
		}
		pending, e := svc.Upsert(tenant, fragment)
		if e != nil || pending.Strength != nil || len(pending.WeakReasons) == 0 {
			t.Fatalf("opaque legacy weakness erased: %+v %v", pending, e)
		}
		if _, n, e := svc.List(tenant, models.ExternalConnectionFilters{Strength: "unassessed"}); e != nil || n != 1 {
			t.Fatalf("unassessed filter %d %v", n, e)
		}
		summary, e = svc.GetSummary(tenant)
		if e != nil || summary.WeakCrypto != 0 || summary.ReassessmentRequired != 1 {
			t.Fatalf("pending summary %+v %v", summary, e)
		}
		// One reconstructible weakness must not hide a second historical gap.
		if _, e := raw.Exec(`UPDATE external_connections SET protocol_version='TLS 1.0',weak_reasons=ARRAY['Historical key-size evidence unavailable'] WHERE id=$1`, first.ID); e != nil {
			t.Fatal(e)
		}
		if _, _, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200); e != nil {
			t.Fatal(e)
		}
		reconstructed, e := svc.GetByID(tenant, first.ID)
		if e != nil || stringValue(reconstructed.Strength) != "weak" || !containsSubstr(reconstructed.WeakReasons, externalReassessmentReason) {
			t.Fatalf("reconstructed weak fact hid historical gap: %+v %v", reconstructed, e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 1, 1)
		fragment.ProtocolVersion = healthy.ProtocolVersion
		pending, e = svc.Upsert(tenant, fragment)
		if e != nil || pending.Strength != nil || !containsSubstr(pending.WeakReasons, "Historical key-size") {
			t.Fatalf("partial repair hid independent historical weakness: %+v %v", pending, e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 0, 1)
		before := pending.ObservationCount
		lastSeen := pending.LastSeenAt
		cursor, n, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 1)
		if e != nil || n != 1 || cursor != first.ID {
			t.Fatalf("batch cursor %s %d %v", cursor, n, e)
		}
		if _, n, e := svc.ReassessBatch(context.Background(), tenant, cursor, 1); e != nil || n != 0 {
			t.Fatalf("batch completion %d %v", n, e)
		}
		pending, e = svc.GetByID(tenant, first.ID)
		if e != nil || pending.Strength != nil || pending.ObservationCount != before || !pending.LastSeenAt.Equal(lastSeen) {
			t.Fatalf("reassessment fabricated observation or grade: %+v %v", pending, e)
		}
		final, e := svc.Upsert(tenant, healthy)
		if e != nil || stringValue(final.Strength) != "strong" || len(final.WeakReasons) != 0 {
			t.Fatalf("fresh complete evidence must resolve historical gap: %+v %v", final, e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 0, 0)
	})
}

func TestIntegration_ExternalStrength_LegacyUpgradeAndReapply(t *testing.T) {
	admin := testdb.Connect(t)
	root := testdb.RepoRoot(t)
	scratch := newScratchDB(t, admin)
	mustApply(t, scratch, mustGitShow(t, root, "32f4a259", "scripts/database/schema.sql"), "ADR baseline schema")
	mustApply(t, scratch, mustGitShow(t, root, "32f4a259", "scripts/database/seed.sql"), "ADR baseline seed")
	tenant := populateForUpgrade(t, scratch)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for i, old := range []string{"good", "weak", "unknown"} {
		_, e := scratch.Exec(`INSERT INTO external_connections(id,tenant_id,source_ip,dest_ip,dest_port,protocol,crypto_strength) VALUES($1,$2,'192.0.2.16','198.51.100.16',$3,'TLS',$4)`, ids[i], tenant, 443+i, old)
		if e != nil {
			t.Fatal(e)
		}
		_, e = scratch.Exec(`INSERT INTO external_connection_history(external_connection_id,tenant_id,change_type,new_crypto_strength) VALUES($1,$2,'first_seen',$3)`, ids[i], tenant, old)
		if e != nil {
			t.Fatal(e)
		}
	}
	ambiguousID, measuredID := uuid.New(), uuid.New()
	for i, id := range []uuid.UUID{ambiguousID, measuredID} {
		size := 128
		algorithm := "ECDHE"
		if i == 1 {
			size = 1024
			algorithm = "DH"
		}
		if _, e := scratch.Exec(`INSERT INTO external_connections(id,tenant_id,source_ip,dest_ip,dest_port,protocol,crypto_strength,cipher_suite,key_exchange_algorithm,key_size) VALUES($1,$2,'192.0.2.16','198.51.100.16',$3,'TLS','good','TLS_AES_128_GCM_SHA256',$4,$5)`, id, tenant, 446+i, algorithm, size); e != nil {
			t.Fatal(e)
		}
	}
	current := mustReadFile(t, filepath.Join(root, "scripts/database/schema.sql"))
	mustApply(t, scratch, current, "current upgrade")
	db := &database.DB{DB: sqlx.NewDb(scratch, "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	for i, old := range []string{"good", "weak", "unknown"} {
		row, e := svc.GetByID(tenant, ids[i])
		if e != nil || row.Strength != nil {
			t.Fatalf("legacy %s inferred grade %+v %v", old, row, e)
		}
		h, _, e := svc.GetHistory(tenant, ids[i], 1, 10)
		if e != nil || len(h) != 1 || h[0].NewStrength != nil || stringValue(h[0].NewStrengthLegacy) != old || h[0].StrengthVocabularyVersion != 1 {
			t.Fatalf("legacy history %+v %v", h, e)
		}
		if old == "weak" && len(row.WeakReasons) == 0 {
			t.Fatal("legacy weak without facts lost reassessment evidence")
		}
	}
	if _, _, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200); e != nil {
		t.Fatal(e)
	}
	ambiguous, e := svc.GetByID(tenant, ambiguousID)
	if e != nil || ambiguous.Strength != nil || *ambiguous.KeySize != 128 || !containsExternalReason(ambiguous.WeakReasons, externalKeySizeRoleReason) {
		t.Fatalf("migration fabricated weak exchange from cipher bits: %+v %v", ambiguous, e)
	}
	measured, e := svc.GetByID(tenant, measuredID)
	if e != nil || stringValue(measured.Strength) != "weak" || *measured.KeySize != 1024 || containsExternalReason(measured.WeakReasons, externalKeySizeRoleReason) {
		t.Fatalf("migration erased unambiguous undersized DH evidence: %+v %v", measured, e)
	}
	_, e = scratch.Exec(`UPDATE external_connections SET crypto_strength='acceptable' WHERE id=$1`, ids[0])
	if e != nil {
		t.Fatal(e)
	}
	mustApply(t, scratch, current, "idempotent reapply")
	mustApply(t, scratch, mustReadFile(t, filepath.Join(root, "scripts/database/seed.sql")), "idempotent reseed")
	row, e := svc.GetByID(tenant, ids[0])
	if e != nil || stringValue(row.Strength) != "acceptable" {
		t.Fatalf("reapply reset current assessment %+v %v", row, e)
	}
	for _, bad := range []string{"good", "unknown", "critical"} {
		if _, e := scratch.Exec(`UPDATE external_connections SET crypto_strength=$1 WHERE id=$2`, bad, ids[0]); e == nil {
			t.Fatalf("constraint accepted %s", bad)
		}
	}
}

func TestIntegration_ExternalStrength_SingleConnectionPool(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	app.SetMaxOpenConns(1)
	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	testdb.WithSchemaShareLock(t, raw, func() {
		done := make(chan error, 1)
		go func() {
			_, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{SourceIP: "192.0.2.18", DestIP: "198.51.100.18", DestPort: 443, Protocol: "TLS", CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"), KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(256)})
			if err == nil {
				_, _, err = svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200)
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			// Release a deliberately regressed nested checkout before test cleanup.
			app.SetMaxOpenConns(3)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
			t.Fatal("external writer/reassessment starved its own one-connection pool")
		}
	})
}

func TestIntegration_ExternalStrength_AmbiguousLegacySizeAndDiscoveryRoles(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	assets := NewAssetService(db)
	assets.SetExternalConnectionsService(svc)
	testdb.WithSchemaShareLock(t, raw, func() {
		in := models.ExternalConnectionUpsert{SourceIP: "192.0.2.19", DestIP: "198.51.100.19", DestPort: 443, Protocol: "TLS", CipherSuite: strPtr("TLS_AES_128_GCM_SHA256"), KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(128)}
		row, e := svc.Upsert(tenant, in)
		if e != nil {
			t.Fatal(e)
		}
		// Explicit fresh exchange bits are a real undersized key. Identical legacy
		// bits could have been fabricated from AES128 and cannot prove that claim.
		if stringValue(row.Strength) != "weak" {
			t.Fatal("fresh measured EC-128 must be weak")
		}
		if _, e := raw.Exec(`UPDATE external_connections SET crypto_strength=NULL,weak_reasons=ARRAY[$1] WHERE id=$2`, externalKeySizeRoleReason, row.ID); e != nil {
			t.Fatal(e)
		}
		if _, _, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200); e != nil {
			t.Fatal(e)
		}
		row, e = svc.GetByID(tenant, row.ID)
		if e != nil || row.Strength != nil || row.KeySize == nil || *row.KeySize != 128 || !containsExternalReason(row.WeakReasons, externalKeySizeRoleReason) {
			t.Fatalf("ambiguous size was judged or discarded: %+v %v", row, e)
		}
		if _, e := raw.Exec(`UPDATE external_connections SET protocol_version='TLS 1.0' WHERE id=$1`, row.ID); e != nil {
			t.Fatal(e)
		}
		if _, _, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200); e != nil {
			t.Fatal(e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 1, 1)
		fragment := models.ExternalConnectionUpsert{SourceIP: in.SourceIP, DestIP: in.DestIP, DestPort: 443, Protocol: "TLS", ProtocolVersion: strPtr("TLS 1.3"), CipherSuite: strPtr("TLS_AES_256_GCM_SHA384")}
		row, e = svc.Upsert(tenant, fragment)
		if e != nil || row.Strength != nil || !containsExternalReason(row.WeakReasons, externalKeySizeRoleReason) {
			t.Fatalf("independent TLS repair lost size ambiguity: %+v %v", row, e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 0, 1)
		fragment.KeyExchangeAlgorithm = strPtr("ECDHE")
		fragment.KeySize = intPtr(128)
		row, e = svc.Upsert(tenant, fragment)
		if e != nil || stringValue(row.Strength) != "weak" || containsExternalReason(row.WeakReasons, externalKeySizeRoleReason) {
			t.Fatalf("fresh role-correct small key not assessed: %+v %v", row, e)
		}

		assertExternalSummaryCounts(t, svc, tenant, 1, 1)
		// A measured exchange resolves its role, while the whole historical gap
		// needs complete fresh evidence. The real small key remains weak.
		fragment.SupportedTLSVersions = []string{"TLS 1.3"}
		fragment.CertPublicKeyAlgorithm = strPtr("RSA")
		fragment.CertPublicKeySize = intPtr(4096)
		fragment.CertSignatureAlgorithm = strPtr("SHA384")
		if _, e := svc.Upsert(tenant, fragment); e != nil {
			t.Fatal(e)
		}
		assertExternalSummaryCounts(t, svc, tenant, 1, 0)

		// The manual discovery ingress must preserve offered protocols while refusing
		// its generic KeySize; nested metadata carries the explicit exchange role.
		dest := "198.51.100.20"
		port := 443
		finding := IngestFinding{IPAddress: &dest, Port: &port, Protocol: "TLS", ProtocolVersion: strPtr("TLS 1.3"), CipherSuite: in.CipherSuite, KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(128), RawData: map[string]interface{}{"source_ip": in.SourceIP, "raw_metadata": map[string]interface{}{"tls_versions": []interface{}{"TLS 1.0", "TLS 1.3"}}}}
		if e := assets.routeToExternalConnection(tenant, finding); e != nil {
			t.Fatal(e)
		}
		list, _, e := svc.List(tenant, models.ExternalConnectionFilters{Search: dest})
		if e != nil || len(list) != 1 || stringValue(list[0].Strength) != "weak" || list[0].KeySize != nil || len(list[0].SupportedTLSVersions) != 2 {
			t.Fatalf("discovery role/protocol evidence: %+v %v", list, e)
		}
		finding.RawData["raw_metadata"] = map[string]interface{}{"tls_versions": []string{"TLS 1.3"}, "key_exchange_key_size": 256}
		if e := assets.routeToExternalConnection(tenant, finding); e != nil {
			t.Fatal(e)
		}
		list, _, e = svc.List(tenant, models.ExternalConnectionFilters{Search: dest})
		if e != nil || len(list) != 1 || list[0].Strength == nil || *list[0].Strength == "weak" || *list[0].KeySize != 256 {
			t.Fatalf("fresh exchange/protocol correction: %+v %v", list, e)
		}
	})
}

func TestIntegration_ExternalStrength_NullRiskCannotHideWeak(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, raw), "postgres")}
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))
	testdb.WithSchemaShareLock(t, raw, func() {
		code := "NULLRISK" + uuid.NewString()
		if _, e := raw.Exec(`INSERT INTO algorithms(code,name,category,strength,risk_score) VALUES($1,$1,'hash','weak',0)`, code); e != nil {
			t.Fatal(e)
		}
		defer func() { _, _ = raw.Exec(`DELETE FROM algorithms WHERE code=$1`, code) }()
		// Model a historical unscored row without bypassing the explicit-score
		// requirement for new catalogue inserts. Legacy NULL updates remain legal.
		if _, e := raw.Exec(`UPDATE algorithms SET risk_score=NULL WHERE code=$1`, code); e != nil {
			t.Fatal(e)
		}
		row, e := svc.Upsert(tenant, models.ExternalConnectionUpsert{SourceIP: "192.0.2.21", DestIP: "198.51.100.21", DestPort: 443, Protocol: "TLS", KeyExchangeAlgorithm: &code})
		if e != nil || stringValue(row.Strength) != "weak" {
			t.Fatalf("NULL numeric risk hid catalogue weakness on write: %+v %v", row, e)
		}
		if _, e := raw.Exec(`UPDATE external_connections SET crypto_strength=NULL,weak_reasons=NULL WHERE id=$1`, row.ID); e != nil {
			t.Fatal(e)
		}
		if _, _, e := svc.ReassessBatch(context.Background(), tenant, uuid.Nil, 200); e != nil {
			t.Fatal(e)
		}
		row, e = svc.GetByID(tenant, row.ID)
		if e != nil || stringValue(row.Strength) != "weak" {
			t.Fatalf("NULL numeric risk hid catalogue weakness on reassessment: %+v %v", row, e)
		}
	})
}

// Weakness and missing evidence are independent, overlapping summary counts.
func assertExternalSummaryCounts(t *testing.T, svc *ExternalConnectionsService, tenant uuid.UUID, weak, reassessment int) {
	t.Helper()
	summary, err := svc.GetSummary(tenant)
	if err != nil || summary.WeakCrypto != weak || summary.ReassessmentRequired != reassessment {
		t.Fatalf("summary weak=%d reassessment=%d: %+v %v", weak, reassessment, summary, err)
	}
}
