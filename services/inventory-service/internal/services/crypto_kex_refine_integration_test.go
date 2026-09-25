package services

// A passive observation (suite-derived key-exchange label) and an active probe
// (measured group) of ONE endpoint must stay ONE crypto configuration that
// carries the measured group — in either order, and for rows written before
// the group was recorded at all. Before refineCryptoKeyExchange they split into
// two permanent rows: {ECDHE} beside {X25519MLKEM768}, Total=2, and a hybrid
// endpoint read at most half PQC-ready.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"sort"
	"testing"

	"github.com/google/uuid"
)

// passiveTLS13 is what a passive sensor reports for a TLS 1.3 flow: version and
// suite, no key exchange (the suite names none), no key size.
func passiveTLS13() IngestFinding {
	v, suite := "TLS 1.3", "TLS_AES_128_GCM_SHA256"
	return IngestFinding{
		Protocol: "TLS", ProtocolVersion: &v, CipherSuite: &suite,
		RawData: map[string]interface{}{"discovery_method": "passive"},
	}
}

// activeTLS13 is the active probe of the same endpoint: the same version and
// suite, plus the measured group and the leaf key size.
func activeTLS13(group string) IngestFinding {
	f := passiveTLS13()
	g, ks := group, 256
	f.KeyExchangeAlgorithm = &g
	f.KeySize = &ks
	f.RawData = map[string]interface{}{"discovery_method": "active"}
	return f
}

type kexLink struct {
	code     string
	inferred bool
}

func kexState(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) (rows int, columns []string, links []kexLink) {
	t.Helper()
	if err := svc.db.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`,
		tenant, asset).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	cr, err := svc.db.Query(`SELECT COALESCE(key_exchange_algorithm,'') FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL ORDER BY 1`, tenant, asset)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	for cr.Next() {
		var c string
		if err := cr.Scan(&c); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		columns = append(columns, c)
	}
	_ = cr.Close()
	lr, err := svc.db.Query(`
		SELECT a.code, cia.is_inferred
		  FROM crypto_implementations ci
		  JOIN crypto_implementation_algorithms cia ON cia.crypto_implementation_id = ci.id
		  JOIN algorithms a ON a.id = cia.algorithm_id
		 WHERE ci.tenant_id=$1 AND ci.asset_id=$2 AND ci.deleted_at IS NULL AND cia.algorithm_type='key_exchange'`, tenant, asset)
	if err != nil {
		t.Fatalf("read links: %v", err)
	}
	for lr.Next() {
		var l kexLink
		if err := lr.Scan(&l.code, &l.inferred); err != nil {
			t.Fatalf("scan link: %v", err)
		}
		links = append(links, l)
	}
	_ = lr.Close()
	sort.Slice(links, func(i, j int) bool { return links[i].code < links[j].code })
	return rows, columns, links
}

func TestIntegration_KexRefinement_PassiveAndActiveAreOneConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		group      string
		wantReady  int
		wantNeeds  int
		passiveFst bool
	}{
		{"hybrid, passive then active", "X25519MLKEM768", 1, 0, true},
		{"hybrid, active then passive", "X25519MLKEM768", 1, 0, false},
		{"classical X25519, passive then active", "X25519", 0, 1, true},
		{"classical X25519, active then passive", "X25519", 0, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, tenant, asset := newSSHIngestFixture(t, "kex-refine.example.test")
			first, second := passiveTLS13(), activeTLS13(tt.group)
			if !tt.passiveFst {
				first, second = second, first
			}
			ingestSSH(t, svc, tenant, asset, first)
			ingestSSH(t, svc, tenant, asset, second)
			// And passive traffic keeps arriving afterwards.
			ingestSSH(t, svc, tenant, asset, passiveTLS13())

			rows, cols, links := kexState(t, svc, tenant, asset)
			if rows != 1 {
				t.Fatalf("rows = %d (key exchanges %v, links %v), want 1 — the label and the group are one configuration", rows, cols, links)
			}
			if len(cols) != 1 || cols[0] != tt.group {
				t.Errorf("key_exchange_algorithm = %v, want the measured %q", cols, tt.group)
			}
			if len(links) != 1 || links[0].code != tt.group || links[0].inferred {
				t.Errorf("key_exchange links = %+v, want exactly one measured link to %q", links, tt.group)
			}
			counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if counts.Total != 1 || counts.PQCReady != tt.wantReady || counts.NeedsMigration != tt.wantNeeds {
				t.Errorf("classified as %+v, want Total=1 PQCReady=%d NeedsMigration=%d", counts, tt.wantReady, tt.wantNeeds)
			}
		})
	}
}

// A configuration written before the group was recorded holds the ECDHE the
// suite parse assumed — in the column and as a key_exchange link that was then
// marked measured (is_inferred=false). The first active probe after upgrade
// must refine that row in place and drop the stale link, not leave it behind
// beside a new row.
func TestIntegration_KexRefinement_PreUpgradeRowIsRefinedInPlace(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-upgrade.example.test")

	old := activeTLS13("X25519MLKEM768")
	old.KeyExchangeAlgorithm = nil // pre-upgrade: no group recorded
	ingestSSH(t, svc, tenant, asset, old)
	if _, err := svc.db.Exec(`
		UPDATE crypto_implementation_algorithms cia SET is_inferred = false
		  FROM crypto_implementations ci
		 WHERE ci.id = cia.crypto_implementation_id AND ci.tenant_id = $1 AND ci.asset_id = $2
		   AND cia.algorithm_type = 'key_exchange'`, tenant, asset); err != nil {
		t.Fatalf("reproduce the pre-upgrade link: %v", err)
	}
	if rows, cols, links := kexState(t, svc, tenant, asset); rows != 1 || cols[0] != "ECDHE" || len(links) != 1 || links[0].code != "ECDHE" {
		t.Fatalf("pre-upgrade fixture = rows %d, columns %v, links %+v; want one ECDHE row", rows, cols, links)
	}

	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))

	rows, cols, links := kexState(t, svc, tenant, asset)
	if rows != 1 {
		t.Fatalf("rows = %d (key exchanges %v), want 1 — the old ECDHE row must be refined, not left behind", rows, cols)
	}
	if cols[0] != "X25519MLKEM768" {
		t.Errorf("key_exchange_algorithm = %q, want X25519MLKEM768", cols[0])
	}
	if len(links) != 1 || links[0].code != "X25519MLKEM768" {
		t.Errorf("key_exchange links = %+v, want only X25519MLKEM768 — the stale ECDHE link must be gone", links)
	}
	counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if counts.Total != 1 || counts.PQCReady != 1 || counts.NeedsMigration != 0 {
		t.Errorf("classified as %+v, want Total=1 PQCReady=1 NeedsMigration=0", counts)
	}
}

// Equal fingerprints under different discovery methods are two rows by design
// (the method is part of the natural key — see cryptoImplementationKey). Both
// must still be refined by a measured group: the one the observation lands on
// AND the other, which the caller never re-links — so it gets its group link
// and loses its label link inside the refinement itself.
func TestIntegration_KexRefinement_EveryCompatibleLabelRowIsRefined(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-both.example.test")

	passiveFull := activeTLS13("X25519MLKEM768")
	passiveFull.KeyExchangeAlgorithm = nil
	passiveFull.RawData = map[string]interface{}{"discovery_method": "passive"}
	activeOld := activeTLS13("X25519MLKEM768")
	activeOld.KeyExchangeAlgorithm = nil
	ingestSSH(t, svc, tenant, asset, passiveFull)
	ingestSSH(t, svc, tenant, asset, activeOld)
	if rows, cols, _ := kexState(t, svc, tenant, asset); rows != 2 || cols[0] != "ECDHE" || cols[1] != "ECDHE" {
		t.Fatalf("fixture = %d rows %v, want two ECDHE rows (one per method)", rows, cols)
	}

	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))

	rows, cols, links := kexState(t, svc, tenant, asset)
	if rows != 2 {
		t.Fatalf("rows = %d, want the same 2", rows)
	}
	for _, c := range cols {
		if c != "X25519MLKEM768" {
			t.Errorf("key_exchange_algorithm = %v, want both rows refined to X25519MLKEM768", cols)
			break
		}
	}
	if len(links) != 2 || links[0].code != "X25519MLKEM768" || links[1].code != "X25519MLKEM768" {
		t.Errorf("key_exchange links = %+v, want one X25519MLKEM768 link per row and no ECDHE", links)
	}
	counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if counts.PQCReady != 2 || counts.NeedsMigration != 0 {
		t.Errorf("classified as %+v, want both rows PQC-ready", counts)
	}
}

// A measured group with no catalogue row must not strip the label link: that
// would leave the configuration with only a symmetric cipher and a hash, which
// classifies as symmetric-safe — a worse wrong answer than the label's
// needs-migration. Every group the probes record today is catalogued (pinned
// by TestIntegration_TLSKeyExchangeGroup_EveryRecordedNameIsCatalogued), so the
// guard is driven directly with a name no catalogue row carries — the shape a
// group crypto/tls adds in a future release would arrive in — rather than by
// deleting a seeded row other suites read.
func TestIntegration_KexRefinement_UncataloguedGroupKeepsTheLabelLink(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-uncatalogued.example.test")
	ingestSSH(t, svc, tenant, asset, passiveTLS13())
	var implID uuid.UUID
	if err := svc.db.QueryRow(`SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`,
		tenant, asset).Scan(&implID); err != nil {
		t.Fatalf("read implementation: %v", err)
	}

	if err := deleteSupersededKeyExchangeLinks(svc.db, implID, "NOT-A-CATALOGUED-GROUP"); err != nil {
		t.Fatalf("delete superseded links: %v", err)
	}
	if _, _, links := kexState(t, svc, tenant, asset); len(links) != 1 || links[0].code != "ECDHE" {
		t.Errorf("key_exchange links = %+v, want the ECDHE link kept — the group resolves to no catalogue row", links)
	}
	counts, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if counts.SymmetricSafe != 0 {
		t.Errorf("classified as %+v — an uncatalogued key exchange must not read as symmetric-safe", counts)
	}

	// And the other polarity: a catalogued group does remove it.
	if err := deleteSupersededKeyExchangeLinks(svc.db, implID, "X25519"); err != nil {
		t.Fatalf("delete superseded links: %v", err)
	}
	if _, _, links := kexState(t, svc, tenant, asset); len(links) != 0 {
		t.Errorf("key_exchange links = %+v, want the ECDHE label link removed once the group is catalogued", links)
	}
}

// The ECDHE a TLS 1.3 suite parse ASSUMES is linked as inferred, so it can be
// told apart from a measured key exchange.
func TestIntegration_KexRefinement_TLS13AssumedKeyExchangeIsInferred(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-inferred.example.test")
	ingestSSH(t, svc, tenant, asset, passiveTLS13())
	_, _, links := kexState(t, svc, tenant, asset)
	if len(links) != 1 || links[0].code != "ECDHE" || !links[0].inferred {
		t.Errorf("key_exchange links = %+v, want one ECDHE link with is_inferred=true", links)
	}
}
