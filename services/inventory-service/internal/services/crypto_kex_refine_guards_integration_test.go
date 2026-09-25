package services

// The guards around key-exchange refinement (crypto_kex_refine.go): what it
// must repair, which row it must keep fresh, how it links what it adopts, and —
// most of all — every row it must leave alone. Each test here fails when the
// guard it names is removed (mutation log in PR).
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// kexRow is one configuration's key exchange column and its key_exchange links
// ("CODE" or "CODE(inf)"), keyed by row id.
type kexRow struct {
	id           uuid.UUID
	protocol     string
	version      string
	suite        string
	kex          string
	lastVerified time.Time
	links        []string
}

func kexRows(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) map[uuid.UUID]kexRow {
	t.Helper()
	rs, err := svc.db.Query(`
		SELECT id, protocol::text, COALESCE(protocol_version,''), COALESCE(cipher_suite,''),
		       COALESCE(key_exchange_algorithm,''), last_verified_at
		  FROM crypto_implementations
		 WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`, tenant, asset)
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	out := map[uuid.UUID]kexRow{}
	for rs.Next() {
		var r kexRow
		if err := rs.Scan(&r.id, &r.protocol, &r.version, &r.suite, &r.kex, &r.lastVerified); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		out[r.id] = r
	}
	_ = rs.Close()
	for id, r := range out {
		lr, err := svc.db.Query(`
			SELECT a.code || CASE WHEN cia.is_inferred THEN '(inf)' ELSE '' END
			  FROM crypto_implementation_algorithms cia JOIN algorithms a ON a.id = cia.algorithm_id
			 WHERE cia.crypto_implementation_id = $1 AND cia.algorithm_type = 'key_exchange'`, id)
		if err != nil {
			t.Fatalf("read links: %v", err)
		}
		for lr.Next() {
			var s string
			if err := lr.Scan(&s); err != nil {
				t.Fatalf("scan link: %v", err)
			}
			r.links = append(r.links, s)
		}
		_ = lr.Close()
		sort.Strings(r.links)
		out[id] = r
	}
	return out
}

func onlyRow(t *testing.T, rows map[uuid.UUID]kexRow) kexRow {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("rows = %d (%+v), want 1", len(rows), rows)
	}
	for _, r := range rows {
		return r
	}
	return kexRow{}
}

func pqcCountsOf(t *testing.T, svc *AssetService, tenant uuid.UUID) pqcCounts {
	t.Helper()
	c, err := classifyTenantImplementationsPQC(svc.db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	return c
}

// A label link can reach a row AFTER it was refined: a passive observation's
// link step runs after its transaction commits, outside the per-asset lock, so
// an active probe can refine the row in between. The next observation of the
// endpoint — active or passive — must repair it, or the hybrid configuration
// reads vulnerable for ever.
func TestIntegration_KexGuard_LateLabelLinkIsRepaired(t *testing.T) {
	for _, next := range []struct {
		name string
		f    func() IngestFinding
	}{
		{"by the next active probe", func() IngestFinding { return activeTLS13("X25519MLKEM768") }},
		{"by the next passive observation", passiveTLS13},
	} {
		t.Run(next.name, func(t *testing.T) {
			svc, tenant, asset := newSSHIngestFixture(t, "kex-late.example.test")
			ingestSSH(t, svc, tenant, asset, passiveTLS13())
			row := onlyRow(t, kexRows(t, svc, tenant, asset))
			// The passive ingest has committed its row but not yet linked it.
			if _, err := svc.db.Exec(`DELETE FROM crypto_implementation_algorithms WHERE crypto_implementation_id=$1 AND algorithm_type='key_exchange'`, row.id); err != nil {
				t.Fatalf("reproduce the unlinked state: %v", err)
			}
			ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))
			// ...and now the passive ingest's delayed link step runs.
			if err := svc.classifyAndLinkAlgorithms(row.id, passiveTLS13()); err != nil {
				t.Fatalf("late link: %v", err)
			}
			if got := onlyRow(t, kexRows(t, svc, tenant, asset)).links; len(got) != 2 {
				t.Fatalf("fixture links = %v, want the stuck {ECDHE, group} state", got)
			}

			ingestSSH(t, svc, tenant, asset, next.f())

			r := onlyRow(t, kexRows(t, svc, tenant, asset))
			if len(r.links) != 1 || r.links[0] != "X25519MLKEM768" {
				t.Errorf("links = %v, want only X25519MLKEM768 — the late ECDHE link must be repaired", r.links)
			}
			if c := pqcCountsOf(t, svc, tenant); c.PQCReady != 1 || c.NeedsMigration != 0 {
				t.Errorf("classified as %+v, want PQCReady=1", c)
			}
		})
	}
}

// A group that had no catalogue row when it was first measured rewrote the
// column but, correctly, kept the label link. Once the row exists, the next
// probe must finish the job. The pre-catalogue state is reproduced on the
// tenant's own row rather than by deleting a seeded catalogue row other suites
// read.
func TestIntegration_KexGuard_GroupCataloguedLaterIsRepaired(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-later.example.test")
	ingestSSH(t, svc, tenant, asset, passiveTLS13())
	row := onlyRow(t, kexRows(t, svc, tenant, asset))
	if _, err := svc.db.Exec(`UPDATE crypto_implementations SET key_exchange_algorithm='SecP384r1MLKEM1024' WHERE tenant_id=$1 AND id=$2`, tenant, row.id); err != nil {
		t.Fatalf("reproduce the pre-catalogue state: %v", err)
	}

	ingestSSH(t, svc, tenant, asset, activeTLS13("SecP384r1MLKEM1024"))

	r := onlyRow(t, kexRows(t, svc, tenant, asset))
	if r.kex != "SecP384r1MLKEM1024" || len(r.links) != 1 || r.links[0] != "SecP384r1MLKEM1024" {
		t.Errorf("row = %s with links %v, want only SecP384r1MLKEM1024", r.kex, r.links)
	}
	if c := pqcCountsOf(t, svc, tenant); c.PQCReady != 1 {
		t.Errorf("classified as %+v, want PQCReady=1", c)
	}
}

// After a downgrade (hybrid, then plain X25519) there are two configurations,
// correctly. Passive traffic must keep the CURRENT one fresh, not the
// superseded hybrid, or the stale row would never age out.
func TestIntegration_KexGuard_PassiveTrafficKeepsTheCurrentGroupFresh(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-downgrade.example.test")
	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))
	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519"))
	before := kexRows(t, svc, tenant, asset)
	if len(before) != 2 {
		t.Fatalf("rows = %d, want 2 after the downgrade", len(before))
	}

	ingestSSH(t, svc, tenant, asset, passiveTLS13())

	after := kexRows(t, svc, tenant, asset)
	if len(after) != 2 {
		t.Fatalf("rows = %d, want the same 2", len(after))
	}
	for id, a := range after {
		b := before[id]
		switch a.kex {
		case "X25519MLKEM768":
			if !a.lastVerified.Equal(b.lastVerified) {
				t.Errorf("the superseded hybrid row was refreshed by passive traffic (%v → %v)", b.lastVerified, a.lastVerified)
			}
		case "X25519":
			if !a.lastVerified.After(b.lastVerified) {
				t.Errorf("the current X25519 row was not refreshed by passive traffic (%v → %v)", b.lastVerified, a.lastVerified)
			}
		default:
			t.Errorf("unexpected row %+v", a)
		}
		for _, l := range a.links {
			if strings.HasPrefix(l, "ECDHE") {
				t.Errorf("row %s gained a label link %v", a.kex, a.links)
			}
		}
	}
}

// A group a passive observation adopted was not measured by it, and is linked
// as inferred. (Normally the row already holds the measured link, which the
// adopting observation's insert leaves in place; this pins the case where it
// does not.)
func TestIntegration_KexGuard_AdoptedGroupIsLinkedAsInferred(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-adopted.example.test")
	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))
	row := onlyRow(t, kexRows(t, svc, tenant, asset))
	if _, err := svc.db.Exec(`DELETE FROM crypto_implementation_algorithms WHERE crypto_implementation_id=$1 AND algorithm_type='key_exchange'`, row.id); err != nil {
		t.Fatalf("clear links: %v", err)
	}

	ingestSSH(t, svc, tenant, asset, passiveTLS13())

	r := onlyRow(t, kexRows(t, svc, tenant, asset))
	if len(r.links) != 1 || r.links[0] != "X25519MLKEM768(inf)" {
		t.Errorf("links = %v, want X25519MLKEM768 linked as inferred by the adopting observation", r.links)
	}
}

// DH-ECP-256/384/521 are also the catalogue codes of IKE groups. An IPsec
// configuration must never be refined or adopt a group.
func TestIntegration_KexGuard_IPsecIsNeverRefined(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-ipsec.example.test")
	ipsec := func(kex string) IngestFinding {
		v, k := "IKEv2", kex
		return IngestFinding{Protocol: "IPSec", ProtocolVersion: &v, KeyExchangeAlgorithm: &k,
			RawData: map[string]interface{}{"discovery_method": "device_interrogation"}}
	}
	ingestSSH(t, svc, tenant, asset, ipsec("ECDHE"))
	ingestSSH(t, svc, tenant, asset, ipsec("DH-ECP-256"))
	ingestSSH(t, svc, tenant, asset, ipsec("ECDHE"))

	rows := kexRows(t, svc, tenant, asset)
	var kexes []string
	for _, r := range rows {
		kexes = append(kexes, r.kex)
		if r.protocol != "IPSec" {
			t.Fatalf("fixture row protocol = %s, want IPSec", r.protocol)
		}
	}
	sort.Strings(kexes)
	if len(kexes) != 2 || kexes[0] != "DH-ECP-256" || kexes[1] != "ECDHE" {
		t.Errorf("IPsec key exchanges = %v, want [DH-ECP-256 ECDHE] untouched", kexes)
	}
}

// A measured group on one port must not refine, or be adopted by, the
// configuration on another port of the same asset.
func TestIntegration_KexGuard_OtherPortIsUntouched(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-ports.example.test")
	on := func(f IngestFinding, port int) IngestFinding {
		ip, p := "192.0.2.7", port
		f.IPAddress, f.Port = &ip, &p
		return f
	}
	ingestSSH(t, svc, tenant, asset, on(passiveTLS13(), 443))
	ingestSSH(t, svc, tenant, asset, on(activeTLS13("X25519MLKEM768"), 8443))
	ingestSSH(t, svc, tenant, asset, on(passiveTLS13(), 443))

	labels := 0
	for _, r := range kexRows(t, svc, tenant, asset) {
		if r.kex == "ECDHE" {
			labels++
		}
	}
	if labels != 1 {
		t.Errorf("the :443 label configuration was refined by, or adopted, the :8443 group (label rows = %d)", labels)
	}
}

// Every configuration that is not the same TLS configuration seen less
// precisely is left exactly as it was: other protocols, other versions, other
// suites, and key exchanges that are not an ephemeral-EC family label (DHE,
// static ECDH, an SSH kex name). And refinement removes only LABEL links from
// the row it refines — another key_exchange link there is evidence and stays.
func TestIntegration_KexGuard_OtherConfigurationsAreUntouched(t *testing.T) {
	svc, tenant, asset := newSSHIngestFixture(t, "kex-others.example.test")

	withKex := func(kex string) IngestFinding {
		f := passiveTLS13()
		k := kex
		f.KeyExchangeAlgorithm = &k
		return f
	}
	tls12 := passiveTLS13()
	v12 := "TLS 1.2"
	tls12.ProtocolVersion = &v12
	ccm := passiveTLS13()
	ccmSuite := "TLS_AES_128_CCM_SHA256"
	ccm.CipherSuite = &ccmSuite
	// No version and no suite, so every other component is compatible with the
	// TLS observation: only the protocol tells them apart.
	ipsecK := "ECDHE"
	ipsec := IngestFinding{Protocol: "IPSec", KeyExchangeAlgorithm: &ipsecK,
		RawData: map[string]interface{}{"discovery_method": "device_interrogation"}}

	for _, f := range []IngestFinding{
		passiveTLS13(),               // the one configuration the group refines
		modernSSHFinding(),           // SSH: inferred (offered) key_exchange links of its own
		tls12,                        // label, but another version
		ccm,                          // label, but another suite (same cipher and hash)
		ipsec,                        // label, but another protocol
		withKex("DHE"),               // finite-field: not a label
		withKex("ECDH"),              // static ECDH: not a label
		withKex("curve25519-sha256"), // an SSH name: not a label
	} {
		ingestSSH(t, svc, tenant, asset, f)
	}

	before := kexRows(t, svc, tenant, asset)
	var target uuid.UUID
	for id, r := range before {
		if r.protocol == "TLS" && r.version == "TLS 1.3" && r.suite == "TLS_AES_128_GCM_SHA256" && r.kex == "ECDHE" {
			target = id
		}
	}
	if target == uuid.Nil || len(before) != 8 {
		t.Fatalf("fixture = %d rows %+v, want 8 with one TLS 1.3 GCM ECDHE row", len(before), before)
	}
	// Another (non-label) key_exchange link on the row that will be refined.
	if _, err := svc.db.Exec(`
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		SELECT $1, id, 'key_exchange', true FROM algorithms WHERE code = 'DHE'`, target); err != nil {
		t.Fatalf("add offered link: %v", err)
	}

	ingestSSH(t, svc, tenant, asset, activeTLS13("X25519MLKEM768"))

	after := kexRows(t, svc, tenant, asset)
	for id, b := range before {
		a, ok := after[id]
		if !ok {
			t.Errorf("row %+v disappeared", b)
			continue
		}
		if id == target {
			if a.kex != "X25519MLKEM768" {
				t.Errorf("target key exchange = %q, want X25519MLKEM768", a.kex)
			}
			if strings.Join(a.links, ",") != "DHE(inf),X25519MLKEM768" {
				t.Errorf("target links = %v, want the label gone and the other link kept", a.links)
			}
			continue
		}
		if a.kex != b.kex || strings.Join(a.links, ",") != strings.Join(b.links, ",") {
			t.Errorf("%s %s %s row changed: %s %v → %s %v", b.protocol, b.version, b.suite, b.kex, b.links, a.kex, a.links)
		}
	}
}

// Two tenants may hold the SAME asset id (assets are keyed by tenant and id).
// A group measured in one tenant must not touch the other's configuration —
// asserted on the owner connection, where row-level security does not hide a
// missing tenant predicate.
func TestIntegration_KexGuard_OtherTenantIsUntouched(t *testing.T) {
	svc, tenantA, asset := newSSHIngestFixture(t, "kex-tenant-a.example.test")
	tenantB := testdb.NewTenant(t, svc.db.DB.DB)
	if _, err := svc.db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'kex-tenant-b.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, asset, tenantB); err != nil {
		t.Fatalf("insert tenant B asset: %v", err)
	}
	ingestSSH(t, svc, tenantB, asset, passiveTLS13())
	ingestSSH(t, svc, tenantA, asset, activeTLS13("X25519MLKEM768"))

	b := onlyRow(t, kexRows(t, svc, tenantB, asset))
	if b.kex != "ECDHE" || len(b.links) != 1 || b.links[0] != "ECDHE(inf)" {
		t.Errorf("tenant B row = %s %v, want its ECDHE label untouched", b.kex, b.links)
	}
}
