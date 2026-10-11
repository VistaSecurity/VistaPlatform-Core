package services

// The `cert_trust` asset facet and query field and the certificates
// list's trust_status filter.
//
// The facet groups assets by the WORST trust status of their certificates;
// the rail's click writes `cert_trust:<key>`, which compiles to the same
// expression. This pins both the ordering (distrusted > untrusted >
// self_signed > incomplete > private_trusted > public), the two non-status
// buckets (unevaluated, none), and that the click lists exactly the assets
// the bucket counted.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetFacets_CertTrustIsTheWorstAndAgreesWithTheQuery(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	addAsset := func(hostname string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status,
		                          last_seen_at, first_discovered_at, created_at, updated_at)
		      VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
			id, tenant, hostname)
		return id
	}
	// addCert deploys a certificate with the given trust status ("" = NULL)
	// on the asset, through a configuration and the junction — the link
	// ingest writes.
	impls := map[uuid.UUID]uuid.UUID{}
	addCert := func(asset uuid.UUID, status string) uuid.UUID {
		impl, ok := impls[asset]
		if !ok {
			impl = uuid.New()
			impls[asset] = impl
			exec(`INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
			      VALUES ($1, $2, $3, 'TLS', 'passive', NOW(), NOW())`, impl, tenant, asset)
		}
		cert := uuid.New()
		var ts interface{}
		if status != "" {
			ts = status
		}
		exec(`INSERT INTO certificates (id, tenant_id, serial_number, subject_dn, issuer_dn, fingerprint_sha256,
		                                not_before, not_after, trust_status, created_at, updated_at)
		      VALUES ($1, $2, '01', 'CN=a', 'CN=b', encode(gen_random_bytes(32), 'hex'),
		              NOW(), NOW() + interval '1 year', $3, NOW(), NOW())`, cert, tenant, ts)
		exec(`INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		      VALUES ($1, $2, 'leaf')`, impl, cert)
		return cert
	}

	want := map[string][]string{}
	mk := func(key, hostname string, statuses ...string) {
		a := addAsset(hostname)
		for _, s := range statuses {
			addCert(a, s)
		}
		want[key] = append(want[key], hostname)
	}
	mk("distrusted", "h-distrusted", "public", "distrusted", "untrusted")
	mk("untrusted", "h-untrusted", "self_signed", "untrusted", "private_trusted")
	mk("self_signed", "h-self", "incomplete", "self_signed")
	mk("incomplete", "h-incomplete", "private_trusted", "incomplete", "")
	mk("private_trusted", "h-private", "public", "private_trusted")
	mk("public", "h-public-1", "public")
	mk("public", "h-public-2", "public", "public")
	mk("unevaluated", "h-unevaluated", "", "")
	mk("none", "h-none")

	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "cert_trust", 50)
	if err != nil {
		t.Fatalf("GetAssetFacets(cert_trust): %v", err)
	}
	got := map[string]int{}
	for _, b := range buckets {
		got[b.Key] = b.Count
	}
	for key, hosts := range want {
		if got[key] != len(hosts) {
			t.Errorf("bucket %s = %d, want %d (%v)", key, got[key], len(hosts), got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("buckets %v, want exactly %d keys", got, len(want))
	}

	// The click: each bucket's query lists exactly its assets.
	for key, hosts := range want {
		listed, total, err := svc.GetAssets(tenant, models.AssetFilters{Query: "cert_trust:" + key, Page: 1, PageSize: 50})
		if err != nil {
			t.Fatalf("GetAssets(cert_trust:%s): %v", key, err)
		}
		var names []string
		for _, a := range listed {
			if a.Hostname != nil {
				names = append(names, *a.Hostname)
			}
		}
		sort.Strings(names)
		sort.Strings(hosts)
		if total != len(hosts) || len(names) != len(hosts) {
			t.Errorf("cert_trust:%s listed %v (total %d), want %v", key, names, total, hosts)
			continue
		}
		for i := range names {
			if names[i] != hosts[i] {
				t.Errorf("cert_trust:%s listed %v, want %v", key, names, hosts)
				break
			}
		}
	}

	// And the facet honours the list's filter: narrowed to one asset, one bucket.
	narrowed, err := svc.GetAssetFacets(tenant, models.AssetFilters{Query: "hostname:h-private"}, "cert_trust", 50)
	if err != nil {
		t.Fatalf("narrowed facet: %v", err)
	}
	if len(narrowed) != 1 || narrowed[0].Key != "private_trusted" || narrowed[0].Count != 1 {
		t.Errorf("narrowed facet = %+v, want one private_trusted", narrowed)
	}

	advertised := false
	for _, l := range AssetFacetLevels() {
		if l == "cert_trust" {
			advertised = true
		}
	}
	if !advertised {
		t.Error("AssetFacetLevels() does not advertise cert_trust")
	}
}

func TestIntegration_GetCertificates_TrustStatusFilter(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &CertificateService{db: db}

	ids := map[string]uuid.UUID{}
	for _, status := range []string{"public", "untrusted", "distrusted", ""} {
		id := uuid.New()
		var ts interface{}
		if status != "" {
			ts = status
		}
		if _, err := db.Exec(`INSERT INTO certificates (id, tenant_id, serial_number, subject_dn, issuer_dn, fingerprint_sha256,
		                                not_before, not_after, trust_status, created_at, updated_at)
		      VALUES ($1, $2, '01', 'CN=a', 'CN=b', encode(gen_random_bytes(32), 'hex'),
		              NOW(), NOW() + interval '1 year', $3, NOW(), NOW())`, id, tenant, ts); err != nil {
			t.Fatal(err)
		}
		ids[status] = id
	}
	for _, tc := range []struct {
		filter []string
		want   []string
	}{
		{[]string{"untrusted"}, []string{"untrusted"}},
		{[]string{"untrusted", "distrusted"}, []string{"untrusted", "distrusted"}},
		{[]string{"unevaluated"}, []string{""}},
		{[]string{"public", "unevaluated"}, []string{"public", ""}},
	} {
		certs, total, err := svc.GetCertificates(tenant, models.CertificateFilters{TrustStatus: tc.filter, Page: 1, PageSize: 50})
		if err != nil {
			t.Fatalf("%v: %v", tc.filter, err)
		}
		got := map[uuid.UUID]bool{}
		for _, c := range certs {
			got[c.ID] = true
		}
		if total != len(tc.want) || len(got) != len(tc.want) {
			t.Errorf("trust_status=%v: %d certificates (total %d), want %d", tc.filter, len(got), total, len(tc.want))
			continue
		}
		for _, w := range tc.want {
			if !got[ids[w]] {
				t.Errorf("trust_status=%v: missing the %q certificate", tc.filter, w)
			}
		}
	}
}
