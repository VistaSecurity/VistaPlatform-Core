package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"testing"
)

func TestIntegration_CryptoEndpointReads(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	other := testdb.NewTenant(t, raw)
	svc := NewCryptoImplementationService(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	asset := uuid.New()
	if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status) VALUES($1,$2,'multi.example.test','server','hardware.computer.server','monitoring')`, asset, tenant); err != nil {
		t.Fatal(err)
	}
	endpoints := map[uuid.UUID]uuid.UUID{}
	certs := map[uuid.UUID]uuid.UUID{}
	for _, port := range []int{443, 8443} {
		ep, cert, config := uuid.New(), uuid.New(), uuid.New()
		if _, err := raw.Exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport,protocol) VALUES($1,$2,$3,'192.0.2.50',$4,'tcp','TLS')`, ep, tenant, asset, port); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO certificates(id,tenant_id,subject_dn,issuer_dn,fingerprint_sha256) VALUES($1,$2,'CN=multi.example.test','CN=CA',$3)`, cert, tenant, fmt.Sprintf("%x", sha256.Sum256([]byte(cert.String())))); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,endpoint_id,certificate_id,protocol,discovery_method) VALUES($1,$2,$3,$4,$5,'TLS','passive')`, config, tenant, asset, ep, cert); err != nil {
			t.Fatal(err)
		}
		endpoints[config] = ep
		certs[config] = cert
	}
	legacy := uuid.New()
	if _, err := raw.Exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,protocol,discovery_method) VALUES($1,$2,$3,'TLS','passive')`, legacy, tenant, asset); err != nil {
		t.Fatal(err)
	}
	// Name improvement must not disturb either endpoint's certificate or curated placement/class.
	if _, err := raw.Exec(`UPDATE assets SET hostname='aabbccddeeff.local',display_name='aabbccddeeff.local',site='Curated',class_source_kind='declared',metadata='{"name_source_kind":"measured-active"}' WHERE id=$1`, asset); err != nil {
		t.Fatal(err)
	}
	if err := pgrepo.New(raw).PromoteNames(context.Background(), identity.AssetRef{TenantID: tenant.String(), ID: asset.String()}, "multi.example.test", "multi.example.test", "measured-active"); err != nil {
		t.Fatal(err)
	}
	var name, site, class, kind string
	if err := raw.QueryRow(`SELECT hostname,site,class_key,class_source_kind FROM assets WHERE id=$1 AND tenant_id=$2`, asset, tenant).Scan(&name, &site, &class, &kind); err != nil {
		t.Fatal(err)
	}
	if name != "multi.example.test" || site != "Curated" || class != "server" || kind != "declared" {
		t.Fatalf("promotion changed context: %s %s %s %s", name, site, class, kind)
	}
	rows, total, err := svc.GetCryptoImplementations(tenant, models.CryptoImplementationFilters{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total=%d", total)
	}
	for _, row := range rows {
		detail, err := svc.GetCryptoImplementationByID(tenant, row.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, got := range []*models.CryptoImplementation{&row, detail} {
			if row.ID == legacy {
				if got.EndpointID != nil {
					t.Fatal("invented legacy endpoint")
				}
				continue
			}
			if got.EndpointID == nil || *got.EndpointID != endpoints[row.ID] || got.CertificateID == nil || *got.CertificateID != certs[row.ID] {
				t.Fatalf("lost endpoint/certificate attachment: %+v", got)
			}
		}
		if _, err := svc.GetCryptoImplementationByID(other, row.ID); err == nil {
			t.Fatal("cross-tenant detail exposed")
		}
	}
	rows, total, err = svc.GetCryptoImplementations(other, models.CryptoImplementationFilters{})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("cross-tenant list: %v %d %v", rows, total, err)
	}
}
