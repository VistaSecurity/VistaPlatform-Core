package certtrust_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

// Issuer names and key identifiers are claims, not signature verification.
// Both iteration orders matter: an invalid leaf must neither borrow a valid
// leaf's issuer verdict nor prevent a later valid leaf finding its issuer.
func TestIntegration_PresentedCacheVerifiesEveryLeaf(t *testing.T) {
	for _, invalidFirst := range []bool{false, true} {
		name := "valid-first"
		if invalidFirst {
			name = "invalid-first"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			root := issue(t, "Cache Root", true, nil)
			good := issue(t, "valid.example.test", false, &root)
			// Corrupt only the signature; the DER remains parseable with precisely
			// the same issuer DN and AKI as the valid leaf.
			der := append([]byte(nil), good.cert.Raw...)
			der[len(der)-1] ^= 1
			bad, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if bad.CheckSignatureFrom(root.cert) == nil {
				t.Fatal("invalid fixture signature verified")
			}
			ids := f.ingest(t, root.cert)
			_, err = f.store.CreateAnchor(context.Background(), f.tenant, certtrust.CreateRequest{CertificateID: &ids[0], Decision: certtrust.DecisionTrusted})
			if err != nil {
				t.Fatal(err)
			}
			leaves := []*x509.Certificate{good.cert, bad}
			wants := []string{certtrust.StatusPrivateTrusted, certtrust.StatusIncomplete}
			if invalidFirst {
				leaves[0], leaves[1] = leaves[1], leaves[0]
				wants[0], wants[1] = wants[1], wants[0]
			}
			for i, leaf := range leaves {
				id := uuid.UUID{15: byte(i + 1)}
				_, err := f.raw.Exec(`INSERT INTO external_connections (id,tenant_id,source_ip,dest_ip,dest_port,protocol,cert_pem) VALUES ($1,$2,'192.0.2.1','198.51.100.1',$3,'TLS',$4)`, id, f.tenant, 443+i, pemOf(leaf))
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.eval.RecomputeExternalConnections(context.Background(), f.tenant); err != nil {
				t.Fatal(err)
			}
			for i, want := range wants {
				var got string
				if err := f.raw.QueryRow(`SELECT trust_status FROM external_connections WHERE tenant_id=$1 AND id=$2`, f.tenant, uuid.UUID{15: byte(i + 1)}).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Errorf("leaf %d trust=%q; want %q", i, got, want)
				}
			}
		})
	}
}

// Discovery stores served order as issuer links. A server appending a trusted
// CA to an unrelated certificate must not manufacture a trusted chain.
func TestIntegration_TrustVerifiesStoredIssuerLinks(t *testing.T) {
	f := newFixture(t)
	trusted := issue(t, "Trusted Root", true, nil)
	other := issue(t, "Unrelated Root", true, nil)
	leaf := issue(t, "unrelated.example.test", false, &other)
	ids := f.ingest(t, leaf.cert, trusted.cert)
	_, err := f.store.CreateAnchor(context.Background(), f.tenant, certtrust.CreateRequest{CertificateID: &ids[1], Decision: certtrust.DecisionTrusted})
	if err != nil {
		t.Fatal(err)
	}
	got := f.trust(t, ids[0])
	if got.status.String != certtrust.StatusIncomplete {
		t.Fatalf("unverified issuer link gave %q; want incomplete", got.status.String)
	}
}
