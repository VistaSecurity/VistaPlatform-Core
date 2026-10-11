package certtrust_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

// TestIntegration_TrustAnchorFromChain: the chain a server presented, leaf
// first — the CAs are stored (chain_source served), linked, the decision is
// recorded on the TOP CA, the leaf is never stored, and a second decision on
// the same CA is a conflict. Then the internal read returns it for a trust pool.
func TestIntegration_TrustAnchorFromChain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := issue(t, "Example Presented Root", true, nil)
	inter := issue(t, "Example Presented Issuing CA", true, &root)
	leaf := issue(t, "netbox.example.test", false, &inter)

	// Out of order on purpose: root before intermediate. The top is found by
	// signature, not position.
	a, err := f.store.CreateAnchorFromChain(ctx, f.tenant, certtrust.FromChainRequest{
		ChainPEM: pemOf(leaf.cert, root.cert, inter.cert), Decision: certtrust.DecisionTrusted, Note: "netbox",
	})
	if err != nil {
		t.Fatalf("CreateAnchorFromChain: %v", err)
	}
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, certtrustFingerprint(leaf.cert)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the leaf was stored (%d rows, err %v); it never should be", n, err)
	}
	var rootID, interIssuer string
	var rootSrc, interSrc string
	if err := f.raw.QueryRow(`SELECT id, chain_source FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, certtrustFingerprint(root.cert)).Scan(&rootID, &rootSrc); err != nil {
		t.Fatalf("root not stored: %v", err)
	}
	if err := f.raw.QueryRow(`SELECT COALESCE(issuer_certificate_id::text, ''), chain_source FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, certtrustFingerprint(inter.cert)).Scan(&interIssuer, &interSrc); err != nil {
		t.Fatalf("intermediate not stored: %v", err)
	}
	if rootSrc != certtrust.ChainSourceServed || interSrc != certtrust.ChainSourceServed {
		t.Errorf("chain_source root/inter = %s/%s, want served/served", rootSrc, interSrc)
	}
	if interIssuer != rootID {
		t.Errorf("intermediate not linked to the root")
	}
	if a.CertificateID.String() != rootID || a.Decision != certtrust.DecisionTrusted || a.Note == nil || *a.Note != "netbox" {
		t.Errorf("anchor %+v, want a trusted decision on the root", a)
	}

	_, err = f.store.CreateAnchorFromChain(ctx, f.tenant, certtrust.FromChainRequest{
		ChainPEM: pemOf(leaf.cert, inter.cert, root.cert), Decision: certtrust.DecisionDistrusted,
	})
	var conflict *certtrust.ErrConflict
	if !errors.As(err, &conflict) || conflict.ExistingID != a.ID {
		t.Fatalf("second decision on the same CA: err %v, want a conflict naming %s", err, a.ID)
	}

	_, err = f.store.CreateAnchorFromChain(ctx, f.tenant, certtrust.FromChainRequest{
		ChainPEM: pemOf(leaf.cert), Decision: certtrust.DecisionTrusted,
	})
	var invalid *certtrust.ErrInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("a chain with no CA: err %v, want ErrInvalid", err)
	}

	// The internal read for a trust pool: the trusted root's PEM; then, once
	// distrusted, its fingerprint instead.
	out, err := f.store.InternalAnchors(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.TrustedPEM) != 1 || !strings.Contains(out.TrustedPEM[0], "BEGIN CERTIFICATE") ||
		len(out.DistrustedFingerprintsSHA256) != 0 || out.BundleVersion == "" {
		t.Fatalf("internal anchors = %+v", out)
	}
	d := certtrust.DecisionDistrusted
	if _, err := f.store.UpdateAnchor(ctx, f.tenant, a.ID, certtrust.UpdateRequest{Decision: &d}); err != nil {
		t.Fatal(err)
	}
	out, err = f.store.InternalAnchors(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.TrustedPEM) != 0 || len(out.DistrustedFingerprintsSHA256) != 1 ||
		out.DistrustedFingerprintsSHA256[0] != strings.ToLower(certtrustFingerprint(root.cert)) {
		t.Fatalf("internal anchors after distrust = %+v", out)
	}
}
