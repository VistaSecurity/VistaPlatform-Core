package handlers

// bom-ref uniqueness for the bytes we hash, sign, serve and call evidence.
//
// A CycloneDX bom-ref identifies a component *within its document*: the schema
// puts uniqueItems on `components` and on `dependencies`, and refLinkType edges
// are resolved by ref. Algorithm components were de-duplicated on a tuple of
// (implementation, role, code) but published a bom-ref of `crypto/algorithm/
// <code>` alone — neither the implementation nor the role. Two components that
// legitimately survived de-duplication therefore shared one ref.
//
// The reproducing case is ordinary rather than exotic: a TLS configuration that
// negotiates an RSA key exchange against a certificate carrying an RSA public
// key. Two components, both named RSA, both `crypto/algorithm/rsa`, byte-equal
// once serialised — and the artifact is rejected by the very schema an auditor
// runs it through, at `/components: items at N and M are equal`.
//
// The two-assets-one-cipher case is the milder half: the components differ (the
// asset properties differ) so uniqueItems passes, but both claim the same ref,
// so a reader resolving a dependency edge cannot tell which component it names.
//
// These tests validate the real emitter's output against the repo's vendored
// official 1.7 schema, so they fail on the actual defect rather than on a
// restatement of it.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
)

const cdxSchemaBase = "http://cyclonedx.org/schema/"

// A fixed timestamp keeps the emitted document byte-stable between runs.
var fixedGeneratedAt = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

// compileCycloneDX17Schema loads the vendored schema set (the same files the
// formatters package validates against) and compiles the 1.7 BOM schema. The
// sibling documents are registered under the URIs the BOM schema resolves them
// to, so nothing reaches the network.
func compileCycloneDX17Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()
	c.AssertFormat()

	dir := filepath.Join("..", "formatters", "testdata", "cyclonedx")
	for _, name := range []string{
		"bom-1.7.schema.json",
		"spdx.schema.json",
		"jsf-0.82.schema.json",
		"cryptography-defs.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read vendored schema %s: %v", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("parse vendored schema %s: %v", name, err)
		}
		if err := c.AddResource(cdxSchemaBase+name, doc); err != nil {
			t.Fatalf("add vendored schema %s: %v", name, err)
		}
	}

	sch, err := c.Compile(cdxSchemaBase + "bom-1.7.schema.json")
	if err != nil {
		t.Fatalf("compile bom-1.7.schema.json: %v", err)
	}
	return sch
}

// emitCBOM runs the fixture through the same path an artifact takes:
// assembleComponents → CBOMData → FormatCBOMAsCanonicalJSON.
func emitCBOM(t *testing.T, assets, cryptos, certs []map[string]interface{}) []byte {
	t.Helper()

	handler := &CBOMReportHandler{}
	components, _ := handler.assembleComponents(
		assets, cryptos, certs,
		nil, // algorithmLookup — nil triggers the heuristic fallback
		compilePredicate(AssetPredicate{}),
		true, true, true, true, true,
	)

	out, err := formatters.NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(&models.CBOMData{
		SerialNumber: "11111111-2222-3333-4444-555555555555",
		BOMVersion:   1,
		GeneratedAt:  fixedGeneratedAt,
		ReportTitle:  "Cryptographic Bill of Materials",
		Summary:      buildCBOMSummary(components),
		Components:   components,
	})
	if err != nil {
		t.Fatalf("FormatCBOMAsCanonicalJSON: %v", err)
	}
	return out
}

// fixtureRSA is the reproducing case: one crypto
// configuration whose key exchange is RSA and whose certificate's public key is
// also RSA, with the same key size on both — so the two algorithm components
// serialise to identical objects under a single shared bom-ref.
func fixtureRSA() (assets, cryptos, certs []map[string]interface{}) {
	assets = []map[string]interface{}{
		{
			"id":             "asset-1",
			"tenant_id":      "tenant-1",
			"name":           "api-01",
			"asset_type":     "server",
			"environment":    "production",
			"ip_address":     "203.0.113.10",
			"hostname":       "api-01.example.test",
			"risk_level":     "high",
			"certificate_id": "cert-1",
		},
	}
	cryptos = []map[string]interface{}{
		{
			"id":                     "impl-1",
			"tenant_id":              "tenant-1",
			"asset_id":               "asset-1",
			"certificate_id":         "cert-1",
			"protocol":               "TLS",
			"protocol_version":       "1.2",
			"key_exchange_algorithm": "RSA",
			"key_size":               2048,
			"libraries": []map[string]interface{}{
				{"id": "lib-1", "name": "OpenSSL", "version": "3.2.1"},
			},
		},
	}
	certs = []map[string]interface{}{
		{
			"id":                   "cert-1",
			"tenant_id":            "tenant-1",
			"common_name":          "api.example.test",
			"subject_dn":           "CN=api.example.test",
			"issuer_dn":            "CN=Example CA",
			"public_key_algorithm": "RSA",
			"public_key_size":      2048,
			"not_before":           "2026-01-01T00:00:00Z",
			"not_after":            "2027-01-01T00:00:00Z",
		},
	}
	return assets, cryptos, certs
}

// TestEmittedCBOM_RSAKeyExchangeAndRSACertificateValidates is the centrepiece:
// the reproducing fixture, run through the real emitter, checked against the
// official CycloneDX 1.7 schema. Before the fix this failed on uniqueItems.
func TestEmittedCBOM_RSAKeyExchangeAndRSACertificateValidates(t *testing.T) {
	t.Parallel()

	assets, cryptos, certs := fixtureRSA()
	out := emitCBOM(t, assets, cryptos, certs)

	sch := compileCycloneDX17Schema(t)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("emitted document is not valid JSON: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("emitted CBOM does not validate against the official CycloneDX 1.7 "+
			"schema:\n%v\n--- document ---\n%s", err, string(out))
	}
}

// TestEmittedCBOM_BOMRefsAreUnique states the invariant directly, so a future
// regression is reported as what it is rather than as a schema stack trace. It
// also covers `dependencies`, whose entries are emitted one per component and
// carry the same refs.
func TestEmittedCBOM_BOMRefsAreUnique(t *testing.T) {
	t.Parallel()

	assets, cryptos, certs := fixtureRSA()
	out := emitCBOM(t, assets, cryptos, certs)
	doc := decodeEmitted(t, out)

	if len(doc.Components) < 2 {
		t.Fatalf("fixture produced %d components; it no longer exercises the collision", len(doc.Components))
	}

	seen := map[string]int{}
	for _, comp := range doc.Components {
		if comp.BOMRef == "" {
			t.Errorf("component %q has no bom-ref", comp.Name)
			continue
		}
		seen[comp.BOMRef]++
	}
	for ref, n := range seen {
		if n > 1 {
			t.Errorf("bom-ref %q is claimed by %d components; refs must identify exactly one", ref, n)
		}
	}

	// The fixture must actually contain the two RSA components, or a change that
	// dropped one of them would make this test vacuously green.
	var rsaAlgorithms int
	for _, comp := range doc.Components {
		if comp.Name == "RSA" && comp.CryptoProperties != nil && comp.CryptoProperties.AlgorithmProperties != nil {
			rsaAlgorithms++
		}
	}
	if rsaAlgorithms < 2 {
		t.Fatalf("expected both the key-exchange and certificate-key RSA components, got %d", rsaAlgorithms)
	}

	depRefs := map[string]int{}
	for _, dep := range doc.Dependencies {
		depRefs[dep.Ref]++
	}
	if len(depRefs) == 0 {
		t.Fatal("no dependency entries emitted; the fixture no longer exercises the graph")
	}
	for ref, n := range depRefs {
		if n > 1 {
			t.Errorf("dependencies contains %d entries for ref %q; the array requires unique items", n, ref)
		}
	}
}

// TestEmittedCBOM_SameAlgorithmOnTwoAssetsGetsDistinctRefs covers the milder
// half: identical crypto on two assets used to publish one ref for two distinct
// components, so a dependency edge naming that ref was ambiguous to a reader.
func TestEmittedCBOM_SameAlgorithmOnTwoAssetsGetsDistinctRefs(t *testing.T) {
	t.Parallel()

	assets := []map[string]interface{}{
		{"id": "asset-1", "tenant_id": "tenant-1", "name": "api-01", "asset_type": "server", "environment": "production", "ip_address": "203.0.113.10"},
		{"id": "asset-2", "tenant_id": "tenant-1", "name": "api-02", "asset_type": "server", "environment": "production", "ip_address": "203.0.113.11"},
	}
	cryptos := []map[string]interface{}{
		{"id": "impl-1", "tenant_id": "tenant-1", "asset_id": "asset-1", "protocol": "TLS", "protocol_version": "1.3", "symmetric_encryption": "AES-256-GCM", "key_size": 256},
		{"id": "impl-2", "tenant_id": "tenant-1", "asset_id": "asset-2", "protocol": "TLS", "protocol_version": "1.3", "symmetric_encryption": "AES-256-GCM", "key_size": 256},
	}

	out := emitCBOM(t, assets, cryptos, nil)
	doc := decodeEmitted(t, out)

	seen := map[string]int{}
	var aesComponents int
	for _, comp := range doc.Components {
		seen[comp.BOMRef]++
		if comp.Name == "AES-256-GCM" {
			aesComponents++
		}
	}
	if aesComponents != 2 {
		t.Fatalf("expected one AES component per asset, got %d", aesComponents)
	}
	for ref, n := range seen {
		if n > 1 {
			t.Errorf("bom-ref %q is claimed by %d components across two assets", ref, n)
		}
	}
}

// TestResolveComponentRefs_DeduplicatesCollidingRefs exercises the backstop on
// its own. No builder can reach it today — every ref is derived from the
// component id — so it is fed a collision directly, which is the only way to
// know it works at all rather than merely being present. It must rename the
// duplicate (never drop it) and dependency edges, which arrive as internal
// component ids, must resolve to the renamed refs.
func TestResolveComponentRefs_DeduplicatesCollidingRefs(t *testing.T) {
	t.Parallel()

	build := func() []models.CBOMComponent {
		return []models.CBOMComponent{
			{ID: "algorithm:a", BOMRef: "crypto/algorithm/rsa", Name: "RSA", Type: models.CBOMComponentTypeAlgorithm},
			{ID: "algorithm:b", BOMRef: "crypto/algorithm/rsa", Name: "RSA", Type: models.CBOMComponentTypeAlgorithm},
			{ID: "algorithm:c", BOMRef: "crypto/algorithm/rsa", Name: "RSA", Type: models.CBOMComponentTypeAlgorithm},
			{ID: "protocol:p", BOMRef: "crypto/protocol/p", Name: "TLS 1.2", Type: models.CBOMComponentTypeProtocol,
				DependsOn: []string{"algorithm:a", "algorithm:b", "algorithm:c"}},
		}
	}

	components := build()
	resolveComponentRefs(components)

	seen := map[string]bool{}
	for _, c := range components {
		if seen[c.BOMRef] {
			t.Errorf("duplicate bom-ref survived: %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
	if len(components) != 4 {
		t.Fatalf("components were dropped rather than renamed: %d remain", len(components))
	}

	// Every edge must still land on a component in the document — renaming a ref
	// without repointing its edges would trade one broken graph for another.
	deps := components[3].DependsOn
	if len(deps) != 3 {
		t.Fatalf("dependency edges = %v, want 3 resolved refs", deps)
	}
	for _, d := range deps {
		if !seen[d] {
			t.Errorf("dependency %q resolves to nothing in this document", d)
		}
	}

	// Deterministic: same input, same refs. An artifact's content hash depends
	// on it.
	second := build()
	resolveComponentRefs(second)
	for i := range components {
		if components[i].BOMRef != second[i].BOMRef {
			t.Errorf("ref for %s is not deterministic: %q vs %q",
				components[i].ID, components[i].BOMRef, second[i].BOMRef)
		}
	}
}

func decodeEmitted(t *testing.T, raw []byte) formatters.CDXDocument {
	t.Helper()
	var doc formatters.CDXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal emitted document: %v", err)
	}
	return doc
}
