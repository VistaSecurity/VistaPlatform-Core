package handlers

import (
	"testing"
)

// A CBOM artifact's whole claim is "this is everything matching this boundary
// at this moment".
//
// The boundary used to be evaluated HERE — an in-memory matcher over eight
// predicate dimensions — and the tests that lived in this file pinned that
// matcher's semantics. It is gone: a scope is a query string, inventory-service
// applies it in SQL, and the semantics of every dimension are pinned once, in
// shared/query, for every surface that takes a predicate.
//
// What is left for the assembly to decide is one question, and it is the one
// these tests now pin: what happens to a crypto configuration or a certificate
// that names NO asset in the fetched set.

func assets() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":          "asset-prod",
			"tenant_id":   "tenant-1",
			"hostname":    "prod-01",
			"asset_type":  "server",
			"environment": "production",
			"risk_level":  "high",
		},
		{
			"id":          "asset-staging",
			"tenant_id":   "tenant-1",
			"hostname":    "staging-01",
			"asset_type":  "loadbalancer",
			"environment": "staging",
			"risk_level":  "medium",
		},
	}
}

func implementations() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": "impl-prod", "asset_id": "asset-prod", "protocol": "TLS", "protocol_version": "1.3"},
		{"id": "impl-staging", "asset_id": "asset-staging", "protocol": "TLS", "protocol_version": "1.3"},
		// A configuration whose asset is NOT in the fetched set. Under a
		// narrowing scope that is precisely what "out of scope" looks like from
		// here: inventory-service did not return the asset, so the assembly
		// must not include what hangs off it.
		{"id": "impl-orphan", "asset_id": "asset-filtered-out", "protocol": "TLS", "protocol_version": "1.2"},
	}
}

func standaloneCerts() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"id":          "cert-unassigned",
			"tenant_id":   "tenant-1",
			"common_name": "uploaded.example.com",
			"subject_dn":  "CN=uploaded.example.com",
		},
	}
}

func assembleWith(t *testing.T, scoped bool) map[string]bool {
	t.Helper()
	handler := &CBOMReportHandler{}
	components, _ := handler.assembleComponents(
		assets(), implementations(), standaloneCerts(),
		nil,
		scoped,
		false, true, true, false, false,
	)
	present := map[string]bool{}
	for _, c := range components {
		present[c.ID] = true
	}
	return present
}

// TestAssembly_UnderAScopeTheFetchedSetIsTheBoundary: a configuration whose
// asset inventory-service did not return is out of scope, because the set IS
// the scope.
//
// The failure this prevents is the quiet one: fetch a filtered asset list,
// forget that the crypto list is unfiltered, and the artifact silently contains
// configurations from assets the scope excluded.
func TestAssembly_UnderAScopeTheFetchedSetIsTheBoundary(t *testing.T) {
	present := assembleWith(t, true)

	if !present[protocolComponentID("impl-prod")] {
		t.Error("a configuration whose asset IS in the fetched set must be included")
	}
	if present[protocolComponentID("impl-orphan")] {
		t.Error("a configuration whose asset was filtered out by the scope survived; " +
			"the fetched asset set is the boundary")
	}
}

// TestAssembly_UnderAllNothingIsDroppedForMissingAttribution is the other
// polarity. With no scope, inventory-service returned everything it has, so a
// configuration with no matching asset row is a data gap, not an exclusion —
// and dropping it would silently shrink the `All` artifact.
func TestAssembly_UnderAllNothingIsDroppedForMissingAttribution(t *testing.T) {
	present := assembleWith(t, false)

	for _, id := range []string{"impl-prod", "impl-staging", "impl-orphan"} {
		if !present[protocolComponentID(id)] {
			t.Errorf("%s is missing from the All artifact", id)
		}
	}
}

// TestAssembly_UnassignedCertificatesOnlyUnderAll is CBOM-3. Standalone
// certificates carry no asset attributes at all, so a narrower scope cannot
// honestly claim them — and attributing them by guesswork would be worse than
// leaving them out.
func TestAssembly_UnassignedCertificatesOnlyUnderAll(t *testing.T) {
	certID := certificateComponentID("cert-unassigned")

	if !assembleWith(t, false)[certID] {
		t.Error("the All scope must still contain uploaded/unassigned certificates")
	}
	if assembleWith(t, true)[certID] {
		t.Error("an unassigned certificate appeared in a scoped artifact; " +
			"nothing attributes it to that boundary")
	}
}

func TestFlattenTagsAndLocationRegion(t *testing.T) {
	raw := map[string]interface{}{
		"env":      "prod",
		"location": map[string]interface{}{"region": "us-east-1", "site": "dc1"},
	}

	tags := flattenTags(raw)
	if tags["env"] != "prod" {
		t.Errorf("tags[env] = %q, want prod", tags["env"])
	}
	if tags["region"] != "us-east-1" {
		t.Errorf("nested location tags were not flattened: %#v", tags)
	}
	if _, ok := tags["location"]; !ok {
		t.Error("the nesting key itself should stay matchable")
	}

	if got := tagLocationRegion(raw); got != "us-east-1" {
		t.Errorf("tagLocationRegion = %q, want us-east-1", got)
	}
	// The flat fallback inventory's own filter uses.
	if got := tagLocationRegion(map[string]interface{}{"region": "eu-west-1"}); got != "eu-west-1" {
		t.Errorf("tagLocationRegion flat fallback = %q, want eu-west-1", got)
	}
	if got := tagLocationRegion(nil); got != "" {
		t.Errorf("tagLocationRegion(nil) = %q, want empty", got)
	}
}
