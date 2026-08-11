package handlers

import (
	"testing"
)

// A CBOM artifact's whole claim is "this is everything matching this boundary
// at this moment". Before these tests, the assembly evaluated two of the eight
// predicate dimensions and dropped exclude clauses entirely, so the seeded
// Non-Dev/Test scope produced the same document as All and a Production
// artifact carried every uploaded certificate in the tenant. The tests below
// pin the boundary.

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
			"id":          "asset-dev",
			"tenant_id":   "tenant-1",
			"hostname":    "dev-01",
			"asset_type":  "server",
			"environment": "development",
			"risk_level":  "low",
		},
		{
			"id":         "asset-tagged-test",
			"tenant_id":  "tenant-1",
			"hostname":   "unlabelled-01",
			"asset_type": "server",
			// No environment column at all — only a tag says it's test. This is
			// exactly the case the Non-Dev/Test scope's tag arm exists for.
			"tags":       map[string]interface{}{"lifecycle": "test"},
			"risk_level": "medium",
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
		{"id": "impl-dev", "asset_id": "asset-dev", "protocol": "TLS", "protocol_version": "1.2"},
		{"id": "impl-tagged", "asset_id": "asset-tagged-test", "protocol": "TLS", "protocol_version": "1.2"},
		{"id": "impl-staging", "asset_id": "asset-staging", "protocol": "TLS", "protocol_version": "1.3"},
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

func assembleWith(t *testing.T, p AssetPredicate) map[string]bool {
	t.Helper()
	handler := &CBOMReportHandler{}
	components, _ := handler.assembleComponents(
		assets(), implementations(), standaloneCerts(),
		nil,
		compilePredicate(p),
		false, true, true, false, false,
	)
	present := map[string]bool{}
	for _, c := range components {
		present[c.ID] = true
	}
	return present
}

// TestScopeFilter_NonDevTestExcludesDevAndTaggedAssets is the scope the audit
// named: an Exclude-only predicate that used to be ignored outright.
func TestScopeFilter_NonDevTestExcludesDevAndTaggedAssets(t *testing.T) {
	present := assembleWith(t, AssetPredicate{
		Exclude: &AssetClause{
			Environment: []string{"dev", "development", "test", "testing"},
			TagsAnyOf:   []string{"dev", "test"},
		},
	})

	if !present[protocolComponentID("impl-prod")] {
		t.Error("production asset was excluded from Non-Dev/Test")
	}
	if !present[protocolComponentID("impl-staging")] {
		t.Error("staging asset was excluded from Non-Dev/Test")
	}
	if present[protocolComponentID("impl-dev")] {
		t.Error("a development-environment asset survived the Non-Dev/Test exclude")
	}
	if present[protocolComponentID("impl-tagged")] {
		t.Error("an asset tagged 'test' survived the Non-Dev/Test exclude " +
			"(the tag arm exists precisely for assets with no environment column)")
	}
}

// TestScopeFilter_ProductionExcludesStaging pins the Include arm.
func TestScopeFilter_ProductionExcludesStaging(t *testing.T) {
	present := assembleWith(t, AssetPredicate{
		Include: &AssetClause{Environment: []string{"production", "prod"}},
	})

	if !present[protocolComponentID("impl-prod")] {
		t.Error("production asset missing from the Production scope")
	}
	for _, id := range []string{"impl-staging", "impl-dev", "impl-tagged"} {
		if present[protocolComponentID(id)] {
			t.Errorf("%s is not production but appears in the Production scope", id)
		}
	}
}

// TestScopeFilter_UnassignedCertificatesOnlyUnderAll is CBOM-3. Standalone
// certificates carry no asset attributes, so a narrower scope cannot honestly
// claim them.
func TestScopeFilter_UnassignedCertificatesOnlyUnderAll(t *testing.T) {
	certID := certificateComponentID("cert-unassigned")

	all := assembleWith(t, AssetPredicate{})
	if !all[certID] {
		t.Error("the All scope must still contain uploaded/unassigned certificates")
	}

	production := assembleWith(t, AssetPredicate{
		Include: &AssetClause{Environment: []string{"production"}},
	})
	if production[certID] {
		t.Error("an unassigned certificate appeared in a Production-scoped artifact; " +
			"nothing attributes it to production")
	}

	nonDevTest := assembleWith(t, AssetPredicate{
		Exclude: &AssetClause{Environment: []string{"dev", "test"}},
	})
	if nonDevTest[certID] {
		t.Error("an unassigned certificate appeared in an exclude-scoped artifact")
	}
}

// TestScopeFilter_IncludeFieldsAreAnded pins the semantics CBOM-6 corrects in
// the docs: populated Include fields narrow, they do not widen.
func TestScopeFilter_IncludeFieldsAreAnded(t *testing.T) {
	present := assembleWith(t, AssetPredicate{
		Include: &AssetClause{
			Environment: []string{"production"},
			AssetType:   []string{"loadbalancer"},
		},
	})

	// asset-prod is production but a server; asset-staging is a loadbalancer but
	// staging. Under OR-across-fields both would appear. Under AND, neither does.
	for _, id := range []string{"impl-prod", "impl-staging", "impl-dev", "impl-tagged"} {
		if present[protocolComponentID(id)] {
			t.Errorf("%s matched an AND of environment=production and asset_type=loadbalancer", id)
		}
	}
}

// TestScopeFilter_ExcludeWinsOverInclude pins precedence.
func TestScopeFilter_ExcludeWinsOverInclude(t *testing.T) {
	present := assembleWith(t, AssetPredicate{
		Include: &AssetClause{AssetType: []string{"server"}},
		Exclude: &AssetClause{Environment: []string{"production"}},
	})

	if present[protocolComponentID("impl-prod")] {
		t.Error("an asset matching both include and exclude was kept; exclusion must win")
	}
	if !present[protocolComponentID("impl-dev")] {
		t.Error("a server that is not excluded should be present")
	}
}

// TestScopeFilter_EveryPredicateDimensionIsEvaluated walks each dimension the
// predicate can express. Six of these eight were accepted by POST /scopes and
// then ignored at generation time.
func TestScopeFilter_EveryPredicateDimensionIsEvaluated(t *testing.T) {
	ctx := assetContext{
		AssetType:      "server",
		Environment:    "production",
		RiskLevel:      "high",
		AssetOwnership: "internal",
		AssetStatus:    "monitoring",
		BusinessUnit:   "payments",
		LocationRegion: "us-east-1",
		Tags:           map[string]string{"compliance": "pci-in-scope"},
	}

	cases := []struct {
		name    string
		match   AssetClause
		noMatch AssetClause
	}{
		{"environment", AssetClause{Environment: []string{"production"}}, AssetClause{Environment: []string{"staging"}}},
		{"asset_type", AssetClause{AssetType: []string{"server"}}, AssetClause{AssetType: []string{"database"}}},
		{"risk_level", AssetClause{RiskLevel: []string{"high"}}, AssetClause{RiskLevel: []string{"low"}}},
		{"asset_ownership", AssetClause{AssetOwnership: []string{"internal"}}, AssetClause{AssetOwnership: []string{"third_party"}}},
		{"asset_status", AssetClause{AssetStatus: []string{"monitoring"}}, AssetClause{AssetStatus: []string{"archived"}}},
		{"business_unit", AssetClause{BusinessUnit: []string{"payments"}}, AssetClause{BusinessUnit: []string{"hr"}}},
		{"location_region", AssetClause{LocationRegion: []string{"us-east-1"}}, AssetClause{LocationRegion: []string{"eu-west-1"}}},
		{"tags_any_of", AssetClause{TagsAnyOf: []string{"pci-in-scope"}}, AssetClause{TagsAnyOf: []string{"sox"}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match := c.match
			noMatch := c.noMatch

			if !compilePredicate(AssetPredicate{Include: &match}).matches(ctx) {
				t.Errorf("include on %s should have matched", c.name)
			}
			if compilePredicate(AssetPredicate{Include: &noMatch}).matches(ctx) {
				t.Errorf("include on %s matched an asset it should not have", c.name)
			}
			if compilePredicate(AssetPredicate{Exclude: &match}).matches(ctx) {
				t.Errorf("exclude on %s failed to remove a matching asset", c.name)
			}
			if !compilePredicate(AssetPredicate{Exclude: &noMatch}).matches(ctx) {
				t.Errorf("exclude on %s removed an asset it should not have", c.name)
			}
		})
	}
}

// TestScopeFilter_UnsetAttributeNeverMatches: for an attestation boundary the
// safe reading of a missing attribute is "not this one".
func TestScopeFilter_UnsetAttributeNeverMatches(t *testing.T) {
	blank := assetContext{}
	include := AssetClause{Environment: []string{"production"}}
	if compilePredicate(AssetPredicate{Include: &include}).matches(blank) {
		t.Error("an asset with no environment was counted as production")
	}
	exclude := AssetClause{Environment: []string{"development"}}
	if !compilePredicate(AssetPredicate{Exclude: &exclude}).matches(blank) {
		t.Error("an asset with no environment was excluded as development")
	}
}

func TestScopeFilter_MatchingIsCaseInsensitive(t *testing.T) {
	ctx := assetContext{Environment: "Production", Tags: map[string]string{"Lifecycle": "TEST"}}
	include := AssetClause{Environment: []string{"PRODUCTION"}}
	if !compilePredicate(AssetPredicate{Include: &include}).matches(ctx) {
		t.Error("environment matching is case-sensitive")
	}
	exclude := AssetClause{TagsAnyOf: []string{"test"}}
	if compilePredicate(AssetPredicate{Exclude: &exclude}).matches(ctx) {
		t.Error("tag matching is case-sensitive")
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
