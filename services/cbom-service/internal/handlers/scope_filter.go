package handlers

import (
	"strings"
)

// AssetPredicate is the asset-selection rule a CBOM generation is run under —
// the in-memory form of a Scope predicate.
//
// It lives here, not in the scopes package, because this is where the asset
// records are in hand. cbom.Builder translates scopes.Predicate into this and
// reports any predicate field the translation does not cover, so an
// unenforceable scope fails the request instead of quietly widening it.
//
// Semantics (docsv4/internal/developer/architecture/cbom/scope-predicate-shape.md):
//   - Include: an asset must match EVERY populated field; within one field the
//     listed values are OR-ed. An empty Include matches everything.
//   - Exclude: an asset matching ANY populated field is removed. Exclusion wins
//     over inclusion.
type AssetPredicate struct {
	Include *AssetClause `json:"include,omitempty"`
	Exclude *AssetClause `json:"exclude,omitempty"`
}

// AssetClause mirrors scopes.PredicateClause. Field-for-field: the translator
// in cbom.Builder is checked against the scopes struct by reflection, so a new
// predicate field cannot be added there without either being wired here or
// being rejected at request time.
type AssetClause struct {
	Environment    []string `json:"environment,omitempty"`
	AssetType      []string `json:"asset_type,omitempty"`
	AssetOwnership []string `json:"asset_ownership,omitempty"`
	AssetStatus    []string `json:"asset_status,omitempty"`
	BusinessUnit   []string `json:"business_unit,omitempty"`
	LocationRegion []string `json:"location_region,omitempty"`
	RiskLevel      []string `json:"risk_level,omitempty"`
	TagsAnyOf      []string `json:"tags_any_of,omitempty"`
}

// IsEmpty reports whether the predicate constrains nothing — the "All" scope.
func (p AssetPredicate) IsEmpty() bool {
	return p.Include.isEmpty() && p.Exclude.isEmpty()
}

func (c *AssetClause) isEmpty() bool {
	if c == nil {
		return true
	}
	return len(c.Environment) == 0 &&
		len(c.AssetType) == 0 &&
		len(c.AssetOwnership) == 0 &&
		len(c.AssetStatus) == 0 &&
		len(c.BusinessUnit) == 0 &&
		len(c.LocationRegion) == 0 &&
		len(c.RiskLevel) == 0 &&
		len(c.TagsAnyOf) == 0
}

// compiledPredicate is the lower-cased, set-shaped form used per asset.
type compiledPredicate struct {
	include *compiledClause
	exclude *compiledClause
}

type compiledClause struct {
	environment    map[string]bool
	assetType      map[string]bool
	assetOwnership map[string]bool
	assetStatus    map[string]bool
	businessUnit   map[string]bool
	locationRegion map[string]bool
	riskLevel      map[string]bool
	tagsAnyOf      map[string]bool
}

func compilePredicate(p AssetPredicate) compiledPredicate {
	return compiledPredicate{
		include: compileClause(p.Include),
		exclude: compileClause(p.Exclude),
	}
}

func compileClause(c *AssetClause) *compiledClause {
	if c.isEmpty() {
		return nil
	}
	return &compiledClause{
		environment:    lowerSet(c.Environment),
		assetType:      lowerSet(c.AssetType),
		assetOwnership: lowerSet(c.AssetOwnership),
		assetStatus:    lowerSet(c.AssetStatus),
		businessUnit:   lowerSet(c.BusinessUnit),
		locationRegion: lowerSet(c.LocationRegion),
		riskLevel:      lowerSet(c.RiskLevel),
		tagsAnyOf:      lowerSet(c.TagsAnyOf),
	}
}

func (p compiledPredicate) isEmpty() bool { return p.include == nil && p.exclude == nil }

// matches evaluates one asset context against the predicate.
func (p compiledPredicate) matches(ctx assetContext) bool {
	if p.exclude != nil && p.exclude.matchesAny(ctx) {
		return false
	}
	if p.include != nil && !p.include.matchesAll(ctx) {
		return false
	}
	return true
}

// matchesAll is the Include test: every populated field must match.
func (c *compiledClause) matchesAll(ctx assetContext) bool {
	for _, check := range c.fieldChecks(ctx) {
		if len(check.values) > 0 && !check.hit {
			return false
		}
	}
	return true
}

// matchesAny is the Exclude test: one populated field matching is enough.
func (c *compiledClause) matchesAny(ctx assetContext) bool {
	for _, check := range c.fieldChecks(ctx) {
		if len(check.values) > 0 && check.hit {
			return true
		}
	}
	return false
}

type fieldCheck struct {
	values map[string]bool
	hit    bool
}

func (c *compiledClause) fieldChecks(ctx assetContext) []fieldCheck {
	return []fieldCheck{
		{c.environment, inSet(c.environment, ctx.Environment)},
		{c.assetType, inSet(c.assetType, ctx.AssetType)},
		{c.assetOwnership, inSet(c.assetOwnership, ctx.AssetOwnership)},
		{c.assetStatus, inSet(c.assetStatus, ctx.AssetStatus)},
		{c.businessUnit, inSet(c.businessUnit, ctx.BusinessUnit)},
		{c.locationRegion, inSet(c.locationRegion, ctx.LocationRegion)},
		{c.riskLevel, inSet(c.riskLevel, ctx.RiskLevel)},
		{c.tagsAnyOf, matchesAnyTag(c.tagsAnyOf, ctx.Tags)},
	}
}

// inSet is the single-value test. An asset with the attribute unset never
// matches — "unknown environment" is not "production", and for an attestation
// boundary the safe reading of an unset attribute is "not this one".
func inSet(set map[string]bool, value string) bool {
	if len(set) == 0 {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	return set[v]
}

// matchesAnyTag implements the tag rule from the predicate spec: a listed value
// matches if it appears as either a key or a value in the asset's tag map.
func matchesAnyTag(set map[string]bool, tags map[string]string) bool {
	if len(set) == 0 || len(tags) == 0 {
		return false
	}
	for key, value := range tags {
		if set[strings.ToLower(strings.TrimSpace(key))] {
			return true
		}
		if set[strings.ToLower(strings.TrimSpace(value))] {
			return true
		}
	}
	return false
}

func lowerSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		set[v] = true
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// flattenTags reduces the asset's JSONB tags column to a flat string map. Nested
// objects (the `location` sub-map inventory writes) contribute their leaves, so
// a `{"location":{"region":"us-east-1"}}` asset is matchable by the tag value
// `us-east-1` as well as by location_region.
func flattenTags(raw interface{}) map[string]string {
	out := map[string]string{}
	flattenTagsInto(raw, out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func flattenTagsInto(raw interface{}, out map[string]string) {
	switch v := raw.(type) {
	case map[string]interface{}:
		for key, value := range v {
			switch nested := value.(type) {
			case map[string]interface{}, []interface{}:
				flattenTagsInto(nested, out)
				// Keep the key itself matchable ("tags_any_of": ["location"]).
				if _, exists := out[key]; !exists {
					out[key] = ""
				}
			default:
				out[key] = strVal(value)
			}
		}
	case []interface{}:
		for _, item := range v {
			switch nested := item.(type) {
			case map[string]interface{}, []interface{}:
				flattenTagsInto(nested, out)
			default:
				out[strVal(item)] = ""
			}
		}
	}
}

// tagLocationRegion mirrors inventory-service's location_region filter, which
// reads COALESCE(tags->'location'->>'region', tags->>'region').
func tagLocationRegion(raw interface{}) string {
	tags, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	if location, ok := tags["location"].(map[string]interface{}); ok {
		if region := strVal(location["region"]); region != "" {
			return region
		}
	}
	return strVal(tags["region"])
}
