package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestParseSearchQuery_Empty(t *testing.T) {
	terms := parseSearchQuery("")
	assert.Nil(t, terms)
	terms = parseSearchQuery("   ")
	assert.Nil(t, terms)
}

func TestParseSearchQuery_SingleTerm(t *testing.T) {
	terms := parseSearchQuery("server")
	require.Len(t, terms, 1)
	assert.Equal(t, "", terms[0].Field)
	assert.Equal(t, "server", terms[0].Value)
	assert.False(t, terms[0].Exact)
}

func TestParseSearchQuery_ExactPhrase(t *testing.T) {
	terms := parseSearchQuery(`"exact match"`)
	require.Len(t, terms, 1)
	assert.Equal(t, "exact match", terms[0].Value)
	assert.True(t, terms[0].Exact)
}

func TestParseSearchQuery_FieldSpecific(t *testing.T) {
	terms := parseSearchQuery("hostname:server1")
	require.Len(t, terms, 1)
	assert.Equal(t, "hostname", terms[0].Field)
	assert.Equal(t, "server1", terms[0].Value)
}

// TestParseSearchQuery_KeywordIsFullyConsumed pins the off-by-one that made
// `a AND b` parse as THREE terms.
//
// The scanner advanced by len("AND") from the SPACE before it and then skipped
// its own i++, so it resumed on the keyword's last letter: "web AND owner:bob"
// produced "web", "D" and owner:bob, and the list silently searched for a
// free-text "D" as well. The old test asserted `GreaterOrEqual(2)` and passed
// through the whole bug; the count is exact here, which is the assertion that
// can fail.
func TestParseSearchQuery_KeywordIsFullyConsumed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{"and", "server AND production", []string{"server", "production"}},
		{"or", "test OR dev", []string{"test", "dev"}},
		{"and with a field", "web AND owner:bob", []string{"web", "bob"}},
		{"lowercase and", "web and prod", []string{"web", "prod"}},
		{"three terms", "a AND b OR c", []string{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terms := parseSearchQuery(tc.input)
			got := make([]string, 0, len(terms))
			for _, term := range terms {
				got = append(got, term.Value)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidateAssetFilters_Valid(t *testing.T) {
	// Class keys from the registry, which is what asset_type now carries.
	filters := models.AssetFilters{AssetType: []string{"server", "switch"}}
	assert.NoError(t, validateAssetFilters(filters))
}

func TestValidateAssetFilters_InvalidAssetType(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"invalid"}}
	err := validateAssetFilters(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid asset_type")
}

// TestValidateAssetFilters_AcceptsClassKeysTheOldEnumNeverHad is the other
// polarity: the old whitelist was the four values of the dropped enum, so it
// REJECTED every key the class facet writes. Validating against the registry
// has to accept them.
func TestValidateAssetFilters_AcceptsClassKeysTheOldEnumNeverHad(t *testing.T) {
	for _, key := range []string{"switch", "firewall", "hypervisor", "cloud_resource", "unknown_host"} {
		assert.NoError(t, validateAssetFilters(models.AssetFilters{AssetType: []string{key}}), key)
	}
}

func TestValidateAssetFilters_CertificateHint(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"certificate"}}
	err := validateAssetFilters(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificates are not asset types")
}

func TestValidateAssetFilters_LastSeenBefore(t *testing.T) {
	assert.NoError(t, validateAssetFilters(models.AssetFilters{LastSeenBefore: "2026-05-29T00:00:00Z"}))
	assert.Error(t, validateAssetFilters(models.AssetFilters{LastSeenBefore: "yesterday"}), "non-RFC3339 must be rejected")
	assert.NoError(t, validateAssetFilters(models.AssetFilters{}))
}

// ------------------------------------------- legacy filters → query string --

// TestLegacyFiltersToQuery_DefaultStatus: with no filters at all the default
// scope is still stated — and stated as a TERM, so it appears in the query the
// facet rail shows rather than hiding in a builder.
func TestLegacyFiltersToQuery_DefaultStatus(t *testing.T) {
	assert.Equal(t, "status:monitoring", LegacyFiltersToQuery(models.AssetFilters{}))
}

func TestLegacyFiltersToQuery_AssetTypeBecomesClass(t *testing.T) {
	q := LegacyFiltersToQuery(models.AssetFilters{AssetType: []string{"server", "switch"}})
	assert.Contains(t, q, `class in ("server", "switch")`)
}

// TestLegacyFiltersToQuery_RiskLevelUsesTheLadder: "high" in the facet
// vocabulary has always meant high AND ABOVE, and every band term is generated
// from models.RiskBands rather than from a threshold written in the translator.
func TestLegacyFiltersToQuery_RiskLevelUsesTheLadder(t *testing.T) {
	q := LegacyFiltersToQuery(models.AssetFilters{RiskLevel: []string{"high", "medium", "unknown"}})
	assert.Contains(t, q, "risk >= high")
	assert.Contains(t, q, "risk:medium")
	assert.Contains(t, q, "risk:informational")

	c, err := CompileAssetQuery(q, QueryTargetAsset, 1, "a")
	require.NoError(t, err)
	// The bound thresholds are the ladder's rungs, not numbers this package chose.
	highMin, _ := models.RiskBandMin("High")
	mediumMin, _ := models.RiskBandMin("Medium")
	assert.Contains(t, c.Args, highMin)
	assert.Contains(t, c.Args, mediumMin)
}

// TestLegacyFiltersToQuery_EveryParameterCompiles is the claim QUERY_LANGUAGE §8
// makes — that everything in the old filter vocabulary is expressible — turned
// into a check. A parameter whose translation stops compiling fails here rather
// than 500-ing a list page.
func TestLegacyFiltersToQuery_EveryParameterCompiles(t *testing.T) {
	yes := true
	n := 30
	alg := "RSA"
	full := models.AssetFilters{
		Search:                   `web AND owner:bob`,
		AssetType:                []string{"server"},
		Environment:              []string{"production"},
		RiskLevel:                []string{"high"},
		Protocol:                 []string{"tls"},
		BusinessUnit:             []string{"Finance"},
		OperatingSystem:          []string{"Ubuntu 24.04"},
		OwnerEmail:               []string{"a@b.example"},
		LocationRegion:           []string{"us-east-1"},
		LocationSite:             []string{"HQ"},
		LocationBuilding:         []string{"B1"},
		LocationZone:             []string{"z1"},
		LocationID:               []string{"550e8400-e29b-41d4-a716-446655440000"},
		NetworkSegmentID:         []string{"550e8400-e29b-41d4-a716-446655440001"},
		AssetOwnership:           []string{"internal"},
		AssetStatus:              []string{"monitoring"},
		UnscannedOnly:            &yes,
		LastSeenBefore:           "2026-05-29T00:00:00Z",
		HasCertificates:          &yes,
		CertExpiringWithin:       &n,
		CertKeySizeMin:           &n,
		CertAlgorithm:            &alg,
		ProtocolVersion:          []string{"TLSv1.2"},
		HashAlgorithm:            []string{"SHA256"},
		KeySizeMin:               &n,
		UsesDeprecatedAlgorithms: &yes,
	}
	q := LegacyFiltersToQuery(full)
	c, err := CompileAssetQuery(q, QueryTargetAsset, 2, "a")
	require.NoError(t, err, "translated query: %s", q)
	assert.NotEmpty(t, c.Where)
}

// TestLegacyFiltersToQuery_QuotesHostileValues: a value containing a space, a
// parenthesis or a quote must not be able to change the SHAPE of the query
// built around it. It ends up a bind parameter either way, but a value that
// closed a group would make the predicate mean something else entirely.
func TestLegacyFiltersToQuery_QuotesHostileValues(t *testing.T) {
	for _, v := range []string{
		`Finance and Ops`,
		`) or class:server (`,
		`quote"inside`,
		`back\slash`,
	} {
		q := LegacyFiltersToQuery(models.AssetFilters{BusinessUnit: []string{v}})
		c, err := CompileAssetQuery(q, QueryTargetAsset, 1, "a")
		require.NoError(t, err, "value %q produced %q", v, q)
		assert.Contains(t, c.Args, strings.ToLower(v),
			"the value must arrive as a bind parameter, not as query syntax")
	}
}

// TestBuildAssetWhere_AndsTheUserQueryWithTheLegacyFilters: both survive, and
// ONE predicate reaches SQL. Two WHERE-builders is what let the list and the
// facet rail drift.
func TestBuildAssetWhere_AndsTheUserQueryWithTheLegacyFilters(t *testing.T) {
	pred, err := buildAssetWhere("environment:production", models.AssetFilters{
		BusinessUnit: []string{"Finance"},
	}, 2, "a")
	require.NoError(t, err)
	assert.Contains(t, pred.Canonical, "environment:production")
	assert.Contains(t, pred.Canonical, "business_unit")
	assert.Contains(t, pred.Args, "production")
	assert.Contains(t, pred.Args, "finance")
}

// TestBuildAssetWhere_EmptyIsTrue: no query and no filters at all is TRUE,
// which under RLS is "every row this tenant may see" — not "no rows".
func TestBuildAssetWhere_EmptyIsTrue(t *testing.T) {
	pred, err := buildAssetWhere("", models.AssetFilters{AssetStatus: []string{}}, 2, "a")
	require.NoError(t, err)
	// The default status term still applies, so this is not literally TRUE —
	// what matters is that it compiled and bound the status.
	assert.Contains(t, pred.Args, "monitoring")

	bare, err := buildAssetWhere("", models.AssetFilters{}, 2, "a")
	require.NoError(t, err)
	assert.NotEmpty(t, bare.Where)
}

// TestBuildAssetWhere_ReportsTheUsersOwnSpans: when the USER's query is what
// failed, the diagnostics must index into the user's text — not into the
// concatenation of their query with the translated legacy filters, which would
// point the caret at the wrong characters.
func TestBuildAssetWhere_ReportsTheUsersOwnSpans(t *testing.T) {
	_, err := buildAssetWhere("hostnaem:web-1", models.AssetFilters{
		Environment: []string{"production"},
	}, 2, "a")
	require.Error(t, err)
	qe, ok := AsQueryError(err)
	require.True(t, ok, "a bad user query must surface as a QueryError, got %T", err)
	assert.Equal(t, "hostnaem:web-1", qe.Query)
	require.NotEmpty(t, qe.Errors)
	assert.Equal(t, "unknown_field", string(qe.Errors[0].Code))
	assert.LessOrEqual(t, qe.Errors[0].Span.End, len(qe.Query),
		"the span must index into the user's own text")
}

// TestBuildAssetWhere_DefaultStatusStepsAsideForTheUsersOwnStatusTerm is the
// default scope's other polarity.
//
// `status:monitoring` is synthesised on every request that does not set the
// deprecated `asset_status` parameter. AND-ing it unconditionally onto the
// user's own `?query=` made `status:pending_approval` compile to
// `asset_status = 'pending_approval' AND asset_status = 'monitoring'` — a
// predicate no row can satisfy — so the query language could not reach the
// approvals queue, the archived tombstone a merge leaves behind, or §9's worked
// example 12. And it said so by returning an empty page, not an error.
func TestBuildAssetWhere_DefaultStatusStepsAsideForTheUsersOwnStatusTerm(t *testing.T) {
	for _, tc := range []struct {
		name        string
		userQuery   string
		wantDefault bool
	}{
		{"no query at all", "", true},
		{"a query that says nothing about status", "class:server", true},
		{"an explicit status term", "status:pending_approval", false},
		{"an in-set over status", "status in (archived, denied)", false},
		{"a negated status term", "not status:denied", false},
		{"a presence test on status", "exists(status)", false},
		// A sub-predicate is about a DIFFERENT row. An endpoint's status is not
		// the asset's, so it must not widen the default scope.
		{"an endpoint's status", "endpoint:(status:active)", true},
		// Neither is a neighbour's, reached by traversal.
		{"a traversed asset's status", "hosted_on:(status:archived)", true},
		// `stale_status` is a different column, which a substring match on the
		// query text would confuse with this one.
		{"stale_status is a different field", "stale_status:stale", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, !tc.wantDefault, queryConstrainsAssetStatus(tc.userQuery))

			pred, err := buildAssetWhere(tc.userQuery, models.AssetFilters{}, 2, "a")
			require.NoError(t, err)
			// The canonical form is what the "show the query it ran" surface
			// would print, so it is the honest place to look for the term.
			assert.Equal(t, tc.wantDefault, strings.Contains(pred.Canonical, defaultStatusTerm),
				"the default scope must be present iff the caller said nothing "+
					"about the asset's own status; canonical=%q", pred.Canonical)
		})
	}
}

// TestBuildAssetWhere_LegacyStatusParameterStillWins: the deprecated
// `asset_status` parameter is a statement about status too, and the default has
// always stepped aside for it.
func TestBuildAssetWhere_LegacyStatusParameterStillWins(t *testing.T) {
	pred, err := buildAssetWhere("", models.AssetFilters{AssetStatus: []string{"archived"}}, 2, "a")
	require.NoError(t, err)
	assert.Contains(t, pred.Args, "archived")
	assert.NotContains(t, pred.Args, "monitoring",
		"the default must not be AND-ed onto an explicit asset_status parameter")
}
