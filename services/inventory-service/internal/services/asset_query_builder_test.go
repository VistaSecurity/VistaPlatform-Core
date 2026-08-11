package services

import (
	"testing"
	"time"

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

func TestParseSearchQuery_AND(t *testing.T) {
	terms := parseSearchQuery("server AND production")
	require.GreaterOrEqual(t, len(terms), 2)
	assert.Equal(t, "server", terms[0].Value)
	last := terms[len(terms)-1]
	assert.Equal(t, "production", last.Value)
}

func TestParseSearchQuery_OR(t *testing.T) {
	terms := parseSearchQuery("test OR dev")
	require.GreaterOrEqual(t, len(terms), 2)
	last := terms[len(terms)-1]
	assert.Equal(t, "dev", last.Value)
}

func TestValidateAssetFilters_Valid(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"server", "endpoint"}}
	err := validateAssetFilters(filters)
	assert.NoError(t, err)
}

func TestValidateAssetFilters_InvalidAssetType(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"invalid"}}
	err := validateAssetFilters(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid asset_type")
}

func TestValidateAssetFilters_CertificateHint(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"certificate"}}
	err := validateAssetFilters(filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificates are not asset types")
}

func TestBuildAssetListWhereAndHaving_DefaultStatus(t *testing.T) {
	filters := models.AssetFilters{}
	where, _, args := buildAssetListWhereAndHaving(filters, 2)
	require.Len(t, where, 1)
	assert.Equal(t, `a.asset_status = 'monitoring'`, where[0])
	assert.Empty(t, args)
}

func TestBuildAssetListWhereAndHaving_AssetType(t *testing.T) {
	filters := models.AssetFilters{AssetType: []string{"server"}}
	where, _, args := buildAssetListWhereAndHaving(filters, 2)
	require.Len(t, where, 2) // status + asset_type
	assert.Len(t, args, 1)
	assert.Equal(t, "server", args[0])
}

func TestBuildAssetListWhereAndHaving_RiskLevel(t *testing.T) {
	filters := models.AssetFilters{RiskLevel: []string{"Critical", "High"}}
	where, having, args := buildAssetListWhereAndHaving(filters, 2)
	assert.NotEmpty(t, where)
	require.Len(t, having, 1)
	assert.Contains(t, having[0], ">= 90")
	assert.Contains(t, having[0], ">= 70")
	assert.Contains(t, having[0], "< 90")
	assert.NotContains(t, having[0], ">= 80")
	assert.NotContains(t, having[0], ">= 60")
	assert.Empty(t, args)
}

// last_seen_before filter ( — the time arm of the Stale lens's server-side cut).

func TestValidateAssetFilters_LastSeenBefore(t *testing.T) {
	assert.NoError(t, validateAssetFilters(models.AssetFilters{LastSeenBefore: "2026-05-29T00:00:00Z"}))
	assert.Error(t, validateAssetFilters(models.AssetFilters{LastSeenBefore: "yesterday"}), "non-RFC3339 must be rejected")
	assert.NoError(t, validateAssetFilters(models.AssetFilters{}))
}

func TestBuildAssetListWhereAndHaving_LastSeenBefore(t *testing.T) {
	filters := models.AssetFilters{LastSeenBefore: "2026-05-29T00:00:00Z"}
	where, _, args := buildAssetListWhereAndHaving(filters, 2)
	require.Len(t, where, 2) // status default + last_seen cutoff
	assert.Contains(t, where[1], "a.last_seen_at < $")
	require.Len(t, args, 1)
	cutoff, ok := args[0].(time.Time)
	require.True(t, ok, "cutoff must be bound as a parsed timestamp, got %#v", args[0])
	assert.True(t, cutoff.Equal(time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)))
}
