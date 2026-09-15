package producers

// The `crypto` producer must resolve "which asset does this belong to" the SAME
// way findings.AssetSubjects does, and this test is what holds it there.
//
// They disagreed. The producer read bare `ci.asset_id` for its configuration and
// certificate populations while AssetSubjects — the ONE definition of which
// findings are "on" an asset, used by the query language, the `has_findings`
// facet and the asset page's Findings tab — resolved the endpoint's asset first.
// `crypto_implementations.endpoint_id` is nullable and an endpoint can move to
// another host, so for a moved endpoint the producer wrote a
// `producer_assessments` coverage row naming asset A ("assessed, and clean")
// while the `weak_configuration` / `pqc_vulnerable` finding it raised was
// reachable only from asset B. One pass, two contradictory answers, no error.
//
// Both sides now splice findings.ConfigurationAssetSQL. A source guard rather
// than a behavioural one because the failure mode is a SECOND spelling appearing
// anywhere in this file — which no single fixture would catch — and because a
// guard that reads the SQL cannot be satisfied by a coincidence in the data.
// The behavioural half is
// TestIntegration_CryptoProducer_MovedEndpointCoversTheEndpointsAsset.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// assetIDRef matches any `<alias>.asset_id` reference.
var assetIDRef = regexp.MustCompile(`\b([a-z][a-z0-9_]*)\.asset_id\b`)

// coalesceRef matches the RENDERED asset-resolution expression, capturing the
// two aliases so the test can re-derive it from findings.ConfigurationAssetSQL
// and compare — a diff of the two definitions, not a spelling check.
var coalesceRef = regexp.MustCompile(`COALESCE\(([a-z][a-z0-9_]*)\.asset_id, ([a-z][a-z0-9_]*)\.asset_id\)`)

// configurationAssetSQLCall matches the splice site in the source.
var configurationAssetSQLCall = regexp.MustCompile(`findings\.ConfigurationAssetSQL\("([a-z0-9_]+)", "([a-z0-9_]+)"\)`)

// cryptoProducerSQL is crypto.go with its comment lines dropped and every
// ConfigurationAssetSQL call replaced by what it returns — the SQL as Postgres
// will see it, with the prose that merely TALKS about asset_id out of the way.
func cryptoProducerSQL(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("crypto.go")
	if err != nil {
		t.Fatalf("read crypto.go: %v", err)
	}
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	src := strings.Join(kept, "\n")
	rendered := configurationAssetSQLCall.ReplaceAllStringFunc(src, func(m string) string {
		g := configurationAssetSQLCall.FindStringSubmatch(m)
		return findings.ConfigurationAssetSQL(g[1], g[2])
	})
	if rendered == src {
		t.Fatal("crypto.go calls findings.ConfigurationAssetSQL nowhere — the producer is resolving assets on its own again")
	}
	return rendered
}

// Every asset reference in the producer's SQL is the shared fragment, never a
// bare `ci.asset_id`.
//
// Mutation: put `ci.asset_id` back into liveConfigurationsSQL and this fails.
func TestCryptoProducer_ResolvesAssetsThroughTheSharedFragment(t *testing.T) {
	sql := cryptoProducerSQL(t)

	sites := 0
	stripped := coalesceRef.ReplaceAllStringFunc(sql, func(m string) string {
		g := coalesceRef.FindStringSubmatch(m)
		// g[1] is the endpoint alias and g[2] the crypto_implementations alias:
		// ConfigurationAssetSQL(ci, endpoint) renders the endpoint first.
		if want := findings.ConfigurationAssetSQL(g[2], g[1]); want != m {
			t.Errorf("asset resolution %q is not findings.ConfigurationAssetSQL's %q", m, want)
		}
		sites++
		return ""
	})
	for _, bare := range assetIDRef.FindAllStringSubmatch(stripped, -1) {
		// `reachable.asset_id` / `cfg.asset_id` read a column the CTE already
		// resolved through the fragment; they are not a second definition.
		switch bare[1] {
		case "reachable", "cfg":
			continue
		}
		t.Errorf("crypto.go SQL resolves an asset as %q, not through findings.ConfigurationAssetSQL", bare[0])
	}
	// Three populations — configurations, certificates, keys — each resolving in
	// its SELECT list and again in its `assets` join.
	if sites < 6 {
		t.Errorf("expected at least 6 spliced asset-resolution sites (3 populations x select + join), got %d", sites)
	}
}
