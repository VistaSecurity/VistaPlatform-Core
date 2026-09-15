package services

// The banner contract, from the producer's side (workstream 2.10b).
//
// classify.ClassifyInput documents a Banners value as one LINE exactly as the
// service sent it, header name included — `Server: nginx/1.24`, not
// `nginx/1.24`. Every shipped banner rule anchors on `(?i)^server:\s*…`, because
// the map KEY is not matched and the header name is the only thing that says
// which header the value came from.
//
// That contract fails silently in the one direction a producer is most likely to
// break it. A collector that stores the bare header value under a name like
// `server_header` hands over `nginx/1.24`, matches no rule, and nothing anywhere
// reports it: the classifier simply stops proposing `web_application` and the
// queue goes quiet, which looks exactly like a network with no web servers on
// it.
//
// bannersFromRawData renders those back into their line. It was the only part of
// the intake with no test, and "a check that cannot fail is worse than no check"
// applies to a RENDERER just as much: a rewrite that matched nothing would
// return its input and say nothing.

import (
	"context"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// Every shipped banner rule fires on BOTH shapes a producer can hand over: the
// whole line, and a bare header value rendered back into one.
//
// Driven off the shipped table rather than a fixture, so a ninth banner rule
// added tomorrow is covered without editing this file — and so a rule whose
// anchor a producer cannot satisfy fails here rather than in a deployment.
func TestBannerRules_FireOnBothShapesAProducerCanSend(t *testing.T) {
	ctx := context.Background()
	engine := classify.Default()

	rules := 0
	for _, r := range engine.Rules() {
		if r.Kind != classify.KindBanner {
			continue
		}
		rules++
		value := bannerValueFor(t, r.Pattern)

		t.Run(r.Pattern, func(t *testing.T) {
			// Shape 1: the collector captured the whole line.
			whole := findingClassEvidenceFor(map[string]interface{}{
				"banner": "Server: " + value,
			})
			if got := engine.Classify(ctx, whole); got.Class != r.Class {
				t.Errorf("a whole `Server: %s` line classified as %q, want %q", value, got.Class, r.Class)
			}

			// Shape 2: the collector kept only the header VALUE. This is the
			// one that fails silently without the renderer.
			for _, key := range []string{"server_header", "http_server", "http_server_header"} {
				bare := findingClassEvidenceFor(map[string]interface{}{key: value})
				if got := engine.Classify(ctx, bare); got.Class != r.Class {
					t.Errorf("a bare %s=%q classified as %q, want %q — bannersFromRawData "+
						"must render it back into its line", key, value, got.Class, r.Class)
				}
			}

			// And nested, which is where the sensor's payload actually puts it.
			nested := findingClassEvidenceFor(map[string]interface{}{
				"raw_metadata": map[string]interface{}{"server_header": value},
			})
			if got := engine.Classify(ctx, nested); got.Class != r.Class {
				t.Errorf("a nested raw_metadata.server_header=%q classified as %q, want %q",
					value, got.Class, r.Class)
			}
		})
	}
	if rules == 0 {
		t.Fatal("no banner rules were exercised; this test would then prove nothing")
	}
}

// The renderer does not touch a value that is already a line, and does not
// invent one out of nothing.
func TestBannersFromRawData_LeavesWholeLinesAloneAndInventsNothing(t *testing.T) {
	// `banner` and `ssh_banner` are whole lines as the service sent them.
	got := bannersFromRawData(map[string]interface{}{
		"banner":     "Server: nginx/1.24",
		"ssh_banner": "SSH-2.0-OpenSSH_9.6",
	})
	if got["banner"] != "Server: nginx/1.24" {
		t.Errorf("banner = %q; a whole line must pass through unchanged", got["banner"])
	}
	if got["ssh_banner"] != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("ssh_banner = %q; a protocol with no header name has none added", got["ssh_banner"])
	}
	// A bare value gains exactly one header, not two.
	got = bannersFromRawData(map[string]interface{}{"server_header": "Server: nginx/1.24"})
	if strings.Count(got["server_header"], "Server:") != 1 {
		t.Errorf("server_header = %q; rendering a value that already carries the header "+
			"must not double it", got["server_header"])
	}
	// Nothing present means nil, not an empty map the engine would iterate.
	if b := bannersFromRawData(map[string]interface{}{"unrelated": "x"}); b != nil {
		t.Errorf("bannersFromRawData with no banner keys = %+v, want nil", b)
	}
	if b := bannersFromRawData(nil); b != nil {
		t.Errorf("bannersFromRawData(nil) = %+v, want nil", b)
	}
	// An OUTER key wins over the same key nested, because the outer one is the
	// finding's own observation and the nested one is what a producer copied in.
	got = bannersFromRawData(map[string]interface{}{
		"banner":       "Server: nginx/1.24",
		"raw_metadata": map[string]interface{}{"banner": "Server: apache/2.4"},
	})
	if got["banner"] != "Server: nginx/1.24" {
		t.Errorf("banner = %q; the outer value must win over the nested one", got["banner"])
	}
}

// findingClassEvidenceFor runs the real projection, so the test exercises the
// path intake takes rather than a second copy of it.
func findingClassEvidenceFor(raw map[string]interface{}) classEvidence {
	return findingClassEvidence(IngestFinding{RawData: raw})
}

// bannerValueFor turns a shipped rule's regexp into a header value that satisfies
// it, without hand-maintaining a table beside the rules.
//
// Every shipped banner pattern is `(?i)^server:\s*<alternation>(?:[/ …]|$)`, so
// the product token is the literal run after the anchor, with the first branch
// of any alternation taken. A pattern this cannot read fails the test loudly
// rather than being skipped — a rule silently excluded from a parity test is the
// hole the parity test exists to close.
func bannerValueFor(t *testing.T, pattern string) string {
	t.Helper()
	const anchor = `(?i)^server:\s*`
	rest, ok := strings.CutPrefix(pattern, anchor)
	if !ok {
		t.Fatalf("banner pattern %q does not anchor on %q; if the shipped rules have grown "+
			"a new shape, teach this helper about it rather than letting the rule go unchecked",
			pattern, anchor)
	}
	rest = strings.TrimSuffix(rest, `(?:[/ ]|$)`)
	rest = strings.TrimSuffix(rest, `(?:[/( ]|$)`)
	rest = strings.TrimPrefix(rest, `(?:`)
	rest = strings.TrimSuffix(rest, `)`)
	if i := strings.IndexByte(rest, '|'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || strings.ContainsAny(rest, `\[](){}^$*+?`) {
		t.Fatalf("could not derive a matching banner value from pattern %q (got %q)", pattern, rest)
	}
	return rest + "/1.0"
}
