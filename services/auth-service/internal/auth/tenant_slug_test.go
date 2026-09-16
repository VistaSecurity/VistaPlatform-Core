package auth

import (
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The CHECK the database actually enforces, copied from schema.sql:
//
//	CONSTRAINT valid_slug CHECK (((slug)::text ~ '^[a-z0-9-]+$'::text))
//
// Asserting against the real pattern rather than a paraphrase: a test that
// agreed with the code but not with the constraint would have passed happily
// while self-signup returned 500.
var validSlug = regexp.MustCompile(`^[a-z0-9-]+$`)

// The column is varchar(100); a longer value is a 500 of its own.
const slugColumnLimit = 100

func TestTenantSlug_SatisfiesEveryColumnConstraint(t *testing.T) {
	names := []string{
		"Acme, Inc.",                       // comma and period — observed 500 on a live install
		"O'Brien Ltd",                      // apostrophe
		"Müller GmbH",                      // non-ASCII
		"RC Verification Data v1.0.0-rc.6", // rc-verify's own fresh tenant
		"Plain Name",
		"  leading and trailing  ",
		"Acme,,,   Inc...", // runs of punctuation must not become runs of dashes
		"日本",               // slugifies to nothing at all
		"!!!",              // ditto
		"-leading-dash",
		"trailing-dash-",
		strings.Repeat("A", 250), // far past the column
		"",
	}
	for _, name := range names {
		slug := tenantSlug(name, uuid.New())
		if !validSlug.MatchString(slug) {
			t.Errorf("tenantSlug(%q) = %q, which the valid_slug CHECK rejects", name, slug)
		}
		if len(slug) > slugColumnLimit {
			t.Errorf("tenantSlug(%q) = %q (%d chars), longer than the varchar(%d) column", name, slug, len(slug), slugColumnLimit)
		}
		if strings.Contains(slug, "--") {
			t.Errorf("tenantSlug(%q) = %q — a run of punctuation collapsed into a run of dashes", name, slug)
		}
	}
}

// Two tenants may legitimately carry the same display name. The slug is UNIQUE
// (tenants_slug_key), so a derivation that ignored the tenant id would make the
// second signup a 500 — the same failure in a different disguise.
func TestTenantSlug_SameNameDiffersPerTenant(t *testing.T) {
	a := tenantSlug("Acme Inc", uuid.New())
	b := tenantSlug("Acme Inc", uuid.New())
	if a == b {
		t.Fatalf("two tenants named %q both got slug %q — tenants_slug_key would reject the second", "Acme Inc", a)
	}
	for _, s := range []string{a, b} {
		if !strings.HasPrefix(s, "acme-inc-") {
			t.Errorf("slug %q lost the readable stem; a slug people never recognise is worse than no slug", s)
		}
	}
}

// The readable part must survive, or the fix trades a 500 for an unusable URL.
func TestTenantSlug_KeepsTheReadableStem(t *testing.T) {
	for name, want := range map[string]string{
		"Acme, Inc.":  "acme-inc-",
		"O'Brien Ltd": "o-brien-ltd-",
		"Müller GmbH": "m-ller-gmbh-",
		"Plain Name":  "plain-name-",
	} {
		if got := tenantSlug(name, uuid.New()); !strings.HasPrefix(got, want) {
			t.Errorf("tenantSlug(%q) = %q, want prefix %q", name, got, want)
		}
	}
}
