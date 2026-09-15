package postgres

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// The writer's half of the identity contract, stated where the writer is.
//
// software.Product.Identity hands back a distinct name@version for each
// purl-less product; storing the EMPTY STRING rather than NULL would key every
// one of them on that one string in the database, so the second would collide
// with the first. Nothing on the Go side can observe that happening — the
// package's integration tests (TestIntegration_SBOM_PurlLessProductsAreDistinct
// Rows, TestIntegration_HostInventory_Materialises_LocalMode) are what catch it
// against a real Postgres. This is the unit-level statement of the rule.
func TestNullableIsTheAbsentMeansNULLRule(t *testing.T) {
	for _, empty := range []string{"", " ", "\t", "\n  "} {
		if got := nullable(empty); got != nil {
			t.Errorf("nullable(%q) = %v, want nil — '' is a VALUE to coalesce and NULL is not", empty, got)
		}
	}
	if got := nullable("pkg:npm/left-pad@1.3.0"); got != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("nullable dropped a real value: %v", got)
	}
}

// A CPE is folded to lowercase AT THE WRITER, and the fold must happen BEFORE
// the identity is computed — otherwise Go would key on the mixed-case string
// and the unique index on the stored lowercase one, which is two answers for
// one product.
func TestFoldForWriteLowercasesTheCPEBeforeComputingIdentity(t *testing.T) {
	upper := software.Product{Name: "openssl", Version: "3.0.13", CPE: "cpe:2.3:a:OpenSSL:OpenSSL:3.0.13:*:*:*:*:*:*:*"}
	lower := software.Product{Name: "openssl", Version: "3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"}

	gotUpper := FoldForWrite(upper)
	gotLower := FoldForWrite(lower)

	if gotUpper.CPE != gotLower.CPE {
		t.Fatalf("stored CPE differs by case: %q vs %q", gotUpper.CPE, gotLower.CPE)
	}
	if gotUpper.Identity() != gotLower.Identity() {
		t.Fatalf("identity differs by case: %q vs %q — two catalogue rows for one product line",
			gotUpper.Identity(), gotLower.Identity())
	}
	if strings.ContainsAny(gotUpper.CPE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Fatalf("CPE was not folded: %q", gotUpper.CPE)
	}

	// The polarity that matters as much: the fold must not damage a CPE that
	// was already canonical.
	if gotLower.CPE != lower.CPE {
		t.Fatalf("an already-lowercase CPE changed: %q → %q", lower.CPE, gotLower.CPE)
	}
}

// A purl is the strongest identity form and must survive the fold untouched —
// purl case is significant in the name component for some ecosystems, and
// NormalizePURL already decided what is canonical. Folding it here would be the
// CPE rule applied where it does not hold.
func TestFoldForWriteDoesNotTouchThePURL(t *testing.T) {
	p := software.Product{Name: "AngularJS", PURL: "pkg:npm/%40angular/core@17.0.0"}
	if got := FoldForWrite(p); got.PURL != p.PURL {
		t.Fatalf("purl changed: %q → %q", p.PURL, got.PURL)
	}
}
