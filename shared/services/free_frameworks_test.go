package services

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The free/regulated framework partition is enforced in three places, and this
// list is only trustworthy while all three agree:
//
//   - scripts/audit-edition-boundary.mjs (FREE_FRAMEWORKS / REGULATED_FRAMEWORKS),
//     run by `make audit` — it fails if a free framework leaves seed.sql or a
//     regulated one enters it;
//   - scripts/database/seed.sql's final summary block, which counts the six;
//   - FreeFrameworkCodes here, which decides what consumes cap.
//
// Adding a seventh free framework to the audit script without adding it here
// would leave it published, advertised, and unreachable to any tenant whose
// compliance_frameworks_max is 0 — which is exactly the bug (CMP-6) this list
// was introduced to fix. So the drift is a test failure, not a review item.
func TestFreeFrameworkCodesMatchTheEditionBoundaryAudit(t *testing.T) {
	root := testdb.RepoRoot(t)

	auditPath := filepath.Join(root, "scripts", "audit-edition-boundary.mjs")
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read %s: %v", auditPath, err)
	}

	block := regexp.MustCompile(`(?s)const FREE_FRAMEWORKS\s*=\s*\[(.*?)\]`).FindStringSubmatch(string(body))
	if block == nil {
		t.Fatal("could not find FREE_FRAMEWORKS in scripts/audit-edition-boundary.mjs — if it was renamed, update this test rather than deleting it")
	}
	var fromAudit []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(block[1], -1) {
		fromAudit = append(fromAudit, m[1])
	}

	got := append([]string(nil), FreeFrameworkCodes...)
	sort.Strings(got)
	sort.Strings(fromAudit)

	if strings.Join(got, ",") != strings.Join(fromAudit, ",") {
		t.Errorf("FreeFrameworkCodes and the edition-boundary audit disagree:\n  Go:    %v\n  audit: %v", got, fromAudit)
	}

	// And the regulated catalog must stay OUT of the exemption: those are what
	// the cap is for.
	regBlock := regexp.MustCompile(`const REGULATED_FRAMEWORKS\s*=\s*\[(.*?)\]`).FindStringSubmatch(string(body))
	if regBlock == nil {
		t.Fatal("could not find REGULATED_FRAMEWORKS in scripts/audit-edition-boundary.mjs")
	}
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(regBlock[1], -1) {
		for _, free := range FreeFrameworkCodes {
			if free == m[1] {
				t.Errorf("regulated framework %q is exempted from the compliance-framework cap", m[1])
			}
		}
	}
}
