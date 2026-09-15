package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// Every audit category this service writes must be one the database will store
// (security review X.5, found while closing X5-09).
//
// `audit.activity_logs.event_category` carries a CHECK constraint. An entry
// carrying anything else is REJECTED by Postgres with SQLSTATE 23514 — and the
// failure is invisible from here: logAuditActivity discards LogActivity's
// error, LogActivity appends to a batch, and the flush is a background
// goroutine talking to another service.
//
// Three of this build's own audit events were written that way and never
// landed anywhere:
//
//	settings.identification.updated   "configuration"
//	settings.drift.updated            "configuration"
//	asset.merge.auto_accepted         "data_modification"
//
// Each looked fully audited. Each had a test asserting the handler called the
// logger. Each wrote nothing. "configuration" came from this package's own
// audit constants, which published two values the database rejects.
//
// So the guard is a scan of the source rather than a runtime check: the
// category is a literal at the call site, and that is where it has to be right.
//
// To mutation-test: change any category argument back to "configuration" or
// "data_modification". This fails and names the call site.
func TestEveryAuditCategoryThisServiceWritesIsStorable(t *testing.T) {
	roots := []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")}

	// logAuditActivity(c, "<event>", "<category>", …) and a struct literal's
	// EventCategory: "<category>". Constants are checked by the compiler
	// against the package that declares them, so only string literals need it.
	callSite := regexp.MustCompile(`logAuditActivity\(\s*c\s*,\s*"[^"]*"\s*,\s*"([a-z_]+)"`)
	structField := regexp.MustCompile(`EventCategory:\s*"([a-z_]+)"`)

	var checked int
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, re := range []*regexp.Regexp{callSite, structField} {
				for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
					checked++
					if !auditmiddleware.ValidEventCategory(m[1]) {
						t.Errorf("%s writes event_category %q, which audit.activity_logs rejects — "+
							"the entry is discarded on INSERT and the action is unaudited. Valid: %v",
							path, m[1], auditmiddleware.EventCategories())
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	if checked == 0 {
		t.Fatal("no audit category literals were found; the scan matched nothing and proved nothing")
	}
}
