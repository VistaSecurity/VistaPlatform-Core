package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/api"
)

// Where a licence token can come from. These MUST match the names the
// Enterprise verifier reads (ee/edition/token.go: EDITION_TOKEN[_FILE], and the
// legacy LICENSE_TOKEN[_FILE]); Core cannot import that package, so they are
// repeated here. The chart always sets LICENSE_TOKEN_FILE and mounts the
// licence Secret there, on every edition.
var licenceTokenEnvVars = []string{"EDITION_TOKEN", "LICENSE_TOKEN"}
var licenceTokenFileEnvVars = []string{"EDITION_TOKEN_FILE", "LICENSE_TOKEN_FILE"}

// applyEdition runs the edition's licence hook at start-up. On a Core build
// there is no hook — nothing in the binary can verify a token — and until now
// that was silent: an operator who installed a licence on the Core images saw
// the install stay Core with no log line saying why (a Core → Enterprise
// upgrade rehearsal hit exactly this). So when a token is present on a Core
// build, say that it is being ignored and what it takes instead.
func applyEdition(
	h api.EditionHooks,
	db *sql.DB,
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	logf func(format string, args ...any),
) {
	if h.ApplyEditionToken != nil {
		h.ApplyEditionToken(db)
		return
	}
	if src := coreBuildTokenSource(getenv, readFile); src != "" {
		logf("[edition] WARNING: a licence token source is configured (%s), but this is a Core build, "+
			"which has no licence verifier — the token is ignored and the install runs as Core. "+
			"A licence takes effect only on the Enterprise images: upgrade the release to the "+
			"Enterprise chart and images (see \"Upgrading from Core\" in the Enterprise documentation).", src)
	}
}

// coreBuildTokenSource names where a non-empty licence token was found, or ""
// when there is none. An absent token file is "none": the chart mounts the
// Secret on every install, and a Core install without one is the ordinary case,
// not something to warn about. A configured file that is empty or cannot be
// read does warn; that is an attempted (but invalid) licence install, not an
// absent optional Secret. Files are checked before env vars, in the same order
// as the Enterprise readToken, so the warning names the source an Enterprise
// build would actually have used.
func coreBuildTokenSource(getenv func(string) string, readFile func(string) ([]byte, error)) string {
	for _, name := range licenceTokenFileEnvVars {
		path := strings.TrimSpace(getenv(name))
		if path == "" {
			continue
		}
		raw, err := readFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Sprintf("%s=%q (unreadable: %v)", name, path, err)
		}
		if err == nil {
			if strings.TrimSpace(string(raw)) == "" {
				return fmt.Sprintf("%s=%q (empty)", name, path)
			}
			return fmt.Sprintf("%s=%q", name, path)
		}
	}
	for _, name := range licenceTokenEnvVars {
		if strings.TrimSpace(getenv(name)) != "" {
			return name
		}
	}
	return ""
}
