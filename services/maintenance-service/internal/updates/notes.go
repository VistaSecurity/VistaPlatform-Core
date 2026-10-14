package updates

import "strings"

// DefaultNotesBaseURL is the website's per-release notes page root; the
// version is appended (docsv4/core/releases/<version>.md is published at
// https://vistasecurity.io/docs/releases/<version>/, the same docs base as
// scripts/feature-status.mjs DOCS_BASE). MAINTENANCE_NOTES_BASE_URL overrides
// it.
const DefaultNotesBaseURL = "https://vistasecurity.io/docs/releases/"

// CoreReleaseURL is the public Core repository's GitHub Release page prefix.
const CoreReleaseURL = "https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v"

// NotesURL is where an operator reads what a release changes. Core ships from
// ghcr.io and its GitHub Release is public; the commercial line's repository is
// private, so anything else gets the docs release page (spec D3).
func NotesURL(registry, version, docsBase string) string {
	if strings.EqualFold(strings.TrimSpace(registry), "ghcr.io") {
		return CoreReleaseURL + version
	}
	if docsBase == "" {
		docsBase = DefaultNotesBaseURL
	}
	if !strings.HasSuffix(docsBase, "/") {
		docsBase += "/"
	}
	return docsBase + version + "/"
}
