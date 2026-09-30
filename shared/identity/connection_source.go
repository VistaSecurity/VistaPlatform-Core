package identity

// Which imported sources are CONNECTIONS.
//
// SourceImported covers two very different things. A connection is a system of
// record the tenant connected once and the platform then reads on its own — a
// CMDB profile (`cmdb:<profile id>`), a NetBox connection
// (`netbox:<connection id>`). A spreadsheet upload (`import`) is a person
// handing over an explicit list, every time. Rules that are about what a
// connection brings in unattended — admission authority, and whether its assets
// may be actively scanned without anyone asking (platform ADR-0002 D10) — must
// apply to connections only, never to a person's upload.
//
// The prefixes are defined once, here, and both the Go check and the SQL
// predicate are generated from them, so the two cannot drift.

import (
	"strings"
)

// connectionSourceRefPrefixes are the source-ref prefixes of connected systems
// of record. A new connector kind that imports assets is added here.
var connectionSourceRefPrefixes = []string{"cmdb:", "netbox:"}

// SpreadsheetImportSourceRef is the source ref of a person's spreadsheet
// upload (Inventory → Import).
const SpreadsheetImportSourceRef = "import"

// IsConnectionSourceRef reports whether ref names a connected system of record.
func IsConnectionSourceRef(ref string) bool {
	for _, p := range connectionSourceRefPrefixes {
		if strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

// IsConnectionSource reports whether s is an import from a connected system of
// record (not a spreadsheet, not an SBOM, not a catalogue).
func IsConnectionSource(s Source) bool {
	return s.Kind == SourceImported && IsConnectionSourceRef(s.Ref)
}

// ConnectionSourceRefSQL is a boolean SQL expression, TRUE when the text column
// expression col names a connected system of record — IsConnectionSourceRef in
// SQL. col is interpolated as written; pass a column reference, never input.
func ConnectionSourceRefSQL(col string) string {
	parts := make([]string, 0, len(connectionSourceRefPrefixes))
	for _, p := range connectionSourceRefPrefixes {
		// Prefixes are constants without LIKE metacharacters or quotes.
		parts = append(parts, col+" LIKE '"+p+"%'")
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}
