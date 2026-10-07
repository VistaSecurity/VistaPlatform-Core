package database

import "strings"

// LikeEscapeClause is the SQL to append after a LIKE / ILIKE pattern built
// with EscapeLike or ContainsPattern. Backslash is already Postgres's default
// LIKE escape character, but naming it makes the contract visible in the query
// and survives a session or driver that changes the default.
//
//	"u.email ILIKE $2" + database.LikeEscapeClause
const LikeEscapeClause = ` ESCAPE '\'`

// EscapeLike neutralises the LIKE metacharacters (`\`, `%`, `_`) in s so it
// matches itself literally.
//
// The value is always a bound parameter, so this is not about injection — it is
// about a search meaning what the user typed. Unescaped, typing `%` matches
// every row and `_` matches any single character, and both occur in the
// hostnames, e-mail local-parts and package names these searches exist to find
// (`build_agent_01`, `first_last@example.com`).
func EscapeLike(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ContainsPattern returns the LIKE pattern for "contains s" with s matched
// literally: `%` + EscapeLike(s) + `%`. Pair it with LikeEscapeClause.
func ContainsPattern(s string) string {
	return "%" + EscapeLike(s) + "%"
}
