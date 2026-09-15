package ast

import "strings"

// The grammar's fixed vocabulary: the eight sub-predicate collections (§3) and
// the twenty relationship names (ADR-0003 D2 — ten canonical types and their
// ten reverse labels). These are part of the grammar, not of the generated
// field catalogue, because the parser must disambiguate `x:(…)` before any
// catalogue is consulted. A Catalog re-exports the relationship list so a
// production catalogue can still be asked for it.

// Collections are the sub-predicate names (§3 `collection`).
var Collections = []string{
	"endpoint", "software", "finding", "cert", "crypto",
	"identifier", "relationship", "asset",
}

// IsCollection reports whether s names a sub-predicate collection,
// case-insensitively.
func IsCollection(s string) bool {
	s = strings.ToLower(s)
	for _, c := range Collections {
		if c == s {
			return true
		}
	}
	return false
}

// AnyRel is the wildcard traversal name.
const AnyRel = "any_rel"

// RelKeyword is the head of the explicit traversal form `rel(type, dir, n)`.
const RelKeyword = "rel"

// Relationship is one spelling of an edge type: either the canonical type or
// its reverse label, with the direction that spelling walks the edge.
type Relationship struct {
	// Name is the spelling, as it appears in a query.
	Name string
	// Type is the canonical edge type stored in asset_relationships.type.
	Type string
	// Direction is the direction this spelling walks the canonical edge.
	Direction Direction
	// Reverse reports whether Name is the reverse label.
	Reverse bool
}

// canonicalPairs are ADR-0003 D2's ten types with their reverse labels.
var canonicalPairs = [10][2]string{
	{"runs_on", "runs"},
	{"hosted_on", "hosts"},
	{"virtualized_by", "virtualizes"},
	{"depends_on", "used_by"},
	{"connects_to", "connected_from"},
	{"member_of", "members"},
	{"contains", "contained_by"},
	{"manages", "managed_by"},
	{"sends_data_to", "receives_data_from"},
	{"impacts", "impacted_by"},
}

// Relationships is the flat list of all twenty names, canonical first.
var Relationships = buildRelationships()

func buildRelationships() []Relationship {
	out := make([]Relationship, 0, 20)
	for _, p := range canonicalPairs {
		out = append(out, Relationship{Name: p[0], Type: p[0], Direction: DirOut})
	}
	for _, p := range canonicalPairs {
		out = append(out, Relationship{Name: p[1], Type: p[0], Direction: DirIn, Reverse: true})
	}
	return out
}

// RelationshipTypes is the ten canonical type keys, in ADR-0003 D2 order.
var RelationshipTypes = func() []string {
	out := make([]string, 0, len(canonicalPairs))
	for _, p := range canonicalPairs {
		out = append(out, p[0])
	}
	return out
}()

// LookupRelationship resolves a name (canonical or reverse) to its edge type
// and direction, case-insensitively.
func LookupRelationship(name string) (Relationship, bool) {
	name = strings.ToLower(name)
	for _, r := range Relationships {
		if r.Name == name {
			return r, true
		}
	}
	return Relationship{}, false
}

// IsRelationshipType reports whether s is one of the ten canonical types, which
// is what the explicit `rel(type, …)` form requires.
func IsRelationshipType(s string) bool {
	s = strings.ToLower(s)
	for _, t := range RelationshipTypes {
		if t == s {
			return true
		}
	}
	return false
}

// ParseDirection parses the direction argument of the explicit form.
func ParseDirection(s string) (Direction, bool) {
	switch Direction(strings.ToLower(s)) {
	case DirOut:
		return DirOut, true
	case DirIn:
		return DirIn, true
	case DirAny:
		return DirAny, true
	}
	return "", false
}
