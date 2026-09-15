// Package ast holds the node types of the asset-inventory query language.
//
// The node set is fixed by QUERY_LANGUAGE.md §7.1 and is the cross-language
// contract: a TypeScript port must produce the same tree for the same text.
// Nothing here knows about SQL, the field catalogue, or the source text beyond
// the spans it carries.
//
// Spec: docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md
package ast

// Span is a half-open byte range [Start, End) into the query source. Every node
// and every FieldRef carries one so an error can underline the offending text
// (§10).
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Merge returns the smallest span covering both s and other.
func (s Span) Merge(other Span) Span {
	out := s
	if other.Start < out.Start {
		out.Start = other.Start
	}
	if other.End > out.End {
		out.End = other.End
	}
	return out
}

// Op is a comparison operator. The ":=" spelling is normalised to "=" at parse
// time (§10: canonical form writes ":=" as "=").
type Op string

const (
	// OpColon is ":" — loose, type-dependent match (§4.4). Equality for most
	// types, substring for text, subtree for class, containment for inet.
	OpColon Op = ":"
	// OpEq is "=" — exact, case-sensitive equality.
	OpEq Op = "="
	// OpNe is "!=".
	OpNe Op = "!="
	// OpLt is "<".
	OpLt Op = "<"
	// OpLte is "<=".
	OpLte Op = "<="
	// OpGt is ">".
	OpGt Op = ">"
	// OpGte is ">=".
	OpGte Op = ">="
)

// Ordering reports whether op is one of < <= > >=.
func (o Op) Ordering() bool {
	switch o {
	case OpLt, OpLte, OpGt, OpGte:
		return true
	}
	return false
}

// Direction is the traversal direction of a Traverse node.
type Direction string

const (
	// DirOut follows edges in the canonical stored direction.
	DirOut Direction = "out"
	// DirIn follows edges backwards (what a reverse label means).
	DirIn Direction = "in"
	// DirAny follows edges in both directions.
	DirAny Direction = "any"
)

// TraverseForm records which of the three surface spellings a traversal used,
// so the formatter can write back the form the author chose (§3).
type TraverseForm string

const (
	// FormNamed is `depends_on:(…)` / `used_by(2):(…)`.
	FormNamed TraverseForm = "named"
	// FormExplicit is `rel(connects_to, in, 2):(…)`.
	FormExplicit TraverseForm = "rel"
	// FormAny is `any_rel:(…)` / `any_rel(2):(…)`.
	FormAny TraverseForm = "any"
)

// Node is one node of the parsed query. The set is closed: the eleven types
// below are the whole language (§7.1).
type Node interface {
	// Span returns the source range the node was parsed from.
	Span() Span
	// Kind returns the stable node tag used by the compact JSON encoding.
	Kind() string
	node()
}

// And is a conjunction. Juxtaposition in the source is an And (§2).
type And struct {
	Children []Node
	Sp       Span
}

// Or is a disjunction.
type Or struct {
	Children []Node
	Sp       Span
}

// Not negates its child. `-term` and `not term` both parse to this.
type Not struct {
	Child Node
	Sp    Span
}

// Compare is a single field/operator/literal term.
type Compare struct {
	Field FieldRef
	Op    Op
	Value Literal
	Sp    Span
}

// InSet is `field in (a, b)` and `field not in (a, b)`. Negated is kept on the
// node rather than wrapped in a Not so the formatter can write back `not in`.
type InSet struct {
	Field   FieldRef
	Values  []Literal
	Negated bool
	Sp      Span
}

// Range is `field:[lo to hi]`, inclusive at both ends (§3).
type Range struct {
	Field  FieldRef
	Lo, Hi Literal
	Sp     Span
}

// Match is `field ~ "regex"`. The regex is RE2 and is validated, never run,
// by the validator.
type Match struct {
	Field FieldRef
	Regex string
	Sp    Span
}

// Exists is `exists(field)`. `exists(<collection>)` parses to a Sub with a nil
// predicate instead, because that is an EXISTS over a child table.
type Exists struct {
	Field FieldRef
	Sp    Span
}

// FreeText is a term with no field (§5.4).
type FreeText struct {
	Value Literal
	Sp    Span
}

// Sub is an EXISTS over a child collection: `endpoint:(…)`. A nil Predicate
// means "at least one row exists", the shape `exists(endpoint)` produces.
type Sub struct {
	Collection string
	Predicate  Node
	Sp         Span
}

// Traverse is a depth-bounded walk over asset_relationships (§5.6).
//
// Name is what the author wrote (a canonical type, a reverse label, or
// "any_rel"); Type and Direction are the resolved canonical edge type and the
// direction to walk it. Depth 1 is the grammar default.
type Traverse struct {
	Form      TraverseForm
	Name      string
	Type      string
	Direction Direction
	Depth     int
	Predicate Node
	Sp        Span
}

func (n *And) Span() Span      { return n.Sp }
func (n *Or) Span() Span       { return n.Sp }
func (n *Not) Span() Span      { return n.Sp }
func (n *Compare) Span() Span  { return n.Sp }
func (n *InSet) Span() Span    { return n.Sp }
func (n *Range) Span() Span    { return n.Sp }
func (n *Match) Span() Span    { return n.Sp }
func (n *Exists) Span() Span   { return n.Sp }
func (n *FreeText) Span() Span { return n.Sp }
func (n *Sub) Span() Span      { return n.Sp }
func (n *Traverse) Span() Span { return n.Sp }

func (n *And) Kind() string      { return "and" }
func (n *Or) Kind() string       { return "or" }
func (n *Not) Kind() string      { return "not" }
func (n *Compare) Kind() string  { return "cmp" }
func (n *InSet) Kind() string    { return "in" }
func (n *Range) Kind() string    { return "range" }
func (n *Match) Kind() string    { return "match" }
func (n *Exists) Kind() string   { return "exists" }
func (n *FreeText) Kind() string { return "text" }
func (n *Sub) Kind() string      { return "sub" }
func (n *Traverse) Kind() string { return "traverse" }

func (*And) node()      {}
func (*Or) node()       {}
func (*Not) node()      {}
func (*Compare) node()  {}
func (*InSet) node()    {}
func (*Range) node()    {}
func (*Match) node()    {}
func (*Exists) node()   {}
func (*FreeText) node() {}
func (*Sub) node()      {}
func (*Traverse) node() {}

// Walk calls fn for n and, unless fn returns false, for every descendant in
// source order.
func Walk(n Node, fn func(Node) bool) {
	if n == nil {
		return
	}
	if !fn(n) {
		return
	}
	switch t := n.(type) {
	case *And:
		for _, c := range t.Children {
			Walk(c, fn)
		}
	case *Or:
		for _, c := range t.Children {
			Walk(c, fn)
		}
	case *Not:
		Walk(t.Child, fn)
	case *Sub:
		Walk(t.Predicate, fn)
	case *Traverse:
		Walk(t.Predicate, fn)
	}
}

// Fields calls fn for every FieldRef in the tree, by pointer, so a resolver can
// fill in Namespace, Type and Accessor in place.
func Fields(n Node, fn func(*FieldRef)) {
	Walk(n, func(node Node) bool {
		switch t := node.(type) {
		case *Compare:
			fn(&t.Field)
		case *InSet:
			fn(&t.Field)
		case *Range:
			fn(&t.Field)
		case *Match:
			fn(&t.Field)
		case *Exists:
			fn(&t.Field)
		}
		return true
	})
}
