// Package syncauthority is the field-level authority model every bidirectional
// sync applies (asset-inventory ADR-0010 D7; DCIM SYNC_MODEL §2 and §4).
//
// The defaults — which fields of which object kinds are synced, and who wins
// each — are generated from standards/sync-authority.yaml into
// authority_gen.go. A tenant may override a field's authority per connection
// ([Overrides]); [Decide] is the one function that turns two values and their
// change history into push, pull, merge, nothing, or a conflict for a person.
//
// Nothing here talks to a peer or a database. The NetBox connector is the
// first caller; Device42 and the CMDB connectors reuse the same decision.
package syncauthority

import (
	"fmt"
	"sort"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Authority is who wins one field (SYNC_MODEL §2).
type Authority string

// Valid reports whether a is one of the five classes.
func (a Authority) Valid() bool {
	for _, x := range AllAuthorities {
		if a == x {
			return true
		}
	}
	return false
}

// FieldSpec is one synced field and its default authority.
type FieldSpec struct {
	Field     string
	Authority Authority
}

// KindSpec is one synced object kind.
type KindSpec struct {
	Kind dcim.ObjectKind
	// NetBox is the peer's REST endpoint, module/object ("ipam/prefixes").
	NetBox string
	// Order is the dependency order: a kind is planned and applied after every
	// kind with a lower order, so the objects it references already have a
	// peer id.
	Order int
	// Identity is the natural identity on the wire, in our column names — the
	// third matching step after the peer id and our id in the peer. Identity
	// columns are matched, never synced as fields.
	Identity []string
	Fields   []FieldSpec
}

// Field returns the spec of one field of k.
func (k KindSpec) Field(name string) (FieldSpec, bool) {
	for _, f := range k.Fields {
		if f.Field == name {
			return f, true
		}
	}
	return FieldSpec{}, false
}

// Kinds returns every synced kind in dependency order. The slice is a copy.
func Kinds() []KindSpec {
	out := make([]KindSpec, len(kinds))
	copy(out, kinds)
	return out
}

// Kind returns the spec of one kind.
func Kind(k dcim.ObjectKind) (KindSpec, bool) {
	for _, s := range kinds {
		if s.Kind == k {
			return s, true
		}
	}
	return KindSpec{}, false
}

// Default returns the default authority of kind.field.
func Default(kind dcim.ObjectKind, field string) (Authority, bool) {
	k, ok := Kind(kind)
	if !ok {
		return "", false
	}
	f, ok := k.Field(field)
	return f.Authority, ok
}

// Overrides are a connection's per-field authority choices:
// kind → field → authority. A field not named keeps its default.
type Overrides map[string]map[string]Authority

// Validate refuses an override naming a kind or field that is not synced, or
// an authority that does not exist. A typo must be a 400 on save, not a
// setting that appears to save and does nothing.
func (o Overrides) Validate() error {
	kinds := make([]string, 0, len(o))
	for k := range o {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		spec, ok := Kind(dcim.ObjectKind(kind))
		if !ok {
			return fmt.Errorf("field authority: %q is not a synced object kind", kind)
		}
		fields := make([]string, 0, len(o[kind]))
		for f := range o[kind] {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, field := range fields {
			if _, ok := spec.Field(field); !ok {
				return fmt.Errorf("field authority: %s has no synced field %q", kind, field)
			}
			if a := o[kind][field]; !a.Valid() {
				return fmt.Errorf("field authority: %s.%s: %q is not an authority (observed, declared_here, peer, merge, newest)", kind, field, a)
			}
		}
	}
	return nil
}

// Resolve returns the authority of kind.field under the overrides: the
// override when one is set, the default otherwise. ok is false for a field
// that is not synced at all.
func (o Overrides) Resolve(kind dcim.ObjectKind, field string) (Authority, bool) {
	def, ok := Default(kind, field)
	if !ok {
		return "", false
	}
	if a, set := o[string(kind)][field]; set && a.Valid() {
		return a, true
	}
	return def, true
}
