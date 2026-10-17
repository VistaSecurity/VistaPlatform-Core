// Package customfields validates the values in an object's `custom_fields`
// jsonb against the tenant's custom field definitions (asset-inventory
// ADR-0010 D5; DCIM DATA_MODEL §8; BUILD_PLAN row 5.1). NetBox-shaped: the
// definition types, `required`, `default`, choice sets, the numeric
// minimum/maximum, the regex and the related-object check are NetBox's
// extras.CustomField.validate.
//
// Every DCIM write path calls [Validate] (or [Apply]) inside its tenant
// transaction, so the definitions are read under RLS from the same snapshot the
// row is written in. That per-transaction read is the definitions cache a write
// needs: one indexed read per write, and never a definition that another
// replica has already changed.
package customfields

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Type is a custom field type (NetBox CustomFieldTypeChoices).
type Type string

// The thirteen types, exactly the schema CHECK's list.
const (
	TypeText        Type = "text"
	TypeLongText    Type = "longtext"
	TypeInteger     Type = "integer"
	TypeDecimal     Type = "decimal"
	TypeBoolean     Type = "boolean"
	TypeDate        Type = "date"
	TypeDateTime    Type = "datetime"
	TypeURL         Type = "url"
	TypeJSON        Type = "json"
	TypeSelect      Type = "select"
	TypeMultiSelect Type = "multiselect"
	TypeObject      Type = "object"
	TypeMultiObject Type = "multiobject"
)

// Types lists every type, in the schema's order.
var Types = []Type{
	TypeText, TypeLongText, TypeInteger, TypeDecimal, TypeBoolean, TypeDate, TypeDateTime,
	TypeURL, TypeJSON, TypeSelect, TypeMultiSelect, TypeObject, TypeMultiObject,
}

// Valid reports whether t is one of [Types].
func (t Type) Valid() bool {
	for _, x := range Types {
		if x == t {
			return true
		}
	}
	return false
}

// UsesChoices reports whether the type draws from a choice set.
func (t Type) UsesChoices() bool { return t == TypeSelect || t == TypeMultiSelect }

// UsesObjects reports whether the type references objects.
func (t Type) UsesObjects() bool { return t == TypeObject || t == TypeMultiObject }

// Numeric reports whether minimum/maximum apply.
func (t Type) Numeric() bool { return t == TypeInteger || t == TypeDecimal }

// Textual reports whether the regex applies (NetBox: text, longtext, url).
func (t Type) Textual() bool { return t == TypeText || t == TypeLongText || t == TypeURL }

// ErrInvalid wraps every validation failure; callers map it to 400.
var ErrInvalid = errors.New("invalid custom field value")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// NamePattern is the identifier a field name must be: the jsonb key and the
// query language's `cf.<name>`. Mirrors the schema CHECK.
var NamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,49}$`)

// Definition is one custom field, as the validator needs it.
type Definition struct {
	ID                uuid.UUID
	Name              string
	Label             string
	Type              Type
	ObjectKinds       []string
	Required          bool
	Default           json.RawMessage // nil: no default
	Choices           []string        // the choice set's values (select/multiselect)
	RelatedObjectKind string
	Minimum, Maximum  *float64
	Regex             string
}

// Querier is the slice of *sql.Tx the package needs.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Load reads the definitions that apply to kind, ordered by name. It runs on
// the caller's tenant transaction: RLS limits it to the tenant's own rows.
func Load(ctx context.Context, q Querier, kind dcim.ObjectKind) ([]Definition, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT f.id, f.name, coalesce(f.label, ''), f.type, f.object_kinds, f.required, f."default",
		       coalesce(cs.choices, '[]'::jsonb), coalesce(f.related_object_kind, ''),
		       f.validation_minimum::float8, f.validation_maximum::float8, coalesce(f.validation_regex, '')
		  FROM public.custom_fields f
		  LEFT JOIN public.custom_field_choice_sets cs ON cs.tenant_id = f.tenant_id AND cs.id = f.choice_set_id
		 WHERE $1 = ANY (f.object_kinds)
		 ORDER BY f.name`, string(kind))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Definition
	for rows.Next() {
		var d Definition
		var kinds pq.StringArray
		var def, choices []byte
		var lo, hi sql.NullFloat64
		var typ string
		if err := rows.Scan(&d.ID, &d.Name, &d.Label, &typ, &kinds, &d.Required, &def, &choices,
			&d.RelatedObjectKind, &lo, &hi, &d.Regex); err != nil {
			return nil, err
		}
		d.Type = Type(typ)
		d.ObjectKinds = kinds
		if len(def) > 0 && string(def) != "null" {
			d.Default = def
		}
		if d.Choices, err = ChoiceValues(choices); err != nil {
			return nil, err
		}
		if lo.Valid {
			v := lo.Float64
			d.Minimum = &v
		}
		if hi.Valid {
			v := hi.Float64
			d.Maximum = &v
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ChoiceValues reads NetBox's `[[value, label], …]` (a bare string is taken as
// a value that is its own label) and returns the values.
func ChoiceValues(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, invalid("choices must be an array of [value, label] pairs")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		var pair []string
		if err := json.Unmarshal(it, &pair); err == nil {
			if len(pair) < 1 || len(pair) > 2 || strings.TrimSpace(pair[0]) == "" {
				return nil, invalid("each choice must be [value, label] with a non-empty value")
			}
			out = append(out, pair[0])
			continue
		}
		var s string
		if err := json.Unmarshal(it, &s); err != nil || strings.TrimSpace(s) == "" {
			return nil, invalid("each choice must be [value, label] with a non-empty value")
		}
		out = append(out, s)
	}
	return out, nil
}

// Options says how a write is checked.
type Options struct {
	// Create fills absent fields from their defaults before checking.
	Create bool
	// EnforceRequired refuses a write that leaves a required field empty.
	// Person-initiated writes (ui/api) enforce it; intake, sync and system
	// writes do not, so a tenant's new required field cannot stop discovery
	// (the person fills it in when they next edit the object).
	EnforceRequired bool
}

// Validate loads kind's definitions and checks values against them,
// including that each referenced object exists for the tenant. It returns
// the normalised map to store (numbers as numbers, dates canonical).
func Validate(ctx context.Context, q Querier, kind dcim.ObjectKind, values map[string]any, opts Options) (map[string]any, error) {
	defs, err := Load(ctx, q, kind)
	if err != nil {
		return nil, err
	}
	out, refs, err := Check(defs, values, opts)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		if err := objectExists(ctx, q, r.kind, r.id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Defaults returns the default value of every field that has one: what a new
// object starts with (NetBox populates defaults on create).
func Defaults(defs []Definition) map[string]any {
	out := map[string]any{}
	for _, d := range defs {
		if d.Default == nil {
			continue
		}
		var v any
		if err := decodeJSON(d.Default, &v); err == nil && v != nil {
			out[d.Name] = v
		}
	}
	return out
}

type objectRef struct {
	field string
	kind  dcim.ObjectKind
	id    uuid.UUID
}

// Check validates values against defs without touching the database (the
// related objects it returns are checked by [Validate]).
func Check(defs []Definition, values map[string]any, opts Options) (map[string]any, []objectRef, error) {
	byName := make(map[string]Definition, len(defs))
	for _, d := range defs {
		byName[d.Name] = d
	}
	in := map[string]any{}
	for k, v := range values {
		in[k] = v
	}
	if opts.Create {
		for k, v := range Defaults(defs) {
			if isEmpty(in[k]) {
				in[k] = v
			}
		}
	}
	names := make([]string, 0, len(in))
	for k := range in {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make(map[string]any, len(in))
	var refs []objectRef
	for _, name := range names {
		d, ok := byName[name]
		if !ok {
			return nil, nil, invalid("unknown custom field %q", name)
		}
		v := in[name]
		if isEmpty(v) {
			// NetBox stores an unset field as null; an empty string or list is
			// the same "no value".
			out[name] = nil
			continue
		}
		nv, r, err := checkValue(d, v)
		if err != nil {
			return nil, nil, err
		}
		out[name] = nv
		refs = append(refs, r...)
	}
	if opts.EnforceRequired {
		for _, d := range defs {
			if d.Required && isEmpty(out[d.Name]) {
				return nil, nil, invalid("custom field %q is required", d.Name)
			}
		}
	}
	return out, refs, nil
}

func checkValue(d Definition, v any) (any, []objectRef, error) {
	switch d.Type {
	case TypeText, TypeLongText:
		s, ok := v.(string)
		if !ok {
			return nil, nil, invalid("custom field %q must be text", d.Name)
		}
		if err := checkRegex(d, s); err != nil {
			return nil, nil, err
		}
		return s, nil, nil
	case TypeURL:
		s, ok := v.(string)
		if !ok {
			return nil, nil, invalid("custom field %q must be a URL", d.Name)
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, nil, invalid("custom field %q must be an absolute URL", d.Name)
		}
		if err := checkRegex(d, s); err != nil {
			return nil, nil, err
		}
		return s, nil, nil
	case TypeInteger:
		f, ok := number(v)
		if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
			return nil, nil, invalid("custom field %q must be an integer", d.Name)
		}
		if err := checkRange(d, f); err != nil {
			return nil, nil, err
		}
		return int64(f), nil, nil
	case TypeDecimal:
		f, ok := number(v)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, nil, invalid("custom field %q must be a number", d.Name)
		}
		if err := checkRange(d, f); err != nil {
			return nil, nil, err
		}
		return f, nil, nil
	case TypeBoolean:
		b, ok := v.(bool)
		if !ok {
			return nil, nil, invalid("custom field %q must be true or false", d.Name)
		}
		return b, nil, nil
	case TypeDate:
		s, ok := v.(string)
		if !ok {
			return nil, nil, invalid("custom field %q must be a date (YYYY-MM-DD)", d.Name)
		}
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return nil, nil, invalid("custom field %q must be a date (YYYY-MM-DD)", d.Name)
		}
		return t.Format("2006-01-02"), nil, nil
	case TypeDateTime:
		s, ok := v.(string)
		if !ok {
			return nil, nil, invalid("custom field %q must be a date and time (RFC 3339)", d.Name)
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, nil, invalid("custom field %q must be a date and time (RFC 3339)", d.Name)
		}
		return t.UTC().Format(time.RFC3339), nil, nil
	case TypeJSON:
		return v, nil, nil
	case TypeSelect:
		s, ok := v.(string)
		if !ok || !contains(d.Choices, s) {
			return nil, nil, invalid("custom field %q: %v is not one of its choices", d.Name, v)
		}
		return s, nil, nil
	case TypeMultiSelect:
		items, ok := v.([]any)
		if !ok {
			return nil, nil, invalid("custom field %q must be a list of choices", d.Name)
		}
		out := make([]any, 0, len(items))
		for _, it := range items {
			s, ok := it.(string)
			if !ok || !contains(d.Choices, s) {
				return nil, nil, invalid("custom field %q: %v is not one of its choices", d.Name, it)
			}
			out = append(out, s)
		}
		return out, nil, nil
	case TypeObject:
		id, err := objectID(d, v)
		if err != nil {
			return nil, nil, err
		}
		return id.String(), []objectRef{{field: d.Name, kind: dcim.ObjectKind(d.RelatedObjectKind), id: id}}, nil
	case TypeMultiObject:
		items, ok := v.([]any)
		if !ok {
			return nil, nil, invalid("custom field %q must be a list of object ids", d.Name)
		}
		out := make([]any, 0, len(items))
		var refs []objectRef
		for _, it := range items {
			id, err := objectID(d, it)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, id.String())
			refs = append(refs, objectRef{field: d.Name, kind: dcim.ObjectKind(d.RelatedObjectKind), id: id})
		}
		return out, refs, nil
	}
	return nil, nil, invalid("custom field %q has an unknown type %q", d.Name, d.Type)
}

func objectID(d Definition, v any) (uuid.UUID, error) {
	s, ok := v.(string)
	if !ok {
		return uuid.Nil, invalid("custom field %q must reference a %s by id", d.Name, d.RelatedObjectKind)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, invalid("custom field %q must reference a %s by id", d.Name, d.RelatedObjectKind)
	}
	return id, nil
}

func checkRegex(d Definition, s string) error {
	if d.Regex == "" {
		return nil
	}
	re, err := regexp.Compile(d.Regex)
	if err != nil {
		return invalid("custom field %q has an invalid validation regex", d.Name)
	}
	if !re.MatchString(s) {
		return invalid("custom field %q must match %s", d.Name, d.Regex)
	}
	return nil
}

func checkRange(d Definition, f float64) error {
	if d.Minimum != nil && f < *d.Minimum {
		return invalid("custom field %q must be at least %s", d.Name, strconv.FormatFloat(*d.Minimum, 'f', -1, 64))
	}
	if d.Maximum != nil && f > *d.Maximum {
		return invalid("custom field %q must be at most %s", d.Name, strconv.FormatFloat(*d.Maximum, 'f', -1, 64))
	}
	return nil
}

// number reads a JSON number in any of the shapes a decoder produces.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	}
	return 0, false
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func decodeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	return dec.Decode(v)
}

// objectExists checks a referenced object is a row of its kind's table that
// the tenant can see. The table comes from the generated vocabulary, never
// from the request; RLS scopes the read.
func objectExists(ctx context.Context, q Querier, kind dcim.ObjectKind, id uuid.UUID) error {
	table := kind.Table()
	if table == "" {
		return invalid("custom field references an unknown kind %q", kind)
	}
	var present bool
	if err := q.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&present); err != nil {
		return err
	}
	if !present {
		return invalid("no %s %s", kind, id)
	}
	var exists bool
	if err := q.QueryRowContext(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM public.%s WHERE id = $1)`, pq.QuoteIdentifier(table)), id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return invalid("no %s %s", kind, id)
	}
	return nil
}

// FromJSON decodes a stored or posted custom_fields object (numbers kept as
// json.Number). Empty input is an empty map.
func FromJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := decodeJSON(raw, &m); err != nil {
		return nil, invalid("custom_fields must be a JSON object")
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// AsMap reads a custom_fields value from a decoded JSON row: an object, or
// nil / absent for none.
func AsMap(v any) (map[string]any, error) {
	switch m := v.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return m, nil
	}
	return nil, invalid("custom_fields must be a JSON object")
}

// CheckDefinition validates a definition before it is stored: what the schema
// CHECKs cannot say (the regex compiles, the default is a valid value of the
// field's own type and choices).
func CheckDefinition(d Definition) error {
	if !NamePattern.MatchString(d.Name) {
		return invalid("name must be a lowercase identifier (letters, digits, underscores; starting with a letter)")
	}
	if !d.Type.Valid() {
		return invalid("unknown type %q", d.Type)
	}
	if len(d.ObjectKinds) == 0 {
		return invalid("object_kinds must name at least one object kind")
	}
	for _, k := range d.ObjectKinds {
		if _, ok := dcim.ParseObjectKind(k); !ok {
			return invalid("unknown object kind %q", k)
		}
	}
	if d.Type.UsesObjects() {
		if _, ok := dcim.ParseObjectKind(d.RelatedObjectKind); !ok {
			return invalid("an %s field needs related_object_kind", d.Type)
		}
	}
	if d.Regex != "" {
		if !d.Type.Textual() {
			return invalid("validation_regex applies to text, longtext and url fields only")
		}
		if _, err := regexp.Compile(d.Regex); err != nil {
			return invalid("validation_regex does not compile: %v", err)
		}
	}
	if (d.Minimum != nil || d.Maximum != nil) && !d.Type.Numeric() {
		return invalid("validation_minimum / validation_maximum apply to integer and decimal fields only")
	}
	if d.Default != nil {
		var v any
		if err := decodeJSON(d.Default, &v); err != nil {
			return invalid("default must be JSON")
		}
		if !isEmpty(v) {
			if _, _, err := checkValue(d, v); err != nil {
				return fmt.Errorf("default: %w", err)
			}
		}
	}
	return nil
}

// ParseCell reads one CSV cell (the bulk importer's `cf.<name>` column) as a
// value of d's type, ready for [Check]. Lists (multiselect, multiobject) are
// separated by `|`, as every list column of the importer is.
func ParseCell(d Definition, cell string) (any, error) {
	cell = strings.TrimSpace(cell)
	switch d.Type {
	case TypeInteger:
		n, err := strconv.ParseInt(cell, 10, 64)
		if err != nil {
			return nil, invalid("cf.%s: %q is not a whole number", d.Name, cell)
		}
		return n, nil
	case TypeDecimal:
		if _, err := strconv.ParseFloat(cell, 64); err != nil {
			return nil, invalid("cf.%s: %q is not a number", d.Name, cell)
		}
		return json.Number(cell), nil
	case TypeBoolean:
		switch strings.ToLower(cell) {
		case "true", "yes", "y", "1":
			return true, nil
		case "false", "no", "n", "0":
			return false, nil
		}
		return nil, invalid("cf.%s: %q is not true or false", d.Name, cell)
	case TypeJSON:
		var v any
		if err := decodeJSON([]byte(cell), &v); err != nil {
			return nil, invalid("cf.%s: not valid JSON", d.Name)
		}
		return v, nil
	case TypeMultiSelect, TypeMultiObject:
		var out []any
		for _, p := range strings.Split(cell, "|") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, nil
	}
	return cell, nil
}

// FormatCell writes a stored value as a CSV cell, the inverse of [ParseCell]:
// blank for no value, `|`-joined lists, JSON for a json field.
func FormatCell(d Definition, v any) string {
	if isEmpty(v) {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	case []any:
		if d.Type == TypeMultiSelect || d.Type == TypeMultiObject {
			parts := make([]string, len(x))
			for i, e := range x {
				parts[i] = fmt.Sprint(e)
			}
			return strings.Join(parts, "|")
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// ByName indexes definitions by name.
func ByName(defs []Definition) map[string]Definition {
	out := make(map[string]Definition, len(defs))
	for _, d := range defs {
		out[d.Name] = d
	}
	return out
}

// ColumnPrefix is the prefix of a custom field column in a CSV import or
// export (`cf.<name>`), the query language's namespace spelling.
const ColumnPrefix = "cf."
