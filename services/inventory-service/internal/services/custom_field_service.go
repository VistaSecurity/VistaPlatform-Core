package services

// Custom fields (DCIM BUILD_PLAN row 5.1; ADR-0010 D5; DATA_MODEL §8): the
// tenant's custom field definitions and choice sets, served by the object
// engine (ipam_engine.go) so they get its CRUD, RLS scoping and change
// recording; and the one hook every engine write runs —
// applyEngineCustomFields — that validates an object's `custom_fields`
// against those definitions through shared/dcim/customfields.
//
// The hand-written write paths call validateCustomFieldsTx themselves:
// interfaces (interface_service.go), business units (business_unit_service.go)
// and assets (asset_custom_fields.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
)

// CustomFieldService serves /dcim/custom-fields and
// /dcim/custom-field-choice-sets over the object engine.
type CustomFieldService struct {
	*IPAMService
}

// NewCustomFieldService returns the service over db (the app-role pool).
func NewCustomFieldService(db *sql.DB) *CustomFieldService {
	return &CustomFieldService{IPAMService: newObjectEngine(db, customFieldSpecs())}
}

func customFieldSpecs() []*ipamSpec {
	substrate := []ipamCol{
		{Name: "description", Type: colText},
		{Name: "source_kind", Type: colText},
		{Name: "source_ref", Type: colText},
		{Name: "custom_fields", Type: colJSON},
	}
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindCustomFieldChoiceSet, Table: "custom_field_choice_sets", Route: "custom-field-choice-sets",
			Cols: append([]ipamCol{
				{Name: "name", Type: colText, Required: true},
				{Name: "choices", Type: colJSONValue, Required: true},
				{Name: "order_alphabetically", Type: colBool},
			}, substrate...),
			Search:  []string{"name", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareChoiceSet,
		},
		{
			Kind: dcim.ObjectKindCustomField, Table: "custom_fields", Route: "custom-fields",
			Cols: append([]ipamCol{
				{Name: "name", Type: colText, Required: true},
				{Name: "label", Type: colText},
				{Name: "type", Type: colText, Required: true},
				{Name: "object_kinds", Type: colTextArray, Required: true},
				{Name: "required", Type: colBool},
				{Name: "default", Type: colJSONValue},
				{Name: "choice_set_id", Type: colUUID},
				{Name: "related_object_kind", Type: colText},
				{Name: "validation_minimum", Type: colNumeric},
				{Name: "validation_maximum", Type: colNumeric},
				{Name: "validation_regex", Type: colText},
				{Name: "ui_visible", Type: colText},
				{Name: "ui_editable", Type: colText},
				{Name: "weight", Type: colInt},
				{Name: "group_name", Type: colText},
				{Name: "is_cloneable", Type: colBool},
			}, substrate...),
			Filters: []ipamFilter{
				{Param: "type", Column: "type", Type: colText},
				{Param: "name", Column: "name", Type: colText},
				{Param: "choice_set_id", Column: "choice_set_id", Type: colUUID},
				{Param: "object_kind", Custom: func(v string, n int) (string, any, error) {
					if _, ok := dcim.ParseObjectKind(v); !ok {
						return "", nil, ipamInvalid("object_kind: unknown kind %q", v)
					}
					return fmt.Sprintf("$%d = ANY (t.object_kinds)", n), v, nil
				}},
			},
			Search:  []string{"name", "label", "description", "group_name"},
			Order:   "t.group_name NULLS FIRST, t.weight, t.name, t.id",
			Prepare: prepareCustomField,
		},
	}
}

func prepareChoiceSet(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	raw, err := json.Marshal(row["choices"])
	if err != nil {
		return ipamInvalid("choices must be JSON")
	}
	vals, err := customfields.ChoiceValues(raw)
	if err != nil {
		return wrapCustomFieldError(err)
	}
	if len(vals) == 0 {
		return ipamInvalid("a choice set needs at least one choice")
	}
	seen := map[string]bool{}
	for _, v := range vals {
		if seen[v] {
			return ipamInvalid("choice %q appears twice", v)
		}
		seen[v] = true
	}
	return nil
}

// prepareCustomField checks a definition: the schema's CHECKs plus what they
// cannot say (the regex compiles, the default is a valid value), with the
// choice set read under RLS so the default is checked against its choices.
func prepareCustomField(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	d := customfields.Definition{
		Name:              str(row["name"]),
		Type:              customfields.Type(str(row["type"])),
		RelatedObjectKind: str(row["related_object_kind"]),
		Regex:             str(row["validation_regex"]),
	}
	switch k := row["object_kinds"].(type) {
	case []any:
		for _, x := range k {
			d.ObjectKinds = append(d.ObjectKinds, fmt.Sprint(x))
		}
	case []string:
		d.ObjectKinds = k
	}
	for name, dst := range map[string]**float64{"validation_minimum": &d.Minimum, "validation_maximum": &d.Maximum} {
		if v, ok := row[name]; ok && v != nil {
			f, err := json.Number(fmt.Sprint(v)).Float64()
			if err != nil {
				return ipamInvalid("%s must be a number", name)
			}
			*dst = &f
		}
	}
	if v, ok := row["default"]; ok && v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return ipamInvalid("default must be JSON")
		}
		d.Default = b
	}
	if d.Type.UsesChoices() {
		if row["choice_set_id"] == nil || row["choice_set_id"] == "" {
			return ipamInvalid("a %s field needs choice_set_id", d.Type)
		}
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT choices FROM public.custom_field_choice_sets WHERE id = $1::uuid`, fmt.Sprint(row["choice_set_id"])).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ipamInvalid("no such choice set %v", row["choice_set_id"])
		}
		if err != nil {
			return mapIPAMError(err, false)
		}
		if d.Choices, err = customfields.ChoiceValues(raw); err != nil {
			return wrapCustomFieldError(err)
		}
	} else if row["choice_set_id"] != nil && row["choice_set_id"] != "" {
		return ipamInvalid("only select and multiselect fields take a choice set")
	}
	if !d.Type.UsesObjects() && d.RelatedObjectKind != "" {
		return ipamInvalid("only object and multiobject fields take related_object_kind")
	}
	return wrapCustomFieldError(customfields.CheckDefinition(d))
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// wrapCustomFieldError maps a customfields validation failure onto the
// engine's 400.
func wrapCustomFieldError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, customfields.ErrInvalid) {
		return fmt.Errorf("%w: %s", ErrIPAMInvalid, customFieldMessage(err))
	}
	return err
}

// enforcesRequired: a person's write (ui / api) must fill required fields; an
// intake, sync or system write is not refused for a field nobody could have
// filled (customfields.Options.EnforceRequired).
func enforcesRequired(ctx context.Context, source changes.Source) bool {
	if source == "" {
		source, _ = changes.SourceFrom(ctx)
	}
	if source == BulkChangeSource {
		// A CSV import is a person's write through a file, held to the rules
		// their form would be (NetBox's import enforces required fields).
		return true
	}
	s := string(source)
	return s != string(changes.SourceSystem) && !strings.HasPrefix(s, "intake:") && !strings.HasPrefix(s, "sync:")
}

// validateCustomFieldsTx validates an object's custom_fields on a write. On
// an update, patch is merged over the stored values (NetBox's PATCH replaces
// only the fields it names). The result is what to store; a refusal wraps
// customfields.ErrInvalid.
//
// enforceRequired is enforcesRequired(ctx, source) for an explicit write; a
// path that creates an object implicitly (a business unit named on an asset
// form) passes false.
func validateCustomFieldsTx(ctx context.Context, tx customfields.Querier, kind dcim.ObjectKind, create bool, stored, patch map[string]any, enforceRequired bool) (map[string]any, error) {
	merged := map[string]any{}
	for k, v := range stored {
		merged[k] = v
	}
	for k, v := range patch {
		merged[k] = v
	}
	return customfields.Validate(ctx, tx, kind, merged, customfields.Options{
		Create:          create,
		EnforceRequired: enforceRequired,
	})
}

// customFieldMessage is a validation failure's message without the sentinel
// prefix, for a path that has its own error type.
func customFieldMessage(err error) string {
	return strings.TrimPrefix(err.Error(), customfields.ErrInvalid.Error()+": ")
}

// applyEngineCustomFields is the engine's custom-field hook, run by createTx
// and updateTx on every object whose spec carries custom_fields. An update
// that does not name custom_fields is not re-validated, so approving a
// discovered object is never refused for a field defined after it was seen.
func applyEngineCustomFields(ctx context.Context, tx *sql.Tx, sp *ipamSpec, create bool, pre, patch, row map[string]any, source changes.Source) error {
	if _, ok := sp.col("custom_fields"); !ok {
		return nil
	}
	p, touched := patch["custom_fields"]
	if !create && !touched {
		return nil
	}
	pm, err := customfields.AsMap(p)
	if err != nil {
		return wrapCustomFieldError(err)
	}
	var stored map[string]any
	if !create {
		if stored, err = customfields.AsMap(pre["custom_fields"]); err != nil {
			return wrapCustomFieldError(err)
		}
	}
	out, err := validateCustomFieldsTx(ctx, tx, sp.Kind, create, stored, pm, enforcesRequired(ctx, source))
	if err != nil {
		return wrapCustomFieldError(err)
	}
	row["custom_fields"] = out
	return nil
}

// CustomFieldObjects describes the two definition objects for the contract
// test (custom_fields_contract_test.go): table, kind, writable and required
// columns.
func CustomFieldObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range customFieldSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
