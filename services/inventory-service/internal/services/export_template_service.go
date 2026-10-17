package services

// ExportTemplateService owns export templates (DCIM BUILD_PLAN row 5.5). CRUD
// runs on the IPAM object engine over exportTemplateSpecs(): one tenant-scoped
// transaction per call, RLS in force, every write recorded in object_changes.
// Prepare validates the template body against the sandbox before it is stored.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// RouteExportTemplates is the route segment under /dcim.
const RouteExportTemplates = "export-templates"

// ExportTemplate is a stored template, as the renderer reads it.
type ExportTemplate struct {
	ID            uuid.UUID
	Name          string
	ObjectKinds   []string
	Template      string
	MimeType      string
	FileExtension string
}

// ExportTemplateService is the export-template store.
type ExportTemplateService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewExportTemplateService returns the store over db (the raw pool; RLS is set per transaction).
func NewExportTemplateService(db *sql.DB) *ExportTemplateService {
	return &ExportTemplateService{db: db, eng: newObjectEngine(db, exportTemplateSpecs())}
}

// List returns one page of export templates (?object_kind= narrows to a kind).
func (s *ExportTemplateService) List(ctx context.Context, tenant uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, RouteExportTemplates, p)
}

// Get returns one export template.
func (s *ExportTemplateService) Get(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	return s.eng.Get(ctx, tenant, RouteExportTemplates, id)
}

// Create creates an export template.
func (s *ExportTemplateService) Create(ctx context.Context, tenant uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Create(ctx, tenant, RouteExportTemplates, body)
}

// Update patches an export template.
func (s *ExportTemplateService) Update(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.eng.Update(ctx, tenant, RouteExportTemplates, id, body)
}

// Delete removes an export template.
func (s *ExportTemplateService) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, RouteExportTemplates, id)
}

// Template loads one template for rendering. ErrIPAMNotFound when the tenant
// has no such template.
func (s *ExportTemplateService) Template(ctx context.Context, tenant, id uuid.UUID) (ExportTemplate, error) {
	raw, err := s.eng.Get(ctx, tenant, RouteExportTemplates, id)
	if err != nil {
		return ExportTemplate{}, err
	}
	var row struct {
		ID            uuid.UUID `json:"id"`
		Name          string    `json:"name"`
		ObjectKinds   []string  `json:"object_kinds"`
		Template      string    `json:"template"`
		MimeType      string    `json:"mime_type"`
		FileExtension string    `json:"file_extension"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return ExportTemplate{}, err
	}
	return ExportTemplate{ID: row.ID, Name: row.Name, ObjectKinds: row.ObjectKinds, Template: row.Template, MimeType: row.MimeType, FileExtension: row.FileExtension}, nil
}

// ExportTemplateObjects lists the objects the engine serves, for the contract tests.
func ExportTemplateObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range exportTemplateSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}

func prepareExportTemplate(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if s, ok := row["name"].(string); ok {
		row["name"] = strings.TrimSpace(s)
	}
	var kinds []string
	switch k := row["object_kinds"].(type) {
	case []any:
		for _, x := range k {
			kinds = append(kinds, fmt.Sprint(x))
		}
	case []string:
		kinds = k
	}
	if len(kinds) == 0 {
		return ipamInvalid("object_kinds needs at least one kind")
	}
	for _, k := range kinds {
		if _, ok := dcim.ParseObjectKind(k); !ok || !slices.Contains(bulkKindOrder, k) {
			return ipamInvalid("object_kinds: %q is not an exportable kind", k)
		}
	}
	src, _ := row["template"].(string)
	return ValidateExportTemplate(src)
}

func exportTemplateSpecs() []*ipamSpec {
	return []*ipamSpec{{
		Kind: dcim.ObjectKindExportTemplate, Table: "export_templates", Route: RouteExportTemplates,
		Cols: withSubstrate(
			ipamCol{Name: "name", Type: colText, Required: true},
			ipamCol{Name: "object_kinds", Type: colTextArray, Required: true},
			ipamCol{Name: "template", Type: colText, Required: true},
			ipamCol{Name: "mime_type", Type: colText},
			ipamCol{Name: "file_extension", Type: colText},
		),
		Filters: []ipamFilter{
			{Param: "object_kind", Custom: func(v string, n int) (string, any, error) {
				if !slices.Contains(bulkKindOrder, v) {
					return "", nil, ipamInvalid("object_kind: %q is not an exportable kind", v)
				}
				return fmt.Sprintf("$%d = ANY (t.object_kinds)", n), v, nil
			}},
		},
		Search:  []string{"name", "description"},
		Order:   "lower(t.name), t.id",
		Prepare: prepareExportTemplate,
	}}
}
