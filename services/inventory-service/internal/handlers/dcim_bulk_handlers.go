package handlers

// HTTP surface of bulk CSV import and export (DCIM BUILD_PLAN row 2.7), under
// /api/v2/inventory-service/dcim:
//
//	GET  /import/kinds              dcim.read     the importable kinds and their columns
//	GET  /import/template?kind=     dcim.read     header row + one example row (CSV)
//	POST /import?kind=&mode=        <kind manage> CSV body; mode=dry_run (default) | apply
//	GET  /export?kind=&format=      <kind read>   CSV (default), JSON, or format=template&template_id= (row 5.5), honouring the lens's filters
//	POST /export/preview            dcim.manage + <kind read>   a template body rendered over the first 5 rows (row 5.5)
//
// Which permission an import or export needs depends on the kind (an IPAM
// kind needs ipam.manage, a business unit business_units.manage, …), so the
// handler asks the gate for the kind's permission rather than the route
// declaring one (cmd/dcim_bulk_routes.go builds the gates).

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// BulkStore is what the handlers need; services.BulkImportService implements it.
type BulkStore interface {
	Kinds() []services.BulkKindInfo
	Kind(kind string) (services.BulkKindInfo, error)
	Template(kind string) (header, example []string, err error)
	Import(ctx context.Context, tenant uuid.UUID, kind string, body io.Reader, apply bool) (*services.BulkPlan, error)
	Export(ctx context.Context, tenant uuid.UUID, kind string, q services.BulkExportQuery, emit func(services.BulkRecord) error) error
	BulkColumnNames(kind string) ([]string, error)
	// CustomFieldColumns are the tenant's `cf.<name>` export columns (row 5.1).
	CustomFieldColumns(ctx context.Context, tenant uuid.UUID, kind string) ([]string, error)
}

// BulkAuthorizer runs the gate for a permission against the request and
// reports whether it passed (the gate has already written the refusal if not).
type BulkAuthorizer func(c *gin.Context, permission string) bool

// ExportTemplateStore loads a stored export template; services.ExportTemplateService implements it.
type ExportTemplateStore interface {
	Template(ctx context.Context, tenant, id uuid.UUID) (services.ExportTemplate, error)
}

// BulkHandler serves the bulk import/export routes.
type BulkHandler struct {
	store     BulkStore
	authorize BulkAuthorizer
	templates ExportTemplateStore
	limits    services.ExportRenderLimits
}

// WithTemplates enables format=template exports and the preview route.
func (h *BulkHandler) WithTemplates(t ExportTemplateStore) *BulkHandler {
	h.templates = t
	return h
}

// WithRenderLimits overrides the render deadline and output cap (tests).
func (h *BulkHandler) WithRenderLimits(l services.ExportRenderLimits) *BulkHandler {
	h.limits = l
	return h
}

// NewBulkHandler returns the handler.
func NewBulkHandler(store BulkStore, authorize BulkAuthorizer) *BulkHandler {
	return &BulkHandler{store: store, authorize: authorize}
}

const bulkMaxBody = 8 << 20

func bulkError(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg}})
}

func (h *BulkHandler) kind(c *gin.Context) (services.BulkKindInfo, bool) {
	info, err := h.store.Kind(c.Query("kind"))
	if err != nil {
		bulkError(c, http.StatusBadRequest, "unknown_kind", "kind must be one of the importable object kinds (GET /dcim/import/kinds).")
		return info, false
	}
	return info, true
}

// Kinds lists the importable kinds.
func (h *BulkHandler) Kinds(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": h.store.Kinds()})
}

// Template serves a kind's header and example row as a CSV download.
func (h *BulkHandler) Template(c *gin.Context) {
	info, ok := h.kind(c)
	if !ok {
		return
	}
	header, example, err := h.store.Template(info.Kind)
	if err != nil {
		bulkError(c, http.StatusBadRequest, "unknown_kind", err.Error())
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+info.Kind+`-template.csv"`)
	w := csv.NewWriter(c.Writer)
	_ = w.Write(header)
	_ = w.Write(example)
	w.Flush()
}

// Import plans or applies an uploaded CSV.
func (h *BulkHandler) Import(c *gin.Context) {
	info, ok := h.kind(c)
	if !ok {
		return
	}
	if !h.authorize(c, info.Permission) {
		return
	}
	tenant, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		bulkError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
		return
	}
	apply := false
	switch c.DefaultQuery("mode", "dry_run") {
	case "dry_run":
	case "apply":
		apply = true
	default:
		bulkError(c, http.StatusBadRequest, "invalid_mode", "mode must be dry_run or apply.")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, bulkMaxBody)
	var body io.Reader = c.Request.Body
	if strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") {
		f, _, err := c.Request.FormFile("file")
		if err != nil {
			bulkError(c, http.StatusBadRequest, "invalid_file", "A multipart upload needs a `file` part.")
			return
		}
		defer func() { _ = f.Close() }()
		body = f
	}
	plan, err := h.store.Import(c.Request.Context(), tenant, info.Kind, body, apply)
	if err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			bulkError(c, http.StatusRequestEntityTooLarge, "file_too_large", "The file is larger than 8 MiB; split it.")
		case errors.Is(err, services.ErrBulkBadFile):
			bulkError(c, http.StatusBadRequest, "invalid_file", err.Error())
		default:
			_ = c.Error(err)
			bulkError(c, http.StatusInternalServerError, "internal_error", "The import could not be completed.")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": plan})
}

// Export streams a kind's rows as CSV or JSON.
func (h *BulkHandler) Export(c *gin.Context) {
	info, ok := h.kind(c)
	if !ok {
		return
	}
	if !h.authorize(c, info.ReadPermission) {
		return
	}
	tenant, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		bulkError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
		return
	}
	format := c.DefaultQuery("format", "csv")
	if format != "csv" && format != "json" && (format != "template" || h.templates == nil) {
		bulkError(c, http.StatusBadRequest, "invalid_format", "format must be csv, json or template.")
		return
	}
	var tpl services.ExportTemplate
	if format == "template" {
		id, err := uuid.Parse(c.Query("template_id"))
		if err != nil {
			bulkError(c, http.StatusBadRequest, "invalid_template_id", "format=template needs a template_id.")
			return
		}
		tpl, err = h.templates.Template(c.Request.Context(), tenant, id)
		if errors.Is(err, services.ErrIPAMNotFound) {
			bulkError(c, http.StatusNotFound, "not_found", "No such export template.")
			return
		}
		if err != nil {
			_ = c.Error(err)
			bulkError(c, http.StatusInternalServerError, "internal_error", "The export could not be completed.")
			return
		}
		if !slices.Contains(tpl.ObjectKinds, info.Kind) {
			bulkError(c, http.StatusBadRequest, "template_not_for_kind", "This template is not offered for "+info.Kind+".")
			return
		}
	}
	q := services.BulkExportQuery{Q: c.Query("query"), Filters: map[string]string{}}
	if q.Q == "" {
		q.Q = c.Query("q")
	}
	for k, v := range c.Request.URL.Query() {
		switch k {
		case "kind", "format", "query", "q", "template_id":
		default:
			if len(v) > 0 {
				q.Filters[k] = v[0]
			}
		}
	}
	cols, err := h.store.BulkColumnNames(info.Kind)
	if err != nil {
		bulkError(c, http.StatusBadRequest, "unknown_kind", err.Error())
		return
	}
	ctx := c.Request.Context()
	cf, err := h.store.CustomFieldColumns(ctx, tenant, info.Kind)
	if err != nil {
		h.exportError(c, err)
		return
	}
	cols = append(cols, cf...)
	if format == "template" {
		rows, err := h.collect(ctx, tenant, info.Kind, q, 0)
		if err != nil {
			h.exportError(c, err)
			return
		}
		out, err := services.RenderExportTemplate(ctx, tpl.Template, info.Kind, cols, rows, h.limits)
		if err != nil {
			h.renderError(c, err)
			return
		}
		c.Header("Content-Disposition", `attachment; filename="`+info.Kind+`-export.`+tpl.FileExtension+`"`)
		c.Data(http.StatusOK, tpl.MimeType, out)
		return
	}
	if format == "json" {
		rows := []services.BulkRecord{}
		if err := h.store.Export(ctx, tenant, info.Kind, q, func(r services.BulkRecord) error { rows = append(rows, r); return nil }); err != nil {
			h.exportError(c, err)
			return
		}
		c.Header("Content-Disposition", `attachment; filename="`+info.Kind+`-export.json"`)
		c.JSON(http.StatusOK, gin.H{"data": rows})
		return
	}
	// CSV: held back until the first row or the end, so a bad filter is still a
	// 400 rather than a half-written 200.
	var w *csv.Writer
	start := func() {
		if w != nil {
			return
		}
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", `attachment; filename="`+info.Kind+`-export.csv"`)
		w = csv.NewWriter(c.Writer)
		_ = w.Write(cols)
	}
	err = h.store.Export(ctx, tenant, info.Kind, q, func(r services.BulkRecord) error {
		start()
		row := make([]string, len(cols))
		for i, n := range cols {
			row[i] = r[n]
		}
		return w.Write(row)
	})
	if err != nil && w == nil {
		h.exportError(c, err)
		return
	}
	start()
	w.Flush()
}

func (h *BulkHandler) exportError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrIPAMInvalid):
		bulkError(c, http.StatusBadRequest, "invalid_filter", err.Error())
	default:
		_ = c.Error(err)
		bulkError(c, http.StatusInternalServerError, "internal_error", "The export could not be completed.")
	}
}

// collect gathers a kind's export rows (limit 0 = all).
func (h *BulkHandler) collect(ctx context.Context, tenant uuid.UUID, kind string, q services.BulkExportQuery, limit int) ([]map[string]string, error) {
	rows := []map[string]string{}
	err := h.store.Export(ctx, tenant, kind, q, func(r services.BulkRecord) error {
		rows = append(rows, map[string]string(r))
		if limit > 0 && len(rows) >= limit {
			return errPreviewEnough
		}
		return nil
	})
	if errors.Is(err, errPreviewEnough) {
		err = nil
	}
	return rows, err
}

var errPreviewEnough = errors.New("enough rows")

func (h *BulkHandler) renderError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrIPAMInvalid):
		bulkError(c, http.StatusBadRequest, "invalid_template", err.Error())
	case errors.Is(err, services.ErrExportRenderTimeout):
		bulkError(c, http.StatusUnprocessableEntity, "render_timeout", "The template took too long to render.")
	case errors.Is(err, services.ErrExportRenderTooLarge):
		bulkError(c, http.StatusUnprocessableEntity, "render_too_large", "The rendered output is larger than 10 MB.")
	default:
		_ = c.Error(err)
		bulkError(c, http.StatusInternalServerError, "internal_error", "The export could not be completed.")
	}
}

// PreviewRows is how many rows a preview renders.
const PreviewRows = 5

// Preview renders an unsaved template body over the first five rows of a kind.
func (h *BulkHandler) Preview(c *gin.Context) {
	var body struct {
		Kind     string `json:"kind"`
		Template string `json:"template"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		bulkError(c, http.StatusBadRequest, "invalid_body", "Expected {kind, template}.")
		return
	}
	info, err := h.store.Kind(body.Kind)
	if err != nil {
		bulkError(c, http.StatusBadRequest, "unknown_kind", "kind must be one of the importable object kinds (GET /dcim/import/kinds).")
		return
	}
	if !h.authorize(c, info.ReadPermission) {
		return
	}
	tenant, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		bulkError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
		return
	}
	ctx := c.Request.Context()
	cols, err := h.store.BulkColumnNames(info.Kind)
	if err != nil {
		bulkError(c, http.StatusBadRequest, "unknown_kind", err.Error())
		return
	}
	cf, err := h.store.CustomFieldColumns(ctx, tenant, info.Kind)
	if err != nil {
		h.exportError(c, err)
		return
	}
	cols = append(cols, cf...)
	rows, err := h.collect(ctx, tenant, info.Kind, services.BulkExportQuery{Filters: map[string]string{}}, PreviewRows)
	if err != nil {
		h.exportError(c, err)
		return
	}
	out, err := services.RenderExportTemplate(ctx, body.Template, info.Kind, cols, rows, h.limits)
	if err != nil {
		h.renderError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"output": string(out), "rows": len(rows)}})
}
