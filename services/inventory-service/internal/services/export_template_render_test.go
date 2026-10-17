package services

// The export-template sandbox (DCIM BUILD_PLAN row 5.5).
//
// Mutations: allow `call` / drop the root-field check in walkExportNode, or
// stop calling ValidateExportTemplate in prepareExportTemplate -> the refusal
// tests go red; drop the cappedWriter limit or the select on ctx.Done -> the
// cap and timeout tests go red.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var sampleRows = []map[string]string{
	{"name": "10.0.0.0/8", "status": "active", "cf.owner": "net"},
	{"name": "10.1.0.0/16", "status": "reserved", "cf.owner": ""},
}

func render(t *testing.T, src string) string {
	t.Helper()
	out, err := RenderExportTemplate(context.Background(), src, "prefix", []string{"name", "status"}, sampleRows, ExportRenderLimits{})
	if err != nil {
		t.Fatalf("render %q: %v", src, err)
	}
	return string(out)
}

func TestExportTemplate_RendersRowsWithHelpers(t *testing.T) {
	got := render(t, `{{.Kind}} {{.Count}}{{range .Rows}}
{{upper .status}},{{index . "cf.owner" | default "-"}},{{csv .name .status}}{{end}}`)
	want := "prefix 2\nACTIVE,net,10.0.0.0/8,active\nRESERVED,-,\"10.1.0.0/16\",reserved"
	want = strings.ReplaceAll(want, `"10.1.0.0/16"`, `10.1.0.0/16`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := render(t, `{{date "2006" "2026-10-16T10:00:00Z"}}|{{add 1 2}}|{{json .Columns}}`); got != `2026|3|["name","status"]` {
		t.Fatalf("helpers: %q", got)
	}
}

func TestExportTemplate_SandboxRefusesEscapes(t *testing.T) {
	for _, src := range []string{
		`{{.ReadFile "/etc/passwd"}}`,
		`{{.Exec "id"}}`,
		`{{.Env}}`,
		`{{$.ReadFile}}`,
		`{{range .Rows}}{{.ReadFile}}{{end}}`,
		`{{exec "id"}}`,
		`{{env "HOME"}}`,
		`{{readFile "/etc/passwd"}}`,
		`{{call .Rows}}`,
		`{{printf "%1000000000s" "x"}}`,
		`{{template "x"}}`,
		`{{define "x"}}y{{end}}{{template "x"}}`,
		`{{.Secret}}`,
		`{{`,
		``,
	} {
		if err := ValidateExportTemplate(src); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("ValidateExportTemplate(%q) = %v, want an invalid-template error", src, err)
		}
		// Refused again at render, whatever reached the table.
		if _, err := RenderExportTemplate(context.Background(), src, "prefix", nil, sampleRows, ExportRenderLimits{}); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("RenderExportTemplate(%q) = %v, want an invalid-template error", src, err)
		}
	}
	// Column names that look like methods are just columns inside a range.
	if err := ValidateExportTemplate(`{{range .Rows}}{{.name}}{{end}}`); err != nil {
		t.Fatal(err)
	}
}

func TestExportTemplate_OutputCap(t *testing.T) {
	_, err := RenderExportTemplate(context.Background(), `{{range .Rows}}{{range $.Rows}}0123456789{{end}}{{end}}x{{range .Rows}}0123456789{{end}}`, "prefix", nil, sampleRows,
		ExportRenderLimits{MaxOutput: 30})
	if !errors.Is(err, ErrExportRenderTooLarge) {
		t.Fatalf("err = %v, want too large", err)
	}
	// Exactly at the cap is fine.
	if _, err := RenderExportTemplate(context.Background(), `0123456789`, "prefix", nil, nil, ExportRenderLimits{MaxOutput: 10}); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
}

func TestExportTemplate_Timeout(t *testing.T) {
	rows := make([]map[string]string, 300)
	for i := range rows {
		rows[i] = map[string]string{"a": "b"}
	}
	start := time.Now()
	_, err := RenderExportTemplate(context.Background(),
		`{{range .Rows}}{{range $.Rows}}{{range $.Rows}}{{range $.Rows}}{{end}}{{end}}{{end}}{{end}}`, "prefix", nil, rows,
		ExportRenderLimits{Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrExportRenderTimeout) {
		t.Fatalf("err = %v, want timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("returned after %s; the deadline is not enforced", d)
	}
}
