package services

// The export-template sandbox (DCIM BUILD_PLAN row 5.5). A template is a Go
// text/template run over the rows of a DCIM list export. It is tenant-authored
// text, so it is held to a closed world:
//
//   - the only functions are exportTemplateFuncs plus a short list of
//     text/template builtins; there is no file, exec, environment or network
//     function, and `call` (which invokes an arbitrary method or function value)
//     and printf/printf-style padding (a memory bomb) are not available;
//   - the data are plain maps, slices and strings, which have no methods, and a
//     top-level field must be one of Kind, Columns, Rows, Count;
//   - `template`, `define` and `block` are refused (no recursion);
//   - output is capped and the whole render has a deadline.
//
// ValidateExportTemplate runs on every save; RenderExportTemplate runs the same
// check again before it executes, so a row that reached the table by any other
// route is still refused.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

// Render limits (brief: 10 s, 10 MB).
const (
	ExportTemplateRenderTimeout = 10 * time.Second
	ExportTemplateMaxOutput     = 10 << 20
)

var (
	// ErrExportRenderTimeout: the render outran its deadline.
	ErrExportRenderTimeout = errors.New("export template render timed out")
	// ErrExportRenderTooLarge: the output passed the cap.
	ErrExportRenderTooLarge = errors.New("export template output is too large")
)

// ExportRenderLimits bound one render; the zero value means the defaults.
type ExportRenderLimits struct {
	Timeout   time.Duration
	MaxOutput int
}

func (l ExportRenderLimits) withDefaults() ExportRenderLimits {
	if l.Timeout <= 0 {
		l.Timeout = ExportTemplateRenderTimeout
	}
	if l.MaxOutput <= 0 {
		l.MaxOutput = ExportTemplateMaxOutput
	}
	return l
}

// exportRootFields are the fields of the data a template can read at top level.
var exportRootFields = map[string]bool{"Kind": true, "Columns": true, "Rows": true, "Count": true}

// exportAllowedBuiltins are the text/template builtins a template may name.
// Absent on purpose: call (arbitrary invocation), printf (width bomb).
var exportAllowedBuiltins = map[string]bool{
	"and": true, "or": true, "not": true, "eq": true, "ne": true, "lt": true, "le": true, "gt": true, "ge": true,
	"len": true, "index": true, "slice": true, "print": true, "println": true,
	"html": true, "js": true, "urlquery": true,
}

// exportForbiddenFields are refused by name at any depth: a future change that
// puts a struct with such a method into the data must not make it callable.
var exportForbiddenFields = map[string]bool{
	"readfile": true, "readdir": true, "open": true, "exec": true, "env": true, "getenv": true,
	"environ": true, "run": true, "command": true, "system": true, "call": true, "stat": true,
}

func exportTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper":     strings.ToUpper,
		"lower":     strings.ToLower,
		"trim":      strings.TrimSpace,
		"replace":   func(s, old, repl string) string { return strings.ReplaceAll(s, old, repl) },
		"join":      func(sep string, items []string) string { return strings.Join(items, sep) },
		"split":     func(sep, s string) []string { return strings.Split(s, sep) },
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"default": func(def, v string) string {
			if v == "" {
				return def
			}
			return v
		},
		"quote": func(s string) string { return strconv.Quote(s) },
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"csv": func(fields ...string) (string, error) {
			var b bytes.Buffer
			w := csv.NewWriter(&b)
			if err := w.Write(fields); err != nil {
				return "", err
			}
			w.Flush()
			return strings.TrimRight(b.String(), "\n"), w.Error()
		},
		"int": func(s string) (int64, error) {
			n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			return n, err
		},
		"float": func(s string) (float64, error) { return strconv.ParseFloat(strings.TrimSpace(s), 64) },
		"add":   func(a, b int64) int64 { return a + b },
		"sub":   func(a, b int64) int64 { return a - b },
		"mul":   func(a, b int64) int64 { return a * b },
		"div": func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, errors.New("division by zero")
			}
			return a / b, nil
		},
		"mod": func(a, b int64) (int64, error) {
			if b == 0 {
				return 0, errors.New("division by zero")
			}
			return a % b, nil
		},
		// date reformats an RFC 3339 timestamp (or YYYY-MM-DD) with a Go layout;
		// an unparseable value is returned as it was.
		"date": func(layout, s string) string {
			for _, in := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
				if t, err := time.Parse(in, s); err == nil {
					return t.UTC().Format(layout)
				}
			}
			return s
		},
	}
}

// ExportTemplateFuncNames lists the helper functions, for the editor's hint.
func ExportTemplateFuncNames() []string {
	var out []string
	for k := range exportTemplateFuncs() {
		out = append(out, k)
	}
	return out
}

// ValidateExportTemplate parses src and walks it for anything outside the
// sandbox. The error is an ErrIPAMInvalid, so the route answers 400.
func ValidateExportTemplate(src string) error {
	_, err := parseExportTemplate(src)
	return err
}

func parseExportTemplate(src string) (*template.Template, error) {
	if strings.TrimSpace(src) == "" {
		return nil, ipamInvalid("template is empty")
	}
	t, err := template.New("export").Funcs(exportTemplateFuncs()).Option("missingkey=zero").Parse(src)
	if err != nil {
		return nil, ipamInvalid("template: %s", err)
	}
	if n := len(t.Templates()); n > 1 {
		return nil, ipamInvalid("template: define and block are not allowed")
	}
	if t.Tree == nil || t.Root == nil {
		return nil, ipamInvalid("template is empty")
	}
	if err := walkExportNode(t.Root, true); err != nil {
		return nil, ipamInvalid("template: %s", err)
	}
	return t, nil
}

func checkExportField(idents []string, atRoot bool) error {
	if len(idents) == 0 {
		return nil
	}
	if exportForbiddenFields[strings.ToLower(idents[0])] {
		return fmt.Errorf("%q is not available in export templates", idents[0])
	}
	if atRoot && !exportRootFields[idents[0]] {
		return fmt.Errorf("unknown field .%s (the data have Kind, Columns, Rows and Count)", idents[0])
	}
	return nil
}

// walkExportNode checks every node. atRoot is true while dot is the root data
// (outside range/with bodies).
func walkExportNode(n parse.Node, atRoot bool) error {
	switch n := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := walkExportNode(c, atRoot); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return walkExportNode(n.Pipe, atRoot)
	case *parse.PipeNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Cmds {
			if err := walkExportNode(c, atRoot); err != nil {
				return err
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			if err := walkExportNode(a, atRoot); err != nil {
				return err
			}
		}
	case *parse.IdentifierNode:
		if _, own := exportTemplateFuncs()[n.Ident]; !own && !exportAllowedBuiltins[n.Ident] {
			return fmt.Errorf("function %q is not allowed", n.Ident)
		}
	case *parse.FieldNode:
		return checkExportField(n.Ident, atRoot)
	case *parse.VariableNode:
		// `$` is the root data wherever it appears; other variables hold values.
		if len(n.Ident) > 1 && n.Ident[0] == "$" {
			return checkExportField(n.Ident[1:], true)
		}
		if len(n.Ident) > 1 {
			return checkExportField(n.Ident[1:], false)
		}
	case *parse.ChainNode:
		if err := walkExportNode(n.Node, atRoot); err != nil {
			return err
		}
		return checkExportField(n.Field, false)
	case *parse.IfNode:
		return walkExportBranch(&n.BranchNode, atRoot, atRoot)
	case *parse.RangeNode:
		return walkExportBranch(&n.BranchNode, false, atRoot)
	case *parse.WithNode:
		return walkExportBranch(&n.BranchNode, false, atRoot)
	case *parse.TemplateNode:
		return errors.New("the template action is not allowed")
	}
	return nil
}

// walkExportBranch checks a branch: the pipeline and else list see the outer
// dot; the body sees bodyRoot.
func walkExportBranch(b *parse.BranchNode, bodyRoot, outerRoot bool) error {
	if err := walkExportNode(b.Pipe, outerRoot); err != nil {
		return err
	}
	if err := walkExportNode(b.List, bodyRoot); err != nil {
		return err
	}
	return walkExportNode(b.ElseList, outerRoot)
}

// cappedWriter stops a render at the output cap or the deadline.
type cappedWriter struct {
	ctx context.Context
	buf bytes.Buffer
	max int
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, ErrExportRenderTimeout
	}
	if w.buf.Len()+len(p) > w.max {
		return 0, ErrExportRenderTooLarge
	}
	return w.buf.Write(p)
}

// RenderExportTemplate renders src over the rows. The sandbox check runs
// again here: nothing reaches Execute unvalidated.
func RenderExportTemplate(ctx context.Context, src, kind string, columns []string, rows []map[string]string, lim ExportRenderLimits) ([]byte, error) {
	lim = lim.withDefaults()
	t, err := parseExportTemplate(src)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()
	if rows == nil {
		rows = []map[string]string{}
	}
	if columns == nil {
		columns = []string{}
	}
	data := map[string]any{"Kind": kind, "Columns": columns, "Rows": rows, "Count": len(rows)}
	w := &cappedWriter{ctx: ctx, max: lim.MaxOutput}
	done := make(chan error, 1)
	go func() { done <- t.Execute(w, data) }()
	select {
	case err := <-done:
		switch {
		case err == nil:
			return w.buf.Bytes(), nil
		case errors.Is(err, ErrExportRenderTooLarge), errors.Is(err, ErrExportRenderTimeout):
			return nil, err
		default:
			return nil, ipamInvalid("template: %s", err)
		}
	case <-ctx.Done():
		return nil, ErrExportRenderTimeout
	}
}
