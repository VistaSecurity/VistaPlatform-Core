// Command gen-ts-fields generates the TypeScript mirror of the production
// query catalogue's hand-written half.
//
//	out: packages/primitives/src/query/registry-fields.gen.ts
//
// Run by `make generate`; `make audit` runs it with --check and fails on drift.
//
// Why this exists. registrycatalog splits its vocabulary in two: the namespaces
// (attr., fact., id., class, the finding vocabularies) come from the generated
// registries and cannot drift, while the first-class field table is
// hand-written — a column name is not a field name, the language says
// `first_seen` where the column is `first_discovered_at`, and nothing in the
// schema records which columns are queryable at all. fields.go says why it is
// exported:
//
//	"It is exported so the TypeScript mirror can be generated from it rather
//	 than typed again: AllTargets and FirstClassFields are the whole input a
//	 generator needs, and they are plain data."
//
// Until this command existed, nothing did that. The TypeScript table was a hand
// copy, and its own header admitted the asymmetry: Go's TestEnumsMatchSchema
// parses scripts/database/schema.sql and fails on any difference in either
// direction, so the SOURCE was guarded, but nothing guarded the mirror. A value
// added to a Postgres enum reached the TypeScript editor only when somebody
// remembered to retype it — and an editor whose closed value set is short by one
// rejects a query the server would have answered.
//
// It is a Go program rather than another entry in scripts/*.mjs because the
// input is Go values, not a YAML file. Reading fields.go with a parser would be
// a second implementation of Go's own semantics; calling AllTargets() and
// FirstClassFields() is reading exactly what the catalogue publishes.
//
// Five value sets are emitted as REFERENCES rather than literals — the finding
// producers, kinds and subject types, the stored identifier kinds, and the
// relationship types. Each of those already has a generated TypeScript home, so
// repeating the values here would create two generated files that could
// disagree. The reference is only emitted after this command has checked that
// the field's value set still equals the registry's; if fields.go ever stops
// deriving one of them from its registry, the generator fails rather than
// silently emitting a literal.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
)

const outRelPath = "packages/primitives/src/query/registry-fields.gen.ts"

func main() {
	check := flag.Bool("check", false, "fail if the generated file is out of date instead of writing it")
	out := flag.String("out", "", "output path (default: <repo root>/"+outRelPath+")")
	flag.Parse()

	path := *out
	if path == "" {
		root, err := repoRoot()
		if err != nil {
			fail(err.Error())
		}
		path = filepath.Join(root, filepath.FromSlash(outRelPath))
	}

	want, err := render()
	if err != nil {
		fail(err.Error())
	}

	if *check {
		current, err := os.ReadFile(path) //nolint:gosec // generator output path, not user input
		if err != nil && !os.IsNotExist(err) {
			fail(err.Error())
		}
		if string(current) != want {
			fail(fmt.Sprintf("%s is out of date — run `make generate`", outRelPath))
		}
		fmt.Printf("query-ts-fields check OK (%d targets)\n", len(registrycatalog.AllTargets()))
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil { //nolint:gosec // generated source, world-readable by design
		fail(err.Error())
	}
	fmt.Printf("Generated: %s (%d targets)\n", outRelPath, len(registrycatalog.AllTargets()))
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "gen-ts-fields: %s\n", msg)
	os.Exit(1)
}

// repoRoot walks up from the working directory looking for go.work, so the
// command works whether `make` runs it from the repository root or from
// shared/.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.work above %q — pass -out", dir)
		}
		dir = parent
	}
}

// ---------------------------------------------------------------- symbols --

// symbolicEnum is a value set that already has a generated TypeScript home.
type symbolicEnum struct {
	// expr is the TypeScript expression emitted in place of the literal.
	expr string
	// want is the registry list the field's value set must still equal. The
	// check is what makes the reference honest: it fails if fields.go stops
	// building that enum from its registry.
	want []string
}

// symbolicEnums is keyed "<target>.<field>". Deliberately explicit rather than
// matched by value: `asset.ownership` and `observation.network.ownership` hold
// the same three strings and come from entirely different places, so a
// value-matching rule would substitute one for the other and be wrong in a way
// nothing would notice.
func symbolicEnums() map[string]symbolicEnum {
	producers := make([]string, 0, len(findings.Producers))
	for _, p := range findings.Producers {
		producers = append(producers, p.Key)
	}
	kinds := make([]string, 0, len(findings.All))
	seen := make(map[string]bool, len(findings.All))
	for _, k := range findings.All {
		if seen[k.Key] {
			continue
		}
		seen[k.Key] = true
		kinds = append(kinds, k.Key)
	}
	return map[string]symbolicEnum{
		"finding.producer":     {"[...FINDING_PRODUCER_KEYS]", producers},
		"finding.kind":         {"[...FINDING_KIND_KEYS]", kinds},
		"finding.subject_type": {"[...FINDING_SUBJECT_TYPES]", findings.SubjectTypes},
		"identifier.kind":      {"[...IDENTIFIER_KINDS]", assetclass.IdentifierKinds},
		"relationship.type":    {"[...RELATIONSHIP_TYPES]", ast.RelationshipTypes},
	}
}

// ----------------------------------------------------------------- render --

func render() (string, error) {
	targets := registrycatalog.AllTargets()
	symbols := symbolicEnums()
	used := make(map[string]bool, len(symbols))

	var b strings.Builder
	b.WriteString(header)

	b.WriteString("export const REGISTRY_TARGETS: readonly Target[] = [\n")
	for _, t := range targets {
		b.WriteString(renderTarget(t))
	}
	b.WriteString("];\n\n")

	b.WriteString(fieldsDoc)
	b.WriteString("export const REGISTRY_FIELDS_BY_TARGET: " +
		"Readonly<Record<string, readonly FieldInfo[]>> = {\n")
	for _, t := range targets {
		fields := registrycatalog.FirstClassFields(t.Name)
		if len(fields) == 0 {
			return "", fmt.Errorf("target %q has no first-class fields", t.Name)
		}
		b.WriteString("  " + tsKey(t.Name) + ": [\n")
		for _, f := range fields {
			s, err := renderField(t.Name, f, symbols, used)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		b.WriteString("  ],\n")
	}
	b.WriteString("};\n\n")

	// An unused entry means the field it names has been renamed or removed and
	// the reference is now describing nothing. Reported rather than ignored,
	// for the same reason the conformance exemption list is asserted in both
	// directions: a guard that cannot fail is worse than no guard.
	for key := range symbols {
		if !used[key] {
			return "", fmt.Errorf(
				"symbolic enum %q matches no field — remove it from symbolicEnums or fix the name", key)
		}
	}

	b.WriteString(operatorsDoc)
	b.WriteString("export const OPERATORS_BY_TYPE: Readonly<Record<string, readonly string[]>> = {\n")
	for _, t := range catalog.KnownTypes() {
		ops := catalog.OperatorsFor(t)
		quoted := make([]string, 0, len(ops))
		for _, op := range ops {
			quoted = append(quoted, tsStr(op))
		}
		fmt.Fprintf(&b, "  %s: [%s],\n", tsKey(string(t)), strings.Join(quoted, ", "))
	}
	b.WriteString("};\n")

	return b.String(), nil
}

func renderTarget(t catalog.Target) string {
	var b strings.Builder
	b.WriteString("  {\n")
	b.WriteString("    name: " + tsStr(t.Name) + ",\n")
	b.WriteString("    table: " + tsStr(t.Table) + ",\n")
	b.WriteString("    alias: " + tsStr(t.Alias) + ",\n")
	b.WriteString("    idColumn: " + tsStr(t.IDColumn) + ",\n")
	if t.AssetIDColumn != "" {
		b.WriteString("    assetIdColumn: " + tsStr(t.AssetIDColumn) + ",\n")
	}
	subs := make([]string, 0, len(t.Subs))
	for _, s := range t.Subs {
		subs = append(subs, tsStr(s))
	}
	b.WriteString("    subs: [" + strings.Join(subs, ", ") + "],\n")
	fmt.Fprintf(&b, "    traversable: %t,\n", t.Traversable)
	fmt.Fprintf(&b, "    freeTextable: %t,\n", t.FreeTextable)
	if t.InMemory {
		b.WriteString("    inMemory: true,\n")
	}
	b.WriteString("  },\n")
	return b.String()
}

func renderField(target string, f catalog.FieldInfo, symbols map[string]symbolicEnum, used map[string]bool) (string, error) {
	if f.Type == ast.TypeUnresolved {
		return "", fmt.Errorf("%s.%s has no type", target, f.Name)
	}

	var b strings.Builder
	b.WriteString("    {\n")
	b.WriteString("      name: " + tsStr(f.Name) + ",\n")
	b.WriteString("      type: " + tsStr(string(f.Type)) + ",\n")
	b.WriteString("      accessor: " + renderAccessor(f.Accessor) + ",\n")

	if len(f.Enum) > 0 {
		key := target + "." + f.Name
		if sym, ok := symbols[key]; ok {
			if !equalStrings(sym.want, f.Enum) {
				return "", fmt.Errorf(
					"%s no longer matches its registry: catalogue has %v, registry has %v — "+
						"fields.go must build this enum from the registry, or the symbolic "+
						"reference must go",
					key, f.Enum, sym.want)
			}
			used[key] = true
			b.WriteString("      enum: " + sym.expr + ",\n")
		} else {
			values := make([]string, 0, len(f.Enum))
			for _, v := range f.Enum {
				values = append(values, tsStr(v))
			}
			b.WriteString("      enum: [" + strings.Join(values, ", ") + "],\n")
		}
	}
	if f.Description != "" {
		b.WriteString("      description: " + tsStr(f.Description) + ",\n")
	}
	b.WriteString("    },\n")
	return b.String(), nil
}

func renderAccessor(a ast.Accessor) string {
	parts := []string{"kind: " + tsStr(string(a.Kind))}
	for _, kv := range []struct{ name, value string }{
		{"rel", a.Rel},
		{"column", a.Column},
		{"jsonColumn", a.JSONColumn},
		{"key", a.Key},
		{"derived", a.Derived},
		{"cast", a.Cast},
		{"pathColumn", a.PathColumn},
		{"labelColumn", a.LabelColumn},
		{"sortColumn", a.SortColumn},
		{"assessedBy", a.AssessedBy},
	} {
		if kv.value != "" {
			parts = append(parts, kv.name+": "+tsStr(kv.value))
		}
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------- TS quoting --

// tsStr quotes a value as a single-quoted TypeScript string literal, the house
// style in packages/primitives.
func tsStr(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`'`, `\'`,
		"\r", `\r`,
		"\n", `\n`,
	)
	return "'" + r.Replace(s) + "'"
}

// tsKey quotes an object key, leaving a plain identifier unquoted.
func tsKey(s string) string {
	if s != "" && isIdentifier(s) {
		return s
	}
	return tsStr(s)
}

func isIdentifier(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '$':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

const header = `// Code generated by shared/query/catalog/registrycatalog/cmd/gen-ts-fields.
// DO NOT EDIT — edit the Go tables in shared/query/catalog/registrycatalog and
// run ` + "`make generate`" + `.
//
// The production catalogue's targets and first-class field table, and §4.4's
// type → operator matrix, mirrored from Go.
//
// This half of the catalogue is HAND-WRITTEN on the Go side and cannot be
// otherwise: a column name is not a field name — the language says
// ` + "`first_seen`" + ` where the column is ` + "`first_discovered_at`" + `, ` + "`segment_id`" + ` where it is
// ` + "`network_segment_id`" + ` — and nothing in the schema records which columns are
// queryable at all. What is generated is this MIRROR of it. Every closed value
// set below is a Postgres enum type or the ARRAY of a CHECK constraint, and Go's
// TestEnumsMatchSchema parses scripts/database/schema.sql and fails on any
// difference in either direction; before this file was generated the TypeScript
// copy had no such guard, so a value added to the schema reached the editor only
// when somebody retyped it.
//
// Five value sets are references rather than literals, because each already has
// a generated TypeScript home and two generated copies of one list can
// disagree. The generator checks the values still match before emitting the
// reference.

import type { FieldInfo, Target } from './catalog';
import { IDENTIFIER_KINDS } from './targets';
import { RELATIONSHIP_TYPES } from './vocabulary';
import {
  FINDING_KIND_KEYS,
  FINDING_PRODUCER_KEYS,
  FINDING_SUBJECT_TYPES,
} from '../findings';

/**
 * §4.1's targets with the physical shape a translator joins, from Go's
 * ` + "`AllTargets()`" + `.
 *
 * ` + "`targets.ts`" + ` carries the copy both catalogues share — Go's two catalogues
 * declare identical target tables — and ` + "`registry-fields.gen.test.ts`" + ` pins that
 * copy against this one.
 */
`

const fieldsDoc = `/**
 * The production catalogue's first-class fields, keyed by target name, from
 * Go's ` + "`FirstClassFields(target)`" + `. Sorted by name, as that function returns
 * them.
 *
 * The namespaces (` + "`attr.`" + `, ` + "`fact.`" + `, ` + "`id.`" + `, ` + "`tag`" + `) are NOT here: they are
 * generated from the registries and ` + "`base-catalog.ts`" + ` appends them.
 */
`

const operatorsDoc = `/**
 * §4.4's type → operator matrix, from Go's ` + "`catalog.OperatorsFor`" + `.
 *
 * ` + "`catalog.ts`" + ` implements the matrix directly rather than reading this — the
 * validator asks four narrow questions of it (` + "`operatorAllowed`" + `, ` + "`inAllowed`" + `,
 * ` + "`matchAllowed`" + `, ` + "`rangeAllowed`" + `) and a lookup table of operator strings is the
 * wrong shape for those. So this is the pin, not the source:
 * ` + "`registry-fields.gen.test.ts`" + ` asserts the two agree for every type, which is
 * the only thing that would notice §4.4 being changed on one side.
 */
`
