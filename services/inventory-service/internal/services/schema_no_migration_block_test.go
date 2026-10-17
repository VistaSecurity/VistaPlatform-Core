package services

// The 5.0 cycle rule's guard (asset-inventory ADR-0010 D11).
//
// scripts/database/schema.sql is the 5.0.0 baseline: every 5.0 release
// candidate is a fresh install, so the file carries each object's final shape
// in its one definition and NO migration block. A migration statement slipped
// back in is not harmless on a fresh install — it is a second place an
// object's shape lives, the drift the re-baseline removed, and it reads as an
// upgrade path that 5.0.0 deliberately does not have.
//
// What counts as a migration statement, in executable SQL (comments and
// function bodies are not looked at — a function that UPDATEs its own table at
// run time is not a migration):
//
//   - `ADD COLUMN IF NOT EXISTS`   — the column belongs in its CREATE TABLE;
//   - `ADD VALUE IF NOT EXISTS`    — the value belongs in its CREATE TYPE;
//   - a statement line opening with UPDATE or DELETE FROM — a data backfill or
//     repair (seed rows belong in seed.sql), bare or inside a DO block;
//   - the word POST-MIGRATIONS anywhere past the header comment.
//
// It reads the file, needs no database, and so runs in the ordinary unit suite
// as well as under `make test-integration-db`. Once core-v5.0.0 ships the
// tripwire in schema_upgrade_tripwire_test.go fails until the upgrade rules are
// restored, and this test is retired in the same change.
//
// MUTATION (goes red): add `ALTER TABLE public.tenants ADD COLUMN IF NOT EXISTS
// x text;` anywhere in schema.sql; add a bare `UPDATE public.tenants SET ...`;
// add an `-- POST-MIGRATIONS` banner below the header. TestMigrationBlockScanner
// pins both polarities of the scanner itself.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var (
	migrationAddColumn = regexp.MustCompile(`(?i)\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\b`)
	migrationAddValue  = regexp.MustCompile(`(?i)\bADD\s+VALUE\s+IF\s+NOT\s+EXISTS\b`)
	migrationDML       = regexp.MustCompile(`(?i)^\s*(UPDATE|DELETE\s+FROM)\s`)
	functionStart      = regexp.MustCompile(`(?i)^\s*CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\b`)
	dollarTag          = regexp.MustCompile(`\$[A-Za-z_]*\$`)
	// A POST-MIGRATIONS *banner* opens a migration block. Prose that merely
	// mentions the word ("no POST-MIGRATIONS block") in a later comment is fine.
	postMigrationsBanner = regexp.MustCompile(`(?i)^\s*--\s*=*\s*POST-MIGRATIONS\b`)
)

// migrationBlockViolations returns one message per migration statement in a
// schema file. The header — the comment lines before the first statement —
// may name POST-MIGRATIONS (it states the rule); nothing after it may.
func migrationBlockViolations(sql string) []string {
	var out []string
	inHeader := true
	pendingFunction := false
	inFunctionTag := ""
	for i, line := range strings.Split(sql, "\n") {
		n := i + 1
		trimmed := strings.TrimSpace(line)
		if inHeader && trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			inHeader = false
		}
		if !inHeader && postMigrationsBanner.MatchString(line) {
			out = append(out, lineMsg(n, "names POST-MIGRATIONS", line))
		}
		if inFunctionTag != "" {
			if strings.Contains(line, inFunctionTag) {
				inFunctionTag = ""
			}
			continue
		}
		code := line
		if before, _, ok := strings.Cut(code, "--"); ok {
			code = before
		}
		if functionStart.MatchString(code) {
			pendingFunction = true
		}
		if pendingFunction {
			if tag := dollarTag.FindString(code); tag != "" {
				pendingFunction = false
				rest := code[strings.Index(code, tag)+len(tag):]
				if !strings.Contains(rest, tag) {
					inFunctionTag = tag
				}
				continue
			}
		}
		switch {
		case migrationAddColumn.MatchString(code):
			out = append(out, lineMsg(n, "ADD COLUMN IF NOT EXISTS (fold the column into its CREATE TABLE)", line))
		case migrationAddValue.MatchString(code):
			out = append(out, lineMsg(n, "ALTER TYPE ... ADD VALUE IF NOT EXISTS (fold the value into its CREATE TYPE)", line))
		case migrationDML.MatchString(code):
			out = append(out, lineMsg(n, "UPDATE / DELETE FROM outside a function (a backfill; seed rows belong in seed.sql)", line))
		}
	}
	return out
}

func lineMsg(n int, what, line string) string {
	return "line " + strconv.Itoa(n) + ": " + what + ": " + strings.TrimSpace(line)
}

func TestIntegration_Schema_HasNoMigrationBlock(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			if !strings.Contains(string(body), "CREATE TABLE IF NOT EXISTS public.tenants") {
				t.Fatalf("%s does not look like the schema (no tenants table) — the scanner would pass on anything", rel)
			}
			for _, v := range migrationBlockViolations(string(body)) {
				t.Errorf("%s %s\n  The 5.0 cycle rule (asset-inventory ADR-0010 D11): schema.sql is the "+
					"5.0.0 baseline; edit the object's one definition in place, never add a migration.", rel, v)
			}
		})
	}
}

// Both polarities of the scanner, so a matcher that silently stops matching
// cannot leave TestIntegration_Schema_HasNoMigrationBlock passing on anything.
func TestMigrationBlockScanner(t *testing.T) {
	const header = "-- header: there is no POST-MIGRATIONS block\n--\nCREATE TABLE IF NOT EXISTS public.t (id uuid);\n"
	for _, c := range []struct {
		name string
		sql  string
		want int
	}{
		{"the header may state the rule", header, 0},
		{"a later comment may mention the word in prose", header + "-- cycle rule (ADR-0010 D11): no POST-MIGRATIONS block.\nCREATE TABLE IF NOT EXISTS public.u (id uuid);\n", 0},
		{"a POST-MIGRATIONS banner below the header is a migration block", header + "-- POST-MIGRATIONS: retire x\nCREATE TABLE IF NOT EXISTS public.u (id uuid);\n", 1},
		{"an ADD COLUMN is a migration", header + "ALTER TABLE public.t ADD COLUMN IF NOT EXISTS x text;\n", 1},
		{"an ADD COLUMN inside a DO block is a migration", header + "DO $$ BEGIN\n  ALTER TABLE public.t ADD COLUMN IF NOT EXISTS x text;\nEND $$;\n", 1},
		{"an enum ADD VALUE is a migration", header + "ALTER TYPE public.e ADD VALUE IF NOT EXISTS 'v';\n", 1},
		{"a bare UPDATE is a backfill", header + "UPDATE public.t SET id = NULL;\n", 1},
		{"a DELETE inside a DO block is a repair", header + "DO $$ BEGIN\n    DELETE FROM public.t WHERE id IS NULL;\nEND $$;\n", 1},
		{"a POST-MIGRATIONS banner below the header", header + "-- POST-MIGRATIONS: something\n", 1},
		{"a commented-out ADD COLUMN is prose", header + "-- ALTER TABLE public.t ADD COLUMN IF NOT EXISTS x text;\n", 0},
		{"a function body may UPDATE", header + "CREATE OR REPLACE FUNCTION public.f() RETURNS trigger\n    LANGUAGE plpgsql\n    AS $$\nBEGIN\n    UPDATE public.t SET id = NULL;\n    DELETE FROM public.t;\n    RETURN NEW;\nEND;\n$$;\n", 0},
		{"a tagged function body may UPDATE", header + "CREATE OR REPLACE FUNCTION public.f() RETURNS integer\nLANGUAGE plpgsql\nAS $fold$\nBEGIN\n  UPDATE public.t SET id = NULL;\n  RETURN 1;\nEND\n$fold$;\nUPDATE public.t SET id = NULL;\n", 1},
		{"a one-line SQL function does not swallow what follows", header + "CREATE OR REPLACE FUNCTION public.g() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\nUPDATE public.t SET id = NULL;\n", 1},
		{"an ON DELETE clause is not a DELETE", header + "ALTER TABLE ONLY public.t ADD CONSTRAINT f FOREIGN KEY (id) REFERENCES public.u(id) ON DELETE CASCADE;\n", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := migrationBlockViolations(c.sql); len(got) != c.want {
				t.Errorf("got %d violation(s) %v, want %d", len(got), got, c.want)
			}
		})
	}
}
