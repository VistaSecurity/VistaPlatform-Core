# `shared/query` — the asset-inventory query language

One predicate form for scopes, saved views, the inventory facet rail and URL,
auto-approval rules, alert and rule triggers, compliance measurements, the MCP
`query` argument, and the grounded-query seam's translation target.

**The contract is
[`docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md`](../../docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md)**
(workstream 0.8a). This package is part B: the Go implementation. Section
references below (§2, §5.6, …) are to that document.

```go
c, err := query.Compile("environment:production and risk >= high", "asset", cat, opts)
// c.Canonical → "environment:production and risk >= high"   (store this)
// c.Where     → "((lower((a.environment)::text) = $1) AND (a.risk_score >= $2))"
// c.Args      → ["production", 70]
```

The caller writes the outer `SELECT … FROM assets a WHERE <c.Where>` and runs it
in a transaction that has already executed `SET LOCAL app.tenant_id`.

## Layout

| Package | What it does |
|---|---|
| `ast` | The eleven node types of §7.1, `FieldRef`, spans, literal parsing, the grammar's fixed vocabulary (eight collections, twenty relationship names), and the compact JSON encoding that is the cross-language contract. |
| `lexer` | Mode-driven scanner. §2's rule that a bare value may contain `:` and `/` is why the parser asks for a token *in a mode* rather than reading one stream. |
| `parser` | Hand-written recursive descent over §3. Knows the grammar, not the schema: every field comes out unresolved. |
| `catalog` | The `Catalog` interface, the §4.4 type→operator matrix, and `BandLadder`. `catalog/registrycatalog` is the production catalogue; `catalog/testcatalog` is the static one implementing §4.3; `catalog/ladder` builds a `BandLadder` from its rungs. |
| `validate` | Every §6 rule with its error code, field resolution, the traversal budget, and the size caps. Fails closed. |
| `format` | Canonical form per §10, with `Format(Format(q)) == Format(q)` as a property test. |
| `sql` | The five SQL shapes of §7.2 over the DATA_MODEL tables, parameterised. |
| `queryerr` | The structured `{code, message, span, suggestion?}` error of §10, plus the caret rendering and the suggestion helpers. |

`query` itself is the façade: `Compile` (text → SQL), `Check` (text → validated
AST, for a target that is evaluated somewhere other than the database) and
`Canonicalize` (text → canonical text, no catalogue needed — the facet rail
round-trips what the user is still typing).

## Catalogues

There are two, and the difference is where the vocabulary comes from.

| | `catalog/registrycatalog` | `catalog/testcatalog` |
|---|---|---|
| Vocabulary | the generated registries + the real schema | QUERY_LANGUAGE §4.3, statically |
| Used by | production (`query.DefaultCatalog()`) | the conformance fixtures |
| `attr.`, `fact.`, `id.`, `class`, finding kinds | generated — add to the YAML, `make generate`, done | a representative handful |
| Closed value sets | copied from `schema.sql`, pinned by a test | typed out |

**Use `query.DefaultCatalog()`** unless you are testing the language itself:

```go
cat  := query.DefaultCatalog()              // registry catalogue, CVSS×10 ladder
opts := query.DefaultOptionsFor(cat)        // takes the ladder FROM the catalogue
c, err := query.Compile(src, "asset", cat, opts)
```

A service should build it with the real ladder rather than take the default —
see "Plugging in the band ladder" below:

```go
cat := registrycatalog.New(registrycatalog.Options{Ladder: riskBandLadder{}})
```

### What the registry catalogue generates, and what it cannot

Generated, and therefore unable to drift: `attr.<name>` from every class's
attribute schema (`shared/assetclass`), `fact.<key>` from `shared/facts`,
`id.<kind>` from ADR-0002 D3, `class` from the 49-node hierarchy, the finding
producer/kind/subject vocabularies from `shared/findings`, and the ten
relationship types.

Hand-written, because nothing in the schema carries it: the **first-class field
table** (a column name is not a field name — the language says `first_seen`
where the column is `first_discovered_at` — and nothing records which columns
are queryable at all) and the **closed value sets**, every one of which is
pinned to `scripts/database/schema.sql` by `TestEnumsMatchSchema`.

### The TypeScript mirrors are generated too

The editor has its own catalogue (`packages/primitives/src/query`), and the same
vocabulary reaching it by hand is the drift this package exists to prevent. Four
artefacts close that, all written by `make generate` and all re-checked by
`make audit`:

| TypeScript artefact | Written by | From |
|---|---|---|
| `assets/attribute-schemas.gen.ts` | `scripts/generate-asset-classes.mjs` | `standards/asset-classes.yaml` — the same effective per-class schemas as `shared/assetclass/attribute_schemas_gen.json` |
| `findings/registry.gen.ts` | `scripts/generate-findings-registry.mjs` | `standards/findings-registry.yaml` — the same registry as `shared/findings` |
| `query/registry-fields.gen.ts` | `registrycatalog/cmd/gen-ts-fields` | **this package** — `AllTargets()`, `FirstClassFields()`, and `catalog.OperatorsFor` |
| `facts/keys.gen.ts` | `scripts/generate-fact-keys.mjs` | `standards/fact-keys.yaml` (predates this) |

`gen-ts-fields` is a Go program rather than another `scripts/*.mjs` because its
input is Go values, not a file: reading `fields.go` with a parser would be a
second implementation of Go's own semantics, while calling the two exported
functions is reading exactly what the catalogue publishes. Five of the value
sets it emits — the finding producers, kinds and subject types, the stored
identifier kinds, the relationship types — are emitted as *references* to the
other generated TypeScript registries rather than as literals, so two generated
files cannot come to disagree; the generator verifies the values still match
before emitting the reference, and fails if `fields.go` ever stops deriving one
of them from its registry.

### The type-mapping rule

A registry declares a value's type; this is how it becomes a query type.

| YAML type | Query type | |
|---|---|---|
| `string` | `keyword` (+ `EnumValues` when the YAML declares an enum) | |
| `integer`, `number` | `number` | guarded `::numeric` cast out of jsonb |
| `boolean` | `boolean` | guarded `::boolean` cast |
| `date` | `timestamp` | guarded `::timestamptz` cast |
| `array`, `object` | `json` | **`exists` only** |
| anything else | not published | resolves as `unknown_field` |

Two rows are decisions rather than transcription:

- **`string` → `keyword`, not `text`.** `:` on keyword is case-insensitive
  equality; on text it is substring. Every string in these registries is a short
  structured value a collector wrote, and a facet chip built from
  `attr.provider` has to mean equality. `~ "regex"` and `attr.model:Cat*` cover
  partial matching. A registry that ever declares prose needs a signal in the
  YAML saying so — guessing from the attribute's *name* would be the kind of
  second opinion this catalogue exists to remove.
- **`array`/`object` → `json`, not `keyword[]`.** A jsonb value read through
  `->>` or `#>> '{}'` is TEXT. `keyword[]` would generate `unnest(text)` and
  `array_length(text)` — errors from the database. `text` would make
  `fact.net.vlans:10` a substring search that matches the stored `[100]`.
  `ast.TypeJSON` is §4.4's json row taken at its word: `exists` and nothing
  else, refused rather than guessed, exactly as a band with no ladder is.
  `keyword[]` stays for a real `text[]` **column** (`risk_assessed_by`, `sni`,
  `alpn`), which is a first-class field, not a registry key.

### The fixtures run through both

`testdata/conformance.json` is executed a second time against the registry
catalogue (`TestConformance_RegistryCatalog`). Every case must produce the same
canonical form, AST, diagnostics and SQL, or appear in an **asserted** exemption
list with a reason — asserted in both directions, so an exemption that stops
being needed fails the test.

**No case is exempt.** There used to be eight, in three groups, and each named a
key the registries do not define or define with a different type:
`attr.os_version` typed `number` in the static catalogue and `keyword` in the
registry (the YAML declares a version string), `attr.managed`, and
`fact.cve.max_cvss`. Every one meant a predicate the fixtures accepted and the
product refused — `attr.os_version < 3` is `operator_not_allowed` against a
keyword — so the fixtures documented a language nobody could type.

They are resolved in the REGISTRY's favour rather than exempted: the fixtures
now use `attr.cpu_count`, `attr.controller_managed`, `fact.sw.package_count` and
`fact.eol.sw.date`, which exist, and which keep every SQL shape the old cases
pinned. `registryExemptions` stays declared and empty, and the harness fails on
an entry that no longer applies, so a future divergence has to arrive with a
reason attached.

The SQL shapes these pinned are re-covered through keys the registry does
declare, in `TestRegistryCatalog_JSONBCasts`.

A fourth group is deliberately absent. Three fixtures wrote `prod`, which
`environment_type` cannot hold, and the static catalogue left the field open so
they passed there — but that was the fixtures lagging §12 A1, not two catalogues
disagreeing, so it was **fixed at the source**: `testcatalog` closes the enum
too and the fixtures now write what the amended spec writes. An exemption would
have dressed a stale fixture up as a catalogue difference, which is the one
thing this list must not be used for.

## Plugging in a catalogue

The parser, validator and translator only ever see `catalog.Catalog`:

```go
type Catalog interface {
    Targets() []Target
    Fields(target string) []FieldInfo
    Resolve(target string, path []string) (ast.FieldRef, error)
    RelationshipNames() []ast.Relationship
    ClassExists(key string) (ClassInfo, bool)
    EnumValues(field ast.FieldRef) ([]string, bool)
}
```

`catalog/testcatalog` implements it statically from §4.3 and is what the
conformance fixtures resolve against; `catalog/registrycatalog` implements the
same interface over the generated registries and is what production uses
(see **Catalogues** above). Nothing outside the catalogue changed when the
second one was added — which is the property the fixtures now check by running
the whole file through both. Two things a catalogue owns and the rest of the
package does not:

- **Accessors.** `ast.Accessor` is how the translator reaches a value: a
  column, a jsonb key, a fact row, an identifier row, or a named derived
  builder. Every identifier in the generated SQL comes from here, which is what
  keeps user text out of SQL identifiers. The *key* inside a jsonb or fact
  accessor is user text and is always bound as a parameter.
- **Types.** The `FieldType` decides the operators (§4.4) and the SQL shape.

Optionally implement `validate.ClassLister` (`ClassKeys() []string`) so an
unknown class key gets a "did you mean".

## Plugging in the band ladder

`risk >= high` must be generated from one ladder, never from a threshold written
in a query (§5.5 — this is the drift that once put badges at ≥ 60 while facets
used ≥ 70). The ladder lives in
`services/inventory-service/internal/models/risk_bands.go`, which `shared/`
cannot import, so the caller supplies it:

```go
type ladder struct{}
func (ladder) Bands() []catalog.Band {
    out := make([]catalog.Band, 0, len(models.RiskBands))
    for _, b := range models.RiskBands {
        out = append(out, catalog.Band{Label: b.Label, Min: b.Min})
    }
    return out
}

opts := query.DefaultOptions(ladder{})
```

Without a ladder, a band field is `untranslatable` — refused, not guessed.

`catalog/ladder` builds one from its rungs — `ladder.FromRungs(90, 70, 40, 1)`,
labels fixed and `Informational` always 0 — and `ladder.CVSS` is that default.
`registrycatalog` carries whichever ladder it was built with, and
`query.DefaultOptionsFor(cat)` takes it from there, so the catalogue and the
translator cannot be handed two different ladders. `testcatalog.Ladder` is the
older copy the §4.3 tests use. All three are pinned to `models.RiskBands` by
`services/inventory-service/internal/services/query_{ladder_parity,registry_catalog}_test.go`.

## The three invariants

Each is a test, and each was mutation-tested by breaking it and watching the
test fail:

1. **No tenant predicate, ever.** RLS scopes every statement; a `tenant_id`
   predicate emitted here would make a bug in this package look like an
   isolation control. `TestNoTenantPredicate`, `TestConformance_NoTenantPredicate`.
2. **Every literal is bound.** The generated SQL contains no quoted literal at
   all — not one `'`. That is a stronger and cheaper check than hunting for
   interpolated values. `TestEveryLiteralIsBound`, `TestInjectionAttemptsStayValues`.
3. **Canonical form round-trips.** `Parse(Format(q)) == q` as trees, and
   `Format(Format(q)) == Format(q)` as text. Held by the conformance suite, a
   generated-grammar property test, and `FuzzParse`.

## The conformance fixtures

`testdata/conformance.json` is the cross-language contract: a TypeScript port
(a later workstream) must produce the same canonical text, the same AST and the
same SQL for every case. One table-driven test runs the whole file.

To add a case, append the shape you want covered:

```json
{ "name": "shape-something", "query": "class:server", "target": "asset",
  "note": "§5.3: what this pins and why" }
```

then

```bash
cd shared && go test ./query -run TestConformance -update
```

and **read the diff**. The `-update` flag fills in `canonical`, `ast`, `sql` and
`errors` from the current implementation, which makes it exactly as good as your
review of what it wrote. A blessed snapshot nobody read is how a bug becomes a
contract.

Fields: `options` overrides the §6 caps so a cap can be exercised with a short
query instead of a four-kilobyte one; `errors` holds parse/validation codes;
`sql_errors` holds translation codes, for a query that is valid but has no SQL
(the `observation` and `measurement` targets); `sql.args` is the bind
parameters, which are checked as well as counted — a count alone said nothing
about a reversed range, a LIKE pattern padded on the wrong side, or a band
bound off by a rung.

**Every failing case must name a passing twin**, by the `<x>-bad`/`<x>-ok`
convention or with an explicit `"twin"` field, and every `-ok` must be claimed
by one — both polarities, because an over-strict guard is the same bug pointed
the other way. The rule used to fire only on names ending `-bad`, which made
it opt-in; five failing cases had quietly opted out.

`FuzzParse` seeds from every fixture query. Regressions it has already found are
committed under `testdata/fuzz/FuzzParse/`.

## Decisions this implementation had to make

The spec is precise, and these are the places it was silent or inconsistent.
Each is a decision, not an accident.

### Contradictions found in QUERY_LANGUAGE.md

1. **`environment` was named as the `environment_type` enum (§4.3) while §8 and
   §9 example 18 used `prod`, which is not one of its four values.** **Settled
   by §12 A1: the enum wins**, and §8's row and example 18 were rewritten. Both
   catalogues close the set. `assets.environment` IS the Postgres type, so a row
   holding `prod` cannot exist, and an open set would turn a typo into an empty
   result where a closed one gives a diagnostic with a suggestion. (Three
   fixtures went on writing `prod` for a while after the amendment; they were
   corrected with the production catalogue, in the same change that would
   otherwise have had to exempt them.)
2. **§9 example 12 writes `status:pending`; the asset status vocabulary
   (DATA_MODEL §2) is `pending_approval`.** Enforced as written — the fixture
   records the example as an `unknown_value` error with a suggestion, and a
   second fixture shows the working form. Cheap to fix in either direction.
3. **§8 reserves the name `value` for a measurement's extracted scalar, but
   §4.1 lists no `measurement` target for it to resolve against.** Added, with
   no table: like `observation`, a measurement predicate is evaluated where the
   scalar is, not in SQL.
4. **The §3 cheat sheet writes `id.mac`; ADR-0002 D3 names the identifier kind
   `mac_address`.** Both resolve in the static catalogue (`mac` is registered
   as an alias). The registry should settle which one is canonical.
   Separately, the cheat sheet's `id:"<value>"` for "an identifier of any
   kind" collided with §4.3's `id` uuid column and won, which made the column
   unreachable and published two fields under one name. Settled in §13 A1: a
   bare `id` is the row's uuid on every target, and the any-kind form is
   `id.any`.
5. **§4.3 gives no field table for the `crypto_configuration` target**, though
   §4.1 lists it as one. Populated from `crypto_implementations` plus §8's two
   derived fields.
6. **§4.3 types `endpoint.service_version` as `version`, but DATA_MODEL gives a
   normalised `version_sort` only to `software_products`.** §5.5 forbids a
   lexical fallback, so the accessor names `asset_endpoints.service_version_sort`
   — a column workstream 1.1 must add, or the field must become text.
7. **§4.3's `proposed_by` is sugar for `source=inferred and source_ref=…`, but
   DATA_MODEL §2 gives `assets` a `class_source_kind` with no matching ref
   column.** The derived builder emits `class_source_ref`; workstream 1.1 must
   add it.

### Choices the spec left open

- **`field:(a or b)` is sugar.** §7.1's node set has no group node, so a value
  group desugars at parse time into Or/And/Not over the same field, and the
  canonical form is the desugared one (`tag:(dev or test)` →
  `tag:dev or tag:test`). The AST is the cross-language
  contract, and it has eleven node types.
- **`field in (a, b)` and `field:(a or b)` produce identical SQL**, because the
  §3 cheat sheet says they mean the same thing. `in` keeps its own node so the
  formatter can write `not in`.
- **Durations canonicalise to the largest exactly-dividing unit**, so `24h`
  becomes `1d` (the spec's example) and `14d` becomes `2w` (the same rule, one
  step further). Calendar units convert only among themselves: `12mo` is `1y`,
  and no number of days is ever a month.
  Consequence, because the formatter is type-free: a *string* value shaped
  exactly like `now±<duration>` is rewritten too. `display_name:"now-24h"`
  canonicalises to `display_name:now-1d`.
- **Free text is quoted more eagerly than a value.** `a:b` is a fine value but,
  written alone, it is a field and a value; `web.01` starts a field path. A
  free-text term that starts like an identifier and contains `.` or `:` is
  therefore quoted in canonical form. In free text `*` is an ordinary
  character — §5.4 is already a substring search — so quoting it changes
  nothing, and the AST encoding says so.
- **An unknown relationship name in `name:(…)` is `unknown_field`, not
  `unknown_value`.** `depands_on:(class:server)` is syntactically a field with a
  value group, because `:` is legal inside a bare value; the validator's
  suggestion names the relationship. The explicit `rel(depands_on, out):(…)`
  form *is* unambiguous, and that one reports `unknown_value` as §6 specifies.
- **The explicit `rel(type, direction)` form takes a canonical type only.** A
  reverse label plus a direction argument has no defined meaning; the error says
  so and offers both working spellings.
- **`fact.<key>` compares against the ONE reconciled value** (§13 A4), not
  against any producer's row: a scalar subquery over `asset_facts` ordered by
  source precedence (`measured` > `declared` > `imported` > `inferred`, then
  most recently observed). `exists(fact.<key>)` is the exception and stays an
  EXISTS over the raw rows, because presence is a question about the rows.
- **Traversal is only available where the row is an asset**, because edges join
  assets. From another target, write `asset:(depends_on:(…))`.
- **A parse error reports `syntax_error`**, a code §6's table does not list
  because §6 covers validation. Everything else uses §6's codes exactly. The
  one exception is the parser's own depth ceiling (`parser.MaxDepth`, 64):
  recursive descent recurses, and a stack overflow is a runtime *fatal* error
  that `recover()` cannot catch, so the parser refuses absurd nesting itself
  with `too_many_clauses` — the same code §6 gives the validator's
  configurable paren cap, because it is the same kind of limit. The numeric
  ceiling is implementation-defence, not contract: a port needs *a* ceiling,
  not this one.

### Deliberately not done here

- The **TypeScript port** — a later workstream, held to `conformance.json`.
- The two **derived fields** §8 calls for (`strength`,
  `algorithm.deprecated`) are implemented here as whitelisted builders so the
  §9 examples work end to end, but workstream 1.9 owns confirming their join
  paths against the shipped schema.
- **`version_sort` is written by nobody yet.** `ast.VersionSortKey` is the
  definition of that column's contents; whatever writes it must call this
  function, or a comparison compares two different normalisations and quietly
  returns the wrong rows.
- **The one shape still unexecuted.** Every fixture's clause is now EXPLAINed
  against a live Postgres (`TestIntegration_QuerySQLExecutes`, skips without
  `TEST_DATABASE_URL`), and the three-valued answers that only a database can
  give are asserted over real rows (`TestIntegration_QuerySemanticsOverRealRows`).
  What still cannot run is the `crypto_configuration` target's endpoint join:
  `crypto_implementations` is a view over the pre-inventory partitioned table
  and has no `endpoint_id`. Eleven fixtures skip on it, and the test fails if
  that exemption ever stops being needed, so it cannot outlive the column.

## Running the tests

```bash
cd shared
go test ./query/... -race
go test ./query -run TestConformance                 # the fixture file
go test ./query -run FuzzParse -fuzz FuzzParse -fuzztime 2m
golangci-lint run ./query/...
```
