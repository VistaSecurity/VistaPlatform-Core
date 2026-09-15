# `@vistasecurity/primitives/query` — the query language, in TypeScript

The editor half of the asset-inventory query language: **parse, validate,
format, autocomplete**. The server half is Go's
[`shared/query`](../../../../shared/query/README.md), and the two are held to
the same fixture file.

**The contract is
[`docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md`](../../../../docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md)**
(workstream 0.8a). Go is part B; this is part C. Section references throughout
the package (§2, §5.6, …) are to that document.

```ts
import { check, format, newRegistryCatalog, CVSS_LADDER, defaultOptions, withLadder }
  from '@vistasecurity/primitives/query';

const cat  = newRegistryCatalog();
const opts = withLadder(defaultOptions(), CVSS_LADDER);

const out = check('environment:production and risk >= high', 'asset', cat, opts);
if (out.ok) {
  out.value.canonical;  // "environment:production and risk >= high" — store THIS
} else {
  out.errors;           // [{ code, message, span: {start, end}, suggestion? }]
}
```

## There is no SQL here, deliberately

The server translates. A second translator would be a second opinion about what
a query means, and the one thing the language exists to prevent is two opinions
about a predicate. What this side owns is everything a user sees *before* the
query is sent: the caret under the offending span, the "did you mean", the
completion list, and the canonical text a saved view stores.

Everything else about the language is identical on both sides, and
`conformance.test.ts` is what makes that a fact rather than an intention.

## Layout

| Module | What it does |
|---|---|
| `ast.ts` | The eleven node types of §7.1, `FieldRef`, spans, and the walkers. |
| `literal.ts` | §2's literal forms: numbers, durations, dates, uuids, inet, and §10's quoting rules. |
| `versionsort.ts` | §5.5's normalised version key — the definition of a `*_sort` column's contents. |
| `json.ts` | The compact tree encoding that **is** the cross-language contract. |
| `lexer.ts` | Mode-driven scanner. §2's rule that a bare value may contain `:` and `/` is why the parser asks for a token *in a mode*. |
| `parser.ts` | Hand-written recursive descent over §3. Knows the grammar, not the schema. |
| `catalog.ts` | The `Catalog` interface, the §4.4 type→operator matrix, and `BandLadder`. |
| `base-catalog.ts` | The resolution rules both catalogues share. |
| `test-fields.ts` / `test-catalog.ts` | The static §4.3 catalogue — the mirror of Go's `catalog/testcatalog`, which the conformance fixtures resolve against. |
| `registry-fields.gen.ts` / `registry-catalog.ts` | The production catalogue — the mirror of Go's `catalog/registrycatalog`, over the generated registries. **This is the one the UI uses.** The `.gen.ts` half is generated; see below. |
| `validate.ts` | Every §6 rule with its error code, field resolution, the traversal budget and the size caps. |
| `regex.ts` | §13 A6's common subset of RE2 and Postgres ARE. |
| `format.ts` | Canonical form per §10, with idempotence as a property test. |
| `errors.ts` | The structured `{code, message, span, suggestion?}` of §10, plus the caret rendering. |
| `analyse.ts` / `suggest.ts` | Autocomplete: where the cursor is, and what may go there. |
| `index.ts` | The façade: `check`, `canonicalize`, `formatOrSelf`. |

## The conformance suite is the point

`conformance.test.ts` reads
`shared/query/testdata/conformance.json` — **the Go tree's copy, not a copy of
it** — and runs all 228 cases. A copied fixture is one that can go stale without
anything failing, which is the whole hazard the file exists to remove.

Three of the file's five assertions apply here: `canonical`, `ast` and `errors`.
`sql` and `sql_errors` belong to the translator this side does not have, so a
case whose only expectation is an `sql_errors` entry is checked as one that must
*validate cleanly*.

It also re-checks the two properties the table cannot show: canonical text
reparses to the same tree, and formatting is idempotent.

**Every case passes. A case this port cannot pass is a bug in the port.**

## Two catalogues, and why they are not one table

Go ships two, and they genuinely disagree — enough that
`conformance_registry_test.go` carries an exemption list for the eight cases
that reach different answers. So this package ships two as well:

- **`TestCatalog`** mirrors `catalog/testcatalog`: §4.3's examples, a
  representative attribute/fact sample, the ADR-0002 D2 class tree. It is what
  the fixtures resolve against, so it is not a place to improve anything.
- **`RegistryCatalog`** mirrors `catalog/registrycatalog`: the generated class
  taxonomy and attribute schemas (`@vistasecurity/primitives/assets`), the fact
  registry (`@vistasecurity/primitives/facts`), the finding registry
  (`@vistasecurity/primitives/findings`), and the schema's own value sets.

`registry-fields.gen.test.ts` asserts the six differences that remain between
the two tables one by one, so that closing one has to be a deliberate edit — and
asserts the one that is now *closed*: both catalogues use §12 amendment 5's
`signature_algorithm` / `symmetric_algorithm` / `hash_algorithm`. The static one
used the columns' short names until workstream 0.8e, and no conformance fixture
writes any of the six — so Go's exemption list, which only catches a case that
RUNS, could never have noticed the disagreement.

### The vocabulary is generated, all of it

This used to be a list of three gaps. Workstream 0.8e closed them:

| What | Generated into | By |
|---|---|---|
| Class attribute schemas | `../assets/attribute-schemas.gen.ts` | `scripts/generate-asset-classes.mjs` |
| Finding producers / kinds / subject types | `../findings/registry.gen.ts` | `scripts/generate-findings-registry.mjs` |
| First-class fields, targets, §4.4's operator matrix | `registry-fields.gen.ts` | `shared/query/catalog/registrycatalog/cmd/gen-ts-fields` |

`make generate` writes all three; `make audit` re-runs each generator with
`--check` and fails on any difference. That is what closes the asymmetry this
section used to describe: Go's `TestEnumsMatchSchema` guarded the *source*
against `scripts/database/schema.sql`, and nothing guarded the *mirror*, so a
value added to a Postgres enum reached the editor only when somebody retyped
it — and an editor whose closed value set is short by one rejects a query the
server would have answered.

Two consequences worth knowing:

- **`attr.<name>` resolves out of the box.** `RegistryCatalog` no longer ships
  with an empty `attr.` vocabulary. `RegistryCatalogOptions.attributeKeys`
  survives as an override layered on top, not as the only way in. An attribute
  nothing declares is still `unknown_field`: accepting any `attr.<key>` as a
  keyword would take a typo, give it a type nobody declared, and send it to the
  server as if it had been checked.
- **`registry-fields.gen.ts` must not be hand-edited.** Change the Go table and
  run `make generate`. Five of its value sets are *references* into the other
  generated registries rather than literals, so the two cannot disagree; the
  generator checks the values still match before emitting the reference.

## Deliberate divergences from Go

Two, both because JavaScript is not Go — and both isolated so they cannot reach
the contract.

**Spans are UTF-16 code units, not UTF-8 bytes.** A `Span` here indexes a
JavaScript string, which is what a textarea's `selectionStart` gives you. Spans
are not part of the cross-language contract (the compact JSON encoding omits
them), so this is free — *except* for the two lengths that ARE contractual, and
those keep Go's units exactly:

| Cap | Unit | Why |
|---|---|---|
| `maxBytes` (§6 `query_too_long`) | UTF-8 **bytes** | §6: "not characters — the two caps in these adjacent rows use different units on purpose" |
| `maxRegexLen` (§6 `regex_invalid`) | **code points** | §6's "256 characters" |

The conformance file is pure ASCII and cannot tell the difference, so
`literal.test.ts` and `validate.test.ts` pin both. A port that measured both
with `String.length` would pass all 228 fixtures and then disagree with the
server on the first accented hostname.

**There is no RE2 compile.** Go validates a pattern against the §13 A6 subset
*and then* compiles it as RE2. JavaScript's `RegExp` is a backtracking engine
with a different dialect, so it is not a stand-in and this port does not pretend
otherwise. The subset scanner is ported exactly and does the work; `RegExp` is
asked only the one narrow question it can answer compatibly (an out-of-order
character class), and anything else it rejects is ignored as a dialect
difference. The server remains the authority.

## Autocomplete

`suggest(text, cursor, catalog, options)` returns ranked completions with the
span they replace and the target the cursor is inside.

It has no Go counterpart and no fixture — nothing about it crosses the wire —
so it is held to one rule instead: **it may only ever offer what the validator
would accept.** An editor that suggests a field the server then rejects has
taught the user something false about the language, which is worse than
suggesting nothing. `suggest.test.ts` substitutes every completion it produces
back into a whole query and validates it.

That rule is why, for instance, `and` and `or` are offered only where there is a
term to their left, and why `not_assessed` is offered after `risk:` and `risk !=`
but never after `risk >=` — it is the absence of a score, not a rung of the
ladder (§13 A2).

## Running the tests

```bash
cd packages/primitives
npm run test -- --run     # 684 tests, incl. all 228 conformance cases
npm run typecheck
```

`packages/primitives` has no ESLint config of its own — `make lint` covers
`frontend-v2` and `admin-ui-v2` only — so this package is typechecked but not
linted. Wiring it up means facing the existing backlog in `auth/`, `rbac/` and
`features/` too, which is its own change.
