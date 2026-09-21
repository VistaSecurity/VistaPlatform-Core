#!/usr/bin/env node
// Ticket-category parity — four spellings of one list must agree.
//
// A ticket's category is a closed vocabulary written down in four places:
//
//   1. scripts/database/schema.sql
//        - the inline CHECK on CREATE TABLE public.tickets  (fresh installs)
//        - the DROP/ADD pair in POST-MIGRATIONS             (existing installs)
//   2. services/compliance-engine/internal/models/ticket_categories.go
//        - TicketCategoriesWritable + TicketCategoriesLegacy (the 400 gate)
//   3. api/openapi/compliance-engine.openapi.yaml
//        - the TicketCategoryFilter enum                     (the contract)
//   4. packages/primitives/src/tickets/categories.ts
//        - TICKET_CATEGORIES + LEGACY_TICKET_CATEGORIES      (the UI)
//
// Each one fails differently when it falls behind, and three of the four fail
// SILENTLY. Miss the POST-MIGRATIONS edit and psql still exits 0 — the
// constraint simply keeps its old list and the first insert of a new category
// fails in production. Miss the Go list and a legitimate category is rejected
// with a 400. Miss the OpenAPI enum and the generated TS client narrows the
// type, so the UI cannot name a category the server accepts. Miss the
// registry and the queue renders a blank cell.
//
// The inline CHECK and the POST-MIGRATIONS CHECK are compared to each other as
// well as to the rest, because they are the pair most likely to drift: the
// first is what a fresh install gets and the second is what an upgrade gets,
// and a double-apply against an empty database proves neither.
//
// Run standalone for a report; `--strict` (how `make audit` runs it) exits 1
// on any disagreement.

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const strict = process.argv.includes('--strict');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

const problems = [];
const fail = (msg) => problems.push(msg);

/** Pull the quoted values out of a `... = ANY ((ARRAY[...])::text[])` CHECK body. */
function categoriesFromCheckBody(body) {
  return [...body.matchAll(/'([a-z_]+)'::character varying/g)].map((m) => m[1]);
}

// ---------------------------------------------------------------- schema.sql
const schema = read('scripts/database/schema.sql');

// The inline constraint sits on one line inside CREATE TABLE public.tickets.
const inlineMatch = schema.match(
  /CONSTRAINT tickets_category_check CHECK \(\(\(category\)::text = ANY \(\(ARRAY\[([^\]]*)\]\)::text\[\]\)\)\),/,
);
if (!inlineMatch) fail('schema.sql: could not find the inline tickets_category_check on CREATE TABLE');
const inlineCats = inlineMatch ? categoriesFromCheckBody(inlineMatch[1]) : [];

// The POST-MIGRATIONS form is multi-line and comes after an ADD CONSTRAINT.
const postMatch = schema.match(
  /ADD CONSTRAINT tickets_category_check\s*\n\s*CHECK \(\(\(category\)::text = ANY \(\(ARRAY\[([\s\S]*?)\]\)::text\[\]\)\)\);/,
);
if (!postMatch) fail('schema.sql: could not find the POST-MIGRATIONS ADD CONSTRAINT tickets_category_check');
const postCats = postMatch ? categoriesFromCheckBody(postMatch[1]) : [];

if (!schema.includes('ALTER TABLE public.tickets DROP CONSTRAINT IF EXISTS tickets_category_check;')) {
  fail(
    'schema.sql: the POST-MIGRATIONS block must DROP the old constraint before adding it. ' +
      'Without the DROP, ADD CONSTRAINT fails on any database that already has one.',
  );
}

// ------------------------------------------------------------------- Go gate
const go = read('services/compliance-engine/internal/models/ticket_categories.go');
function goList(name) {
  // Non-greedy to the FIRST closing brace, so this works for both the
  // multi-line list and the single-line one. Anchoring on `\n}` instead read
  // straight past a single-line var into the three that follow it.
  const m = go.match(new RegExp(`var ${name} = \\[\\]string\\{([^}]*)\\}`));
  if (!m) {
    fail(`ticket_categories.go: could not find var ${name}`);
    return [];
  }
  return [...m[1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
}
const goWritable = goList('TicketCategoriesWritable');
const goLegacy = goList('TicketCategoriesLegacy');

// -------------------------------------------------------------- API contract
const spec = read('api/openapi/compliance-engine.openapi.yaml');
const enumMatch = spec.match(/TicketCategoryFilter:[\s\S]*?enum:\s*\[([^\]]*)\]/);
if (!enumMatch) fail('compliance-engine.openapi.yaml: could not find the TicketCategoryFilter enum');
const specCats = enumMatch
  ? enumMatch[1].split(',').map((s) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean)
  : [];

// ----------------------------------------------------------------- UI registry
const ts = read('packages/primitives/src/tickets/categories.ts');
const regMatch = ts.match(/export const TICKET_CATEGORIES:[\s\S]*?\n\];/);
if (!regMatch) fail('categories.ts: could not find TICKET_CATEGORIES');
const tsWritable = regMatch ? [...regMatch[0].matchAll(/^\s*key: '([a-z_]+)',$/gm)].map((m) => m[1]) : [];

const legacyMatch = ts.match(/export const LEGACY_TICKET_CATEGORIES[^=]*=\s*\[([^\]]*)\]/);
if (!legacyMatch) fail('categories.ts: could not find LEGACY_TICKET_CATEGORIES');
const tsLegacy = legacyMatch ? [...legacyMatch[1].matchAll(/'([a-z_]+)'/g)].map((m) => m[1]) : [];

// --------------------------------------------------------------- comparisons
const sorted = (a) => [...a].sort();
const same = (a, b) => sorted(a).join(',') === sorted(b).join(',');
const diff = (a, b) => ({
  missing: sorted(b.filter((x) => !a.includes(x))),
  extra: sorted(a.filter((x) => !b.includes(x))),
});
function compare(labelA, a, labelB, b) {
  if (same(a, b)) return;
  const d = diff(a, b);
  fail(
    `${labelA} disagrees with ${labelB}:` +
      (d.missing.length ? `\n      ${labelA} is MISSING: ${d.missing.join(', ')}` : '') +
      (d.extra.length ? `\n      ${labelA} has EXTRA:   ${d.extra.join(', ')}` : ''),
  );
}

const goAll = [...goWritable, ...goLegacy];
const tsAll = [...tsWritable, ...tsLegacy];

// The DB must permit everything writable AND everything legacy — legacy rows
// predate the split and still have to satisfy the constraint.
compare('schema.sql inline CHECK', inlineCats, 'writable + legacy (Go)', goAll);
compare('schema.sql POST-MIGRATIONS CHECK', postCats, 'schema.sql inline CHECK', inlineCats);

// The UI and the write gate must agree on both halves separately: a category
// the UI offers but Go rejects is a button that 400s, and a legacy category Go
// treats as retired but the UI omits is a blank cell on an old row.
compare('categories.ts TICKET_CATEGORIES', tsWritable, 'Go TicketCategoriesWritable', goWritable);
compare('categories.ts LEGACY_TICKET_CATEGORIES', tsLegacy, 'Go TicketCategoriesLegacy', goLegacy);

// The filter enum covers legacy too — you have to be able to FILTER for the
// old rows even though you can no longer create one.
compare('openapi TicketCategoryFilter', specCats, 'writable + legacy (Go)', goAll);

// A retired category that is still writable is the bug this split exists to
// prevent, so check the two sets do not overlap rather than assuming.
const overlap = goWritable.filter((c) => goLegacy.includes(c));
if (overlap.length) fail(`Go: ${overlap.join(', ')} appears in BOTH the writable and legacy lists`);

// ------------------------------------------- hardcoded categories at call sites
// Every place that CREATES a ticket names a category as a literal, and some of
// them live outside the four files above — tools/qa-platform is its own module,
// is not in go.work, and cannot import models.TicketCategoriesWritable.
//
// This is not hypothetical. tools/qa-platform/internal/simulator/seed_tickets.go
// was merged with `"category": "remediation"` hours before the retirement
// landed. Both branches were green on their own; merged, the QA estate baseline
// would have failed on a 400 at the first seeded ticket, and nothing either
// side ran would have said so.
const CALL_SITE_GLOBS = [
  'tools/qa-platform/internal',
  'services',
  'frontend-v2/src',
  'admin-ui-v2/src',
];

function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(resolve(root, dir), { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === 'dist' || e.name.startsWith('.')) continue;
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) walk(rel, out);
    else if (/\.(go|ts|tsx)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// `"category": "x"` (Go map literal / JSON) or `category: 'x'` (TS object).
const CATEGORY_LITERAL = /["']category["']?\s*:\s*["']([a-z_]+)["']/g;
const writableSet = new Set(goWritable);
const legacySet = new Set(goLegacy);

for (const glob of CALL_SITE_GLOBS) {
  for (const file of walk(glob)) {
    // A test may legitimately name a retired category to assert it is refused.
    if (/(_test\.go|\.test\.tsx?|\.jsdom\.test\.tsx)$/.test(file)) continue;
    let body;
    try { body = readFileSync(resolve(root, file), 'utf8'); } catch { continue; }
    if (!body.includes('category')) continue;
    for (const m of body.matchAll(CATEGORY_LITERAL)) {
      const value = m[1];
      if (writableSet.has(value)) continue;
      // Only flag values that LOOK like a ticket category — the same key name
      // is used for finding categories, asset categories and more, and this
      // scan cannot tell them apart from the literal alone. Retired ticket
      // categories are unambiguous and are the failure that actually happened.
      if (legacySet.has(value)) {
        const line = body.slice(0, m.index).split('\n').length;
        fail(
          `${file}:${line} creates something with the RETIRED ticket category ` +
            `"${value}". POST /tickets answers 400 for it — use one of: ${goWritable.join(', ')}`,
        );
      }
    }
  }
}

// --------------------------------------------------------------- SLA parity
// The default due-date windows exist in two languages because both create
// tickets: the UI fills the form, and CreateTicketFromAlert runs server-side
// with no UI involved. Divergence would mean a ticket raised from an alert and
// the same ticket raised by hand carry different deadlines, which nothing
// would report.
const goSla = read('services/compliance-engine/internal/models/ticket_sla.go');
const tsSla = read('packages/primitives/src/tickets/sla.ts');

function slaPairs(src, re) {
  return Object.fromEntries([...src.matchAll(re)].map((m) => [m[1], Number(m[2])]));
}
const goDays = slaPairs(goSla, /"(critical|high|medium|low)":\s*(\d+),/g);
const tsDays = slaPairs(tsSla, /^\s*(critical|high|medium|low):\s*(\d+),/gm);

if (Object.keys(goDays).length !== 4) fail(`ticket_sla.go: expected 4 SLA windows, parsed ${Object.keys(goDays).length}`);
if (Object.keys(tsDays).length !== 4) fail(`sla.ts: expected 4 SLA windows, parsed ${Object.keys(tsDays).length}`);

for (const p of ['critical', 'high', 'medium', 'low']) {
  if (goDays[p] !== tsDays[p]) {
    fail(`default SLA for ${p} differs: ticket_sla.go says ${goDays[p]}d, sla.ts says ${tsDays[p]}d`);
  }
}

// The due-soon window is the backend's, mirrored in TS. A TS copy that drifted
// above the shortest SLA would make every new ticket render as already
// due-soon.
const goDueSoon = Number((goSla.match(/DueSoonDays = (\d+)/) || [])[1]);
const tsDueSoon = Number((tsSla.match(/DUE_SOON_DAYS = (\d+)/) || [])[1]);
if (!goDueSoon || !tsDueSoon) fail('could not parse the due-soon window from both sides');
else if (goDueSoon !== tsDueSoon) fail(`due-soon window differs: Go ${goDueSoon}d, TS ${tsDueSoon}d`);

const shortestSla = Math.min(...Object.values(goDays));
if (goDueSoon && shortestSla <= goDueSoon) {
  fail(
    `the shortest default SLA (${shortestSla}d) is inside the due-soon window (${goDueSoon}d): ` +
      'every ticket filed at that priority would be born already warning',
  );
}

// ------------------------------------------------------------------- report
const B = '\x1b[34m', G = '\x1b[32m', R = '\x1b[31m', D = '\x1b[2m', X = '\x1b[0m';
console.log(`\n${B}Ticket-category parity — schema ↔ Go ↔ OpenAPI ↔ primitives${X}`);
console.log(`${D}  writable            : ${goWritable.length} (${goWritable.join(', ')})${X}`);
console.log(`${D}  legacy (read-only)  : ${goLegacy.length} (${goLegacy.join(', ') || 'none'})${X}`);
console.log(`${D}  schema CHECK inline : ${inlineCats.length}${X}`);
console.log(`${D}  schema CHECK post-m : ${postCats.length}${X}`);
console.log(`${D}  openapi filter enum : ${specCats.length}${X}`);
console.log(`${D}  primitives registry : ${tsWritable.length} + ${tsLegacy.length} legacy${X}`);
console.log(`${D}  default SLA days    : ${['critical', 'high', 'medium', 'low'].map((p) => `${p}=${goDays[p]}`).join(' ')} (due-soon ${goDueSoon}d)${X}\n`);

if (problems.length === 0) {
  console.log(`${G}✅ All four ticket-category lists agree.${X}\n`);
  process.exit(0);
}
for (const p of problems) console.log(`${R}  ✗ ${p}${X}`);
console.log(
  `\n${D}  Adding a category is four edits: schema.sql (inline CHECK AND the` +
    `\n  POST-MIGRATIONS pair), ticket_categories.go, the OpenAPI enum, and` +
    `\n  packages/primitives/src/tickets/categories.ts.${X}\n`,
);
process.exit(strict ? 1 : 0);
