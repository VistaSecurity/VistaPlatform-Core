#!/usr/bin/env node
// Generate the published edition matrix from the code that actually gates.
//
// The matrix tells a reader which capabilities are Core, which are Enterprise,
// and which are MSP. That is a claim about product behaviour, so it must not be
// hand-maintained: a matrix that says "Core" about something the resolver
// denies is worse than no matrix, because it is believed.
//
// Everything here is therefore a JOIN over existing sources of truth, plus a
// guard that fails when they disagree:
//
//   shared/entitlements/editions.go   editionByItem — WHICH keys are gated and
//                                     to which edition. Sole authority. Also
//                                     supplies the rationale prose, which lives
//                                     in its group comments.
//   scripts/database/seed.sql         billable_items rows — display name and
//                                     description per capability.
//                                     Edition-gate corrective UPDATE — the list
//                                     that stops a tier self-granting paid
//                                     capability.
//   standards/editions.yaml           Documentation links, edition blurbs, and
//                                     the MSP surface (carved by service split,
//                                     so absent from editionByItem entirely).
//
// Checks, all of which fail --check:
//
//   1. editions.yaml `docs:` key set === editionByItem key set, both
//      directions. Adding a gated capability forces a documentation decision.
//   2. seed.sql's edition-gate corrective UPDATE list === editionByItem. Both
//      files carry a "keep this in sync" comment; this is what enforces it.
//   3. resolver_test.go's `gated := []string{...}` === editionByItem. Same
//      reason — the test pins the open-core invariant and is worthless if it
//      silently omits a key.
//   4. Every gated key has a billable_items row (advisory: editions.go
//      documents listing planned keys early as fail-closed and safe).
//   5. No MSP surface entry collides with a gated item key, which would mean
//      one capability carved by two different mechanisms.
//   6. The committed matrix matches what this script generates.
//
// Parsing is strict on purpose. Every extraction asserts it matched something,
// because a regex that quietly matches nothing would emit a cheerful, empty,
// completely wrong matrix — the exact failure mode this repository has been
// bitten by before (see the guard notes in CLAUDE.md).
//
// Usage:
//   node scripts/generate-edition-matrix.mjs           # write the matrix
//   node scripts/generate-edition-matrix.mjs --check    # fail on any drift
//
// Wired into `make edition-matrix` (write) and `make audit` (--check).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'yaml';
import { escapeTableCell } from './lib/markdown-table.mjs';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const CHECK = process.argv.includes('--check');

const EDITIONS_GO = join(repoRoot, 'shared', 'entitlements', 'editions.go');
const RESOLVER_TEST = join(repoRoot, 'shared', 'entitlements', 'resolver_test.go');
const SEED_SQL = join(repoRoot, 'scripts', 'database', 'seed.sql');
const EDITIONS_YAML = join(repoRoot, 'standards', 'editions.yaml');
const OUT = join(repoRoot, 'docsv4', 'core', 'editions.md');

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

const problems = [];
const warnings = [];

/** Fail loudly rather than emit a confidently empty matrix. */
function must(condition, message) {
  if (!condition) {
    console.error(`${RED}✖ ${message}${RESET}`);
    process.exit(1);
  }
}

const read = (p, label) => {
  must(existsSync(p), `${label} not found at ${p}`);
  return readFileSync(p, 'utf8');
};

// ── 1. editionByItem, with the rationale prose from its group comments ──────
//
// The map is grouped by comment banners that read:
//
//   // --- Enterprise: compliance authoring ---------------------------
//   // Core keeps the full evaluation engine ...
//   "custom_policies": EditionEnterprise,
//
// The banner names the group, the plain comment lines beneath it are the
// rationale, and both are worth publishing — that prose explains what Core
// keeps, which is the single most useful thing in the matrix.
function parseEditionsGo(src) {
  const start = src.indexOf('var editionByItem = map[string]Edition{');
  must(start !== -1, 'editionByItem map not found in editions.go');
  const end = src.indexOf('\n}', start);
  must(end !== -1, 'could not find the end of the editionByItem map');
  const body = src.slice(start, end);

  const groups = [];
  const byKey = new Map();
  let current = null;

  for (const raw of body.split('\n')) {
    const line = raw.trim();

    const banner = line.match(/^\/\/\s*---\s*(.+?)\s*-{2,}\s*$/);
    if (banner) {
      // "Enterprise: compliance authoring" → editions "Enterprise", name after
      // the colon. "Enterprise + MSP: audit forwarding" keeps both.
      const title = banner[1];
      const colon = title.indexOf(':');
      current = {
        title,
        name: colon === -1 ? title : title.slice(colon + 1).trim(),
        rationale: [],
        keys: [],
      };
      groups.push(current);
      continue;
    }

    const entry = line.match(/^"([a-z0-9_]+)":\s*Edition([A-Za-z]+),/);
    if (entry) {
      const [, key, edition] = entry;
      const ed = edition.toLowerCase();
      byKey.set(key, ed);
      if (current) current.keys.push(key);
      continue;
    }

    const prose = line.match(/^\/\/\s?(.*)$/);
    if (prose && current && current.keys.length === 0) {
      const text = prose[1].trim();
      if (text) current.rationale.push(text);
    }
  }

  must(byKey.size > 0, 'parsed zero entries from editionByItem — the parser is broken, not the map');
  must(groups.length > 0, 'parsed zero comment groups from editionByItem');
  must(
    groups.some((g) => g.keys.length > 0),
    'parsed comment groups but attached no keys to any of them',
  );
  return { byKey, groups };
}

// ── 2. billable_items display names and descriptions ───────────────────────
//
// Rows look like:
//   ('custom_policies', 'Custom Compliance Policies', 'Tenant may ...', ...
// Parsed with an SQL-string reader rather than a regex so an apostrophe inside
// a description (written '' in SQL) cannot truncate the field.
function parseSqlRowStrings(line, want) {
  const out = [];
  let i = line.indexOf('(');
  if (i === -1) return out;
  i += 1;
  while (out.length < want && i < line.length) {
    while (i < line.length && /[\s,]/.test(line[i])) i += 1;
    if (line[i] !== "'") return out; // NULL or a non-string column: stop
    i += 1;
    let value = '';
    while (i < line.length) {
      if (line[i] === "'") {
        if (line[i + 1] === "'") {
          value += "'";
          i += 2;
          continue;
        }
        i += 1;
        break;
      }
      value += line[i];
      i += 1;
    }
    out.push(value);
  }
  return out;
}

function parseBillableItems(src) {
  const start = src.indexOf('INSERT INTO billable_items');
  must(start !== -1, 'INSERT INTO billable_items not found in seed.sql');
  const end = src.indexOf('ON CONFLICT (key) DO NOTHING;', start);
  must(end !== -1, 'could not find the end of the billable_items INSERT');

  const items = new Map();
  for (const line of src.slice(start, end).split('\n')) {
    const t = line.trim();
    if (!t.startsWith("('")) continue;
    const [key, displayName, description] = parseSqlRowStrings(t, 3);
    if (key) items.set(key, { displayName, description });
  }
  must(items.size > 0, 'parsed zero billable_items rows from seed.sql');
  return items;
}

/** The corrective UPDATE that stops any tier self-granting paid capability. */
function parseSeedGatedList(src) {
  const anchor = src.indexOf('Edition-gate correction');
  must(anchor !== -1, "seed.sql's 'Edition-gate correction' block not found");
  const inStart = src.indexOf('bi.key IN (', anchor);
  must(inStart !== -1, 'no `bi.key IN (` list in the edition-gate correction block');
  const inEnd = src.indexOf(')', inStart);
  must(inEnd !== -1, 'unterminated `bi.key IN (` list');
  const keys = [...src.slice(inStart, inEnd).matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1]);
  must(keys.length > 0, 'parsed zero keys from the edition-gate corrective UPDATE');
  return new Set(keys);
}

/** The Go test that pins "no tier may grant an edition-gated capability". */
function parseResolverTestGated(src) {
  const start = src.indexOf('gated := []string{');
  must(start !== -1, 'gated := []string{ not found in resolver_test.go');
  const end = src.indexOf('}', start);
  must(end !== -1, 'unterminated gated := []string{ literal');
  const keys = [...src.slice(start, end).matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1]);
  must(keys.length > 0, 'parsed zero keys from resolver_test.go gated list');
  return new Set(keys);
}

const setDiff = (a, b) => [...a].filter((x) => !b.has(x)).sort();

// ── Load everything ────────────────────────────────────────────────────────
const { byKey, groups } = parseEditionsGo(read(EDITIONS_GO, 'editions.go'));
const items = parseBillableItems(read(SEED_SQL, 'seed.sql'));
const seedGated = parseSeedGatedList(read(SEED_SQL, 'seed.sql'));
const testGated = parseResolverTestGated(read(RESOLVER_TEST, 'resolver_test.go'));
const meta = yaml.parse(read(EDITIONS_YAML, 'editions.yaml'));

must(meta && meta.editions, 'editions.yaml has no `editions:` block');
must(meta.docs && typeof meta.docs === 'object', 'editions.yaml has no `docs:` block');
must(Array.isArray(meta.msp_surface), 'editions.yaml has no `msp_surface:` list');

// Gated capabilities that have no user-facing surface yet. Documenting one
// would describe a control that does not exist, so the matrix says so instead.
const noSelfService = new Set(meta.no_self_service ?? []);

const gatedKeys = new Set(byKey.keys());

// ── Drift checks ───────────────────────────────────────────────────────────
const compare = (label, other, otherLabel) => {
  const missing = setDiff(gatedKeys, other);
  const extra = setDiff(other, gatedKeys);
  if (missing.length) {
    problems.push(`${label}: missing ${missing.join(', ')} (present in editionByItem)`);
  }
  if (extra.length) {
    problems.push(`${label}: has ${extra.join(', ')} which ${otherLabel} does not gate`);
  }
};

compare('standards/editions.yaml `docs:`', new Set(Object.keys(meta.docs)), 'editionByItem');
compare("seed.sql edition-gate corrective UPDATE", seedGated, 'editionByItem');
compare('shared/entitlements/resolver_test.go `gated`', testGated, 'editionByItem');

for (const key of gatedKeys) {
  if (!items.has(key)) {
    warnings.push(
      `${key} is edition-gated but has no billable_items row in seed.sql ` +
        `(fail-closed — the resolver denies unknown items — but it will not appear in the matrix with a description)`,
    );
  }
}

for (const entry of meta.msp_surface) {
  const slug = String(entry.name || '').toLowerCase().replace(/[^a-z0-9]+/g, '_');
  if (gatedKeys.has(slug)) {
    problems.push(
      `msp_surface entry "${entry.name}" collides with gated item key ${slug} — ` +
        `a capability carved both by billable item and by service split`,
    );
  }
}

for (const key of noSelfService) {
  if (!gatedKeys.has(key)) {
    problems.push(`editions.yaml no_self_service lists ${key}, which editionByItem does not gate`);
  }
  if (meta.docs[key]) {
    problems.push(
      `editions.yaml lists ${key} as no_self_service but also gives it a doc ` +
        `(${meta.docs[key]}) — it cannot both have a guide and have no surface`,
    );
  }
}

// Undocumented AND expected to have a surface: a real gap. The no-surface ones
// are tracked separately so the two never get conflated.
const undocumented = Object.entries(meta.docs)
  .filter(([k, v]) => !v && !noSelfService.has(k))
  .map(([k]) => k);

for (const [, docPath] of Object.entries(meta.docs)) {
  if (docPath && !existsSync(join(repoRoot, 'docsv4', docPath))) {
    problems.push(`editions.yaml docs: points at docsv4/${docPath}, which does not exist`);
  }
}

// ── Render ─────────────────────────────────────────────────────────────────
const editionLabel = (ed) => meta.editions[ed]?.label ?? ed;

function render() {
  const L = [];
  L.push('<!-- GENERATED by scripts/generate-edition-matrix.mjs — do not edit.');
  L.push('     Source of truth: shared/entitlements/editions.go (what is gated),');
  L.push('     scripts/database/seed.sql (names and descriptions),');
  L.push('     standards/editions.yaml (doc links, MSP surface).');
  L.push('     Regenerate with `make edition-matrix`; `make audit` fails on drift. -->');
  L.push('');
  L.push('# Editions');
  L.push('');
  L.push(
    'Vista Platform ships as a free, source-available **Vista Platform Core** plus two paid editions — **Vista Platform Enterprise** and **Vista Platform MSP**. ' +
      'An edition is a licensing boundary that decides whether a capability exists ' +
      'in a build at all. It is not the same thing as a *tier* — tiers are ' +
      'commercial packaging that an operator authors, and only the MSP edition can ' +
      'author them.',
  );
  L.push('');
  L.push('Anything not listed on this page is Core.');
  L.push('');

  for (const ed of ['core', 'enterprise', 'msp']) {
    const e = meta.editions[ed];
    if (!e) continue;
    L.push(`## ${e.label}`);
    L.push('');
    if (e.tagline) L.push(`*${e.tagline}*`);
    L.push('');
    if (e.summary) L.push(e.summary.trim());
    L.push('');
  }

  L.push('---');
  L.push('');
  L.push('## Paid capabilities');
  L.push('');
  L.push('| Capability | Edition | What it does | Documentation |');
  L.push('|---|---|---|---|');

  const rows = [...gatedKeys].sort();
  for (const key of rows) {
    const item = items.get(key);
    const name = item?.displayName ?? key;
    const desc = escapeTableCell(item?.description ?? '');
    const docPath = meta.docs[key];
    // The matrix ships in the core/ layer. Linking into enterprise/ or msp/
    // would be a dead link for a Core reader, who does not have that layer —
    // so a paid-layer doc is named, not linked. Readers who DO have the layer
    // reach it from their own site nav.
    const link = noSelfService.has(key)
      ? '*No self-service UI yet*'
      : !docPath
      ? '—'
      : docPath.startsWith('core/')
        ? `[Guide](${docPath.slice('core/'.length)})`
        : `in ${editionLabel(byKey.get(key))} docs`;
    L.push(`| **${name}** | ${editionLabel(byKey.get(key))} | ${desc} | ${link} |`);
  }
  L.push('');

  L.push('### Why each of these is paid');
  L.push('');
  for (const g of groups) {
    if (!g.keys.length) continue;
    L.push(`**${g.title}**`);
    L.push('');
    if (g.rationale.length) {
      L.push(g.rationale.join(' '));
      L.push('');
    }
    L.push(g.keys.map((k) => `\`${k}\``).join(' · '));
    L.push('');
  }

  L.push('---');
  L.push('');
  L.push('## MSP management plane');
  L.push('');
  L.push(
    'The MSP edition is carved by which services ship, not by capability flags, ' +
      'so these areas have no entry in the table above. Tenant *isolation* is ' +
      'Core — MSP sells the plane that manages tenants, not the model that ' +
      'isolates them.',
  );
  L.push('');
  L.push('| Area | What it covers |');
  L.push('|---|---|');
  for (const entry of meta.msp_surface) {
    const summary = escapeTableCell(String(entry.summary ?? '').trim().replace(/\s+/g, ' '));
    L.push(`| **${entry.name}** | ${summary} |`);
  }
  L.push('');

  return L.join('\n');
}

const rendered = render();

// ── Report and exit ────────────────────────────────────────────────────────
if (CHECK) {
  const onDisk = existsSync(OUT) ? readFileSync(OUT, 'utf8') : null;
  if (onDisk === null) {
    problems.push(`${OUT} does not exist — run \`make edition-matrix\``);
  } else if (onDisk !== rendered) {
    problems.push(
      'docsv4/core/editions.md is stale — regenerate with `make edition-matrix`',
    );
  }
}

for (const w of warnings) console.warn(`${YELLOW}⚠ ${w}${RESET}`);

if (undocumented.length) {
  console.warn(
    `${YELLOW}⚠ ${undocumented.length} edition-gated capabilities have no dedicated customer doc: ` +
      `${undocumented.join(', ')}${RESET}`,
  );
}

if (noSelfService.size) {
  console.log(
    `  ${[...noSelfService].join(', ')} — gated with no user-facing surface yet ` +
      `(declared in editions.yaml, shown as such in the matrix).`,
  );
}

if (problems.length) {
  for (const p of problems) console.error(`${RED}✖ ${p}${RESET}`);
  console.error(`${RED}Edition matrix: ${problems.length} problem(s).${RESET}`);
  process.exit(1);
}

if (CHECK) {
  console.log(`${GREEN}✓ Edition matrix in sync (${gatedKeys.size} gated capabilities, ${meta.msp_surface.length} MSP areas).${RESET}`);
} else {
  writeFileSync(OUT, rendered);
  console.log(`${GREEN}✓ Wrote docsv4/core/editions.md (${gatedKeys.size} gated capabilities, ${meta.msp_surface.length} MSP areas).${RESET}`);
}
