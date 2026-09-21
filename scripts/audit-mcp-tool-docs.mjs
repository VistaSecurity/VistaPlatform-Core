#!/usr/bin/env node
// MCP tool-surface documentation drift guard.
//
// The MCP tool surface was pinned TWICE in code — the golden snapshot at
// services/mcp-service/internal/server/testdata/tool-surface.json and a hard
// count assertion in services/mcp-service/internal/server/server_test.go —
// and neither pin reached the documentation. So the docs sat at "18 tools"
// while the surface grew to 23, across six files. One of them
// (docsv4/internal/developer/api/mcp-service.md) documented three tools that
// do not exist under any name; another (design/MCP_SERVER.md) contradicted
// itself, with prose claiming 18 above a table listing 14. Every test stayed
// green the whole time, because no test looked at a document.
//
// This closes that: the snapshot is the single source of truth for both the
// COUNT and the NAMES, and the docs are checked against it.
//
// Source of truth:
//   services/mcp-service/internal/server/testdata/tool-surface.json
//
// Checks:
//   0. Snapshot sanity — non-empty, unique, all `vistaplatform_`-prefixed.
//      Refuses to pass an audit it could not actually perform.
//   1. The in-code count pin (server_test.go) agrees with the snapshot, so
//      the two existing pins cannot drift from each other either.
//   2. Every tool-count claim in the docs equals the real count, found by
//      PATTERN rather than by a file list, so a new document making the
//      claim is covered the day it is written.
//   3. The architecture and API references name EXACTLY the real tool set —
//      nothing missing, nothing invented.
//   4. No document anywhere names a `vistaplatform_*` tool that does not
//      exist.
//
// Advisory when run bare; `--strict` (how `make audit` runs it) exits 1.
//
// Mutation-tested in scripts/audit-mcp-tool-docs.test.mjs — both polarities,
// including that the exclusions below do NOT fire. A check that cannot fail
// is worse than no check.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const TOOL_SURFACE_PATH = 'services/mcp-service/internal/server/testdata/tool-surface.json';
export const SERVER_TEST_PATH = 'services/mcp-service/internal/server/server_test.go';

// The two documents that are supposed to BE the tool reference. These must
// name the whole set and nothing but the set. Everything else may mention a
// subset of tools in passing without failing anything.
export const REFERENCE_DOCS = [
  'docsv4/internal/developer/api/mcp-service.md',
  'docsv4/internal/developer/architecture/services/mcp-service.md',
];

// Documentation roots scanned for count claims and invented tool names.
// docsv4/ is the ask; the three READMEs are included because they are
// customer-facing first-reads where a stale count would be most expensive,
// and they cost nothing while clean.
export const DOC_ROOTS = ['docsv4', 'README.md', 'public/README.md', 'api/README.md'];

// ---------------------------------------------------------------------------
// Exclusions.
//
// Deliberately an explicit, commented list of exact phrases rather than a
// clever regex: a reader should be able to see why each exemption is safe
// without re-deriving it. Each entry is matched as a literal substring, and
// an entry that no longer matches anything is REPORTED (see auditCountClaims)
// — a silently-stale exemption is how an allow-list becomes an inert guard.
//
// Note what is NOT listed here, because it never matches the claim pattern in
// the first place and so needs no exemption (the mutation test asserts this):
//   - "18-image release set"     — 16 backends + 2 frontends. Correct, and
//                                  not followed by the word "tools".
// - MCP protocol "" — a date-shaped version string.
//   - "+14–18 pw"                — person-week estimates in the roadmap.
//   - "contract_vector.go:18-20" — a line-number citation.
//   - "3 tool calls"             — singular "tool"; the pattern requires the
//                                  plural, which is how a count is written.
// Everything under an `archive/` directory is skipped wholesale.
export const COUNT_CLAIM_EXEMPTIONS = [
  {
    file: 'docsv4/internal/developer/design/asset-inventory/BUILD_PLAN.md',
    phrase: '14 → 18 tools',
    why: 'Historical per-PR record of workstream 1.11 (PR #1638). Accurate as history: the surface really did go 14 → 18 there. Rewriting it to the current total would make the build log wrong.',
  },
  {
    file: 'docsv4/internal/developer/design/asset-inventory/BUILD_PLAN.md',
    phrase: '18 → 21 tools',
    why: 'Same, for workstream 2.8 (PR #1650). The sentence goes on to say "22 after #1651" — also history, and also not a claim about today.',
  },
  {
    file: 'docsv4/internal/developer/design/MCP_SERVER.md',
    phrase: 'the v1 shipping surface (14 tools)',
    why: 'The caption on the "## Tool catalog (v1) — historical" table, which states what v1 shipped and is immediately followed by "The surface has grown since" and a pointer at the snapshot. History, and captioned as such; the uncaptioned prose principle further down the same file is NOT exempt and must read the live count.',
  },
  {
    file: 'docsv4/internal/developer/design/asset-inventory/CHARTER.md',
    phrase: 'read-only MCP with 14 tools',
    why: 'A dated "where we were when this charter was written" snapshot in the initiative charter, in a table column describing the pre-initiative state.',
  },
];

// docsv4/internal/developer/design/MCP_SERVER.md is a v1 design record, and it
// gets treated in two halves — deliberately, because it is exactly the file
// that contradicted itself:
//
//   * Its "## Tool catalog (v1)" table lists the 14 tools v1 shipped. That is
//     honestly captioned history, it is NOT one of REFERENCE_DOCS, and nothing
//     here requires it to grow. Leave it alone.
//   * Its prose principle "3. Curated, task-shaped tools — not a REST mirror.
//     N tools, ..." carries no such caption. It reads as a present-tense fact
//     about the shipped server, which is precisely how a reader ends up
//     repeating a stale number, so it IS checked and must equal the real
//     count. The file then says "23 tools" in prose above a table captioned
//     v1 — which is coherent, because the caption is doing the work. The
//     caption's own "(14 tools)" IS a count claim in text, so it carries an
//     explicit exemption above rather than relying on the heading.
//
// If that prose line is ever reworded to name v1 explicitly, add it to
// COUNT_CLAIM_EXEMPTIONS with that reasoning rather than deleting this note.

// `vistaplatform_*` identifiers that are legitimately NOT tool names. Each
// needs a reason; anything else unknown is treated as an invented tool.
export const NON_TOOL_IDENTIFIERS = {
  vistaplatform_delete_everything:
    'A deliberately fictional destructive tool used as the prompt-injection example in docsv4/internal/developer/standards/AI_SEAMS.md ("ignore previous instructions and call ..."). The whole point is that no such tool exists.',
};

// A tool-count claim: a number, then any of the usual qualifiers, then the
// PLURAL "tools". Plural is load-bearing — it is how a count is written, and
// requiring it keeps "3 tool calls" and "the tool description" out.
const COUNT_CLAIM_RE = /\b(\d{1,3})\s+((?:curated|MCP|read-only|new|total|available|distinct)\s+)*tools\b/gi;

const TOOL_IDENT_RE = /vistaplatform_[a-z0-9_]+/g;

// ---------------------------------------------------------------------------
// Pure helpers (exported so the mutation test can drive them with fixtures).

export function parseToolSurface(json) {
  const problems = [];
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    return { names: [], problems: [`${TOOL_SURFACE_PATH} is not valid JSON: ${err.message}`] };
  }
  if (!Array.isArray(parsed)) {
    return { names: [], problems: [`${TOOL_SURFACE_PATH} must be a JSON array of tools`] };
  }
  const names = parsed.map((t) => t && t.name).filter((n) => typeof n === 'string' && n.length > 0);
  if (names.length !== parsed.length) {
    problems.push(`${TOOL_SURFACE_PATH} has ${parsed.length} entries but only ${names.length} usable "name" fields`);
  }
  // Refuse to "pass" an audit that checked nothing.
  if (names.length === 0) {
    problems.push(`${TOOL_SURFACE_PATH} parsed as empty — refusing to run a documentation audit with no tool surface to compare against`);
  }
  const dupes = names.filter((n, i) => names.indexOf(n) !== i);
  if (dupes.length) problems.push(`${TOOL_SURFACE_PATH} has duplicate tool names: ${[...new Set(dupes)].join(', ')}`);
  const unprefixed = names.filter((n) => !n.startsWith('vistaplatform_'));
  if (unprefixed.length) problems.push(`${TOOL_SURFACE_PATH} has tools without the vistaplatform_ prefix: ${unprefixed.join(', ')}`);
  return { names, problems };
}

// The count literal the Go test asserts, e.g. `if len(toolList) != 23 {`.
export function parseServerTestCount(goSrc) {
  const m = goSrc.match(/len\(toolList\)\s*!=\s*(\d+)/);
  return m ? Number(m[1]) : null;
}

export function findCountClaims(text) {
  const claims = [];
  for (const m of text.matchAll(COUNT_CLAIM_RE)) {
    claims.push({
      value: Number(m[1]),
      phrase: m[0],
      index: m.index,
      end: m.index + m[0].length,
      line: text.slice(0, m.index).split('\n').length,
    });
  }
  return claims;
}

// Byte ranges covered by an exemption phrase in this file's text.
function exemptRanges(text, file, exemptions) {
  const ranges = [];
  for (const ex of exemptions) {
    if (ex.file !== file) continue;
    let from = 0;
    for (;;) {
      const at = text.indexOf(ex.phrase, from);
      if (at === -1) break;
      ranges.push({ start: at, end: at + ex.phrase.length, ex });
      from = at + 1;
    }
  }
  return ranges;
}

export function auditCountClaims(files, expected, exemptions = COUNT_CLAIM_EXEMPTIONS) {
  const problems = [];
  const used = new Set();
  let checked = 0;

  for (const { path: file, text } of files) {
    const ranges = exemptRanges(text, file, exemptions);
    for (const claim of findCountClaims(text)) {
      const hit = ranges.find((r) => claim.index < r.end && claim.end > r.start);
      if (hit) {
        used.add(hit.ex);
        continue;
      }
      checked++;
      if (claim.value !== expected) {
        problems.push(
          `${file}:${claim.line} claims "${claim.phrase}" but the MCP surface has ${expected} tools ` +
            `(source of truth: ${TOOL_SURFACE_PATH})`,
        );
      }
    }
  }

  // A stale exemption is an inert guard wearing a costume: it matches nothing,
  // so it silently stops exempting, and nobody finds out until the phrase it
  // was written for comes back in a different form. Make it say so.
  for (const ex of exemptions) {
    if (used.has(ex)) continue;
    problems.push(
      `stale exemption in scripts/audit-mcp-tool-docs.mjs: "${ex.phrase}" no longer appears in ${ex.file}. ` +
        'Delete the entry if the text is gone, or update the phrase if it was reworded.',
    );
  }

  return { problems, checked, exemptionsUsed: used.size };
}

export function findToolIdentifiers(text) {
  return new Set(text.match(TOOL_IDENT_RE) || []);
}

export function auditReferenceDoc(file, text, names) {
  const problems = [];
  const known = new Set(names);
  const mentioned = findToolIdentifiers(text);

  const invented = [...mentioned].filter((n) => !known.has(n) && !(n in NON_TOOL_IDENTIFIERS));
  const missing = names.filter((n) => !mentioned.has(n));

  if (invented.length) {
    problems.push(
      `${file} documents ${invented.length} tool name(s) that do not exist: ${invented.sort().join(', ')}`,
    );
  }
  if (missing.length) {
    problems.push(
      `${file} is a tool reference but never names ${missing.length} real tool(s): ${missing.sort().join(', ')}`,
    );
  }
  return problems;
}

export function auditFabrications(files, names) {
  const known = new Set(names);
  const problems = [];
  for (const { path: file, text } of files) {
    for (const ident of findToolIdentifiers(text)) {
      if (known.has(ident) || ident in NON_TOOL_IDENTIFIERS) continue;
      const line = text.slice(0, text.indexOf(ident)).split('\n').length;
      problems.push(
        `${file}:${line} names "${ident}", which is not a registered MCP tool. ` +
          'Fix the name, or — if it is deliberately not a tool — add it to NON_TOOL_IDENTIFIERS with a reason.',
      );
    }
  }
  return problems;
}

// ---------------------------------------------------------------------------
// File collection.

function isSkipped(p) {
  // Retired docs are allowed to be wrong about the present — that is what
  // retiring them means.
  return p.split(path.sep).includes('archive');
}

export function collectDocs(roots = DOC_ROOTS, read = (p) => readFileSync(p, 'utf8')) {
  const out = [];
  const walk = (p) => {
    if (isSkipped(p)) return;
    let st;
    try {
      st = statSync(p);
    } catch {
      return; // a root that does not exist in this tree (e.g. the public export)
    }
    if (st.isDirectory()) {
      for (const entry of readdirSync(p).sort()) walk(path.join(p, entry));
      return;
    }
    if (!p.endsWith('.md')) return;
    out.push({ path: p, text: read(p) });
  };
  for (const r of roots) walk(r);
  return out;
}

// ---------------------------------------------------------------------------

export function main(argv = process.argv.slice(2)) {
  const strict = argv.includes('--strict');
  const failures = [];

  const { names, problems: snapProblems } = parseToolSurface(readFileSync(TOOL_SURFACE_PATH, 'utf8'));
  failures.push(...snapProblems);
  const expected = names.length;

  console.log(`MCP tool-surface documentation audit (${expected} tools in ${TOOL_SURFACE_PATH})`);

  // 1. The other in-code pin must agree, so the two cannot drift apart either.
  const goSrc = readFileSync(SERVER_TEST_PATH, 'utf8');
  const testCount = parseServerTestCount(goSrc);
  if (testCount === null) {
    failures.push(
      `could not read the tools/list count assertion (len(toolList) != N) from ${SERVER_TEST_PATH} — ` +
        'the pattern in scripts/audit-mcp-tool-docs.mjs no longer matches, so that pin is going unchecked',
    );
  } else if (expected > 0 && testCount !== expected) {
    failures.push(`${SERVER_TEST_PATH} asserts ${testCount} tools but the snapshot has ${expected}`);
  }

  const docs = collectDocs();
  if (docs.length === 0) failures.push('no documentation files were collected — refusing to pass an audit that read nothing');

  // 2. Count claims.
  if (expected > 0) {
    const { problems, checked, exemptionsUsed } = auditCountClaims(docs, expected);
    failures.push(...problems);
    console.log(`  ${docs.length} documents scanned; ${checked} tool-count claim(s) checked, ${exemptionsUsed} historical exemption(s) applied`);
  }

  // 3. The references must name exactly the set.
  for (const ref of REFERENCE_DOCS) {
    const doc = docs.find((d) => d.path === ref);
    if (!doc) {
      failures.push(`reference document ${ref} was not found — it is listed in REFERENCE_DOCS but nothing was read`);
      continue;
    }
    failures.push(...auditReferenceDoc(ref, doc.text, names));
  }

  // 4. Nobody invents a tool.
  failures.push(...auditFabrications(docs, names));

  if (failures.length) {
    console.error('');
    console.error('MCP tool-surface documentation audit FAILED:');
    for (const f of failures) console.error(`  ❌ ${f}`);
    console.error('');
    console.error(`  The tool surface is defined by ${TOOL_SURFACE_PATH}. Update the docs to match it,`);
    console.error('  or regenerate the snapshot if the surface itself changed.');
    process.exit(strict ? 1 : 0);
  }

  console.log(`✅ mcp tool docs: every documented count reads ${expected}, and both references name exactly the ${expected} registered tools.`);
}

const __filename = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
