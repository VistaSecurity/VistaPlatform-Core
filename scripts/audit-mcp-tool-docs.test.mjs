#!/usr/bin/env node
// Mutation tests for scripts/audit-mcp-tool-docs.mjs.
//
// This repo has shipped guards that could not fail — three at once in one
// file. So every rule below is driven with a fixture that MUST fail it and a
// fixture that MUST pass it, and the exclusions are tested against the REAL
// document text rather than a fixture, because the way an exclusion breaks is
// by being written against text that does not look like the text in the tree.

import { readFileSync } from 'node:fs';
import {
  COUNT_CLAIM_EXEMPTIONS,
  NON_TOOL_IDENTIFIERS,
  REFERENCE_DOCS,
  TOOL_SURFACE_PATH,
  SERVER_TEST_PATH,
  auditCountClaims,
  auditFabrications,
  auditReferenceDoc,
  collectDocs,
  findCountClaims,
  parseServerTestCount,
  parseToolSurface,
} from './audit-mcp-tool-docs.mjs';

let failures = 0;
function check(desc, ok, detail = '') {
  if (ok) console.log(`  ✓ ${desc}`);
  else {
    failures++;
    console.error(`  ✗ ${desc}${detail ? `\n      ${detail}` : ''}`);
  }
}

const TOOLS = ['vistaplatform_ask', 'vistaplatform_get_asset', 'vistaplatform_search'];
const N = TOOLS.length;
const doc = (path, text) => [{ path, text }];

// ---------------------------------------------------------------------------
console.log('count claims — detection, both polarities');

check(
  'a correct count passes',
  auditCountClaims(doc('d.md', `The server exposes ${N} tools.`), N, []).problems.length === 0,
);
check(
  'a wrong count fails',
  auditCountClaims(doc('d.md', `The server exposes ${N + 5} tools.`), N, []).problems.length === 1,
);
check(
  'the failure names the file, line and both numbers',
  (() => {
    const [p] = auditCountClaims(doc('d.md', `line one\nexposes ${N + 5} tools.`), N, []).problems;
    return p.includes('d.md:2') && p.includes(String(N + 5)) && p.includes(String(N));
  })(),
);

for (const phrase of ['18 tools', '18 MCP tools', '18 curated tools', '18 curated read-only tools', '18 read-only tools']) {
  check(`"${phrase}" is recognised as a claim`, findCountClaims(`we ship ${phrase} today`).length === 1);
}

// A claim the audit never sees is a claim it can never check.
check(
  'every real count-claim phrasing in the tree is still recognised',
  (() => {
    const wordings = ['18 tools', '18 MCP tools', '18 read-only tools', '18 curated tools', '18 curated read-only tools'];
    return wordings.every((w) => findCountClaims(w).length === 1);
  })(),
);

// ---------------------------------------------------------------------------
console.log('count claims — the things that must NOT fire (over-strictness)');

const NON_CLAIMS = [
  ['18-image release set', 'the release set is 16 backends + 2 frontends, not tools'],
  ['Ships in the 18-image release set (`_ALL_SVCS` + the', 'real sentence from architecture/services/mcp-service.md'],
  ['Streamable HTTP, stateless JSON (MCP `2025-06-18`)', 'MCP protocol version, a date'],
  ['+14–18 pw', 'person-week estimate in the roadmap'],
  ['contract_vector.go:18-20', 'a line-number citation'],
  ['2 translation turns, 3 tool calls, 3 narration', 'singular "tool"; not a count of the surface'],
  ['the tool description teaches the language instead', 'prose about a description'],
  ['15 of the 18-image release set', 'real sentence from product-descriptors/INDEX.md'],
];
for (const [text, why] of NON_CLAIMS) {
  check(`no claim found in "${text.slice(0, 44)}" (${why})`, findCountClaims(text).length === 0);
}

// ---------------------------------------------------------------------------
console.log('count claims — historical exemptions');

for (const ex of COUNT_CLAIM_EXEMPTIONS) {
  const { problems } = auditCountClaims(doc(ex.file, `prefix ${ex.phrase} suffix`), N, [ex]);
  check(`exempt phrase "${ex.phrase}" does not fail in ${ex.file.split('/').pop()}`, problems.length === 0, problems.join('; '));
}

check(
  'an exemption is scoped to ITS file — the same phrase elsewhere still fails',
  (() => {
    const ex = COUNT_CLAIM_EXEMPTIONS[0];
    const { problems } = auditCountClaims(doc('some/other/doc.md', `prefix ${ex.phrase} suffix`), N, [ex]);
    // One problem for the unexempted claim, one for the now-unused exemption.
    return problems.some((p) => p.includes('some/other/doc.md'));
  })(),
);

check(
  'a stale exemption (phrase gone) is reported, not silently ignored',
  (() => {
    const ex = COUNT_CLAIM_EXEMPTIONS[0];
    const { problems } = auditCountClaims(doc(ex.file, `no such phrase here, and ${N} tools`), N, [ex]);
    return problems.some((p) => p.includes('stale exemption'));
  })(),
);

// The exemptions are written against text in the tree. If that text is
// reworded, they stop exempting — this catches it here rather than in CI.
check(
  'every exemption still matches its file in the working tree',
  (() => {
    const stale = COUNT_CLAIM_EXEMPTIONS.filter((ex) => !readFileSync(ex.file, 'utf8').includes(ex.phrase));
    return stale.length === 0;
  })(),
  'stale: ' + COUNT_CLAIM_EXEMPTIONS.filter((ex) => !readFileSync(ex.file, 'utf8').includes(ex.phrase)).map((e) => e.phrase).join(', '),
);

// ---------------------------------------------------------------------------
console.log('reference documents — exact tool set, both polarities');

const refOK = TOOLS.map((t) => `\`${t}\` does a thing.`).join('\n');
check('a reference naming exactly the set passes', auditReferenceDoc('ref.md', refOK, TOOLS).length === 0);
check(
  'a reference that invents a tool fails, and names it',
  (() => {
    const p = auditReferenceDoc('ref.md', refOK + '\nAlso `vistaplatform_does_not_exist`.', TOOLS);
    return p.length === 1 && p[0].includes('vistaplatform_does_not_exist') && p[0].includes('do not exist');
  })(),
);
check(
  'a reference missing a real tool fails, and names it',
  (() => {
    const p = auditReferenceDoc('ref.md', refOK.replace(/`vistaplatform_search`[^\n]*\n?/, ''), TOOLS);
    return p.length === 1 && p[0].includes('vistaplatform_search') && p[0].includes('never names');
  })(),
);
check(
  'both faults at once are reported separately',
  auditReferenceDoc('ref.md', '`vistaplatform_ask` and `vistaplatform_bogus`', TOOLS).length === 2,
);

// ---------------------------------------------------------------------------
console.log('fabrication sweep — any document, both polarities');

check('a real tool name passes', auditFabrications(doc('d.md', '`vistaplatform_ask`'), TOOLS).length === 0);
check(
  'an invented tool name fails anywhere, not just in a reference',
  auditFabrications(doc('some/passing/mention.md', '`vistaplatform_does_not_exist`'), TOOLS).length === 1,
);
check(
  'an allow-listed non-tool identifier passes',
  auditFabrications(doc('d.md', `call ${Object.keys(NON_TOOL_IDENTIFIERS)[0]}`), TOOLS).length === 0,
);
check('every NON_TOOL_IDENTIFIERS entry carries a reason', Object.values(NON_TOOL_IDENTIFIERS).every((v) => typeof v === 'string' && v.length > 20));

// ---------------------------------------------------------------------------
console.log('sources of truth — refuse to audit nothing');

check('a good snapshot parses', parseToolSurface('[{"name":"vistaplatform_a"}]').names.length === 1);
check(
  'an EMPTY snapshot is refused rather than passing vacuously',
  parseToolSurface('[]').problems.some((p) => p.includes('refusing')),
);
check('a duplicate tool name is reported', parseToolSurface('[{"name":"vistaplatform_a"},{"name":"vistaplatform_a"}]').problems.some((p) => p.includes('duplicate')));
check('an unprefixed tool name is reported', parseToolSurface('[{"name":"rogue"}]').problems.some((p) => p.includes('prefix')));
check('invalid JSON is reported', parseToolSurface('{oops').problems.length === 1);

check('the Go count pin is readable', parseServerTestCount('\tif len(toolList) != 23 {') === 23);
check(
  'an unreadable Go count pin returns null so main() can fail loudly',
  parseServerTestCount('if len(somethingElse) != 23 {') === null,
);

// ---------------------------------------------------------------------------
console.log('wiring — the audit reads the real tree');

const realTools = parseToolSurface(readFileSync(TOOL_SURFACE_PATH, 'utf8')).names;
check(`the real snapshot is non-empty (${realTools.length} tools)`, realTools.length > 0);
check(
  'the Go test pin agrees with the snapshot',
  parseServerTestCount(readFileSync(SERVER_TEST_PATH, 'utf8')) === realTools.length,
);
const realDocs = collectDocs();
check(`collectDocs() reads the tree (${realDocs.length} documents)`, realDocs.length > 50);
check('collectDocs() skips archive/', realDocs.every((d) => !d.path.split('/').includes('archive')));
for (const ref of REFERENCE_DOCS) {
  check(`reference ${ref} is collected`, realDocs.some((d) => d.path === ref));
}

// The exclusions, checked against the ACTUAL text in the tree — the only way
// to know they do not fire on the real thing.
check(
  'no "18-image release set" line in the tree is read as a tool count',
  realDocs
    .filter((d) => d.text.includes('18-image'))
    .every((d) =>
      d.text
        .split('\n')
        .filter((l) => l.includes('18-image'))
        .every((l) => findCountClaims(l).length === 0),
    ),
);
check(
  'the MCP protocol version 2025-06-18 is not read as a tool count',
  realDocs
    .filter((d) => d.text.includes('2025-06-18'))
    .every((d) =>
      d.text
        .split('\n')
        .filter((l) => l.includes('2025-06-18'))
        .every((l) => findCountClaims(l).length === 0),
    ),
);

console.log('');
if (failures) {
  console.error(`audit-mcp-tool-docs mutation tests FAILED (${failures})`);
  process.exit(1);
}
console.log('✅ audit-mcp-tool-docs: all mutation tests passed (both polarities).');
