#!/usr/bin/env node
// Remove paid-edition sections from Core-layer documentation.
//
// Most documents split cleanly by layer: a page about a wholly-Enterprise
// capability lives in enterprise/. But some Core pages have one paid section
// inside them — cmdb-integrations documents both the inbound import (Core) and
// the outbound sync (Enterprise), and splitting it into two pages would leave
// both halves worse. Those pages stay in core/ and fence the paid part:
//
//     <!-- edition:enterprise -->
//     ## Syncing out to ServiceNow
//     ...
//     <!-- /edition -->
//
// This strips fenced blocks whose edition is NOT included in the target
// edition, using the same core ⊂ enterprise ⊂ msp layering the site build uses.
// Running it for `msp` is a no-op; running it for `core` removes everything
// fenced.
//
// The markers are HTML comments, so they are invisible in rendered markdown and
// on GitHub. An unstripped page therefore reads correctly for a reader who has
// the capability — the fence only matters when producing a narrower edition.
//
// Usage:
//   node scripts/strip-edition-sections.mjs --edition core <dir>   # rewrite in place
//   node scripts/strip-edition-sections.mjs --check <dir>          # validate fences only
//
// --check verifies every fence is opened, closed, and names a known edition.
// It is wired into `make audit`, because an unterminated fence would silently
// swallow the rest of a page when the Core tree is exported.

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const EDITIONS = ['core', 'enterprise', 'msp'];
/** Which layers a given edition includes. core ⊂ enterprise ⊂ msp. */
const INCLUDES = {
  core: new Set(['core']),
  enterprise: new Set(['core', 'enterprise']),
  msp: new Set(['core', 'enterprise', 'msp']),
};

const OPEN_RE = /^\s*<!--\s*edition:([a-z]+)\s*-->\s*$/;
const CLOSE_RE = /^\s*<!--\s*\/edition\s*-->\s*$/;

const args = process.argv.slice(2);
const CHECK = args.includes('--check');
const edIdx = args.indexOf('--edition');
const edition = edIdx === -1 ? null : args[edIdx + 1];
const targets = args.filter((a, i) => !a.startsWith('--') && i !== edIdx + 1);

if (!CHECK && !EDITIONS.includes(edition)) {
  console.error(`✖ --edition must be one of ${EDITIONS.join(', ')}`);
  process.exit(1);
}
if (targets.length === 0) {
  console.error('✖ give at least one directory to process');
  process.exit(1);
}

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (e.endsWith('.md')) out.push(p);
  }
  return out;
}

const problems = [];
let strippedBlocks = 0;
let changedFiles = 0;
let fencedFiles = 0;

for (const target of targets) {
  for (const file of walk(target)) {
    const src = readFileSync(file, 'utf8');
    if (!src.includes('<!-- edition:') && !src.includes('<!--edition:')) continue;
    fencedFiles += 1;

    const out = [];
    let openAt = null; // { line, edition }
    let dropping = false;
    let lineNo = 0;

    for (const line of src.split('\n')) {
      lineNo += 1;
      const open = line.match(OPEN_RE);
      if (open) {
        if (openAt) {
          problems.push(`${file}:${lineNo}: nested edition fence (opened at line ${openAt.line})`);
        }
        const ed = open[1];
        if (!EDITIONS.includes(ed)) {
          problems.push(`${file}:${lineNo}: unknown edition "${ed}"`);
        }
        openAt = { line: lineNo, edition: ed };
        // Keep the fence itself only when we keep the block, so a stripped
        // page carries no trace of what was removed.
        dropping = !CHECK && !INCLUDES[edition].has(ed);
        if (!dropping) out.push(line);
        continue;
      }
      if (CLOSE_RE.test(line)) {
        if (!openAt) {
          problems.push(`${file}:${lineNo}: closing fence with nothing open`);
        }
        if (!dropping) out.push(line);
        else strippedBlocks += 1;
        openAt = null;
        dropping = false;
        continue;
      }
      if (!dropping) out.push(line);
    }

    if (openAt) {
      problems.push(
        `${file}: edition fence opened at line ${openAt.line} is never closed — ` +
          `it would swallow the rest of the page`,
      );
    }

    if (!CHECK) {
      const next = out.join('\n');
      if (next !== src) {
        writeFileSync(file, next);
        changedFiles += 1;
      }
    }
  }
}

if (problems.length) {
  for (const p of problems) console.error(`✖ ${p}`);
  process.exit(1);
}

if (CHECK) {
  console.log(`✓ edition fences valid (${fencedFiles} fenced file(s))`);
} else {
  console.log(
    `✓ stripped for ${edition}: ${strippedBlocks} block(s) removed from ${changedFiles} file(s) ` +
      `(${fencedFiles} fenced file(s) scanned)`,
  );
}
