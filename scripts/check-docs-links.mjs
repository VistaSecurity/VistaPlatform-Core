#!/usr/bin/env node
// Verify relative links between docsv4 documents resolve to real files.
//
// Written for the edition-layer restructure, which re-rooted 95 files and
// rewrote roughly 1,100 links. A link checker is the only honest way to claim
// that survived, and it keeps earning its place afterwards: docs get moved.
//
// Two additional rules specific to the layer model, because a link can resolve
// on disk and still be wrong in a published site:
//
//   1. core/ must not link INTO enterprise/ or msp/. The layers overlay at
//      publish time, so a Core reader has only core/ — a link into a paid layer
//      is a guaranteed 404 for exactly the readers most likely to click it.
//      (The reverse is fine: enterprise/ may link down into core/.)
//   2. Nothing published may link into internal/, which never ships.
//
// Anchors are not verified — only that the target file exists.
//
// Strict mode fails on:
//   - ANY cross-layer violation (zero tolerance — these are all new, and all
//     mine to keep at zero)
//   - broken links ABOVE the baseline below (a ratchet, not a clean bill of
//     health)
//
// One check fails in EVERY mode, strict or not: a legacy pre-2026-06 path
// (developer-docs/ etc.) whose source file is in the core layer. core/ is the
// only layer the public export ships, it was swept to zero on, and
// those targets now live in internal/ which core/ may not link to — so there
// is no valid repoint and no backlog to tolerate. Other layers' legacy links
// remain warn-only backlog. Fenced blocks are judged by their fence layer,
// same as the ALLOWED checks.
//
// The baseline exists because docsv4 carried 179 broken links before this work
// and fixing them is a separate job. A ratchet stops it getting worse without
// pretending it is clean; lower the number as they get fixed. Setting it to 0
// would be the honest end state.
//
// Lowered 155 -> 153 by the WP-G docs pass: deleting the two
// leaking pre-Helm deployment docs (ec2-deployment.md, rke2-deployment.md)
// removed more referencing links than the rewritten docsv4/core/operate/
// README.md and releases.md reintroduced.
//
// Lowered 153 -> 0 by the W2-4 docs pass: every core/ (32) and
// internal/ (92) broken link was fixed — moved-target repoints where the
// 2026-06/2026-08 restructures left a link pointing at the old path, and
// removed/annotated where the target was a doc that no longer exists at all
// (retired report-generator/reports-page docs, never-written per-service
// architecture pages, dropped feature seeds, etc.). The 29 that remained were
// all inside docsv4/archive/ and are handled separately: see the archiveBroken
// comment below rather than the BROKEN_BASELINE ratchet. This baseline is
// therefore 0 and any future breakage outside docsv4/archive/ is a real
// regression, not backlog.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const DOCS = join(repoRoot, 'docsv4');
const STRICT = process.argv.includes('--strict');

// Pre-existing broken links, measured against HEAD before the edition-layer
// migration (179) and reduced by it. Lower this as they get fixed; never raise
// it to make a build pass. Zero as of the W2-4 docs pass — see the
// comment above. docsv4/archive/ is exempted separately (archiveBroken, below)
// and does not count against this baseline.
const BROKEN_BASELINE = 0;

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

/** Layers a doc in `from` is allowed to link into. */
const ALLOWED = {
  core: new Set(['core']),
  enterprise: new Set(['core', 'enterprise']),
  msp: new Set(['core', 'enterprise', 'msp']),
  internal: new Set(['core', 'enterprise', 'msp', 'internal', 'archive', 'generated']),
  archive: new Set(['core', 'enterprise', 'msp', 'internal', 'archive', 'generated']),
  generated: new Set(['core', 'enterprise', 'msp', 'internal', 'archive', 'generated']),
};

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (e.endsWith('.md')) out.push(p);
  }
  return out;
}

const LINK_RE = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const FENCE_OPEN = /^\s*<!--\s*edition:([a-z]+)\s*-->\s*$/;
const FENCE_CLOSE = /^\s*<!--\s*\/edition\s*-->\s*$/;

const LEGACY_PREFIX = /(^|\/)(developer-docs|platform-admin-docs|customer-docs|tenant-docs)\//;

const broken = [];
const archiveBroken = [];
const legacy = [];
const coreLegacy = [];
const layerViolations = [];
let checked = 0;

for (const file of walk(DOCS)) {
  const rel = relative(repoRoot, file).split('\\').join('/');
  const fileLayer = rel.split('/')[1];
  const src = readFileSync(file, 'utf8');

  // A link inside an <!-- edition:X --> fence only ever reaches readers who
  // have layer X, so it is judged against X's allowances, not the file's. That
  // is the whole point of fencing: a Core page may reference a paid document
  // from inside a fenced block, because the block is stripped for Core.
  let fenceLayer = null;
  for (const line of src.split('\n')) {
    const open = line.match(FENCE_OPEN);
    if (open) {
      fenceLayer = open[1];
      continue;
    }
    if (FENCE_CLOSE.test(line)) {
      fenceLayer = null;
      continue;
    }
    const fromLayer = fenceLayer ?? fileLayer;

  for (const m of line.matchAll(LINK_RE)) {
    const target = m[1];
    if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) continue; // external / anchor-only
    if (target.startsWith('#')) continue;
    const [pathPart] = target.split('#');
    if (!pathPart) continue;
    // Root-absolute links are repo-relative in this tree.
    const resolved = pathPart.startsWith('/')
      ? posix.normalize(pathPart.slice(1))
      : posix.normalize(posix.join(dirname(rel), pathPart));

    checked += 1;

    if (!existsSync(join(repoRoot, resolved))) {
      // docsv4 was reorganised by audience in 2026-06 (developer-docs/,
      // platform-admin-docs/, tenant-docs/, customer-docs/ → customer/,
      // partner/, internal/) and a few hundred links were never repointed.
      // That backlog predates the edition layering and is tracked separately —
      // failing the build on it would mean the guard could never go strict, so
      // it is counted and reported rather than swallowed or enforced — EXCEPT
      // in core/, which is the one layer the public export ships: a legacy
      // path there is a guaranteed dead link for a customer, and core/ was
      // swept clean, so any new one is a regression, not backlog.
      // Fence-aware like the ALLOWED checks: a link inside an
      // <!-- edition:enterprise --> block in a core file is stripped from the
      // public export, so it stays in the warn-only backlog.
      if (LEGACY_PREFIX.test(pathPart)) {
        if (fromLayer === 'core') coreLegacy.push(`${rel} → ${pathPart}`);
        else legacy.push(`${rel} → ${pathPart}`);
      }
      // docsv4/archive/ is retired documentation kept for historical record.
      // Its cross-links point at other since-deleted docs by construction —
      // that's what "archived" means — so fixing them would mean either
      // rewriting archived content (defeats the point of an archive) or
      // deleting the links (destroys the historical record of what those
      // docs used to reference). Tracked and reported, never enforced.
      else if (fileLayer === 'archive') archiveBroken.push(`${rel} → ${pathPart}`);
      else broken.push(`${rel} → ${pathPart}`);
      continue;
    }

    if (resolved.startsWith('docsv4/')) {
      const toLayer = resolved.split('/')[1];
      const allowed = ALLOWED[fromLayer];
      if (allowed && !allowed.has(toLayer)) {
        layerViolations.push(
          `${rel} → ${pathPart}  (${fromLayer} may not link into ${toLayer}` +
            `${fenceLayer ? ', inside an edition fence' : ''})`,
        );
      }
    }
  }
  }
}

console.log(`Docs links: ${checked} relative link(s) checked across docsv4/.`);

const byLayer = {};
for (const b of broken) {
  const m = b.match(/^docsv4\/([^/]+)/);
  const k = m ? m[1] : '(root)';
  byLayer[k] = (byLayer[k] ?? 0) + 1;
}

if (broken.length) {
  console.error(`${RED}\u2716 ${broken.length} broken link(s):${RESET}`);
  for (const b of broken.slice(0, 40)) console.error(`   ${b}`);
  if (broken.length > 40) console.error(`   \u2026 and ${broken.length - 40} more`);
  console.error(`   by layer: ${JSON.stringify(byLayer)}`);
}

if (layerViolations.length) {
  console.error(`${RED}\u2716 ${layerViolations.length} cross-layer link violation(s):${RESET}`);
  for (const v of layerViolations.slice(0, 40)) console.error(`   ${v}`);
  if (layerViolations.length > 40) console.error(`   \u2026 and ${layerViolations.length - 40} more`);
}

if (coreLegacy.length) {
  console.error(
    `${RED}\u2716 ${coreLegacy.length} legacy pre-2026-06 path(s) in the exported core layer ` +
      `(developer-docs/, platform-admin-docs/, customer-docs/, tenant-docs/ no longer exist ` +
      `and core/ may not link into internal/ \u2014 delete the link or repoint it at a core/ doc):${RESET}`,
  );
  for (const v of coreLegacy.slice(0, 40)) console.error(`   ${v}`);
  if (coreLegacy.length > 40) console.error(`   \u2026 and ${coreLegacy.length - 40} more`);
}

if (legacy.length) {
  console.warn(
    `${YELLOW}\u26a0 ${legacy.length} link(s) still point at the pre-2026-06 layout ` +
      `(developer-docs/, platform-admin-docs/, customer-docs/, tenant-docs/). ` +
      `Pre-existing backlog, not enforced.${RESET}`,
  );
}

if (archiveBroken.length) {
  console.warn(
    `${YELLOW}\u26a0 ${archiveBroken.length} broken link(s) inside docsv4/archive/ ` +
      `(links between retired docs; not enforced \u2014 see the comment above ` +
      `archiveBroken in this script).${RESET}`,
  );
}

if (broken.length === 0 && layerViolations.length === 0 && coreLegacy.length === 0) {
  console.log(`${GREEN}\u2713 docs links ok${RESET}`);
  process.exit(0);
}

// Core-layer legacy paths fail even outside --strict: they ship broken to
// every customer of the public export, and the layer is at zero.
if (coreLegacy.length > 0) process.exit(1);

const regressed = broken.length > BROKEN_BASELINE;
if (regressed) {
  console.error(
    `${RED}\u2716 broken links regressed: ${broken.length} > baseline ${BROKEN_BASELINE}.${RESET}`,
  );
} else if (broken.length) {
  console.warn(
    `${YELLOW}\u26a0 ${broken.length} broken link(s), at or below the ${BROKEN_BASELINE} baseline ` +
      `(pre-existing backlog).${RESET}`,
  );
  if (broken.length < BROKEN_BASELINE) {
    console.warn(`${YELLOW}  \u2192 lower BROKEN_BASELINE to ${broken.length} in this script.${RESET}`);
  }
}

if (STRICT && (layerViolations.length > 0 || regressed)) process.exit(1);
if (layerViolations.length === 0 && !regressed) {
  console.log(`${GREEN}\u2713 no cross-layer violations; broken links within baseline${RESET}`);
}
