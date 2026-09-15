#!/usr/bin/env node
/**
 * CHANGELOG.md duplication guard.
 *
 * Three times in one day a branch that merged `origin/main` *after* a
 * release-prep consolidation (`## [Unreleased]` bullets moved into a new
 * `## [X.Y.Z]` section) re-added bullets git had already relocated — because
 * the merge replayed a stale `[Unreleased]` diff on top of a tree where those
 * bullets already lived one section down. The shipped release section (which
 * `release-core.yml` lifts verbatim as the GitHub Release body) ended up with
 * the same bullet twice, and with duplicate `### Added` / `### Fixed`
 * headings. Nobody automated catching this; reviewers caught it by hand, each
 * time.
 *
 * Checks (`auditChangelog(text)`, each problem names the offending line):
 *
 *   1. No bullet's first line (`- **…**` or `- …`, whitespace-normalised)
 *      appears twice ANYWHERE in the file. Global — a bullet is a discrete,
 *      shipped statement; running into its exact opening line a second time
 *      is always a sign the same change was recorded twice.
 *
 *   2. Within the ACTIVE window — the `## [Unreleased]` section and the
 *      section immediately after it (the most-recently-cut release) — no
 *      `### Heading` appears twice in the same section. Scoped rather than
 *      whole-file on purpose: this file carries pre-`Keep a Changelog`
 *      history (`## [0.2.0]` predates the one-section-per-release discipline
 *      and legitimately repeats `### Fixed`/`### Changed`/`### Security`
 *      several times as it aggregates what today would be several releases).
 *      Flagging that permanently-frozen history would be a check that can
 *      never pass on real data — exactly the "over-strict, rejects a correct
 *      setup" failure mode CLAUDE.md warns about — while the actual bug this
 *      guard exists for can only ever land in the two sections a merge can
 *      still touch: `[Unreleased]` and the section it was just consolidated
 *      into.
 *
 *   3. Exactly one `## [Unreleased]` heading, and it is the first `## [`
 *      heading in the file.
 *
 *   4. Every `## [X.Y.Z]` heading (every one that is not `[Unreleased]`)
 *      carries ` - YYYY-MM-DD` (Keep a Changelog form), matching how every
 *      existing versioned heading in this file is written.
 *
 *   5. When the `## [Unreleased]` section is non-empty, every `### Heading`
 *      inside it is drawn from the file's own established heading
 *      vocabulary. That vocabulary is DERIVED, not hard-coded: any
 *      `### Heading` anywhere in the file whose text is a single run of
 *      letters (no punctuation, digits, or em-dashed narrative titles) is
 *      treated as a real category rather than a one-off section title like
 *      `### Tenant RBAC — backend enforcement + role re-scoping`. A brand-new
 *      single-word heading typo'd into `[Unreleased]` (e.g. "Fixes" instead
 *      of "Fixed") still slips past this — no shape rule catches every typo —
 *      but every narrative or punctuated stray heading does not.
 *
 *   node scripts/audit-changelog.mjs [--strict]
 *
 * Mutation-test BOTH polarities in scripts/audit-changelog.test.mjs: each
 * check has a fixture that must fail it and a clean fixture that must pass.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');
const DEFAULT_SOURCE = path.join(ROOT, 'CHANGELOG.md');

const VERSION_HEADING_RE = /^## \[(.+?)\](.*)$/;
const SUBHEADING_RE = /^### (.+)$/;
const BULLET_RE = /^- (.+)$/;
const DATE_SUFFIX_RE = /^ - (\d{4})-(\d{2})-(\d{2})\s*$/;
const SIMPLE_WORD_RE = /^[A-Za-z]+$/;

function normalise(text) {
  return text.replace(/\s+/g, ' ').trim();
}

function truncate(text, max = 100) {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * Runs every check against CHANGELOG.md's raw text and returns the list of
 * problems found. Pure and side-effect-free so the mutation tests can drive
 * it directly against fixture strings.
 */
export function auditChangelog(text) {
  const lines = text.split(/\r?\n/);
  const problems = [];

  // --- Parse every `## [...]` heading -------------------------------------
  const headings = [];
  lines.forEach((line, i) => {
    const m = line.match(VERSION_HEADING_RE);
    if (m) {
      headings.push({ lineNum: i + 1, bracket: m[1], rest: m[2], raw: line });
    }
  });

  if (headings.length === 0) {
    problems.push('no "## [...]" heading found anywhere in the file');
    return { problems };
  }

  // --- Check 3: exactly one Unreleased section, and it is first ----------
  const unreleasedHeadings = headings.filter((h) => h.bracket === 'Unreleased');
  if (unreleasedHeadings.length === 0) {
    problems.push('no "## [Unreleased]" section found — every changelog must keep one at the top');
  } else if (unreleasedHeadings.length > 1) {
    const lineNums = unreleasedHeadings.map((h) => h.lineNum).join(', ');
    problems.push(`multiple "## [Unreleased]" sections found (lines ${lineNums}) — there must be exactly one`);
  } else if (headings[0].bracket !== 'Unreleased') {
    problems.push(
      `"## [Unreleased]" (line ${unreleasedHeadings[0].lineNum}) is not the first "## [" heading in the file — ` +
        `line ${headings[0].lineNum} ("${truncate(headings[0].raw)}") comes before it`
    );
  }

  // --- Check 4: every non-Unreleased heading carries " - YYYY-MM-DD" -----
  for (const h of headings) {
    if (h.bracket === 'Unreleased') continue;
    const dm = h.rest.match(DATE_SUFFIX_RE);
    if (!dm) {
      problems.push(
        `line ${h.lineNum}: "${truncate(h.raw)}" does not carry a " - YYYY-MM-DD" date suffix ` +
          `(Keep a Changelog form) after "## [${h.bracket}]"`
      );
      continue;
    }
    const month = Number(dm[2]);
    const day = Number(dm[3]);
    if (month < 1 || month > 12 || day < 1 || day > 31) {
      problems.push(`line ${h.lineNum}: "${truncate(h.raw)}" has an invalid calendar date`);
    }
  }

  // --- Section boundaries, for checks 2 and 5 -----------------------------
  const sectionEnd = (idx) => (idx + 1 < headings.length ? headings[idx + 1].lineNum - 1 : lines.length);
  const subheadingsOf = (idx) => {
    const start = headings[idx].lineNum; // 1-based line of "## [...]" itself
    const end = sectionEnd(idx);
    const found = [];
    for (let ln = start + 1; ln <= end; ln++) {
      const m = lines[ln - 1].match(SUBHEADING_RE);
      if (m) found.push({ lineNum: ln, text: normalise(m[1]) });
    }
    return found;
  };

  // --- Check 2: no duplicate "### Heading" within the ACTIVE window ------
  // Active window = the Unreleased section + the section immediately after
  // it (the most-recently-cut release) — see header comment for why this is
  // scoped rather than whole-file.
  const activeIndices = [];
  if (headings[0].bracket === 'Unreleased') {
    activeIndices.push(0);
    if (headings.length > 1) activeIndices.push(1);
  } else {
    // Best effort even if check 3 already failed: still guard the first two
    // sections found, whatever they are.
    activeIndices.push(0);
    if (headings.length > 1) activeIndices.push(1);
  }

  for (const idx of activeIndices) {
    const seen = new Map();
    for (const sub of subheadingsOf(idx)) {
      if (seen.has(sub.text)) {
        problems.push(
          `"## [${headings[idx].bracket}]" (line ${headings[idx].lineNum}) has "### ${sub.text}" twice — ` +
            `first at line ${seen.get(sub.text)}, again at line ${sub.lineNum}`
        );
      } else {
        seen.set(sub.text, sub.lineNum);
      }
    }
  }

  // --- Check 1: no duplicate bullet first line ANYWHERE in the file ------
  const seenBullets = new Map();
  lines.forEach((line, i) => {
    const m = line.match(BULLET_RE);
    if (!m) return;
    const norm = normalise(m[1]);
    if (seenBullets.has(norm)) {
      problems.push(
        `bullet at line ${i + 1} duplicates the one at line ${seenBullets.get(norm)}: "${truncate(norm)}"`
      );
    } else {
      seenBullets.set(norm, i + 1);
    }
  });

  // --- Check 5: Unreleased heading vocabulary -----------------------------
  const canonicalHeadings = new Set();
  lines.forEach((line) => {
    const m = line.match(SUBHEADING_RE);
    if (!m) return;
    const text = normalise(m[1]);
    if (SIMPLE_WORD_RE.test(text)) canonicalHeadings.add(text);
  });

  if (unreleasedHeadings.length >= 1) {
    const unreleasedIdx = headings.findIndex((h) => h.bracket === 'Unreleased');
    const unreleasedSubs = subheadingsOf(unreleasedIdx);
    for (const sub of unreleasedSubs) {
      if (!canonicalHeadings.has(sub.text)) {
        const allowed = [...canonicalHeadings].sort().join(', ');
        problems.push(
          `"## [Unreleased]" has "### ${sub.text}" (line ${sub.lineNum}), which is not part of the ` +
            `changelog's established heading vocabulary (${allowed})`
        );
      }
    }
  }

  return { problems };
}

/**
 * The same duplicate-bullet check, extended ACROSS files.
 *
 * A release whose entry is too large for the changelog keeps its per-change
 * detail in `docsv4/core/releases/<version>.md` and the changelog carries only
 * the lead (see RELEASE_PROCESS.md). That moves most of the bullets this
 * guard exists to police out of the file the guard reads — and the merge bug it
 * was written for (a stale `[Unreleased]` diff replayed on top of a tree where
 * those bullets already live one section down) lands in exactly those bullets.
 * So the check follows them: every bullet's first line must be unique across
 * the changelog AND every release-notes document, considered together.
 *
 * `entries` is a list of `{ name, text }`. Order matters only for which
 * occurrence is reported as the original.
 */
export function auditBulletsAcrossFiles(entries) {
  const problems = [];
  const seen = new Map();
  for (const { name, text } of entries) {
    text.split(/\r?\n/).forEach((line, i) => {
      const m = line.match(BULLET_RE);
      if (!m) return;
      const norm = normalise(m[1]);
      const at = `${name}:${i + 1}`;
      if (seen.has(norm)) {
        problems.push(`bullet at ${at} duplicates the one at ${seen.get(norm)}: "${truncate(norm)}"`);
      } else {
        seen.set(norm, at);
      }
    });
  }
  return { problems };
}

/** The release-notes documents that pair with this changelog, if any. */
function releaseNotesDocs() {
  const dir = path.join(ROOT, 'docsv4', 'core', 'releases');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => path.join(dir, f));
}

function main() {
  const fileArgs = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const source = fileArgs[0] ? path.resolve(fileArgs[0]) : DEFAULT_SOURCE;

  if (!fs.existsSync(source)) {
    console.error(`❌ changelog audit: file not found: ${path.relative(ROOT, source)}`);
    process.exit(1);
  }

  const text = fs.readFileSync(source, 'utf8');
  const { problems } = auditChangelog(text);

  // Bullets that moved out to a release-notes document are still bullets this
  // guard is responsible for, so the duplicate check spans both.
  const docs = releaseNotesDocs();
  const entries = [
    { name: path.relative(ROOT, source), text },
    ...docs.map((d) => ({ name: path.relative(ROOT, d), text: fs.readFileSync(d, 'utf8') })),
  ];
  // Duplicates wholly inside the changelog are already reported by check 1
  // above, so only the ones a release-notes document is involved in are added
  // here — otherwise every such bullet would be named twice.
  const docNames = docs.map((d) => path.relative(ROOT, d));
  problems.push(
    ...auditBulletsAcrossFiles(entries).problems.filter((p) => docNames.some((n) => p.includes(`${n}:`)))
  );

  if (problems.length === 0) {
    console.log(
      `✅ changelog audit: no duplicate bullets/headings (across ${entries.length} file(s)), ` +
        'exactly one leading [Unreleased], every version dated'
    );
    process.exit(0);
  }

  for (const p of problems) {
    console.error(`${STRICT ? '❌' : '⚠️'} changelog audit: ${p}`);
  }
  process.exit(STRICT ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
