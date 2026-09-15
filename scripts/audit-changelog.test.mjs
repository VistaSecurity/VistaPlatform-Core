#!/usr/bin/env node
// Mutation tests for scripts/audit-changelog.mjs.
//
// A check that cannot fail is worse than no check, so every rule below is
// driven with a fixture that must fail it AND a fixture that must pass —
// both polarities, per CLAUDE.md.

import { auditChangelog, auditBulletsAcrossFiles } from './audit-changelog.mjs';

let failures = 0;

function check(desc, ok, detail = '') {
  if (ok) {
    console.log(`  ✓ ${desc}`);
  } else {
    failures++;
    console.error(`  ✗ ${desc}${detail ? `\n      ${detail}` : ''}`);
  }
}

function problemsFor(text) {
  return auditChangelog(text).problems;
}

// A minimal, fully clean changelog: Unreleased first, one dated release
// after it, standard headings, no duplicate bullets or headings.
const CLEAN = `## [Unreleased]

### Fixed

- **First fix.** Some detail about the first fix.

## [1.0.0] -

### Added

- **First add.** Some detail about the first add.

### Fixed

- **Second fix.** Some detail about the second fix.

## [0.9.0] -

### Fixed

- **Third fix.** Some detail about the third fix.
`;

check('clean fixture has zero problems', problemsFor(CLEAN).length === 0, JSON.stringify(problemsFor(CLEAN)));

// --- Check 1: duplicate bullet first line, anywhere in the file ----------

const DUP_BULLET_ACROSS_SECTIONS = CLEAN.replace(
  '- **Third fix.** Some detail about the third fix.',
  '- **First fix.** Some detail about the first fix.'
);
{
  const problems = problemsFor(DUP_BULLET_ACROSS_SECTIONS);
  check(
    'duplicate bullet first line across two different sections is caught',
    problems.some((p) => /duplicates the one at line/.test(p)),
    JSON.stringify(problems)
  );
}

const DUP_BULLET_WHITESPACE_ONLY = CLEAN.replace(
  '- **Third fix.** Some detail about the third fix.',
  '-   **First fix.**   Some detail   about the first fix.'
);
{
  const problems = problemsFor(DUP_BULLET_WHITESPACE_ONLY);
  check(
    'duplicate bullet detection is whitespace-normalised (extra spaces still counts as a duplicate)',
    problems.some((p) => /duplicates the one at line/.test(p)),
    JSON.stringify(problems)
  );
}

check(
  'clean fixture: no false-positive duplicate bullets (distinct bullets stay distinct)',
  !problemsFor(CLEAN).some((p) => /duplicates the one at line/.test(p))
);

// --- Check 2: duplicate ### heading within the active window -------------

const DUP_HEADING_IN_UNRELEASED = `## [Unreleased]

### Fixed

- **A fix.** Detail.

### Fixed

- **Another fix.** Detail.

## [1.0.0] -

### Added

- **An add.** Detail.
`;
{
  const problems = problemsFor(DUP_HEADING_IN_UNRELEASED);
  check(
    'duplicate "### Fixed" within [Unreleased] itself is caught',
    problems.some((p) => /has "### Fixed" twice/.test(p) && /\[Unreleased\]/.test(p)),
    JSON.stringify(problems)
  );
}

const DUP_HEADING_IN_NEWEST_RELEASE = `## [Unreleased]

### Fixed

- **A fix.** Detail.

## [1.0.0] -

### Added

- **An add.** Detail.

### Added

- **Another add re-inserted by a stale merge.** Detail.
`;
{
  const problems = problemsFor(DUP_HEADING_IN_NEWEST_RELEASE);
  check(
    'duplicate "### Added" within the newest ([1.0.0]) section is caught — the exact reported bug shape',
    problems.some((p) => /has "### Added" twice/.test(p) && /\[1\.0\.0\]/.test(p)),
    JSON.stringify(problems)
  );
}

// Old, pre-Keep-a-Changelog history repeating headings must NOT be flagged —
// this is the "over-strict, rejects a correct setup" polarity: the real
// CHANGELOG.md has exactly this shape in its `[0.2.0]` section.
const OLD_HISTORY_REPEATS_HEADINGS = `## [Unreleased]

### Fixed

- **A fix.** Detail.

## [1.0.0] -

### Added

- **An add.** Detail.

## [0.2.0] -

### Fixed

- **Old fix one.** Detail.

### Changed

- **Old change one.** Detail.

### Fixed

- **Old fix two, added on a later day within the same aggregated release.** Detail.
`;
{
  const problems = problemsFor(OLD_HISTORY_REPEATS_HEADINGS);
  check(
    'a repeated "### Fixed" in an OLD, already-released section (outside the active window) is NOT flagged',
    !problems.some((p) => /\[0\.2\.0\]/.test(p)),
    JSON.stringify(problems)
  );
}

check(
  'clean fixture: no false-positive duplicate headings',
  !problemsFor(CLEAN).some((p) => /has "### .*" twice/.test(p))
);

// --- Check 3: exactly one [Unreleased], and it is first -------------------

const NO_UNRELEASED = CLEAN.replace('## [Unreleased]\n\n### Fixed\n\n- **First fix.** Some detail about the first fix.\n\n', '');
{
  const problems = problemsFor(NO_UNRELEASED);
  check(
    'missing "## [Unreleased]" entirely is caught',
    problems.some((p) => /no "## \[Unreleased\]" section found/.test(p)),
    JSON.stringify(problems)
  );
}

const TWO_UNRELEASED = `## [Unreleased]

### Fixed

- **A fix.** Detail.

## [Unreleased]

### Added

- **An add.** Detail.

## [1.0.0] -

### Added

- **Another add.** Detail.
`;
{
  const problems = problemsFor(TWO_UNRELEASED);
  check(
    'two "## [Unreleased]" sections is caught',
    problems.some((p) => /multiple "## \[Unreleased\]" sections found/.test(p)),
    JSON.stringify(problems)
  );
}

const UNRELEASED_NOT_FIRST = `## [1.0.0] - 2026-09-14

### Added

- **An add.** Detail.

## [Unreleased]

### Fixed

- **A fix.** Detail.
`;
{
  const problems = problemsFor(UNRELEASED_NOT_FIRST);
  check(
    '"## [Unreleased]" present but not first in the file is caught',
    problems.some((p) => /is not the first "## \[" heading in the file/.test(p)),
    JSON.stringify(problems)
  );
}

check('clean fixture: [Unreleased] presence/position checks pass', !problemsFor(CLEAN).some((p) => /Unreleased/.test(p) && /(missing|multiple|not the first)/.test(p)));

// --- Check 4: every non-Unreleased heading carries " - YYYY-MM-DD" -------

const MISSING_DATE = CLEAN.replace('## [1.0.0] - 2026-09-14', '## [1.0.0]');
{
  const problems = problemsFor(MISSING_DATE);
  check(
    'a versioned heading with no date suffix at all is caught',
    problems.some((p) => /does not carry a " - YYYY-MM-DD" date suffix/.test(p) && /\[1\.0\.0\]/.test(p)),
    JSON.stringify(problems)
  );
}

const WRONG_DATE_FORMAT = CLEAN.replace('## [1.0.0] - 2026-09-14', '## [1.0.0] (2026-09-14)');
{
  const problems = problemsFor(WRONG_DATE_FORMAT);
  check(
    'a versioned heading with the date in the wrong punctuation form is caught',
    problems.some((p) => /does not carry a " - YYYY-MM-DD" date suffix/.test(p)),
    JSON.stringify(problems)
  );
}

const INVALID_CALENDAR_DATE = CLEAN.replace('## [1.0.0] - 2026-09-14', '## [1.0.0] - 2026-13-40');
{
  const problems = problemsFor(INVALID_CALENDAR_DATE);
  check(
    'a syntactically-shaped but calendrically-invalid date is caught',
    problems.some((p) => /invalid calendar date/.test(p)),
    JSON.stringify(problems)
  );
}

check(
  '"## [Unreleased]" itself is exempt from the date-suffix rule',
  !problemsFor(CLEAN).some((p) => /Unreleased/.test(p) && /date suffix/.test(p))
);

check('clean fixture: all dated headings pass', !problemsFor(CLEAN).some((p) => /date suffix|invalid calendar date/.test(p)));

// --- Check 5: [Unreleased] heading vocabulary -----------------------------

const NARRATIVE_HEADING_IN_UNRELEASED = `## [Unreleased]

### Fixed

- **A fix.** Detail.

### Tenant RBAC — a one-off narrative heading

- **A behavioral note.** Detail.

## [1.0.0] -

### Added

- **An add.** Detail.
`;
{
  const problems = problemsFor(NARRATIVE_HEADING_IN_UNRELEASED);
  check(
    'a narrative/punctuated one-off heading pasted into [Unreleased] is caught',
    problems.some((p) => /not part of the changelog's established heading vocabulary/.test(p) && /Tenant RBAC/.test(p)),
    JSON.stringify(problems)
  );
}

// A heading that is a real, single-word category used ELSEWHERE in the file
// (even only in a past release, never before in Unreleased) must be accepted
// — this proves the vocabulary is derived from the file, not a hard-coded
// list that would need editing every time a legitimate category is reused.
const REUSED_CATEGORY_HEADING = `## [Unreleased]

### Security

- **A security note.** Detail.

## [1.0.0] -

### Added

- **An add.** Detail.

## [0.9.0] -

### Security

- **An older security note.** Detail.
`;
{
  const problems = problemsFor(REUSED_CATEGORY_HEADING);
  check(
    'a single-word heading already used in an older release (not previously in Unreleased) is accepted',
    !problems.some((p) => /not part of the changelog's established heading vocabulary/.test(p)),
    JSON.stringify(problems)
  );
}

check(
  'clean fixture: [Unreleased] heading vocabulary passes',
  !problemsFor(CLEAN).some((p) => /not part of the changelog's established heading vocabulary/.test(p))
);

// An empty [Unreleased] section (no ### headings at all) must not be flagged
// by the vocabulary check — "when non-empty" is explicit in the spec.
const EMPTY_UNRELEASED = `## [Unreleased]

## [1.0.0] -

### Added

- **An add.** Detail.
`;
{
  const problems = problemsFor(EMPTY_UNRELEASED);
  check(
    'an empty [Unreleased] section is not flagged by the vocabulary check',
    !problems.some((p) => /established heading vocabulary/.test(p)),
    JSON.stringify(problems)
  );
}

// --- The cross-file duplicate check --------------------------------------
//
// A release too large for the changelog keeps its detail in
// docsv4/core/releases/<version>.md, which is where most of the bullets the
// duplicate guard polices then live. Both polarities:
{
  const changelog = `## [Unreleased]

## [1.0.0] -

**Full list of changes:** docsv4/core/releases/1.0.0.md
`;
  const doc = `# 1.0.0

### Added

- **An add.** Detail.
`;
  const clean = auditBulletsAcrossFiles([
    { name: 'CHANGELOG.md', text: changelog },
    { name: 'docsv4/core/releases/1.0.0.md', text: doc },
  ]).problems;
  check('a bullet living only in the release-notes doc is accepted', clean.length === 0, JSON.stringify(clean));

  const dirty = auditBulletsAcrossFiles([
    { name: 'CHANGELOG.md', text: `${changelog}\n- **An add.** Detail.\n` },
    { name: 'docsv4/core/releases/1.0.0.md', text: doc },
  ]).problems;
  check(
    'the same bullet in the changelog AND the release-notes doc is caught',
    dirty.length === 1 && dirty[0].includes('docsv4/core/releases/1.0.0.md:'),
    JSON.stringify(dirty)
  );

  const twiceInDoc = auditBulletsAcrossFiles([
    { name: 'docsv4/core/releases/1.0.0.md', text: `${doc}\n- **An add.** Detail.\n` },
  ]).problems;
  check('a bullet repeated inside the release-notes doc is caught', twiceInDoc.length === 1, JSON.stringify(twiceInDoc));
}

if (failures) {
  console.error(`\n${failures} changelog audit regression check(s) failed`);
  process.exit(1);
}

console.log('Changelog audit catches the expected duplication/format regressions and does not flag frozen history');
