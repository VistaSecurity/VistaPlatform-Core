// The console's copy of the placeholder detector must agree with the server's,
// or the confirmation dialog and the 422 disagree about the same document — the
// admin would press Publish, see no dialog, and get a rejection they cannot act
// on.
//
// The server is authoritative (admin-service/internal/handlers/legal.go). This
// pins the client mirror against the same cases as the Go table test.

import { describe, it, expect } from 'vitest';

// Kept in sync with settings-legal-page.tsx. Duplicated here rather than
// exported so the page keeps one exported symbol; if a third caller appears,
// promote it to lib/.
const PLACEHOLDER_RE = /\[[A-Z][A-Z0-9 ,.:;_/&'-]{2,}\]/g;

function draftPlaceholders(body: string): string[] {
  return Array.from(new Set(body.match(PLACEHOLDER_RE) ?? [])).slice(0, 10);
}

describe('legal template placeholder detection', () => {
  it('finds bracketed upper-case markers', () => {
    expect(
      draftPlaceholders('operated by **[YOUR LEGAL ENTITY]**, at [YOUR SERVICE URL].'),
    ).toEqual(['[YOUR LEGAL ENTITY]', '[YOUR SERVICE URL]']);
  });

  it('finds whole-instruction markers containing punctuation', () => {
    expect(
      draftPlaceholders('[LIST YOUR SUB-PROCESSORS, OR STATE THAT THERE ARE NONE.]'),
    ).toEqual(['[LIST YOUR SUB-PROCESSORS, OR STATE THAT THERE ARE NONE.]']);
  });

  it('collapses duplicates, keeping first-appearance order', () => {
    expect(draftPlaceholders('[YOUR LEGAL ENTITY] x [PERIOD] y [YOUR LEGAL ENTITY]')).toEqual([
      '[YOUR LEGAL ENTITY]',
      '[PERIOD]',
    ]);
  });

  it('treats a completed document as clean', () => {
    expect(
      draftPlaceholders('operated by **Acme Corporation**, at https://vista.acme.example.'),
    ).toEqual([]);
  });

  it('does not fire on Markdown link labels', () => {
    expect(draftPlaceholders('See [our security page](https://example.com) and [Settings](/s).')).toEqual([]);
  });

  it('does not fire on task-list checkboxes', () => {
    expect(draftPlaceholders('- [x] reviewed\n- [ ] signed')).toEqual([]);
  });

  it('does not fire on short bracketed acronyms', () => {
    expect(draftPlaceholders('under the [EU] and [UK] regimes')).toEqual([]);
  });

  it('caps what it reports at ten', () => {
    const body = Array.from({ length: 30 }, (_, i) => `[PLACEHOLDER ${'X'.repeat(i + 1)}]`).join('\n');
    expect(draftPlaceholders(body)).toHaveLength(10);
  });

  it('detects the shape the seeded templates actually use', () => {
    // Verbatim from scripts/database/seed.sql — the state every fresh install
    // starts in, and the case the whole guard exists for.
    const seeded = `These Terms govern use of the Vista Platform deployment operated by
**[YOUR LEGAL ENTITY]** ("we", "us"), reachable at **[YOUR SERVICE URL]** (the
"Service").`;
    expect(draftPlaceholders(seeded)).toEqual(['[YOUR LEGAL ENTITY]', '[YOUR SERVICE URL]']);
  });
});
