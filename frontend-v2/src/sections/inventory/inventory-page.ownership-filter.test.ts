// B-30 regression guard — Certificate lens: changing the Ownership filter
// must reset pagination.
//
// fCertOwner is a server-side filter (mapped to the `ownership` query param
// and part of the query key), but its FilterSelect was the only filter on
// the page whose onChange did not also call setPage(1) — the search box, the
// three Data Protection filters, and the lens-change effect all do. A tenant
// on page 2+ who narrowed Ownership landed on a page past the end of the new,
// smaller result set and saw the empty state.
//
// inventory-page.tsx has no JSX/DOM-rendering test harness in this repo, so
// this pins the fix structurally: the source line for the Ownership
// FilterSelect must call setPage(1) from its onChange, same as every other
// filter on the page.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(fileURLToPath(new URL('./inventory-page.tsx', import.meta.url)), 'utf8');

describe('B-30: Ownership filter resets pagination', () => {
  it('the Ownership FilterSelect onChange also resets the page', () => {
    const line = src.split('\n').find((l) => l.includes('label="Ownership"'));
    expect(line, 'Ownership FilterSelect not found in inventory-page.tsx').toBeTruthy();
    expect(
      line,
      'Ownership FilterSelect onChange must call setPage(1) — otherwise changing ' +
        'Ownership while on page 2+ can land on an empty page (B-30)',
    ).toMatch(/setFCertOwner\(v\);\s*setPage\(1\)/);
  });
});
