// The Stale lens and the hygiene stale ladder must mean the same thing by
// "stale".
//
// They did not. The lens cut at 14 days, the ladder's first rung and IH-004's
// control threshold at 30, so a record could appear under "Stale" with no
// finding and no failing control — and nothing on screen explained why. Both
// now come from `staleLadderDays[0]`, and this reads the Go declaration rather
// than a copy of it, because a test that compared two TypeScript constants
// would pass just as happily after the Go one moved.
//
// Mutation: change either number and this goes red.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { STALE_DAYS } from './stale-threshold';

const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));

function goStaleLadder(): number[] {
  const src = readFileSync(
    repoRoot + 'services/inventory-service/internal/producers/hygiene.go',
    'utf8',
  );
  const m = src.match(/var staleLadderDays = \[\]int\{([^}]*)\}/);
  if (!m) {
    throw new Error(
      'staleLadderDays is no longer declared as `var staleLadderDays = []int{…}` in ' +
        'hygiene.go. If the ladder genuinely moved, point this test at its new home — ' +
        'do not loosen the pattern, because a pattern that matches anything pins nothing.',
    );
  }
  return m[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s));
}

describe('the stale threshold', () => {
  it('is the hygiene ladder’s first rung, not a second opinion', () => {
    const ladder = goStaleLadder();
    expect(ladder.length).toBeGreaterThan(0);
    expect(ladder.every((d) => Number.isInteger(d) && d > 0)).toBe(true);
    expect(STALE_DAYS).toBe(ladder[0]);
  });

  it('is the number the Inventory page actually filters on', () => {
    // The wiring, not the constant. A module exporting the right number that
    // nothing imports is the shape of a fix that ships and does nothing.
    const page = readFileSync(
      repoRoot + 'frontend-v2/src/sections/inventory/inventory-page.tsx',
      'utf8',
    );
    expect(page).toMatch(/from '\.\/stale-threshold'/);
    expect(page).not.toMatch(/const STALE_DAYS\s*=/);
  });
});
