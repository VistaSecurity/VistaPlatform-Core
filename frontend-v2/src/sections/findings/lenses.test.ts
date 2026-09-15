// Reachability for the Findings lenses.
//
// The one thing a user cannot recover from is a finding with no nav home. The
// `eol` and `vulnerability` producers write to the same table the Findings page
// reads, and the page's two original lenses both group by framework CONTROL —
// which only the compliance producer has. Without a lens that groups by
// producer, those findings would have been listed by the API and reachable from
// nowhere.
//
// Both polarities: the producer lens EXISTS and reads the findings stream, and
// the crypto lenses are still crypto (a `scope` that said 'findings' everywhere
// would satisfy the first assertion and break the page).
import { describe, expect, it } from 'vitest';
import { DEFAULT_FINDINGS_LENS, FINDINGS_LENSES, findFindingsLens, isFindingsLens, SCOPE_LABEL, SCOPE_ORDER } from './lenses';

describe('the Findings lens registry', () => {
  it('has a By Producer lens reading the findings stream', () => {
    const producer = FINDINGS_LENSES.find((l) => l.key === 'producer');
    expect(producer).toBeDefined();
    expect(producer!.scope).toBe('findings');
    expect(isFindingsLens('producer')).toBe(true);
  });

  it('defaults the nav home to the full platform-finding stream', () => {
    expect(DEFAULT_FINDINGS_LENS).toBe('producer');
    expect(findFindingsLens(null).scope).toBe('findings');
  });

  it('keeps the framework and control lenses on the findings stream too', () => {
    expect(isFindingsLens('framework')).toBe(true);
    expect(isFindingsLens('control')).toBe(true);
  });

  it('keeps the crypto-risk lenses OFF the findings stream', () => {
    // They read inventory-service's /crypto-risks, a different data set under
    // identical chrome. Folding them in would make "Open" count two things.
    for (const key of ['severity', 'asset', 'category', 'date']) {
      expect(isFindingsLens(key)).toBe(false);
    }
  });

  it('gives every scope a label and an order', () => {
    for (const l of FINDINGS_LENSES) {
      expect(SCOPE_LABEL[l.scope]).toBeTruthy();
      expect(SCOPE_ORDER).toContain(l.scope);
    }
  });

  it('resolves the default lens by KEY, not by position', () => {
    // The fallback used to be FINDINGS_LENSES[1], which silently became a
    // different lens the moment one was inserted above it — which this change
    // did.
    expect(findFindingsLens(null).key).toBe(DEFAULT_FINDINGS_LENS);
    expect(findFindingsLens('not-a-lens').key).toBe(DEFAULT_FINDINGS_LENS);
    expect(findFindingsLens('producer').key).toBe('producer');
  });
});
