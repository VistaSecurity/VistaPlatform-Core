// The platform-CA panel in the agent registration dialog is the operator's
// only in-product way to verify the CA an agent asks them to approve. Both
// failure directions are real defects, so the decision is pinned here:
//
//   - hidden when it should show  → the operator has nothing to compare
//     against and approves the agent's prompt blind, which is exactly the
//     trust-on-first-use hole the panel exists to close.
//   - shown when it should hide   → implies an approval step that does not
//     exist (publicly-trusted platforms never prompt), training operators to
//     click past a security dialog.
import { describe, expect, it } from 'vitest';
import { platformCADisplay } from './sensor-modals';

const anchor = {
  available: true,
  trusted_by_default: false,
  fingerprint_sha256: 'a'.repeat(64),
};

describe('platformCADisplay', () => {
  it('shows the fingerprint for a privately-signed platform', () => {
    expect(platformCADisplay({ isPending: false, isError: false, data: anchor }))
      .toEqual({ kind: 'fingerprint' });
  });

  it('hides entirely when the platform certificate is publicly trusted', () => {
    // No agent prompts in this case, so there is nothing to compare.
    const got = platformCADisplay({
      isPending: false,
      isError: false,
      data: { ...anchor, trusted_by_default: true },
    });
    expect(got).toEqual({ kind: 'hidden' });
  });

  it('hides while loading and on error rather than rendering a half-panel', () => {
    expect(platformCADisplay({ isPending: true, isError: false, data: undefined }))
      .toEqual({ kind: 'hidden' });
    expect(platformCADisplay({ isPending: false, isError: true, data: undefined }))
      .toEqual({ kind: 'hidden' });
    expect(platformCADisplay({ isPending: false, isError: false, data: null }))
      .toEqual({ kind: 'hidden' });
  });

  it('explains why when the fingerprint could not be determined', () => {
    const got = platformCADisplay({
      isPending: false,
      isError: false,
      data: { available: false, trusted_by_default: false, reason: 'WEB_UI_BASE_URL is not set.' },
    });
    expect(got).toEqual({ kind: 'unavailable', reason: 'WEB_UI_BASE_URL is not set.' });
  });

  it('falls back to a reason rather than rendering an empty explanation', () => {
    const got = platformCADisplay({
      isPending: false,
      isError: false,
      data: { available: false, trusted_by_default: false },
    });
    expect(got.kind).toBe('unavailable');
    expect(got.kind === 'unavailable' && got.reason.length > 0).toBe(true);
  });

  it('treats available-but-empty as unavailable instead of showing a blank fingerprint', () => {
    // Defensive: a response claiming availability with no fingerprint would
    // otherwise render an empty box the operator might "compare" against.
    const got = platformCADisplay({
      isPending: false,
      isError: false,
      data: { available: true, trusted_by_default: false, fingerprint_sha256: '' },
    });
    expect(got.kind).toBe('unavailable');
  });
});
