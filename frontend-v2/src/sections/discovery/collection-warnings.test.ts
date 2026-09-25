import { describe, expect, it } from 'vitest';
import { collectionWarningsView, warningReasonLabel, type CollectionWarning } from './collection-warnings';

const base = {
  job_id: 'job-1',
  status: 'completed',
  assets: [],
  summary: { total_assets: 0, with_crypto: 0, with_certificates: 0 },
};

const refused: CollectionWarning = {
  collector: 'fortinet',
  endpoint: '/api/v2/cmdb/system/interface',
  reason: 'permission_denied',
  effect: 'Configured interfaces and VLANs not collected',
};

describe('collectionWarningsView', () => {
  it('is hidden when the run raised none', () => {
    expect(collectionWarningsView(base, false)).toEqual({ state: 'hidden' });
    expect(collectionWarningsView({ ...base, collection_warnings: [] }, false)).toEqual({ state: 'hidden' });
  });

  it('is hidden while results have not loaded — the modal owns the loading line', () => {
    expect(collectionWarningsView(undefined, false)).toEqual({ state: 'hidden' });
  });

  it('lists the warnings when there are some', () => {
    expect(collectionWarningsView({ ...base, collection_warnings: [refused] }, false)).toEqual({
      state: 'list',
      warnings: [refused],
    });
  });

  // "Could not load" must never collapse into "none".
  it('is an error when the results failed to load', () => {
    expect(collectionWarningsView(undefined, true)).toEqual({ state: 'error' });
    expect(collectionWarningsView({ ...base, collection_warnings: [refused] }, true)).toEqual({ state: 'error' });
  });

  it('is an error when the stored list was unreadable', () => {
    expect(collectionWarningsView({ ...base, collection_warnings_unreadable: true }, false)).toEqual({ state: 'error' });
  });
});

describe('warningReasonLabel', () => {
  it('names every reason the API sends', () => {
    expect(warningReasonLabel('permission_denied')).toBe('Permission denied');
    expect(warningReasonLabel('not_supported')).toBe('Not supported on this device or version');
    expect(warningReasonLabel('truncated')).toBe('Truncated');
    expect(warningReasonLabel('timeout')).toBe('Timed out');
    expect(warningReasonLabel('unreachable')).toBe('Unreachable');
    expect(warningReasonLabel('parse_error')).toBe('Response could not be read');
    expect(warningReasonLabel('error')).toBe('Error');
  });

  it('reads anything unrecognised as an error rather than printing the raw key', () => {
    expect(warningReasonLabel('rate_limited')).toBe('Error');
    expect(warningReasonLabel(undefined)).toBe('Error');
    // Not an object-prototype key either.
    expect(warningReasonLabel('constructor')).toBe('Error');
  });
});
