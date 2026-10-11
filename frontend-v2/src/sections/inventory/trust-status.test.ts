// trust_status → label/tone. Every contract value must map to its own
// words, and an unevaluated certificate must never read as trusted.
import { describe, expect, it } from 'vitest';
import {
  TRUST_FILTER_VALUES, TRUST_STATUSES, TRUST_TONE_COLOR, UNTRUSTED_TRUST_FILTER,
  parseTrustFilter, trustFilterParam, trustFilterPresentation, trustPresentation, type TrustStatus,
} from './trust-status';

const expected: Record<TrustStatus, { label: string; tone: string }> = {
  public: { label: 'Public CA', tone: 'ok' },
  private_trusted: { label: 'Trusted (your CA)', tone: 'ok' },
  self_signed: { label: 'Self-signed', tone: 'warn' },
  untrusted: { label: 'Untrusted CA', tone: 'danger' },
  distrusted: { label: 'Distrusted CA', tone: 'danger' },
  incomplete: { label: 'Chain incomplete', tone: 'warn' },
};

describe('trustPresentation', () => {
  it.each(Object.entries(expected))('%s → its own label and tone', (status, want) => {
    const p = trustPresentation(status);
    expect(p.label).toBe(want.label);
    expect(p.tone).toBe(want.tone);
    expect(p.explanation.length).toBeGreaterThan(20);
    expect(TRUST_TONE_COLOR[p.tone]).toBeTruthy();
  });

  it('covers every value the list declares, with distinct labels', () => {
    expect([...TRUST_STATUSES].sort()).toEqual(Object.keys(expected).sort());
    const labels = TRUST_STATUSES.map((s) => trustPresentation(s).label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it.each<[string | null | undefined]>([[null], [undefined], [''], ['something_new']])('%s → "Not yet evaluated", muted', (v) => {
    const p = trustPresentation(v);
    expect(p.label).toBe('Not yet evaluated');
    expect(p.tone).toBe('muted');
  });

  it('does not treat inherited object keys as a status', () => {
    expect(trustPresentation('toString').label).toBe('Not yet evaluated');
  });
});

describe('trust filter values', () => {
  it('offers every status plus "Not yet evaluated", each with its chip label', () => {
    expect(TRUST_FILTER_VALUES).toEqual([...TRUST_STATUSES, 'unevaluated']);
    expect(trustFilterPresentation('unevaluated').label).toBe('Not yet evaluated');
    for (const s of TRUST_STATUSES) expect(trustFilterPresentation(s).label).toBe(trustPresentation(s).label);
  });

  it('parses a comma list into canonical order, dropping unknown words and duplicates', () => {
    expect(parseTrustFilter('distrusted, untrusted,bogus,untrusted')).toEqual(['untrusted', 'distrusted']);
    expect(parseTrustFilter('')).toEqual([]);
    expect(parseTrustFilter(null)).toEqual([]);
    expect(parseTrustFilter('toString')).toEqual([]);
  });

  it('writes the parameter the API takes, or nothing for "any"', () => {
    expect(trustFilterParam(['distrusted', 'untrusted'])).toBe('untrusted,distrusted');
    expect(trustFilterParam(['unevaluated'])).toBe('unevaluated');
    expect(trustFilterParam([])).toBeUndefined();
    expect(UNTRUSTED_TRUST_FILTER).toEqual(['untrusted', 'distrusted']);
  });
});
