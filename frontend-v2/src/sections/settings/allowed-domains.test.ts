import { describe, expect, it } from 'vitest';
import { normalizeAllowedDomains } from './allowed-domains';

describe('normalizeAllowedDomains', () => {
  it('trims, ASCII-lowercases, de-duplicates, and preserves order', () => {
    expect(normalizeAllowedDomains(' Example.COM, example.com, xn--bcher-kva.example ')).toEqual({
      domains: ['example.com', 'xn--bcher-kva.example'], error: null,
    });
  });

  it.each([
    ['bücher.example', 'punycode'],
    ['corp', 'fully qualified'],
    ['*.example.com', 'wildcard'],
    ['example.com.', 'ends with a dot'],
    ['admin@example.com', 'email address'],
    ['https://example.com', 'bare domain'],
    ['-bad.example', 'hyphen'],
    ['bad_.example', 'only letters'],
  ])('refuses %s with an actionable reason', (input, reason) => {
    const result = normalizeAllowedDomains(input);
    expect(result.domains).toEqual([]);
    expect(result.error).toContain(reason);
  });

  it('accepts an empty list and ignores empty comma slots', () => {
    expect(normalizeAllowedDomains(' , ')).toEqual({ domains: [], error: null });
  });

  it('caps the canonical list at 50 entries', () => {
    const input = Array.from({ length: 51 }, (_, i) => `d${i}.example`).join(',');
    expect(normalizeAllowedDomains(input).error).toContain('at most 50');
  });
});
