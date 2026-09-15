// Literal parsing, bounds, quoting and the version sort key.
//
// The conformance file exercises most of this through whole queries, but three
// things it never reaches are pinned here because they are exactly where a port
// diverges quietly: the units the two caps are measured in, the duration bound,
// and the sort key whose *contents* are a column's contract rather than a
// comparison's result.

import { describe, expect, it } from 'vitest';

import {
  canonicalDuration,
  dateText,
  isSafeBareword,
  isSafeFreeText,
  parseDate,
  parseDuration,
  parseInet,
  parseNumber,
  parseUUID,
  quote,
  quoteFreeText,
  quoteLiteral,
} from './literal';
import { looksLikeVersion, versionSortKey } from './versionsort';
import { utf8ByteLength } from './validate';

describe('numbers', () => {
  it('accepts §2 numbers and rejects everything else', () => {
    expect(parseNumber('70')).toBe(70);
    expect(parseNumber('-3.5')).toBe(-3.5);
    expect(parseNumber('0.8')).toBe(0.8);
    // No exponents in v1.
    expect(parseNumber('1e3')).toBeNull();
    expect(parseNumber('.5')).toBeNull();
    expect(parseNumber('5.')).toBeNull();
    expect(parseNumber('1.2.3')).toBeNull();
    expect(parseNumber('')).toBeNull();
    expect(parseNumber('-')).toBeNull();
  });
});

describe('durations', () => {
  it('takes every spelled alias, longest match first', () => {
    expect(parseDuration('30d')).toEqual({ count: 30, unit: 'd' });
    expect(parseDuration('6months')).toEqual({ count: 6, unit: 'mo' });
    // `mo` is months and `m` is minutes — the one ambiguity in the unit set.
    expect(parseDuration('6mo')).toEqual({ count: 6, unit: 'mo' });
    expect(parseDuration('6m')).toEqual({ count: 6, unit: 'm' });
    expect(parseDuration('12')).toBeNull();
    expect(parseDuration('12x')).toBeNull();
  });

  // §13 A5. In Go this bound stops an int64 overflow that turned "two hundred
  // thousand days ago" into an instant in the FUTURE, so `last_seen <
  // now-200000d` matched every asset instead of none. JavaScript would not
  // overflow the same way, which is exactly why the bound has to be ported
  // deliberately: without it this side would accept a query the server refuses.
  it('is bounded at a century, per unit', () => {
    expect(parseDuration('36500d')).toEqual({ count: 36500, unit: 'd' });
    expect(parseDuration('36501d')).toBeNull();
    expect(parseDuration('200000d')).toBeNull();
    expect(parseDuration('100y')).toEqual({ count: 100, unit: 'y' });
    expect(parseDuration('101y')).toBeNull();
    expect(parseDuration('1200mo')).toEqual({ count: 1200, unit: 'mo' });
    expect(parseDuration('1201mo')).toBeNull();
  });

  it('canonicalises to the largest exactly-dividing unit (§10)', () => {
    expect(canonicalDuration({ count: 24, unit: 'h' })).toEqual({ count: 1, unit: 'd' });
    expect(canonicalDuration({ count: 14, unit: 'd' })).toEqual({ count: 2, unit: 'w' });
    expect(canonicalDuration({ count: 90, unit: 'd' })).toEqual({ count: 90, unit: 'd' });
    // Calendar units convert only among themselves: a month is not a number of
    // days, and no number of days is ever a month.
    expect(canonicalDuration({ count: 12, unit: 'mo' })).toEqual({ count: 1, unit: 'y' });
    expect(canonicalDuration({ count: 6, unit: 'mo' })).toEqual({ count: 6, unit: 'mo' });
    expect(canonicalDuration({ count: 30, unit: 'd' })).toEqual({ count: 30, unit: 'd' });
  });
});

describe('dates', () => {
  it('takes one ± term after now, and only one (§11 Q5)', () => {
    expect(parseDate('now')).toEqual({ relative: true });
    expect(parseDate('now-30d')?.offset).toEqual({ count: -30, unit: 'd' });
    expect(parseDate('now+7d')?.offset).toEqual({ count: 7, unit: 'd' });
    expect(parseDate('now-1mo-15d')).toBeNull();
    expect(parseDate('now*30d')).toBeNull();
    expect(parseDate('soon')).toBeNull();
  });

  it('takes the five ISO spellings and validates the components', () => {
    expect(parseDate('2026-09-11')?.dateOnly).toBe(true);
    expect(parseDate('2026-09-11T14:30:00Z')?.absolute?.toISOString()).toBe(
      '2026-09-11T14:30:00.000Z',
    );
    expect(parseDate('2026-09-11T14:30:00+02:00')?.absolute?.toISOString()).toBe(
      '2026-09-11T12:30:00.000Z',
    );
    expect(parseDate('2026-09-11T14:30')?.absolute?.toISOString()).toBe(
      '2026-09-11T14:30:00.000Z',
    );
    // A date that does not exist is not a date, however well-shaped.
    expect(parseDate('2026-02-30')).toBeNull();
    expect(parseDate('2026-13-01')).toBeNull();
    expect(parseDate('2026-09-11T25:00:00Z')).toBeNull();
  });

  it('renders a relative date canonically', () => {
    expect(dateText(parseDate('now-24h') as never)).toBe('now-1d');
    expect(dateText(parseDate('now+90d') as never)).toBe('now+90d');
    expect(dateText(parseDate('now') as never)).toBe('now');
  });
});

describe('uuid and inet', () => {
  it('recognises a canonical uuid only', () => {
    expect(parseUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(parseUUID('550e8400e29b41d4a716446655440000')).toBe(false);
    expect(parseUUID('not-a-uuid')).toBe(false);
  });

  it('recognises addresses and CIDR blocks', () => {
    expect(parseInet('198.51.100.7')).toEqual({ isCIDR: false });
    expect(parseInet('198.51.100.0/24')).toEqual({ isCIDR: true });
    expect(parseInet('2001:db8::1')).toEqual({ isCIDR: false });
    expect(parseInet('2001:db8::/32')).toEqual({ isCIDR: true });
    expect(parseInet('198.51.100.7/33')).toBeNull();
    expect(parseInet('198.51.100.256')).toBeNull();
    expect(parseInet('198.51.100')).toBeNull();
  });
});

describe('quoting (§10)', () => {
  it('quotes a value iff it is not a safe bareword', () => {
    expect(isSafeBareword('production')).toBe(true);
    expect(isSafeBareword('aa:bb:cc')).toBe(true);
    expect(isSafeBareword('has space')).toBe(false);
    // A value spelled like a keyword must be quoted, or it re-lexes as one.
    expect(isSafeBareword('and')).toBe(false);
    expect(isSafeBareword('')).toBe(false);
  });

  it('quotes free text more eagerly than a value', () => {
    // `a:b` is a fine VALUE but, written alone, it is a field and a value.
    expect(isSafeFreeText('payroll')).toBe(true);
    expect(isSafeFreeText('a:b')).toBe(false);
    expect(isSafeFreeText('web.01')).toBe(false);
    // A leading "-" is negation at the start of a term.
    expect(isSafeFreeText('-0')).toBe(false);
    // Not an identifier start, so the path rules do not apply.
    expect(isSafeFreeText('198.51.100.7')).toBe(true);
  });

  it('keeps the quotes that carry meaning', () => {
    // Unquoting a literal asterisk would turn it into a wildcard.
    expect(quoteLiteral({ form: 'string', value: 'five*', span: { start: 0, end: 0 } })).toBe(
      '"five*"',
    );
    // Unquoting a date-shaped string would turn a hostname into an instant, and
    // then rewrite it: `"now-24h"` → `now-24h` → `now-1d` is a different
    // predicate that still parses (§13 S7).
    expect(quoteLiteral({ form: 'string', value: 'now-24h', span: { start: 0, end: 0 } })).toBe(
      '"now-24h"',
    );
    // Free text is a substring search and can never be an instant, so there the
    // same text is unquoted and NOT rewritten.
    expect(quoteFreeText({ form: 'string', value: 'now-24h', span: { start: 0, end: 0 } })).toBe(
      'now-24h',
    );
  });

  it('escapes control characters as \\uXXXX', () => {
    expect(quote('a\nb')).toBe('"a\\nb"');
    expect(quote('ab')).toBe('"a\\u0001b"');
    expect(quote('say "hi"')).toBe('"say \\"hi\\""');
  });
});

describe('the two caps use different units on purpose (§6)', () => {
  // §6: "Query text ≤ 4096 bytes (not characters — the two caps in these
  // adjacent rows use different units on purpose)" and "pattern ≤ 256
  // characters". The conformance file is pure ASCII, so it cannot tell the
  // difference. A port that measured both with `String.length` would pass every
  // fixture and then disagree with the server on the first accented hostname.
  it('measures the query cap in UTF-8 bytes', () => {
    expect(utf8ByteLength('abc')).toBe(3);
    expect(utf8ByteLength('é')).toBe(2);
    expect(utf8ByteLength('日')).toBe(3);
    expect(utf8ByteLength('😀')).toBe(4);
    // The divergence that matters: four code units, ten bytes.
    expect('éé日😀'.length).toBe(5);
    expect(utf8ByteLength('éé日😀')).toBe(11);
  });
});

describe('version sort key (§5.5)', () => {
  it('sorts component-wise, never lexically', () => {
    const a = versionSortKey('1.1.1w') as string;
    const b = versionSortKey('3.0.2') as string;
    expect(a < b).toBe(true);
    // The lexical comparison this replaces gets it backwards.
    expect('1.1.1w' < '3.0.2').toBe(true);
    expect((versionSortKey('1.9') as string) < (versionSortKey('1.10') as string)).toBe(true);
    expect('1.9' < '1.10').toBe(false);
  });

  it('puts a shorter version below a longer one with the same prefix', () => {
    expect((versionSortKey('3.0') as string) < (versionSortKey('3.0.2') as string)).toBe(true);
  });

  it('sorts a pre-release below its release', () => {
    expect((versionSortKey('1.0.0-rc1') as string) < (versionSortKey('1.0.0') as string)).toBe(true);
  });

  it('has no key for a string with no numeric component', () => {
    // No key means a NULL column, and every comparison against it is UNKNOWN —
    // which is the point (§5.2), not a fallback to string order.
    expect(versionSortKey('unknown')).toBeNull();
    expect(versionSortKey('')).toBeNull();
    expect(looksLikeVersion('3.0')).toBe(true);
    expect(looksLikeVersion('v3.0')).toBe(true);
    expect(looksLikeVersion('unknown')).toBe(false);
  });
});
