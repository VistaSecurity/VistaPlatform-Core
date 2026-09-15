// Literal parsing, bounds and canonical quoting (§2, §5.5, §10).
//
// Classification happens at validation time against the field's declared type,
// never at parse time: the same text is a number for one field and a keyword
// for another. Everything here is a pure predicate over the written text.

import type { Literal } from './ast';

/**
 * Reports whether the literal carries a `*` metacharacter, which only a bare
 * literal can (§3).
 */
export function isWildcard(l: Literal): boolean {
  return l.form === 'bare' && l.value.includes('*');
}

/**
 * Reports whether the literal is exactly `*`, the "present at all" spelling of
 * exists (§3 cheat sheet).
 */
export function isBareStar(l: Literal): boolean {
  return l.form === 'bare' && l.value === '*';
}

/**
 * Parses a number literal per §2: an optional sign, digits, and an optional
 * fractional part. No exponents in v1.
 */
export function parseNumber(s: string): number | null {
  if (s === '') return null;
  const body = s.startsWith('-') ? s.slice(1) : s;
  if (body === '') return null;
  let dots = 0;
  for (const r of body) {
    if (r >= '0' && r <= '9') continue;
    if (r === '.') {
      dots++;
      if (dots > 1) return null;
      continue;
    }
    return null;
  }
  if (body.startsWith('.') || body.endsWith('.')) return null;
  const f = Number(s);
  return Number.isFinite(f) ? f : null;
}

/**
 * Parses the two boolean literals. `t` and `yes` are deliberately not accepted
 * (§2).
 */
export function parseBool(s: string): boolean | null {
  switch (s.toLowerCase()) {
    case 'true':
      return true;
    case 'false':
      return false;
    default:
      return null;
  }
}

/**
 * One of the seven duration units. `mo` and `y` are calendar units; the rest
 * are exact multiples of a second.
 */
export type DurationUnit = 's' | 'm' | 'h' | 'd' | 'w' | 'mo' | 'y';

/**
 * Every accepted spelling mapped to its unit. Longest match wins, so `mo` is
 * months and `m` is minutes.
 */
const DURATION_ALIASES: Readonly<Record<string, DurationUnit>> = {
  s: 's', sec: 's', secs: 's', second: 's', seconds: 's',
  m: 'm', min: 'm', mins: 'm', minute: 'm', minutes: 'm',
  h: 'h', hr: 'h', hrs: 'h', hour: 'h', hours: 'h',
  d: 'd', day: 'd', days: 'd',
  w: 'w', week: 'w', weeks: 'w',
  mo: 'mo', month: 'mo', months: 'mo',
  y: 'y', year: 'y', years: 'y',
};

/** A parsed duration literal: a signed count of one unit. */
export interface Duration {
  count: number;
  unit: DurationUnit;
}

/**
 * Bounds a duration literal, in years (§13 A5).
 *
 * Without a bound, `now-200000d` is 1.7e10 seconds and Go's
 * `time.Duration(count) * time.Second` overflowed int64 — so "two hundred
 * thousand days ago" silently WRAPPED to an instant in the future, and
 * `last_seen < now-200000d` returned every asset instead of none. JavaScript
 * would not overflow in the same way, but the bound is part of the language: a
 * port that accepted `now-200000d` would validate a query the server refuses.
 */
export const MAX_DURATION_YEARS = 100;

/** MAX_DURATION_YEARS expressed in each unit. */
const MAX_COUNT_PER_UNIT: Readonly<Record<DurationUnit, number>> = {
  s: MAX_DURATION_YEARS * 365 * 24 * 60 * 60,
  m: MAX_DURATION_YEARS * 365 * 24 * 60,
  h: MAX_DURATION_YEARS * 365 * 24,
  d: MAX_DURATION_YEARS * 365,
  w: Math.trunc((MAX_DURATION_YEARS * 365) / 7),
  mo: MAX_DURATION_YEARS * 12,
  y: MAX_DURATION_YEARS,
};

/**
 * Reports whether d is inside MAX_DURATION_YEARS. parseDuration enforces it,
 * but a Duration is an ordinary object anyone can build, and applyDuration must
 * not wrap for one that was not parsed.
 */
export function durationWithinBounds(d: Duration): boolean {
  const max = MAX_COUNT_PER_UNIT[d.unit];
  if (max === undefined) return false;
  return d.count <= max && d.count >= -max;
}

/**
 * Parses a duration literal (§2). The unit is required; a bare number is a
 * number, not a duration. A count past MAX_DURATION_YEARS is refused, so the
 * validator reports type_mismatch rather than the arithmetic wrapping silently.
 */
export function parseDuration(s: string): Duration | null {
  if (s === '') return null;
  let i = 0;
  if (s[0] === '-' || s[0] === '+') i = 1;
  const start = i;
  while (i < s.length && s[i] >= '0' && s[i] <= '9') i++;
  if (i === start || i === s.length) return null;
  const n = Number.parseInt(s.slice(0, i), 10);
  if (!Number.isSafeInteger(n)) return null;
  const unit = DURATION_ALIASES[s.slice(i).toLowerCase()];
  if (unit === undefined) return null;
  const d: Duration = { count: n, unit };
  return durationWithinBounds(d) ? d : null;
}

/** The exact second count of the non-calendar units. */
const SECONDS_PER_UNIT: Readonly<Partial<Record<DurationUnit, number>>> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
};

/** Walked largest-first when canonicalising a duration. */
const EXACT_LADDER: readonly DurationUnit[] = ['w', 'd', 'h', 'm', 's'];

/**
 * Returns the duration written in the largest unit that represents it exactly
 * (§10: `24h` → `1d`; `90d` stays `90d`). Calendar units convert only between
 * themselves (`12mo` → `1y`), never to or from days, because a month is not a
 * fixed number of days.
 */
export function canonicalDuration(d: Duration): Duration {
  if (d.unit === 'mo') {
    if (d.count % 12 === 0) return { count: d.count / 12, unit: 'y' };
    return d;
  }
  if (d.unit === 'y') return d;
  const secs = d.count * (SECONDS_PER_UNIT[d.unit] as number);
  for (const u of EXACT_LADDER) {
    const per = SECONDS_PER_UNIT[u] as number;
    if (secs % per === 0) return { count: secs / per, unit: u };
  }
  return d;
}

/** Renders the duration in its own unit. */
export function durationText(d: Duration): string {
  return String(d.count) + d.unit;
}

/**
 * Adds the duration to t, using UTC arithmetic for s/m/h/d/w and calendar
 * arithmetic for mo/y (§5.5). Calendar arithmetic clamps to the last day of the
 * target month, matching Postgres minus one month is.
 */
export function applyDuration(d: Duration, t: Date): Date {
  if (!durationWithinBounds(d)) return t;
  const per = SECONDS_PER_UNIT[d.unit];
  if (per !== undefined) return new Date(t.getTime() + d.count * per * 1000);
  let months = d.count;
  if (d.unit === 'y') months *= 12;
  return addMonthsClamped(t, months);
}

function addMonthsClamped(t: Date, n: number): Date {
  const year = t.getUTCFullYear();
  const month = t.getUTCMonth();
  let day = t.getUTCDate();
  const total = month + n;
  const newYear = year + floorDiv(total, 12);
  const newMonth = floorMod(total, 12);
  const last = daysInMonth(newYear, newMonth);
  if (day > last) day = last;
  return new Date(
    Date.UTC(
      newYear,
      newMonth,
      day,
      t.getUTCHours(),
      t.getUTCMinutes(),
      t.getUTCSeconds(),
      t.getUTCMilliseconds(),
    ),
  );
}

function floorDiv(a: number, b: number): number {
  return Math.floor(a / b);
}

function floorMod(a: number, b: number): number {
  return a - floorDiv(a, b) * b;
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
}

/**
 * A parsed date or timestamp literal. Relative dates carry the `now` anchor and
 * at most one duration term (§2: no chaining).
 */
export interface DateLiteral {
  /** True for `now`, `now-30d`, `now+7d`. */
  relative: boolean;
  /** The single ± term; absent when the literal is bare `now`. */
  offset?: Duration;
  /** The parsed instant for a non-relative literal. */
  absolute?: Date;
  /** Records that the source was `` with no time part. */
  dateOnly?: boolean;
}

// The accepted absolute spellings (§2: ISO 8601), mirroring Go's layouts:
// ·  2006-01-02T15:04:05Z07:00 ·  2006-01-02T15:04:05
//   2006-01-02T15:04Z07:00  ·  2006-01-02T15:04
// A fractional second after the seconds field is accepted whether or not the
// layout names one, which is what Go's time.Parse does.
const DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const DATE_TIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?$/;

/**
 * Parses a date literal. It accepts exactly one ± duration term after `now`;
 * `now-1mo-15d` is rejected (§11 Q5).
 */
export function parseDate(s: string): DateLiteral | null {
  const lower = s.toLowerCase();
  if (lower.startsWith('now')) {
    const rest = lower.slice(3);
    if (rest === '') return { relative: true };
    if (rest[0] !== '+' && rest[0] !== '-') return null;
    const sign = rest[0] === '-' ? -1 : 1;
    const term = rest.slice(1);
    // Exactly one term: a second sign anywhere in the remainder is a chain.
    if (term.includes('+') || term.includes('-')) return null;
    const d = parseDuration(term);
    if (d === null || d.count < 0) return null;
    return { relative: true, offset: { count: d.count * sign, unit: d.unit } };
  }

  const dateOnly = DATE_ONLY_RE.exec(s);
  if (dateOnly !== null) {
    const abs = utcFromParts(+dateOnly[1], +dateOnly[2], +dateOnly[3], 0, 0, 0);
    return abs === null ? null : { relative: false, absolute: abs, dateOnly: true };
  }

  const m = DATE_TIME_RE.exec(s);
  if (m === null) return null;
  const abs = utcFromParts(+m[1], +m[2], +m[3], +m[4], +m[5], m[6] === undefined ? 0 : +m[6]);
  if (abs === null) return null;
  let ms = abs.getTime();
  if (m[7] !== undefined) ms += Math.round(Number(m[7]) * 1000);
  if (m[8] !== undefined && m[8] !== 'Z') {
    const zoneSign = m[8][0] === '-' ? -1 : 1;
    const zh = Number(m[8].slice(1, 3));
    const zm = Number(m[8].slice(4, 6));
    if (zh > 23 || zm > 59) return null;
    ms -= zoneSign * (zh * 3600 + zm * 60) * 1000;
  }
  return { relative: false, absolute: new Date(ms) };
}

/** Builds a UTC instant, rejecting out-of-range components the way Go does. */
function utcFromParts(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
): Date | null {
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month - 1)) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}

/**
 * Turns the literal into an instant. `now` is the statement timestamp,
 * evaluated once per query (§5.5).
 */
export function resolveDate(d: DateLiteral, now: Date): Date {
  if (!d.relative) return d.absolute as Date;
  if (d.offset === undefined) return now;
  return applyDuration(d.offset, now);
}

/** Renders the date literal in canonical form. */
export function dateText(d: DateLiteral): string {
  if (d.relative) {
    if (d.offset === undefined) return 'now';
    const c = canonicalDuration(d.offset);
    if (c.count < 0) return 'now-' + durationText({ count: -c.count, unit: c.unit });
    return 'now+' + durationText(c);
  }
  const abs = d.absolute as Date;
  if (d.dateOnly === true) return abs.toISOString().slice(0, 10);
  return abs.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Reports whether s is a canonical 8-4-4-4-12 hex uuid. */
export function parseUUID(s: string): boolean {
  if (s.length !== 36) return false;
  for (let i = 0; i < 36; i++) {
    const c = s[i];
    if (i === 8 || i === 13 || i === 18 || i === 23) {
      if (c !== '-') return false;
      continue;
    }
    if (!isHex(c)) return false;
  }
  return true;
}

function isHex(c: string): boolean {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
 * Reports whether s is an IPv4/IPv6 address or CIDR block, and whether it
 * carries a prefix length. The check is deliberately structural so the error
 * message can name what was wrong.
 */
export function parseInet(s: string): { isCIDR: boolean } | null {
  let host = s;
  let isCIDR = false;
  const i = s.lastIndexOf('/');
  if (i >= 0) {
    host = s.slice(0, i);
    const prefix = s.slice(i + 1);
    if (prefix === '' || !/^\d+$/.test(prefix)) return null;
    const n = Number.parseInt(prefix, 10);
    const max = host.includes(':') ? 128 : 32;
    if (n < 0 || n > max) return null;
    isCIDR = true;
  }
  const ok = host.includes(':') ? isIPv6(host) : isIPv4(host);
  return ok ? { isCIDR } : null;
}

function isIPv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (p === '' || p.length > 3 || !/^\d+$/.test(p)) return false;
    const n = Number.parseInt(p, 10);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function isIPv6(s: string): boolean {
  if (countOccurrences(s, '::') > 1) return false;
  const groups = s.split('::').join(':').split(':');
  let seen = 0;
  for (const g of groups) {
    if (g === '') continue;
    if (g.length > 4) return false;
    for (const c of g) if (!isHex(c)) return false;
    seen++;
  }
  if (s.includes('::')) return seen <= 8;
  return seen === 8;
}

function countOccurrences(s: string, sub: string): number {
  let n = 0;
  let from = 0;
  for (;;) {
    const i = s.indexOf(sub, from);
    if (i < 0) return n;
    n++;
    from = i + sub.length;
  }
}

/** The bare-value character set from §2, beyond alphanumerics. */
const BARE_VALUE_CHARS = '_.:/%*@+#-';

/** Reports whether a code point may appear in a bare value. */
export function isBareValueChar(r: string): boolean {
  if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) return true;
  return r.length === 1 && BARE_VALUE_CHARS.includes(r);
}

/**
 * Reports whether v can be written without quotes: every rune is a bare-value
 * character and it is not a keyword that would re-lex as one.
 */
export function isSafeBareword(v: string): boolean {
  if (v === '') return false;
  for (const r of v) if (!isBareValueChar(r)) return false;
  return !isKeyword(v);
}

/** The reserved words (§2). A value spelled like one must be quoted. */
const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'to', 'exists']);

/** Reports whether s is a reserved word, case-insensitively. */
export function isKeyword(s: string): boolean {
  return KEYWORDS.has(s.toLowerCase());
}

/** The reserved words, for autocomplete. */
export const KEYWORD_LIST: readonly string[] = ['and', 'or', 'not', 'in', 'to', 'exists'];

/**
 * Reports whether a free-text value can be written without quotes and still
 * re-lex as free text.
 *
 * It is stricter than isSafeBareword because a free-text term sits where a
 * field could: `a:b` is a perfectly good bare VALUE but, written on its own, it
 * is a field and a value, and `web.01` is the beginning of a field path. A
 * value that starts like an identifier and carries a "." or a ":" is therefore
 * quoted in canonical form — the alternative is a canonical form that means
 * something else when it is read back.
 */
export function isSafeFreeText(v: string): boolean {
  if (!isSafeBareword(v)) return false;
  const r = v[0];
  if (r === '-') {
    // A leading "-" is negation at the start of a term, so `-0` would come back
    // as `not 0`.
    return false;
  }
  if (r !== '_' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z')) return true;
  // The leading identifier run is lexed on its own at the start of a term, so a
  // value like `not#` would come back as a negation of `#`.
  if (isKeyword(leadingIdentifier(v))) return false;
  return !v.includes('.') && !v.includes(':');
}

/** Returns the run of identifier characters v starts with. */
function leadingIdentifier(v: string): string {
  let i = 0;
  while (i < v.length) {
    const c = v[i];
    if (c === '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
      i++;
      continue;
    }
    break;
  }
  return v.slice(0, i);
}

/**
 * Renders v as a double-quoted string with §2's escapes, whether or not it
 * would also be safe bare.
 */
export function quote(v: string): string {
  let b = '"';
  for (const r of v) {
    switch (r) {
      case '"':
        b += '\\"';
        continue;
      case '\\':
        b += '\\\\';
        continue;
      case '\n':
        b += '\\n';
        continue;
      case '\t':
        b += '\\t';
        continue;
      case '\r':
        b += '\\r';
        continue;
      default:
        break;
    }
    const code = r.codePointAt(0) as number;
    if (code < 0x20) {
      b += '\\u' + code.toString(16).padStart(4, '0');
      continue;
    }
    b += r;
  }
  return b + '"';
}

/**
 * Renders v as a query literal, quoting it iff it is not a safe bareword (§10).
 * The canonical quote is `"`.
 */
export function quoteValue(v: string): string {
  return isSafeBareword(v) ? v : quote(v);
}

/**
 * Returns a literal's value in canonical form: a relative date is rewritten
 * into the largest unit that represents it exactly (§10, `24h` → `1d`), and
 * everything else is returned verbatim.
 *
 * Both the formatter and the compact JSON encoding go through this, so two
 * spellings of the same instant produce the same canonical text AND the same
 * encoded tree. Without that, format would be a rewrite the round-trip test
 * could not see through.
 */
export function canonicalText(l: Literal): string {
  // A QUOTED literal is never rewritten. The formatter is type-free, so it
  // cannot tell a date from a string that looks like one — and
  // `hostname="now-24h"` is a hostname, not an instant.
  if (l.form !== 'bare') return l.value;
  if (!l.value.toLowerCase().startsWith('now')) return l.value;
  // Only a literal that actually carries a duration is rewritten. A bare `now`
  // is left exactly as written, because the formatter does not know the field's
  // type and `noW` on a case-sensitive comparison is a different value.
  const d = parseDate(l.value);
  if (d !== null && d.relative && d.offset !== undefined) return dateText(d);
  return l.value;
}

/**
 * Renders a literal in canonical form.
 *
 * A quoted literal keeps its quotes whenever dropping them would change what
 * the text means rather than how it is spelled. Two cases: it contains `*`,
 * which bare would be a wildcard rather than an asterisk; or it is shaped like
 * `now±<duration>`, which bare is a relative date and would then be rewritten.
 */
export function quoteLiteral(l: Literal): string {
  if (l.form === 'string' && (l.value.includes('*') || isRelativeDateText(l.value))) {
    return quote(l.value);
  }
  return quoteValue(canonicalText(l));
}

/**
 * Reports whether text bare would parse as `now±<duration>` — the one literal
 * shape the formatter rewrites.
 */
function isRelativeDateText(v: string): boolean {
  if (!v.toLowerCase().startsWith('now')) return false;
  const d = parseDate(v);
  return d !== null && d.relative && d.offset !== undefined;
}

/**
 * Renders a free-text literal in canonical form. Unlike a value, a free-text
 * `*` is an ordinary character (§5.4 is a substring search), so quoting is
 * purely lexical here and the two spellings mean the same thing.
 *
 * Free text is never date-canonicalised: §5.4 is a substring search over names,
 * identifiers and tags — it can never be an instant.
 */
export function quoteFreeText(l: Literal): string {
  return isSafeFreeText(l.value) ? l.value : quote(l.value);
}

/** Reports whether s matches the identifier production (§2). */
export function isIdentifier(s: string): boolean {
  if (s === '') return false;
  for (let i = 0; i < s.length; i++) {
    const r = s[i];
    if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r === '_') continue;
    if (r >= '0' && r <= '9') {
      if (i === 0) return false;
      continue;
    }
    return false;
  }
  return true;
}
