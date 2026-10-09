// Plain-language cadences for scheduled scans, and the cron they compile to.
//
// The schedule API stores a cron expression (cron_expression) that
// device-interrogation-service parses with robfig/cron v3 — five fields, no
// seconds, no @descriptors. That parser also accepts a `CRON_TZ=<IANA zone> `
// prefix, which is how a picked "2:00 AM" means 2:00 AM where the person is
// rather than in the server's zone. An expression WITHOUT the prefix runs in
// the service's local zone, which is UTC in the shipped images; those are
// round-tripped untouched (timeZone '') so editing a legacy schedule never
// silently moves it.
//
// Anything the picker cannot express parses as frequency 'custom' and is kept
// verbatim — the cron field stays available for people who want it.

export type Frequency = 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom';

export interface Cadence {
  frequency: Frequency;
  /** hourly: run every N hours (one of HOUR_INTERVALS). */
  everyHours: number;
  /** 0–59. */
  minute: number;
  /** 0–23 (daily / weekly / monthly). */
  hour: number;
  /** weekly: cron day numbers, 0 = Sunday … 6 = Saturday. */
  weekdays: number[];
  /** monthly: 1–28 (29–31 would skip short months). */
  dayOfMonth: number;
  /** IANA zone written as CRON_TZ; '' = no prefix (server time, UTC). */
  timeZone: string;
  /** custom: the raw expression, including any TZ prefix. */
  expression: string;
}

export const HOUR_INTERVALS = [1, 2, 3, 4, 6, 8, 12] as const;
export const MAX_DAY_OF_MONTH = 28;
/** Display order for the day picker: Monday first. Values are cron day numbers. */
export const WEEKDAY_ORDER = [1, 2, 3, 4, 5, 6, 0] as const;
const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
export const DAY_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export function browserTimeZone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return tz && tz !== 'Etc/Unknown' ? tz : 'UTC';
  } catch {
    return 'UTC';
  }
}

/** The starting point for a new schedule: daily at 02:00 in the person's zone. */
export function defaultCadence(timeZone = browserTimeZone()): Cadence {
  return { frequency: 'daily', everyHours: 6, minute: 0, hour: 2, weekdays: [1, 2, 3, 4, 5], dayOfMonth: 1, timeZone, expression: '' };
}

function splitZone(expr: string): { zone: string; body: string } | null {
  const trimmed = expr.trim();
  const m = /^(?:CRON_)?TZ=(\S+)\s+(.*)$/.exec(trimmed);
  if (m) return { zone: m[1], body: m[2].trim() };
  if (/^(?:CRON_)?TZ=/.test(trimmed)) return null;
  return { zone: '', body: trimmed };
}

const isInt = (s: string) => /^\d+$/.test(s);
const inRange = (s: string, lo: number, hi: number) => isInt(s) && Number(s) >= lo && Number(s) <= hi;

/** A list of plain day numbers or ranges ("1-5", "1,3,5", "0,6") → sorted unique days, or null. */
function parseDays(field: string): number[] | null {
  const days = new Set<number>();
  for (const part of field.split(',')) {
    const range = /^(\d)-(\d)$/.exec(part);
    if (range) {
      const [a, b] = [Number(range[1]), Number(range[2])];
      if (a > b || b > 6) return null;
      for (let d = a; d <= b; d++) days.add(d);
    } else if (inRange(part, 0, 6)) {
      days.add(Number(part));
    } else {
      return null;
    }
  }
  return [...days].sort((a, b) => a - b);
}

/** Read a stored expression back into the picker; anything unrecognised is 'custom'. */
export function parseCron(expr: string): Cadence {
  const custom: Cadence = { ...defaultCadence(''), frequency: 'custom', expression: expr.trim() };
  const split = splitZone(expr);
  if (!split) return custom;
  const fields = split.body.split(/\s+/);
  if (fields.length !== 5) return custom;
  const [min, hr, dom, mon, dow] = fields;
  if (!inRange(min, 0, 59) || mon !== '*') return custom;
  const base = { ...defaultCadence(split.zone), minute: Number(min), expression: '' };

  if (dom === '*' && dow === '*') {
    if (hr === '*') return { ...base, frequency: 'hourly', everyHours: 1 };
    const step = /^\*\/(\d+)$/.exec(hr);
    if (step && (HOUR_INTERVALS as readonly number[]).includes(Number(step[1]))) {
      return { ...base, frequency: 'hourly', everyHours: Number(step[1]) };
    }
  }
  if (!inRange(hr, 0, 23)) return custom;
  const hour = Number(hr);
  if (dom === '*' && dow === '*') return { ...base, frequency: 'daily', hour };
  if (dom === '*') {
    const days = parseDays(dow);
    return days && days.length ? { ...base, frequency: 'weekly', hour, weekdays: days } : custom;
  }
  if (dow === '*' && inRange(dom, 1, MAX_DAY_OF_MONTH)) return { ...base, frequency: 'monthly', hour, dayOfMonth: Number(dom) };
  return custom;
}

/** Compress sorted day numbers into cron ranges: [1,2,3,4,5] → "1-5", [0,6] → "0,6". */
function daysField(days: number[]): string {
  const sorted = [...new Set(days)].sort((a, b) => a - b);
  const parts: string[] = [];
  for (let i = 0; i < sorted.length; ) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
    parts.push(j - i >= 2 ? `${sorted[i]}-${sorted[j]}` : sorted.slice(i, j + 1).join(','));
    i = j + 1;
  }
  return parts.join(',');
}

export function toCron(c: Cadence): string {
  if (c.frequency === 'custom') return c.expression.trim();
  let body: string;
  switch (c.frequency) {
    case 'hourly': body = `${c.minute} ${c.everyHours === 1 ? '*' : `*/${c.everyHours}`} * * *`; break;
    case 'daily': body = `${c.minute} ${c.hour} * * *`; break;
    case 'weekly': body = `${c.minute} ${c.hour} * * ${daysField(c.weekdays)}`; break;
    case 'monthly': body = `${c.minute} ${c.hour} ${c.dayOfMonth} * *`; break;
  }
  return c.timeZone ? `CRON_TZ=${c.timeZone} ${body}` : body;
}

// ---- Validation (custom expressions) ----------------------------------------
//
// Mirrors what robfig/cron v3's standard parser accepts, so a typo is caught in
// the form instead of coming back from the API as a bare 500.

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DOWS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const FIELD_BOUNDS: { lo: number; hi: number; names?: string[]; nameBase?: number }[] = [
  { lo: 0, hi: 59 },
  { lo: 0, hi: 23 },
  { lo: 1, hi: 31 },
  { lo: 1, hi: 12, names: MONTHS, nameBase: 1 },
  { lo: 0, hi: 6, names: DOWS, nameBase: 0 },
];

function fieldValid(field: string, b: (typeof FIELD_BOUNDS)[number], allowQuestion: boolean): boolean {
  const value = (s: string): number | null => {
    if (isInt(s)) return Number(s);
    const idx = b.names?.indexOf(s.toUpperCase()) ?? -1;
    return idx >= 0 ? idx + (b.nameBase ?? 0) : null;
  };
  return field.split(',').every((item) => {
    const [range, step, ...rest] = item.split('/');
    if (rest.length || (step !== undefined && (!isInt(step) || Number(step) < 1))) return false;
    if (range === '*' || (allowQuestion && range === '?')) return true;
    const ends = range.split('-');
    if (ends.length > 2) return false;
    const nums = ends.map(value);
    if (nums.some((n) => n === null || n < b.lo || n > b.hi)) return false;
    return nums.length === 1 || (nums[0] as number) <= (nums[1] as number);
  });
}

/** Explains why an expression would be rejected, or null when it is valid. */
export function cronError(expr: string): string | null {
  if (!expr.trim()) return 'Enter a cron expression.';
  const split = splitZone(expr);
  if (!split) return 'A time-zone prefix needs a zone name, e.g. CRON_TZ=America/New_York 0 2 * * *.';
  const fields = split.body.split(/\s+/);
  if (fields.length !== 5) return `Expected 5 fields (minute hour day-of-month month day-of-week), found ${fields.length}.`;
  const names = ['minute', 'hour', 'day-of-month', 'month', 'day-of-week'];
  for (let i = 0; i < 5; i++) {
    if (!fieldValid(fields[i], FIELD_BOUNDS[i], i === 2 || i === 4)) return `The ${names[i]} field "${fields[i]}" is not valid.`;
  }
  return null;
}

export function cadenceError(c: Cadence): string | null {
  if (c.frequency === 'custom') return cronError(c.expression);
  if (c.frequency === 'weekly' && c.weekdays.length === 0) return 'Pick at least one day.';
  return null;
}

// ---- Plain-English description ----------------------------------------------

export function formatTime(hour: number, minute: number, locale?: string): string {
  return new Date(Date.UTC(2000, 0, 1, hour, minute)).toLocaleTimeString(locale, { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' });
}

function ordinal(n: number): string {
  const s = n % 100 >= 11 && n % 100 <= 13 ? 'th' : ['th', 'st', 'nd', 'rd'][n % 10] ?? 'th';
  return `${n}${s}`;
}

function joinWords(words: string[]): string {
  return words.length <= 1 ? words.join('') : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

function zoneLabel(tz: string): string {
  return tz ? tz.replace(/_/g, ' ') : 'UTC';
}

/** "Every weekday at 2:00 AM (America/Chicago)"; null when the cadence is custom. */
export function describeCadence(c: Cadence, locale?: string): string | null {
  const at = `at ${formatTime(c.hour, c.minute, locale)} (${zoneLabel(c.timeZone)})`;
  switch (c.frequency) {
    case 'hourly': {
      const past = c.minute === 0 ? 'on the hour' : `at ${c.minute} minute${c.minute === 1 ? '' : 's'} past`;
      return c.everyHours === 1 ? `Every hour, ${past}` : `Every ${c.everyHours} hours, ${past} (${zoneLabel(c.timeZone)})`;
    }
    case 'daily': return `Every day ${at}`;
    case 'weekly': {
      const days = [...new Set(c.weekdays)].sort((a, b) => a - b);
      if (days.length === 7) return `Every day ${at}`;
      if (days.join() === '1,2,3,4,5') return `Every weekday ${at}`;
      if (days.join() === '0,6') return `Every Saturday and Sunday ${at}`;
      const ordered = WEEKDAY_ORDER.filter((d) => days.includes(d)).map((d) => DAY_NAMES[d]);
      return `Every ${joinWords(ordered)} ${at}`;
    }
    case 'monthly': return `Monthly on the ${ordinal(c.dayOfMonth)} ${at}`;
    case 'custom': return null;
  }
}

/** Describe a stored expression; null when it is a custom cron the picker can't express. */
export function describeCron(expr: string, locale?: string): string | null {
  return describeCadence(parseCron(expr), locale);
}

/** Time-zone options: every zone the browser knows, plus the ones in play. */
export function timeZoneOptions(...include: string[]): string[] {
  let zones: string[];
  try {
    zones = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? [];
  } catch {
    zones = [];
  }
  const set = new Set([...zones, 'UTC', ...include.filter(Boolean)]);
  return [...set].sort((a, b) => a.localeCompare(b));
}
