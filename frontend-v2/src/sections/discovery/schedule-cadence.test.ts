import { describe, expect, it } from 'vitest';
import { type Cadence, cronError, defaultCadence, describeCron, parseCron, toCron } from './schedule-cadence';

const base = (patch: Partial<Cadence>): Cadence => ({ ...defaultCadence('America/Chicago'), ...patch });

describe('toCron', () => {
  it('compiles each frequency with the CRON_TZ prefix robfig/cron reads', () => {
    expect(toCron(base({ frequency: 'hourly', everyHours: 1, minute: 15 }))).toBe('CRON_TZ=America/Chicago 15 * * * *');
    expect(toCron(base({ frequency: 'hourly', everyHours: 6, minute: 0 }))).toBe('CRON_TZ=America/Chicago 0 */6 * * *');
    expect(toCron(base({ frequency: 'daily', hour: 2, minute: 30 }))).toBe('CRON_TZ=America/Chicago 30 2 * * *');
    expect(toCron(base({ frequency: 'weekly', hour: 2, minute: 0, weekdays: [5, 1, 2, 3, 4] }))).toBe('CRON_TZ=America/Chicago 0 2 * * 1-5');
    expect(toCron(base({ frequency: 'weekly', hour: 22, minute: 0, weekdays: [0, 6, 3] }))).toBe('CRON_TZ=America/Chicago 0 22 * * 0,3,6');
    expect(toCron(base({ frequency: 'monthly', hour: 3, minute: 0, dayOfMonth: 15 }))).toBe('CRON_TZ=America/Chicago 0 3 15 * *');
  });

  it('writes no prefix when the zone is server time, and custom verbatim', () => {
    expect(toCron(base({ frequency: 'daily', hour: 2, minute: 0, timeZone: '' }))).toBe('0 2 * * *');
    expect(toCron(base({ frequency: 'custom', expression: '  */5 9-17 * * 1-5 ' }))).toBe('*/5 9-17 * * 1-5');
  });
});

describe('parseCron', () => {
  it.each([
    'CRON_TZ=America/Chicago 15 * * * *',
    'CRON_TZ=Europe/London 0 */6 * * *',
    'CRON_TZ=Asia/Kolkata 30 2 * * *',
    'CRON_TZ=America/Chicago 0 2 * * 1-5',
    'CRON_TZ=America/Chicago 0 22 * * 0,3,6',
    'CRON_TZ=America/Chicago 0 3 15 * *',
    // Legacy schedules (no prefix) must round-trip byte-for-byte, or editing
    // the name would silently move when the scan runs.
    '0 2 * * *',
    '0 */4 * * *',
  ])('round-trips %s', (expr) => {
    const c = parseCron(expr);
    expect(c.frequency).not.toBe('custom');
    expect(toCron(c)).toBe(expr);
  });

  it('accepts the TZ= spelling too', () => {
    expect(parseCron('TZ=UTC 0 2 * * *')).toMatchObject({ frequency: 'daily', timeZone: 'UTC', hour: 2 });
  });

  it.each([
    '*/5 * * * *', // every 5 minutes — not a picker cadence
    '0 */5 * * *', // 5 is not an offered interval
    '0 9-17 * * *',
    '0 2 31 * *', // past the monthly cap
    '0 2 1 * 1', // dom AND dow (cron ORs them)
    '0 2 * 6 *',
    '0 2 * * MON',
    'nonsense',
  ])('keeps %s as custom, verbatim', (expr) => {
    expect(parseCron(expr)).toMatchObject({ frequency: 'custom', expression: expr });
  });
});

describe('describeCron', () => {
  const d = (e: string) => describeCron(e, 'en-US');
  it('reads like a sentence', () => {
    expect(d('CRON_TZ=America/New_York 0 2 * * *')).toBe('Every day at 2:00 AM (America/New York)');
    expect(d('0 2 * * *')).toBe('Every day at 2:00 AM (UTC)');
    expect(d('CRON_TZ=UTC 0 2 * * 1-5')).toBe('Every weekday at 2:00 AM (UTC)');
    expect(d('CRON_TZ=UTC 0 14 * * 0,6')).toBe('Every Saturday and Sunday at 2:00 PM (UTC)');
    expect(d('CRON_TZ=UTC 0 14 * * 0,1,3')).toBe('Every Monday, Wednesday and Sunday at 2:00 PM (UTC)');
    expect(d('CRON_TZ=UTC 0 14 * * 0-6')).toBe('Every day at 2:00 PM (UTC)');
    expect(d('CRON_TZ=UTC 5 3 1 * *')).toBe('Monthly on the 1st at 3:05 AM (UTC)');
    expect(d('CRON_TZ=UTC 5 3 22 * *')).toBe('Monthly on the 22nd at 3:05 AM (UTC)');
    expect(d('CRON_TZ=UTC 5 3 13 * *')).toBe('Monthly on the 13th at 3:05 AM (UTC)');
    expect(d('0 * * * *')).toBe('Every hour, on the hour');
    expect(d('CRON_TZ=UTC 30 */6 * * *')).toBe('Every 6 hours, at 30 minutes past (UTC)');
  });
  it('returns null for a custom expression so the caller shows the raw cron', () => {
    expect(d('*/5 * * * *')).toBeNull();
  });
});

describe('cronError', () => {
  it.each([
    '0 2 * * *', '*/5 * * * *', '0 9-17 * * 1-5', '0 0 1,15 * *', '0 0 * JAN-MAR MON-FRI',
    '0 0 ? * *', 'CRON_TZ=Europe/Berlin 0 6 * * *', '0-30/10 * * * *',
  ])('accepts %s', (expr) => expect(cronError(expr)).toBeNull());

  it.each([
    ['', /Enter/],
    ['0 2 * *', /5 fields/],
    ['0 2 * * * *', /5 fields/], // seconds field — the service parser has none
    ['60 * * * *', /minute/],
    ['0 24 * * *', /hour/],
    ['0 0 0 * *', /day-of-month/],
    ['0 0 * 13 *', /month/],
    ['0 0 * * 7', /day-of-week/], // robfig's day-of-week stops at 6
    ['0 0 * * 5-1', /day-of-week/],
    ['*/0 * * * *', /minute/],
    ['@daily', /5 fields/], // descriptors are not enabled on the service parser
    ['CRON_TZ= 0 2 * * *', /zone name/],
  ])('rejects %j', (expr, why) => expect(cronError(expr)).toMatch(why));
});
