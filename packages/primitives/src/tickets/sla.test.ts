import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SLA_DAYS,
  DUE_SOON_DAYS,
  defaultDueDate,
  dueDateIn,
  fromDateInput,
  isLongHorizon,
  toDateInput,
} from './sla';

const FIXED = new Date('2026-03-10T09:30:00.000Z');

describe('ticket SLA defaults', () => {
  it('never files a ticket that is already due-soon', () => {
    // The reason the shortest default is 7 days and not 1 or 2. A ticket born
    // inside the backend's 3-day due-soon window would show up warning on the
    // queue the moment it was filed, which trains people to ignore the colour.
    for (const days of Object.values(DEFAULT_SLA_DAYS)) {
      expect(days).toBeGreaterThan(DUE_SOON_DAYS);
    }
  });

  it('gives a more urgent priority a nearer date', () => {
    expect(DEFAULT_SLA_DAYS.critical).toBeLessThan(DEFAULT_SLA_DAYS.high);
    expect(DEFAULT_SLA_DAYS.high).toBeLessThan(DEFAULT_SLA_DAYS.medium);
    expect(DEFAULT_SLA_DAYS.medium).toBeLessThan(DEFAULT_SLA_DAYS.low);
  });

  it('computes the due date from the priority', () => {
    expect(defaultDueDate('critical', FIXED).slice(0, 10)).toBe('2026-03-17');
    expect(defaultDueDate('low', FIXED).slice(0, 10)).toBe('2026-05-09');
  });

  it('falls back to the medium window rather than to no due date', () => {
    // No due date is the state this whole mechanism exists to end -- a ticket
    // without one is invisible to every SLA view. An unknown priority must
    // still get a date.
    expect(defaultDueDate('urgent', FIXED)).toBe(defaultDueDate('medium', FIXED));
    expect(defaultDueDate(undefined, FIXED)).toBe(defaultDueDate('medium', FIXED));
    expect(defaultDueDate(null, FIXED)).toBe(defaultDueDate('medium', FIXED));
  });

  it('crosses month and year boundaries correctly', () => {
    expect(dueDateIn(30, new Date('2026-12-20T00:00:00.000Z')).slice(0, 10)).toBe('2027-01-19');
    // 2028 is a leap year: 29 Feb must exist rather than roll to 1 March.
    expect(dueDateIn(1, new Date('2028-02-28T00:00:00.000Z')).slice(0, 10)).toBe('2028-02-29');
  });

  it('round-trips a date input without slipping a day', () => {
    // Midday UTC, not midnight. Midnight lands on the previous calendar day
    // for anyone west of Greenwich, so a ticket typed as due the 30th would
    // render as the 29th and go overdue a day early across the Americas.
    const iso = fromDateInput('2026-03-30');
    expect(iso).not.toBeNull();
    expect(toDateInput(iso)).toBe('2026-03-30');
    expect(iso!).toContain('T12:00:00');
  });

  it('treats an empty date field as no due date', () => {
    expect(fromDateInput('')).toBeNull();
    expect(toDateInput(null)).toBe('');
    expect(toDateInput(undefined)).toBe('');
  });

  it('returns empty rather than Invalid Date for unparseable input', () => {
    expect(toDateInput('not-a-date')).toBe('');
    expect(fromDateInput('not-a-date')).toBeNull();
  });

  it('knows which categories are project-scale work', () => {
    expect(isLongHorizon('pqc')).toBe(true);
    expect(isLongHorizon('lifecycle')).toBe(true);
    expect(isLongHorizon('crypto')).toBe(false);
    expect(isLongHorizon(undefined)).toBe(false);
  });
});
