// Default due dates by priority.
//
// Every ticket in the system had `due_date = NULL` before: neither the
// findings path, the bulk-crypto path nor the alert path ever sent one, and
// there was no create form to type one into. The consequence was not a blank
// column — it was that a whole layer built on both sides did nothing. The work
// queue's Overdue / Due soon / "Keeping pace" cards read 0 / 0 / 100%
// permanently, and the backend's hourly sweep for overdue and due-soon tickets,
// with its `ticket_overdue` and `ticket_due_soon` notifications, had no row it
// could ever act on.
//
// So an automatically-created ticket needs a due date, which means a default,
// which means a policy. This is that policy, in one place, deliberately
// conservative and deliberately overridable: the create form pre-fills from it
// and the user can change the date before filing, and the drawer can move it
// afterwards.
//
// These are NOT a rating scale and do not belong in `shared/severity` or
// `shared/riskbands` — those map a score to a word. This maps a word to a
// number of days, which is an operational commitment about how quickly work
// should happen, not a judgement about how bad something is.

import type { TicketCategory } from './categories';

/** Ticket priority, the vocabulary the `tickets` table enforces. */
export type TicketPriority = 'low' | 'medium' | 'high' | 'critical';

/**
 * Days from creation to the default due date, by priority.
 *
 * Chosen to sit either side of the backend's fixed 3-day "due soon" window so
 * that a freshly-filed ticket is never born already warning: the shortest
 * default is 7 days, which leaves four clear days before it starts nagging.
 */
export const DEFAULT_SLA_DAYS: Record<TicketPriority, number> = {
  critical: 7,
  high: 14,
  medium: 30,
  low: 60,
};

/** The window the backend's due-soon sweep uses. Mirrored, not owned, here. */
export const DUE_SOON_DAYS = 3;

/** `days` from `from`, as an RFC 3339 string — what the API expects. */
export function dueDateIn(days: number, from: Date = new Date()): string {
  const d = new Date(from.getTime());
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

/**
 * The default due date for a ticket of this priority, RFC 3339.
 *
 * An unrecognised priority falls back to the `medium` window rather than to no
 * due date: a ticket with no due date is invisible to every SLA view, which is
 * the failure this whole mechanism exists to end.
 */
export function defaultDueDate(priority: string | undefined | null, from: Date = new Date()): string {
  const days = DEFAULT_SLA_DAYS[(priority ?? '') as TicketPriority] ?? DEFAULT_SLA_DAYS.medium;
  return dueDateIn(days, from);
}

/** `YYYY-MM-DD` for a date input, from an RFC 3339 string. */
export function toDateInput(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

/**
 * A `YYYY-MM-DD` date input back to RFC 3339, or null for an empty field.
 *
 * Midday UTC, not midnight: a due date is a day, not an instant, and midnight
 * UTC lands on the previous calendar day for anyone west of Greenwich — so a
 * ticket typed as due the 30th would show as due the 29th and go overdue a day
 * early for every user in the Americas.
 */
export function fromDateInput(value: string): string | null {
  if (!value) return null;
  const d = new Date(`${value}T12:00:00.000Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Categories whose work is typically slower than its priority suggests. */
const LONG_HORIZON: readonly TicketCategory[] = ['pqc', 'lifecycle'];

/**
 * Whether this category's remediation is a project rather than a task.
 *
 * PQC migration and end-of-life replacement are procurement-and-planning work
 * measured in quarters; the create form uses this to explain why it is not
 * pre-filling an aggressive date, rather than to silently pick a different one.
 * The date stays the caller's decision.
 */
export function isLongHorizon(category: string | undefined | null): boolean {
  return LONG_HORIZON.includes(category as TicketCategory);
}
