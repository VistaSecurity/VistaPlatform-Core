// Control status, score and coverage rendering — pure module.
//
// Kept DOM-free so every rule below is unit-testable, because all three of them
// are the kind that fail silently: a wrong default reads as a green check, a
// null score coerced through Math.round() reads as 0, and a missing coverage
// line reads as "we checked everything".
//
// The model (NIST XCCDF, via the spec at
// docsv4/internal/developer/standards/features/control-status-and-not-assessed.md):
//
//   PASS         — the control was checked and nothing in scope violated it
//   FAIL         — the control was checked and something violated it, at ANY
//                  severity. Severity is the scoring WEIGHT, not the pass/fail
//                  input. There is no WARN any more; it earned no score weight
//                  either way, so it read as "not failing" while counting as a
//                  failure in the arithmetic.
//   NOT_ASSESSED — the control was not checked, so we claim nothing about it.
//                  Excluded from BOTH sides of the score fraction.
//
// The whole point of the change is that "we have not looked" and "everything
// passed" stop looking identical, so the two rules that carry it are:
//   · a null score renders "—", never 0 and never 100
//   · a not-assessed control is neutral/muted — an absence of information, not
//     a middle severity, so it must never borrow a severity colour

export type ControlStatus = 'PASS' | 'FAIL' | 'NOT_ASSESSED';

export type NotAssessedReason = 'no_measurements' | 'nothing_in_scope' | 'check_error' | 'not_evaluated';

/** The single user-facing bucket for all three not-assessed reasons (D2). */
export const NOT_ASSESSED_LABEL = 'Not assessed';

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  PASS: 'Pass',
  FAIL: 'Fail',
  NOT_ASSESSED: NOT_ASSESSED_LABEL,
};

/**
 * One sentence per reason, shown on hover. Operators need the distinction when
 * debugging; tenants get one honest bucket (D2). Wording tracks the customer
 * doc `docsv4/core/features/framework-transparency.md`.
 */
const REASON_TEXT: Record<NotAssessedReason, string> = {
  no_measurements: 'No measurement rule is configured for this control.',
  nothing_in_scope: 'Nothing in scope to check.',
  check_error: 'The check failed. This usually clears on the next evaluation.',
  not_evaluated: 'This control has not been evaluated since it last changed.',
};

/** Fallback when the server sends NOT_ASSESSED without a reason we recognise. */
const REASON_UNKNOWN = 'This control was not checked, so nothing is claimed about it.';

/**
 * Normalise a control status off the wire.
 *
 * Anything unrecognised — including a missing status — becomes NOT_ASSESSED,
 * never PASS. Defaulting an unknown to PASS is precisely the bug this change
 * exists to remove: it turns "we could not tell" into a green check.
 */
export function normalizeControlStatus(raw: string | null | undefined): ControlStatus {
  switch ((raw ?? '').trim().toUpperCase()) {
    case 'PASS':
      return 'PASS';
    case 'FAIL':
      return 'FAIL';
    default:
      return 'NOT_ASSESSED';
  }
}

/** The hover sentence explaining why a control shows "Not assessed". */
export function notAssessedReasonText(reason: string | null | undefined): string {
  const key = (reason ?? '').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(REASON_TEXT, key)
    ? REASON_TEXT[key as NotAssessedReason]
    : REASON_UNKNOWN;
}

/**
 * Render a framework score.
 *
 * A null/undefined score means no control was assessed. It renders "—" — never
 * 0 (which reads as "everything failed") and never 100 (which reads as
 * "everything passed"). `Math.round(null)` is 0, which is exactly how a
 * never-evaluated framework used to display as a hard zero.
 */
export function formatScore(score: number | null | undefined): string {
  return typeof score === 'number' && Number.isFinite(score) ? String(Math.round(score)) : '—';
}

/** True when there is no score to show, so callers can pick a muted treatment. */
export function isUnscored(score: number | null | undefined): boolean {
  return !(typeof score === 'number' && Number.isFinite(score));
}

export interface ControlCounts {
  total?: number | null;
  passing?: number | null;
  failing?: number | null;
  notAssessed?: number | null;
}

const num = (v: number | null | undefined): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/**
 * Controls that actually produced a verdict — the score's denominator.
 * Convention (pinned by the contract): passing + failing + notAssessed == total.
 */
export function assessedCount(c: ControlCounts): number {
  return num(c.passing) + num(c.failing);
}

/**
 * How many controls were skipped. Prefers the server's explicit count and falls
 * back to total - passing - failing, so a response predating the new field
 * still renders an honest coverage line rather than none.
 */
export function notAssessedCount(c: ControlCounts): number {
  if (typeof c.notAssessed === 'number' && Number.isFinite(c.notAssessed)) return Math.max(0, c.notAssessed);
  return Math.max(0, num(c.total) - assessedCount(c));
}

/**
 * True when the server actually reported a breakdown. Several endpoints send
 * every count as null until the engine has produced a rollup at all, and
 * "not computed yet" is NOT the same claim as "assessed nothing" — reporting
 * "0 of 11 assessed" for a framework nobody has evaluated yet would be its own
 * small dishonesty.
 */
export function hasControlCounts(c: ControlCounts): boolean {
  return [c.passing, c.failing, c.notAssessed].some((v) => typeof v === 'number' && Number.isFinite(v));
}

/**
 * "8 of 11 controls assessed" — shown wherever a score appears and any control
 * was skipped, so the number always comes with the size of the sample behind
 * it. Returns null when every control was assessed (nothing to disclose) or
 * when no breakdown has been reported at all.
 */
export function coverageLine(c: ControlCounts): string | null {
  if (!hasControlCounts(c)) return null;
  const skipped = notAssessedCount(c);
  if (skipped <= 0) return null;
  const assessed = assessedCount(c);
  const total = Math.max(num(c.total), assessed + skipped);
  return `${assessed} of ${total} control${total !== 1 ? 's' : ''} assessed`;
}
