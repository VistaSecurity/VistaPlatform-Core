// Guards for the control-status/score/coverage rules.
//
// Every assertion here pins a failure mode that is INVISIBLE in the UI: each
// one renders as a plausible, reassuring number rather than as an error. The
// two that matter most are pinned first — a null score must not render as 0 or
// 100, and an unknown status must not render as a pass.
import { describe, it, expect } from 'vitest';
import {
  normalizeControlStatus,
  notAssessedReasonText,
  formatScore,
  isUnscored,
  assessedCount,
  notAssessedCount,
  coverageLine,
  CONTROL_STATUS_LABEL,
} from './control-status';

describe('formatScore', () => {
  it('renders a null score as "—", never 0 and never 100', () => {
    // The headline guarantee: "we have not looked" must not look like
    // "everything passed" (100) or "everything failed" (0).
    expect(formatScore(null)).toBe('—');
    expect(formatScore(undefined)).toBe('—');
    expect(formatScore(null)).not.toBe('0');
    expect(formatScore(null)).not.toBe('100');
    // Math.round(null) is 0 — the exact coercion this replaces.
    expect(Math.round(null as unknown as number)).toBe(0);
  });

  it('renders a real score, including the honest zero', () => {
    expect(formatScore(86)).toBe('86');
    expect(formatScore(85.6)).toBe('86');
    // 0 is a real, earned score (everything assessed failed) and must survive.
    expect(formatScore(0)).toBe('0');
    expect(formatScore(100)).toBe('100');
  });

  it('treats NaN as unscored rather than rendering "NaN"', () => {
    expect(formatScore(Number.NaN)).toBe('—');
    expect(isUnscored(Number.NaN)).toBe(true);
    expect(isUnscored(0)).toBe(false);
    expect(isUnscored(null)).toBe(true);
  });
});

describe('normalizeControlStatus', () => {
  it('maps the three contract values', () => {
    expect(normalizeControlStatus('PASS')).toBe('PASS');
    expect(normalizeControlStatus('FAIL')).toBe('FAIL');
    expect(normalizeControlStatus('NOT_ASSESSED')).toBe('NOT_ASSESSED');
  });

  it('is case-insensitive (the UI used to compare .toLowerCase())', () => {
    expect(normalizeControlStatus('pass')).toBe('PASS');
    expect(normalizeControlStatus('Fail')).toBe('FAIL');
    expect(normalizeControlStatus('not_assessed')).toBe('NOT_ASSESSED');
  });

  it('never defaults an unknown or missing status to PASS', () => {
    // Defaulting to PASS is the original defect: it turns "we could not tell"
    // into a green check. Anything unrecognised is not-assessed instead.
    for (const raw of [undefined, null, '', '   ', 'WARN', 'unknown', 'error']) {
      expect(normalizeControlStatus(raw)).toBe('NOT_ASSESSED');
      expect(normalizeControlStatus(raw)).not.toBe('PASS');
    }
  });

  it('maps retired WARN to not-assessed, not to a pass', () => {
    // WARN no longer exists in the contract. If a stale cached payload still
    // carries it, it must not be read as passing.
    expect(normalizeControlStatus('WARN')).not.toBe('PASS');
  });

  it('labels not-assessed with the customer-facing wording', () => {
    expect(CONTROL_STATUS_LABEL.NOT_ASSESSED).toBe('Not assessed');
  });
});

describe('notAssessedReasonText', () => {
  it('gives one sentence per contract reason', () => {
    expect(notAssessedReasonText('no_measurements')).toBe('No measurement rule is configured for this control.');
    expect(notAssessedReasonText('nothing_in_scope')).toBe('Nothing in scope to check.');
    expect(notAssessedReasonText('check_error')).toBe('The check failed. This usually clears on the next evaluation.');
  });

  it('falls back to an honest sentence for an unknown or missing reason', () => {
    const fallback = notAssessedReasonText(undefined);
    expect(fallback).toMatch(/not checked/i);
    expect(notAssessedReasonText('something_new')).toBe(fallback);
    // Never claims a pass, whatever it was handed.
    expect(fallback).not.toMatch(/pass/i);
  });
});

describe('assessed / not-assessed counts', () => {
  it('counts a not-assessed control as neither passing nor assessed', () => {
    // The second headline guarantee: an unevaluated control must not be
    // absorbed into the passing tally, which is how an empty inventory scored
    // 100 with "all controls passing".
    const c = { total: 11, passing: 7, failing: 1, notAssessed: 3 };
    expect(assessedCount(c)).toBe(8);
    expect(notAssessedCount(c)).toBe(3);
    expect(assessedCount(c)).not.toBe(c.total);
    expect(assessedCount(c) + notAssessedCount(c)).toBe(c.total);
  });

  it('derives the not-assessed count when the server omits it', () => {
    expect(notAssessedCount({ total: 11, passing: 7, failing: 1 })).toBe(3);
  });

  it('never reports a negative skipped count from inconsistent totals', () => {
    expect(notAssessedCount({ total: 2, passing: 5, failing: 1 })).toBe(0);
  });
});

describe('coverageLine', () => {
  it('reports partial coverage in the documented wording', () => {
    expect(coverageLine({ total: 11, passing: 7, failing: 1, notAssessed: 3 })).toBe('8 of 11 controls assessed');
  });

  it('says "0 of 11" when nothing was assessed — the case that used to read 100%', () => {
    expect(coverageLine({ total: 11, passing: 0, failing: 0, notAssessed: 11 })).toBe('0 of 11 controls assessed');
  });

  it('is silent when every control was assessed', () => {
    expect(coverageLine({ total: 8, passing: 7, failing: 1, notAssessed: 0 })).toBeNull();
    expect(coverageLine({ total: 8, passing: 7, failing: 1 })).toBeNull();
  });

  it('singularises a one-control framework', () => {
    expect(coverageLine({ total: 1, passing: 0, failing: 0, notAssessed: 1 })).toBe('0 of 1 control assessed');
  });

  it('stays silent when the framework has not been scored at all', () => {
    // Every count null = "the engine has not produced a rollup yet", which is
    // not the same claim as "we assessed nothing", and must not be rendered as
    // "0 of 11 controls assessed".
    expect(coverageLine({ total: 11 })).toBeNull();
    expect(coverageLine({ total: 11, passing: null, failing: null, notAssessed: null })).toBeNull();
    // …but once ANY count is reported, the line appears.
    expect(coverageLine({ total: 11, passing: 0, failing: 0, notAssessed: null })).toBe('0 of 11 controls assessed');
  });

  it('trusts the parts over a stale total', () => {
    // If total lags passing+failing+notAssessed, report what we can actually
    // account for rather than an impossible "9 of 5".
    expect(coverageLine({ total: 5, passing: 7, failing: 1, notAssessed: 3 })).toBe('8 of 11 controls assessed');
  });
});
