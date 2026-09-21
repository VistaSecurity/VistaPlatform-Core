import { describe, expect, it } from 'vitest';
import {
  SEVERITY_RUNGS, WORKFLOW_SCOPE_NOTE, activationCoverage, frameworkCards, openFindingsTotal,
  remediationRollup, severityRows, sortFrameworkCards, targetNoun, ticketCategories, workflowStages,
} from './compliance-dashboard-metrics';
import { DASHBOARD_CRITICAL_FINDINGS_ROUTE } from './dashboard-metrics';

const fw = (
  code: string,
  opts: Partial<{ licensed: boolean; score: number | null; passing: number; failing: number; notAssessed: number; name: string }> = {},
) => ({
  platform_framework: { code, name: opts.name ?? code.toUpperCase() },
  is_licensed: opts.licensed ?? false,
  preview_score: opts.score === undefined ? null : opts.score,
  controls_passing: opts.passing ?? 0,
  controls_failing: opts.failing ?? 0,
  controls_not_assessed: opts.notAssessed ?? 0,
});

describe('framework cards', () => {
  it('derives the assessed subset and the total from the control counts', () => {
    const [c] = frameworkCards([fw('soc2', { passing: 12, failing: 3, notAssessed: 5 })]);
    expect(c.assessed).toBe(15);
    expect(c.total).toBe(20);
  });

  it('keeps a null score NULL', () => {
    // Null means both "no rollup yet" and "nothing could be assessed".
    // Neither is 0 and neither is 100; a prospect comparing frameworks must see
    // "—", never a 100 that only means "nothing was evaluated".
    expect(frameworkCards([fw('soc2')])[0].score).toBeNull();
  });

  it('keeps a real zero score as zero', () => {
    // The other half of the same rule: 0 is a legitimate score and must not be
    // collapsed into "unscored" by a falsy check.
    expect(frameworkCards([fw('soc2', { score: 0 })])[0].score).toBe(0);
  });

  it('falls back to the code when the framework has no name', () => {
    const rows = [{ platform_framework: { code: 'iso27001' }, is_licensed: true }];
    expect(frameworkCards(rows)[0].name).toBe('iso27001');
  });

  it('is empty, not undefined, with no rows', () => {
    expect(frameworkCards(undefined)).toEqual([]);
  });
});

describe('framework card ranking', () => {
  it('puts ACTIVATED frameworks before previews, whatever their scores', () => {
    // An unactivated framework's score is what the tenant WOULD score, not an
    // obligation they hold. Ranking a preview above a live commitment puts
    // something the reader is not accountable for at the top of their page.
    const cards = sortFrameworkCards(frameworkCards([
      fw('preview-bad', { licensed: false, score: 10 }),
      fw('live-good', { licensed: true, score: 95 }),
    ]));
    expect(cards.map((c) => c.code)).toEqual(['live-good', 'preview-bad']);
  });

  it('ranks worst score first within a group', () => {
    const cards = sortFrameworkCards(frameworkCards([
      fw('a', { licensed: true, score: 90 }),
      fw('b', { licensed: true, score: 40 }),
      fw('c', { licensed: true, score: 70 }),
    ]));
    expect(cards.map((c) => c.code)).toEqual(['b', 'c', 'a']);
  });

  it('sorts UNSCORED last, not first', () => {
    // A null is not a bad score. Treating it as one ("0 sorts first") is the
    // same collapse that renders it as 0 on screen.
    const cards = sortFrameworkCards(frameworkCards([
      fw('unscored', { licensed: true, score: null }),
      fw('bad', { licensed: true, score: 5 }),
    ]));
    expect(cards.map((c) => c.code)).toEqual(['bad', 'unscored']);
  });

  it('breaks ties by name so the order is stable across renders', () => {
    const cards = sortFrameworkCards(frameworkCards([
      fw('z', { licensed: true, score: 50, name: 'Zeta' }),
      fw('a', { licensed: true, score: 50, name: 'Alpha' }),
    ]));
    expect(cards.map((c) => c.name)).toEqual(['Alpha', 'Zeta']);
  });

  it('does not mutate its input', () => {
    const cards = frameworkCards([fw('b', { score: 1 }), fw('a', { score: 9 })]);
    const before = cards.map((c) => c.code);
    sortFrameworkCards(cards);
    expect(cards.map((c) => c.code)).toEqual(before);
  });
});

describe('activation coverage', () => {
  it('counts activated against the whole catalogue', () => {
    const cards = frameworkCards([fw('a', { licensed: true }), fw('b'), fw('c', { licensed: true })]);
    expect(activationCoverage(cards)).toEqual({ activated: 2, available: 3 });
  });

  it('is zero-of-zero on an empty catalogue rather than throwing', () => {
    expect(activationCoverage([])).toEqual({ activated: 0, available: 0 });
  });
});

describe('the severity strip', () => {
  it('runs worst-first across the four registry rungs', () => {
    expect(SEVERITY_RUNGS).toEqual(['critical', 'high', 'medium', 'low']);
    expect(severityRows({}).map((r) => r.key)).toEqual(['critical', 'high', 'medium', 'low']);
  });

  it('links each rung at the Findings page filtered to that rung', () => {
    // "A tile that counts a subset must link to that subset." The severity is
    // applied SERVER-side by the Findings page, because that page caps at five
    // pages of 200 and narrowing in the browser would under-report a tenant
    // whose Criticals sit past the cap.
    for (const row of severityRows({})) {
      expect(row.href).toContain(`severity=${row.key}`);
    }
  });

  it('agrees with the shared Dashboard about where Critical goes', () => {
    // Two spellings of this URL is two things to keep in step. This pins the
    // Compliance dashboard's Critical tile to the same destination the shared
    // Dashboard's has used since H-2.
    const critical = severityRows({}).find((r) => r.key === 'critical')!;
    expect(critical.href).toBe(DASHBOARD_CRITICAL_FINDINGS_ROUTE);
  });

  it('shows every rung even when a tenant has none of it', () => {
    // Dropping the empty rungs would make "Critical 4" the whole strip, which
    // reads as "every finding is critical".
    expect(severityRows({ critical: 4 })).toHaveLength(4);
    expect(severityRows({ critical: 4 }).find((r) => r.key === 'low')!.count).toBe(0);
  });

  it('survives an absent counts object', () => {
    expect(severityRows(undefined).every((r) => r.count === 0)).toBe(true);
  });
});

// `/findings/statistics` is two populations in one payload, and mixing them is
// the H-2 divergence again: every top-level count carries
// `complianceProducerScope` + the licensed-framework gate, while
// `all_producer_severity_counts` spans the whole stream. Observed live
//: `active_findings: 15` beside rungs summing to 110.
describe('the open-findings total', () => {
  it('sums the rungs, so the tile agrees with the strip beneath it', () => {
    expect(openFindingsTotal({ critical: 0, high: 6, medium: 66, low: 38 })).toBe(110);
  });

  it('is null when the stats call failed, not 0', () => {
    expect(openFindingsTotal(undefined)).toBeNull();
  });

  it('is a real 0 for a tenant with no open findings', () => {
    expect(openFindingsTotal({ critical: 0, high: 0, medium: 0, low: 0 })).toBe(0);
  });

  it('counts only the four rungs, ignoring anything else in the payload', () => {
    // A stray key must not inflate the total — the rungs ARE the population.
    expect(openFindingsTotal({ critical: 1, high: 1, medium: 1, low: 1, info: 99 } as never)).toBe(4);
  });
});

describe('finding workflow stages', () => {
  it('names the five states', () => {
    expect(workflowStages({}).map((s) => s.key)).toEqual(['new', 'notified', 'resolved', 'suppressed', 'resurfaced']);
  });

  it('reads each state from its own field', () => {
    const stages = workflowStages({
      new_findings: 1, notified_findings: 2, resolved_findings: 3, suppressed_findings: 4, resurfaced_findings: 5,
    });
    expect(stages.map((s) => s.count)).toEqual([1, 2, 3, 4, 5]);
  });

  it('carries a note saying which producer it covers', () => {
    // The panel sits under a strip counting 110 findings while describing 15.
    // Without this note a reader takes "0 resolved" as the whole picture.
    expect(WORKFLOW_SCOPE_NOTE).toMatch(/compliance/i);
    expect(WORKFLOW_SCOPE_NOTE).toMatch(/crypto|hygiene|producer/i);
  });

  it('gives every state a plain-language hint', () => {
    // "Suppressed" and "resurfaced" are terms of art. A state nobody can read
    // is a state nobody acts on.
    for (const s of workflowStages({})) expect(s.hint.length).toBeGreaterThan(10);
  });
});

describe('what affected_assets is counting', () => {
  it('uses the endpoint\'s own target_kind', () => {
    // Saying "12 assets" when the twelve are certificates costs the reader a
    // click into a list with no assets in it.
    expect(targetNoun('certificate', 12)).toBe('certificates');
    expect(targetNoun('configuration', 1)).toBe('configuration');
    expect(targetNoun('asset', 3)).toBe('assets');
  });

  it('singularizes at exactly one', () => {
    expect(targetNoun('asset', 1)).toBe('asset');
    expect(targetNoun('asset', 0)).toBe('assets');
  });

  it('falls back to the neutral noun for a kind it does not know', () => {
    expect(targetNoun('mixed', 2)).toBe('targets');
    expect(targetNoun(undefined, 2)).toBe('targets');
    expect(targetNoun('something-new', 2)).toBe('targets');
  });
});

describe('remediation rollup', () => {
  it('computes the on-track share of open tickets', () => {
    expect(remediationRollup({ total: 10, overdue: 2 })).toEqual({ total: 10, overdue: 2, onTrackPercent: 80 });
  });

  it('returns null on-track when there are NO tickets', () => {
    // 100% on track with nothing in flight is a number that reads as an
    // achievement.
    expect(remediationRollup({ total: 0, overdue: 0 }).onTrackPercent).toBeNull();
  });

  it('is all-null when the stats call failed', () => {
    expect(remediationRollup(null)).toEqual({ total: null, overdue: null, onTrackPercent: null });
  });

  it('keeps a real zero overdue distinct from an absent one', () => {
    expect(remediationRollup({ total: 4, overdue: 0 }).overdue).toBe(0);
    expect(remediationRollup({ total: 4 }).overdue).toBeNull();
  });
});

describe('ticket categories', () => {
  it('ranks biggest first', () => {
    expect(ticketCategories({ by_category: { compliance: 2, remediation: 9, certificate: 5 } }).map((c) => c.label))
      .toEqual(['remediation', 'certificate', 'compliance']);
  });

  it('drops empty categories rather than listing zeros', () => {
    expect(ticketCategories({ by_category: { compliance: 0, remediation: 3 } }).map((c) => c.label)).toEqual(['remediation']);
  });

  it('is empty with no stats', () => {
    expect(ticketCategories(null)).toEqual([]);
    expect(ticketCategories({})).toEqual([]);
  });
});
