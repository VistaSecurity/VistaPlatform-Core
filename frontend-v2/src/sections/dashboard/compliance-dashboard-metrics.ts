// The Compliance dashboard's arithmetic and routes.
//
// This page deliberately overlaps Risk & Compliance → Posture → Overview: the
// owner's call, taken with the overlap named. The mitigation is in
// this file and in the page's hooks rather than in a scope cut — **nothing here
// derives a compliance number**. Every score comes back from the same endpoints
// Posture reads, under the same react-query keys, so the two surfaces share one
// cached answer and cannot drift the way the Dashboard's "0 critical" and the
// Findings page's "4 Critical" once did (H-2).
//
// The one thing this file is allowed to do is SHAPE: pick which rows to show,
// rank them, and decide what a null means. Those are presentation decisions.
// Recomputing a score from control counts would not be, and is why
// `overallScore` reads the server's number instead of averaging the cards.
import { riskColor } from '../../components/ui';
import { sevLevel } from '../findings/model';
import { findingsSeverityRoute } from './dashboard-metrics';

// ------------------------------------------------------------- frameworks --

/** The subset of GET /frameworks/available a card needs. Structural, so the
 *  generated contract type satisfies it without an import. */
export interface AvailableFrameworkRow {
  platform_framework: { id?: string; code: string; name?: string; version?: string };
  is_licensed: boolean;
  preview_score?: number | null;
  controls_passing?: number | null;
  controls_failing?: number | null;
  controls_not_assessed?: number | null;
}

export interface FrameworkCard {
  code: string;
  name: string;
  /** null renders "—". Null means BOTH "not scored yet" and "nothing could be
   * assessed"; neither is 0 and neither is 100. */
  score: number | null;
  passing: number;
  failing: number;
  notAssessed: number;
  /** Assessed = passing + failing. The "N of M controls assessed" denominator. */
  assessed: number;
  total: number;
  activated: boolean;
}

export function frameworkCards(rows: AvailableFrameworkRow[] | undefined): FrameworkCard[] {
  return (rows ?? []).map((r) => {
    const passing = r.controls_passing ?? 0;
    const failing = r.controls_failing ?? 0;
    const notAssessed = r.controls_not_assessed ?? 0;
    return {
      code: r.platform_framework.code,
      // Explicit rather than `||`: an EMPTY name is not a name either, and
      // `??` would let one through and render a blank card title.
      name: r.platform_framework.name === undefined || r.platform_framework.name === ''
        ? r.platform_framework.code
        : r.platform_framework.name,
      score: typeof r.preview_score === 'number' ? r.preview_score : null,
      passing,
      failing,
      notAssessed,
      assessed: passing + failing,
      total: passing + failing + notAssessed,
      activated: r.is_licensed,
    };
  });
}

/**
 * Activated frameworks first, then worst score, then name.
 *
 * Activated-first because an unactivated framework's score is a PREVIEW — a
 * sales affordance, not an obligation the tenant has taken on — and ranking a
 * preview above a live commitment would put something the reader is not
 * accountable for at the top of their compliance page.
 *
 * Within each group, unscored (`null`) sorts LAST rather than first. A null is
 * not a bad score; treating it as one ("0 sorts first") is the same collapse
 * that renders it as 0 on screen.
 */
export function sortFrameworkCards(cards: FrameworkCard[]): FrameworkCard[] {
  return [...cards].sort((a, b) => {
    if (a.activated !== b.activated) return a.activated ? -1 : 1;
    if (a.score === null && b.score === null) return a.name.localeCompare(b.name);
    if (a.score === null) return 1;
    if (b.score === null) return -1;
    return a.score - b.score || a.name.localeCompare(b.name);
  });
}

/** How many of the catalogue's frameworks this tenant has taken on. */
export function activationCoverage(cards: FrameworkCard[]): { activated: number; available: number } {
  return { activated: cards.filter((c) => c.activated).length, available: cards.length };
}

// --------------------------------------------------------------- severity --

/** The findings ladder, worst first. `info` is absent: SeverityCounts carries
 *  four rungs, and inventing a fifth bucket that is always 0 reads as a claim. */
export const SEVERITY_RUNGS = ['critical', 'high', 'medium', 'low'] as const;
export type SeverityRung = (typeof SEVERITY_RUNGS)[number];

export const SEVERITY_LABEL: Readonly<Record<SeverityRung, string>> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export interface SeverityRow {
  key: SeverityRung;
  label: string;
  count: number;
  /**
   * The canonical colour for this rung.
   *
   * `sevLevel` → `riskColor`, never a local map. ADR-0016 makes
   * `shared/severity` the single owner of the finding/alert ladder and its
   * presentation, and `make audit`'s rating-ladder guard fails on a local copy —
   * correctly: this file's first draft mapped High to `--danger-soft` while the
   * canonical ladder maps it to `--warn-strong`, so a High finding would have
   * been a different colour here than on every other surface in the product.
   */
  tone: string;
  href: string;
}

/**
 * The severity strip.
 *
 * Fed from `all_producer_severity_counts`, never `severity_counts`. The latter
 * is scoped to the COMPLIANCE producer — failed controls on activated
 * frameworks — so a tenant whose only Criticals are end-of-life or vulnerability
 * findings reads 0 here while the Findings page lists them. That divergence has
 * shipped twice; the fix both times was to widen the COUNT, because the
 * product's position is that findings are one stream with several producers.
 */
/**
 * The all-producer open-findings TOTAL — the sum of the rungs.
 *
 * NOT `active_findings`, and this is the subtle one.
 * `GET /findings/statistics` puts `complianceProducerScope` + the licensed-
 * framework gate on every top-level count it returns — `total_findings`,
 * `active_findings`, and all five workflow counts. Only
 * `all_producer_severity_counts` spans the whole stream. The service says so in
 * its own comment: "The Dashboard reads AllProducerSeverityCounts now …; these
 * four remain the compliance-scoped answer."
 *
 * So `active_findings` beside these rungs is two populations in one strip.
 * Observed live: an "Active 15" tile beside rungs summing to 110
 * (15 compliance + 54 crypto + 41 hygiene), under a heading promising every
 * producer — and the tile links to a Findings page that lists 110. Summing the
 * rungs gives the number that agrees with both the strip and the destination.
 */
export function openFindingsTotal(counts: Partial<Record<SeverityRung, number>> | undefined): number | null {
  if (!counts) return null;
  return SEVERITY_RUNGS.reduce((n, k) => n + (counts[k] ?? 0), 0);
}

export function severityRows(counts: Partial<Record<SeverityRung, number>> | undefined): SeverityRow[] {
  return SEVERITY_RUNGS.map((key) => ({
    key,
    label: SEVERITY_LABEL[key],
    count: counts?.[key] ?? 0,
    tone: riskColor(sevLevel(key)),
    href: findingsSeverityRoute(key),
  }));
}

// ---------------------------------------------------------------- workflow --

/** The shape of GET /findings/statistics this page reads. */
export interface FindingStatsRollup {
  active_findings?: number | null;
  new_findings?: number | null;
  notified_findings?: number | null;
  resolved_findings?: number | null;
  suppressed_findings?: number | null;
  resurfaced_findings?: number | null;
  total_findings?: number | null;
}

export interface WorkflowStage {
  key: string;
  label: string;
  /** What this stage means, in a sentence the reader has not had to learn. */
  hint: string;
  count: number;
  tone: string;
}

/**
 * Where the tenant's findings sit in their workflow.
 *
 * These are NOT a funnel that sums to the total and are not drawn as one:
 * `resurfaced` is a finding that was resolved and came back, so it is counted
 * in its current state as well. Drawing them as segments of one bar would
 * assert a partition that does not exist — the mistake the PQC tiles avoid by
 * classifying each implementation exactly once.
 *
 * They also describe a NARROWER population than the severity strip above:
 * these five fields carry `complianceProducerScope` and the licensed-framework
 * gate, so they cover failed controls on activated frameworks and nothing from
 * the crypto, hygiene, EOL or vulnerability producers. The panel says so —
 * `WORKFLOW_SCOPE_NOTE` — rather than letting a reader take 15 resolved out of
 * 110 open as the whole picture.
 */
export function workflowStages(stats: FindingStatsRollup | undefined): WorkflowStage[] {
  return [
    { key: 'new', label: 'New', hint: 'nobody has looked yet', count: stats?.new_findings ?? 0, tone: 'var(--info)' },
    { key: 'notified', label: 'Notified', hint: 'an alert went out', count: stats?.notified_findings ?? 0, tone: 'var(--warn)' },
    { key: 'resolved', label: 'Resolved', hint: 'closed by someone', count: stats?.resolved_findings ?? 0, tone: 'var(--ok)' },
    { key: 'suppressed', label: 'Suppressed', hint: 'accepted with a reason', count: stats?.suppressed_findings ?? 0, tone: 'var(--app-t3)' },
    { key: 'resurfaced', label: 'Resurfaced', hint: 'closed, then detected again', count: stats?.resurfaced_findings ?? 0, tone: 'var(--danger-soft)' },
  ];
}

// ---------------------------------------------------------------- exposures --

/** The subset of GET /findings/by-control a row needs. */
export interface ControlGroupRow {
  control_name: string;
  framework_name: string;
  worst_severity: string;
  finding_count: number;
  affected_assets: number;
  target_kind?: string;
}

/**
 * What `affected_assets` is actually counting.
 *
 * The endpoint says so in `target_kind`, and saying "12 assets" when the twelve
 * are certificates is a small lie that costs a reader real time when they open
 * the list and find no assets in it.
 */
const TARGET_NOUN: Readonly<Record<string, { one: string; many: string }>> = {
  asset: { one: 'asset', many: 'assets' },
  certificate: { one: 'certificate', many: 'certificates' },
  configuration: { one: 'configuration', many: 'configurations' },
  mixed: { one: 'target', many: 'targets' },
};

export function targetNoun(kind: string | undefined, n: number): string {
  const nouns = TARGET_NOUN[kind ?? 'mixed'] ?? TARGET_NOUN.mixed;
  return n === 1 ? nouns.one : nouns.many;
}

// ----------------------------------------------------------------- tickets --

export interface TicketStatsRollup {
  total?: number | null;
  overdue?: number | null;
  by_status?: Record<string, number> | null;
  by_category?: Record<string, number> | null;
}

export interface RemediationRollup {
  total: number | null;
  overdue: number | null;
  /** Share of open tickets not past SLA. null when there are none — 100% "on
   *  track" with nothing in flight is a number that reads as an achievement. */
  onTrackPercent: number | null;
}

export function remediationRollup(stats: TicketStatsRollup | null | undefined): RemediationRollup {
  if (!stats) return { total: null, overdue: null, onTrackPercent: null };
  const total = typeof stats.total === 'number' ? stats.total : null;
  const overdue = typeof stats.overdue === 'number' ? stats.overdue : null;
  const onTrackPercent =
    total !== null && overdue !== null && total > 0 ? Math.round(((total - overdue) / total) * 100) : null;
  return { total, overdue, onTrackPercent };
}

/** Ticket categories, biggest first, for the remediation mix. */
export function ticketCategories(stats: TicketStatsRollup | null | undefined): { label: string; count: number }[] {
  const by = stats?.by_category ?? {};
  return Object.entries(by)
    .filter(([, n]) => n > 0)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

// ------------------------------------------------------------------ routes --

/**
 * What the workflow panel has to tell the reader about its own scope.
 *
 * Kept beside the function that produces those counts so the caveat cannot be
 * dropped from the JSX without this constant going unused.
 */
export const WORKFLOW_SCOPE_NOTE =
  'Compliance-framework findings only — the other producers (crypto, hygiene, end-of-life, vulnerability) are not counted here.';

export const COMPLIANCE_FRAMEWORKS_ROUTE = '/risk-compliance/posture?tab=frameworks';
export const COMPLIANCE_POSTURE_ROUTE = '/risk-compliance/posture';
export const COMPLIANCE_FINDINGS_ROUTE = '/risk-compliance/findings';
export const COMPLIANCE_REMEDIATION_ROUTE = '/remediation/queue';
