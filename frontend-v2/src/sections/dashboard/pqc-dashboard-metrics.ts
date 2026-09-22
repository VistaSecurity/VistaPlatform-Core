// The PQC dashboard's arithmetic.
//
// The classifier that produces these numbers lives in the backend
// (`classifyTenantImplementationsPQC`, services/inventory-service/internal/
// services/pqc_readiness.go) and is deliberately a DENYLIST of Shor-breakable
// CycloneDX primitives per NIST IR 8547 — not an allowlist of "safe" ones. The
// allowlist version silently misclassified eleven catalogue algorithms,
// including plain AES128 and AES256, as needing PQC migration.
//
// Nothing here re-classifies anything. This file shapes the four categories the
// server already partitioned into, and turns `by_family` into a worklist.
//
// The one trap worth naming up front: `total_implementations` and the sum of
// `by_family` counts ARE NOT THE SAME NUMBER, by design. An implementation is
// classified exactly once, so the four categories sum to the total; a family
// breakdown counts an implementation under every family it uses, so those
// counts intentionally sum past it. Presenting a family table under a "total"
// header is how a reader concludes the page contradicts itself.

/** The shape of `progress` from GET /pqc/progress. Structural. */
export interface PqcProgress {
  total_implementations?: number | null;
  pqc_ready?: number | null;
  symmetric_safe?: number | null;
  non_pqc?: number | null;
  unclassified?: number | null;
  pqc_percentage?: number | null;
  by_family?: PqcFamily[] | null;
}

export interface PqcFamily {
  family: string;
  count: number;
  is_pqc: boolean;
  quantum_safe: boolean;
  /** Recommended PQC target; omitted when the catalogue has none. */
  migrate_to?: string;
}

// ------------------------------------------------------------- partition ---

export interface PqcCategory {
  key: 'pqc_ready' | 'symmetric_safe' | 'non_pqc' | 'unclassified';
  label: string;
  /** The sentence that stops the category being misread. */
  hint: string;
  count: number;
  tone: string;
  icon: string;
}

/**
 * The four mutually exclusive categories, in reading order.
 *
 * `unclassified` is kept SEPARATE from `non_pqc` everywhere it appears. They are
 * different facts: `non_pqc` is an implementation with a real quantum-vulnerable
 * component — a migration target — while `unclassified` is one whose algorithms
 * did not resolve against the catalogue at all, which is a data-quality gap.
 * Folding the second into the first is what the shared Dashboard's tiles were
 * fixed for (M-2), and it overstates the migration workload by exactly the
 * number of things nobody has looked at.
 */
export function pqcCategories(p: PqcProgress | null | undefined): PqcCategory[] {
  return [
    {
      key: 'pqc_ready', label: 'PQC-ready', icon: 'shield-check', tone: 'var(--ok)',
      hint: 'uses post-quantum algorithms and no classical asymmetric ones',
      count: p?.pqc_ready ?? 0,
    },
    {
      key: 'symmetric_safe', label: 'Symmetric-safe', icon: 'lock', tone: 'var(--info)',
      hint: 'no asymmetric cryptography at all, so nothing to migrate',
      count: p?.symmetric_safe ?? 0,
    },
    {
      key: 'non_pqc', label: 'Needs migration', icon: 'shield-alert', tone: 'var(--warn-strong)',
      hint: 'at least one classical asymmetric component (RSA, ECDSA, EdDSA, DH, ECDH)',
      count: p?.non_pqc ?? 0,
    },
    {
      key: 'unclassified', label: 'Not yet assessed', icon: 'circle-help', tone: 'var(--app-t3)',
      hint: 'no algorithm data resolved — a gap in what we know, not classical crypto',
      count: p?.unclassified ?? 0,
    },
  ];
}

export interface PqcHeadline {
  /** Whole percent. `pqc_percentage` is a float, so 4 of 11 arrives as
   *  36.36363636363637 and renders as that unless it is rounded here. */
  readinessPercent: number | null;
  total: number;
  /** pqc_ready + symmetric_safe — everything needing no migration. */
  safe: number;
  needsMigration: number;
  unclassified: number;
  /**
   * True when the classifier partitioned nothing, i.e. the tenant has no crypto
   * configurations at all. The page shows its empty state rather than a 0%
   * readiness gauge, which reads as "you have failed" instead of "we have not
   * found any crypto yet".
   */
  empty: boolean;
}

export function pqcHeadline(p: PqcProgress | null | undefined): PqcHeadline {
  const total = p?.total_implementations ?? 0;
  const safe = (p?.pqc_ready ?? 0) + (p?.symmetric_safe ?? 0);
  return {
    readinessPercent: total > 0 && typeof p?.pqc_percentage === 'number' ? Math.round(p.pqc_percentage) : null,
    total,
    safe,
    needsMigration: p?.non_pqc ?? 0,
    unclassified: p?.unclassified ?? 0,
    empty: total === 0,
  };
}

// -------------------------------------------------------------- worklist ---

export interface WorklistRow {
  family: string;
  count: number;
  /** The catalogue's recommended PQC target, or null when it has none. */
  migrateTo: string | null;
}

/**
 * Fold rows that share a family NAME.
 *
 * The server no longer sends duplicates. It did: verified live on, a
 * tenant whose `by_family` held `AES` at 18 and again at 5, and `SHA-2` at 11
 * and again at 7, with identical `is_pqc`/`quantum_safe` and no field telling
 * them apart. The cause was not the component role guessed here — the query
 * grouped by the algorithm's PRIMITIVE and then dropped it, and
 * `PQCFamilyStats` has nowhere to put one. AES spans {ae, block-cipher, mac} in
 * the catalogue, SHA-2 {hash, mac}. Fixed in `GetPQCProgress`
 * (services/inventory-service/internal/services/algorithm_service.go), which
 * now groups by family alone and answers both flags for the family as a whole;
 * `TestIntegration_PQC_EveryFamilyAppearsAtMostOnce` is the guard.
 *
 * This fold stays anyway, as version skew tolerance: during a rolling upgrade
 * this bundle can be served beside a backend from the previous release, and two
 * rows with one name and nothing to distinguish them read on screen as a
 * rendering bug. Against a current server it is a no-op.
 *
 * What it could never fix, and why the server fix was the necessary one: the
 * page filters on `quantum_safe` BEFORE folding, so a family the old query
 * reported safe under one primitive and unsafe under another would appear under
 * "Replace these" and "Already quantum-safe" at the same time — two lists, one
 * merge each, nothing in a position to notice. And its counts were
 * COUNT(DISTINCT implementation) taken within a primitive group, so summing
 * them over-counted any configuration that used one family twice. A fold cannot
 * recover a distinct count from two overlapping ones; it can only stop the
 * screen looking broken.
 *
 * `migrate_to` takes the first non-empty recommendation; duplicates observed
 * agreed, and there is no basis for preferring one over the other.
 */
function mergeByFamily(rows: PqcFamily[]): WorklistRow[] {
  const out = new Map<string, WorklistRow>();
  for (const f of rows) {
    const migrateTo = f.migrate_to === undefined || f.migrate_to === '' ? null : f.migrate_to;
    const seen = out.get(f.family);
    if (seen) {
      seen.count += f.count;
      seen.migrateTo = seen.migrateTo ?? migrateTo;
    } else {
      out.set(f.family, { family: f.family, count: f.count, migrateTo });
    }
  }
  return [...out.values()].sort((a, b) => b.count - a.count || a.family.localeCompare(b.family));
}

/**
 * The migration worklist: algorithm families that are NOT quantum-safe, biggest
 * first.
 *
 * This is the part of `/pqc/progress` nothing in the product surfaced before.
 * The PQC Readiness feature shipped as a compliance framework and
 * deliberately added no page, so `by_family` — which is the only place the
 * catalogue's per-family `migrate_to` recommendation reaches the UI — has been
 * computed on every request and thrown away.
 *
 * Filtered on `quantum_safe`, not on `is_pqc`. They are different questions:
 * AES-256 is not a post-quantum algorithm and never will be, but it is
 * quantum-safe at its key size and belongs nowhere near a migration worklist.
 * Filtering on `!is_pqc` would put every symmetric cipher in the tenant on a
 * list of things to replace.
 */
export function migrationWorklist(p: PqcProgress | null | undefined): WorklistRow[] {
  return mergeByFamily((p?.by_family ?? []).filter((f) => !f.quantum_safe));
}

/**
 * The families this page is NOT asking you to replace.
 *
 * "Quantum-safe", and deliberately not "safe". SHA-1 lands here — correctly, on
 * this page's terms, because its weakness is classical collision resistance and
 * neither Shor nor Grover is what breaks it — and a panel that called that
 * "needs no action" would be making a security claim about SHA-1 that is false
 * in every sense except the one narrow sense meant. Observed live: a tenant with
 * 5 SHA-1 configurations. The caption carries the caveat; see the page.
 */
export function safeFamilies(p: PqcProgress | null | undefined): WorklistRow[] {
  return mergeByFamily((p?.by_family ?? []).filter((f) => f.quantum_safe))
    .map((r) => ({ ...r, migrateTo: null }));
}

// -------------------------------------------------------------- timeline ---

/**
 * NIST IR 8547's two dates for classical asymmetric cryptography.
 *
 * These are the published milestones, not our opinion: RSA, ECDSA, EdDSA, DH and
 * ECDH are **deprecated after 2030** and **disallowed after 2035**. They are the
 * same source the backend classifier cites for its denylist, so the page and the
 * classifier are quoting one document.
 */
export const NIST_DEPRECATED_YEAR = 2030;
export const NIST_DISALLOWED_YEAR = 2035;

export interface TimelineMilestone {
  year: number;
  label: string;
  detail: string;
  /** Whole years from `now` to 1 Jan of `year`. Negative once the date passes. */
  yearsAway: number;
  passed: boolean;
}

/**
 * The two milestones, measured from a caller-supplied `now`.
 *
 * `now` is a parameter rather than `new Date()` inside so the test can pin a
 * date. A countdown that silently uses the wall clock is untestable, and this
 * one goes negative in 2031 — which the page has to render as "passed", not as
 * "-1 years away".
 */
export function nistTimeline(now: Date): TimelineMilestone[] {
  const year = now.getUTCFullYear();
  return [
    {
      year: NIST_DEPRECATED_YEAR,
      label: 'Deprecated',
      detail: 'Classical asymmetric algorithms are deprecated for new use.',
      yearsAway: NIST_DEPRECATED_YEAR - year,
      passed: year > NIST_DEPRECATED_YEAR,
    },
    {
      year: NIST_DISALLOWED_YEAR,
      label: 'Disallowed',
      detail: 'Classical asymmetric algorithms are no longer permitted.',
      yearsAway: NIST_DISALLOWED_YEAR - year,
      passed: year > NIST_DISALLOWED_YEAR,
    },
  ];
}

// ---------------------------------------------------------------- routes ---

/** The Configuration lens — where a crypto configuration is actually listed. */
export const PQC_CONFIGURATIONS_ROUTE = '/inventory?lens=configuration';
export const PQC_KEYS_ROUTE = '/inventory?lens=keys';
export const PQC_ALGORITHMS_ROUTE = '/risk-compliance/posture?tab=algorithms';
export const PQC_FRAMEWORK_ROUTE = '/risk-compliance/posture?tab=frameworks';

/** The Core framework whose score is the PQC compliance number (feature). */
export const PQC_FRAMEWORK_CODE = 'pqc-readiness';
