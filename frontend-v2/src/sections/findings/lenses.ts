// Findings lenses — ported from the mock's FIND_LENSES (Findings.jsx). One
// adaptation: the mock's "By Network Zone" needs a per-finding segment, which
// the crypto-risk stream doesn't carry today, so it's replaced by "By Category"
// (protocol / algorithm / key size / certificate — first-class on CryptoRisk).

export interface FindingsLens {
  key: string;
  label: string;
  /** Icon-kit name (components/ui/icon.tsx). */
  icon: string;
  /**
   * Which finding universe this lens reads (L-5).
   *
   * `findings` lenses read the ONE `findings` table, through compliance-engine's
   * GET /findings — every PRODUCER, not only `compliance`, since the `eol` and
   * `vulnerability` producers shipped (workstreams 3.3/3.4 part 2). The scope
   * was called `compliance` while that was the only producer writing; the name
   * is now wrong in the direction that hides things, which is the direction
   * this page has been wrong in before.
   *
   * `crypto` lenses count inventory-service /crypto-risks rows. They are a
   * different data set under identical chrome — a tenant with 4 findings and
   * 19 crypto risks sees "Open" jump 4 ↔ 19 switching lenses, which reads as
   * broken counting unless the scope is visible.
   */
  scope: 'crypto' | 'findings';
}

export const FINDINGS_LENSES: FindingsLens[] = [
  // First, because it is the only lens that shows every producer's findings
  // without a framework in the way — the nav home for end-of-life and
  // vulnerability findings.
  { key: 'producer', label: 'By Producer', icon: 'layers', scope: 'findings' },
  { key: 'framework', label: 'By Framework', icon: 'shield-check', scope: 'findings' },
  { key: 'control', label: 'By Control', icon: 'list-checks', scope: 'findings' },
  { key: 'severity', label: 'By Severity', icon: 'octagon-alert', scope: 'crypto' },
  { key: 'asset', label: 'By Asset', icon: 'server', scope: 'crypto' },
  { key: 'category', label: 'By Category', icon: 'layers', scope: 'crypto' },
  { key: 'date', label: 'By Date Observed', icon: 'calendar-clock', scope: 'crypto' },
];

export const SCOPE_LABEL: Record<FindingsLens['scope'], string> = {
  crypto: 'Crypto findings',
  findings: 'Platform findings',
};

/** The order the rail groups the lenses in. */
export const SCOPE_ORDER: readonly FindingsLens['scope'][] = ['findings', 'crypto'];

export const DEFAULT_FINDINGS_LENS = 'producer';

/**
 * The lens a key names, or the default.
 *
 * Resolved BY KEY rather than by position: the fallback used to be
 * `FINDINGS_LENSES[1]`, which silently became a different lens the moment one
 * was inserted above it.
 */
export const findFindingsLens = (key: string | null): FindingsLens =>
  FINDINGS_LENSES.find((l) => l.key === key)
  ?? FINDINGS_LENSES.find((l) => l.key === DEFAULT_FINDINGS_LENS)!;

/** Whether a lens key reads the `findings` table rather than the crypto-risk stream. */
export const isFindingsLens = (key: string): boolean =>
  FINDINGS_LENSES.some((l) => l.key === key && l.scope === 'findings');

/**
 * The lens a deep link carrying a SUBJECT or PRODUCER filter must land on.
 *
 * `subject_type`/`subject_id`, `producer` and `q` are read only by the
 * findings-scoped lenses; the crypto lenses read a different data set that
 * ignores all three. A link without a lens landed on the page default, which
 * was `severity` — so it rendered an unfiltered crypto list under a banner
 * claiming it was narrowed to one subject: a page that says it is filtered and
 * is not. The default is findings-scoped now, but these links stay explicit,
 * because a default is a thing that changes and the filter has to survive it.
 * `producer` is the one findings-scoped lens that shows every producer's rows
 * without a framework in the way, so it is the destination for every such link.
 *
 * Named here rather than written out at each call site so the link builders and
 * the tests that pin them share ONE answer, and `isFindingsLens` can be asserted
 * over it.
 */
export const FINDINGS_SUBJECT_LENS = 'producer';
