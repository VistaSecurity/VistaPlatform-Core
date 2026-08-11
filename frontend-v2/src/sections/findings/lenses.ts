// Findings lenses — ported from the mock's FIND_LENSES (Findings.jsx). One
// adaptation: the mock's "By Network Zone" needs a per-finding segment, which
// the crypto-risk stream doesn't carry today, so it's replaced by "By Category"
// (protocol / algorithm / key size / certificate — first-class on CryptoRisk).

export interface FindingsLens {
  key: string;
  label: string;
  /** Icon-kit name (components/ui/icon.tsx). */
  icon: string;
}

export const FINDINGS_LENSES: FindingsLens[] = [
  { key: 'framework', label: 'By Framework', icon: 'shield-check' },
  { key: 'severity', label: 'By Severity', icon: 'octagon-alert' },
  { key: 'control', label: 'By Control', icon: 'list-checks' },
  { key: 'asset', label: 'By Asset', icon: 'server' },
  { key: 'category', label: 'By Category', icon: 'layers' },
  { key: 'date', label: 'By Date Observed', icon: 'calendar-clock' },
];

export const DEFAULT_FINDINGS_LENS = 'severity';

export const findFindingsLens = (key: string | null): FindingsLens =>
  FINDINGS_LENSES.find((l) => l.key === key) ?? FINDINGS_LENSES[1];
