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
   * Which finding universe this lens reads (L-5). "crypto" lenses count
   * inventory-service /crypto-risks rows; "compliance" lenses count
   * compliance-engine's persisted /findings. They are different data sets
   * under identical chrome — a tenant with 4 compliance findings and 19
   * crypto risks sees the "Open" count jump 4 ↔ 19 switching lenses, which
   * reads as broken counting unless the scope is visible.
   */
  scope: 'crypto' | 'compliance';
}

export const FINDINGS_LENSES: FindingsLens[] = [
  { key: 'framework', label: 'By Framework', icon: 'shield-check', scope: 'compliance' },
  { key: 'severity', label: 'By Severity', icon: 'octagon-alert', scope: 'crypto' },
  { key: 'control', label: 'By Control', icon: 'list-checks', scope: 'compliance' },
  { key: 'asset', label: 'By Asset', icon: 'server', scope: 'crypto' },
  { key: 'category', label: 'By Category', icon: 'layers', scope: 'crypto' },
  { key: 'date', label: 'By Date Observed', icon: 'calendar-clock', scope: 'crypto' },
];

export const SCOPE_LABEL: Record<FindingsLens['scope'], string> = {
  crypto: 'Crypto findings',
  compliance: 'Compliance findings',
};

export const DEFAULT_FINDINGS_LENS = 'severity';

export const findFindingsLens = (key: string | null): FindingsLens =>
  FINDINGS_LENSES.find((l) => l.key === key) ?? FINDINGS_LENSES[1];
