// Risk-level model — the shared scoring vocabulary (high score = worse).
// Ported from the mock's primitives.jsx. The authoritative severity *grading*
// (which value → which level) is a backend concern (Severity Ratings, ADR-0009,
// stubbed for now); this module only owns the presentation of a level.

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export const LEVELS: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

export const LEVEL_COLOR: Record<RiskLevel, string> = {
  Critical: 'var(--danger)',
  High: 'var(--warn-strong)',
  Medium: 'var(--warn)',
  Low: 'var(--ok)',
  Informational: 'var(--neutral)',
};

export const LEVEL_ABBR: Record<RiskLevel, string> = {
  Critical: 'C', High: 'H', Medium: 'M', Low: 'L', Informational: 'I',
};

export const riskColor = (lvl: string): string => LEVEL_COLOR[lvl as RiskLevel] ?? 'var(--neutral)';

// Ladder must match the backend's canonical, CVSS-anchored bands exactly —
// see services/inventory-service/internal/models/risk_bands.go (RiskBands /
// GetRiskLevel). Critical >=90, High >=70, Medium >=40, Low >=1,
// Informational == 0 only (0 means NOT ASSESSED, not "safe" — keep it a
// distinct band, not folded into Low). Do not hand-drift these boundaries;
// a mismatch here previously made an asset scoring 60-69 show a "High" badge
// while the backend summary/facets counted it "Medium" (F5 in the audit).
export const levelFromScore = (s: number): RiskLevel =>
  s >= 90 ? 'Critical' : s >= 70 ? 'High' : s >= 40 ? 'Medium' : s >= 1 ? 'Low' : 'Informational';

// The minimum score for each band, exported so captions ("risk score ≥ N")
// can be built from the same numbers levelFromScore uses instead of a
// hand-typed literal drifting out of sync with it (L-4: a caption once read
// "≥ 60" while the actual High threshold was 70).
export const LEVEL_MIN: Record<RiskLevel, number> = {
  Critical: 90, High: 70, Medium: 40, Low: 1, Informational: 0,
};

/** Heat ramp for matrices: 0 → transparent, rising → amber → red. */
export function heatColor(ratio: number): string {
  if (ratio <= 0) return 'transparent';
  const t = Math.min(1, ratio);
  const r = Math.round(226 + (255 - 226) * t);
  const g = Math.round(176 + (90 - 176) * t);
  const b = Math.round(51 + (90 - 51) * t);
  return `rgba(${r},${g},${b},${0.13 + 0.74 * t})`;
}

/** Count items by level into a {level: n} record. */
export function byLevel<T>(items: T[], get: (t: T) => string): Record<RiskLevel, number> {
  const out = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 } as Record<RiskLevel, number>;
  for (const it of items) {
    const l = get(it) as RiskLevel;
    if (l in out) out[l]++;
  }
  return out;
}

export const worstLevel = (counts: Record<RiskLevel, number>): RiskLevel =>
  LEVELS.find((l) => counts[l] > 0) ?? 'Informational';
