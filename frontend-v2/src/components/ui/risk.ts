// Risk presentation tokens. Numeric grading comes from the generated,
// React-free twin of the Go owner in @vistasecurity/primitives/ratings.
import {
  RISK_BANDS, RISK_LEVELS, riskLevelFromScore, type RiskLevel as CanonicalRiskLevel,
} from '@vistasecurity/primitives/ratings';

export type RiskLevel = CanonicalRiskLevel;

export const LEVELS: RiskLevel[] = [...RISK_LEVELS];

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
// Informational is measured zero; availability is a separate field contract.
// Do not hand-drift these boundaries;
// a mismatch here previously made an asset scoring 60-69 show a "High" badge
// while the backend summary/facets counted it "Medium" (F5 in the audit).
export const levelFromScore = riskLevelFromScore;

// The minimum score for each band, exported so captions ("risk score ≥ N")
// can be built from the same numbers levelFromScore uses instead of a
// hand-typed literal drifting out of sync with it (L-4: a caption once read
// "≥ 60" while the actual High threshold was 70).
export const LEVEL_MIN = Object.fromEntries(
  RISK_BANDS.map((band) => [band.label, band.min]),
) as Record<RiskLevel, number>;

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
  const out = Object.fromEntries(LEVELS.map((level) => [level, 0])) as Record<RiskLevel, number>;
  for (const it of items) {
    const l = get(it) as RiskLevel;
    if (l in out) out[l]++;
  }
  return out;
}

export function worstLevel(counts: Record<RiskLevel, number>, fallback: 'Unknown'): RiskLevel | 'Unknown';
export function worstLevel(counts: Record<RiskLevel, number>): RiskLevel;
export function worstLevel(counts: Record<RiskLevel, number>, fallback: RiskLevel | 'Unknown' = 'Informational'): RiskLevel | 'Unknown' {
  return LEVELS.find((l) => counts[l] > 0) ?? fallback;
}
