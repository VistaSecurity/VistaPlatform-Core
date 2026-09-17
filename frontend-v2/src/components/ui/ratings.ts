/**
 * Presentation policies for rating-like values that are not individual risk.
 *
 * These helpers deliberately name the field contract they adapt. A percentage
 * is not automatically a risk score, and 1 means very different things on an
 * asset's stored 0..100 confidence and the matcher's 0..1 probability.
 */

export type RatingColor =
  | 'var(--ok)'
  | 'var(--warn)'
  | 'var(--warn-strong)'
  | 'var(--danger)'
  | 'var(--neutral)';

/** Owner-approved Inventory Hygiene colour policy: 90/70 boundaries. */
export function hygienePercentageColor(value: number | null | undefined): RatingColor {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) return 'var(--neutral)';
  if (value >= 90) return 'var(--ok)';
  if (value >= 70) return 'var(--warn)';
  return 'var(--danger)';
}

/** Owner-approved framework compliance colour policy: 85/70/50 boundaries. */
export function frameworkPercentageColor(value: number | null | undefined): RatingColor {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) return 'var(--neutral)';
  if (value >= 85) return 'var(--ok)';
  if (value >= 70) return 'var(--warn)';
  if (value >= 50) return 'var(--warn-strong)';
  return 'var(--danger)';
}

/** A numerator as a percentage of its actual population, or unknown if empty. */
export function proportionPercent(numerator: number, denominator: number): number | null {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0 || numerator < 0 || numerator > denominator) return null;
  return Math.round((numerator / denominator) * 100);
}

/** Assets persist confidence as an integer percentage (0..100). */
export function assetConfidencePercent(value: number | null | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) return null;
  return Math.round(value);
}

/** Nullable class/identifier probabilities: zero is a recorded value, not absence. */
export function probabilityConfidencePercent(value: number | null | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return null;
  return Math.round(value * 100);
}

/** Matcher scores are probabilities (0..1); zero is the contract's unscored sentinel. */
export function matcherConfidencePercent(value: number | null | undefined): number | null {
  return value === 0 ? null : probabilityConfidencePercent(value);
}

export function percentLabel(value: number | null): string {
  return value === null ? '—' : `${value}%`;
}
