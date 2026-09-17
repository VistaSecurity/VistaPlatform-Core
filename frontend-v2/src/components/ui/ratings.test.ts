import { describe, expect, it } from 'vitest';
import {
  assetConfidencePercent, frameworkPercentageColor, hygienePercentageColor,
  matcherConfidencePercent, probabilityConfidencePercent, percentLabel, proportionPercent,
} from './ratings';

describe('percentage colour policies', () => {
  it.each([
    [100, 'var(--ok)'], [90, 'var(--ok)'], [89, 'var(--warn)'],
    [70, 'var(--warn)'], [69, 'var(--danger)'], [0, 'var(--danger)'],
    [null, 'var(--neutral)'], [-1, 'var(--neutral)'], [101, 'var(--neutral)'],
  ])('keeps the Inventory Hygiene 90/70 policy at %s', (value, color) => {
    expect(hygienePercentageColor(value)).toBe(color);
  });

  it.each([
    [100, 'var(--ok)'], [85, 'var(--ok)'], [84, 'var(--warn)'],
    [70, 'var(--warn)'], [69, 'var(--warn-strong)'], [50, 'var(--warn-strong)'],
    [49, 'var(--danger)'], [0, 'var(--danger)'], [undefined, 'var(--neutral)'], [-1, 'var(--neutral)'], [101, 'var(--neutral)'],
  ])('keeps the framework 85/70/50 policy at %s', (value, color) => {
    expect(frameworkPercentageColor(value)).toBe(color);
  });
});

describe('field-specific confidence adapters', () => {
  it.each([[0, 0], [1, 1], [100, 100]])('keeps asset %s as a 0..100 percentage', (value, expected) => {
    expect(assetConfidencePercent(value)).toBe(expected);
  });

  it.each([[0, null], [0.01, 1], [1, 100]])('maps matcher %s from 0..1 and preserves zero-as-unscored', (value, expected) => {
    expect(matcherConfidencePercent(value)).toBe(expected);
  });

  it.each([[0, 0], [0.01, 1], [1, 100], [null, null], [undefined, null], [-0.01, null], [1.01, null], [NaN, null]])('preserves nullable probability %s', (value, expected) => {
    expect(probabilityConfidencePercent(value)).toBe(expected);
  });

  it('does not guess units from magnitude', () => {
    expect(assetConfidencePercent(0.01)).toBe(0);
    expect(matcherConfidencePercent(50)).toBeNull();
  });
});

describe('percentage formatting', () => {
  it('keeps an empty denominator visibly unknown', () => {
    expect(proportionPercent(0, 0)).toBeNull();
    expect(proportionPercent(-1, 8)).toBeNull();
    expect(proportionPercent(9, 8)).toBeNull();
    expect(percentLabel(proportionPercent(0, 0))).toBe('—');
  });

  it('uses the supplied population as the denominator', () => {
    expect(proportionPercent(2, 8)).toBe(25);
    expect(percentLabel(proportionPercent(2, 8))).toBe('25%');
  });
});
