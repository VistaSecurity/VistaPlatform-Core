import { describe, expect, it } from 'vitest';
import { healthColor, healthIndexPresentation } from './primitives';

describe('tenant health index presentation', () => {
  it.each([
    [100, 'Excellent', 'var(--ok)'], [90, 'Excellent', 'var(--ok)'],
    [89, 'Good', 'var(--ok-lime)'], [75, 'Good', 'var(--ok-lime)'],
    [74.9, 'Fair', 'var(--warn)'], [89.9, 'Good', 'var(--ok-lime)'],
    [74, 'Fair', 'var(--warn)'], [60, 'Fair', 'var(--warn)'],
    [59, 'Poor', 'var(--warn-strong)'], [40, 'Poor', 'var(--warn-strong)'],
    [39, 'Failing', 'var(--danger)'], [0, 'Failing', 'var(--danger)'],
  ])('uses the shared health band at %s', (score, label, color) => {
    expect(healthIndexPresentation(score)).toMatchObject({ score, label, text: `${score}/100 · ${label}`, color });
    expect(healthColor(score)).toBe(color);
  });

  it('keeps missing and explicitly unavailable health neutral', () => {
    expect(healthIndexPresentation(null)).toBeNull();
    expect(healthIndexPresentation(0, false)).toBeNull();
    expect(healthColor(null)).toBe('var(--neutral)');
  });
});
