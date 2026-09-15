// The risk chip in an asset list, and the one distinction it was collapsing.
//
// `assetRisk` reports `level: 'Informational'` for an unassessed asset so the
// chip's colour stays neutral — but the chip then rendered the same "I" that a
// genuinely-assessed, nothing-found asset wears. "We looked and found nothing"
// and "nobody has looked" became one glyph, visible only on hover, which is
// precisely the two-valued flattening the risk model exists to prevent. The
// asset PAGE has said "Not assessed" in words all along; the list did not.
import { describe, expect, it } from 'vitest';
import { riskChipGlyph } from './risk-viz';
import { assetRisk } from '../../sections/inventory/asset-shape';

describe('riskChipGlyph (gate1 C10)', () => {
  it('does not show an unassessed asset the Informational glyph', () => {
    expect(riskChipGlyph('Informational', false)).not.toBe(riskChipGlyph('Informational', true));
  });

  it('shows the em dash the row’s score column already shows', () => {
    const notAssessed = assetRisk({ risk_score: 0, risk_assessed_by: [] });
    expect(notAssessed.assessed).toBe(false);
    expect(riskChipGlyph(notAssessed.level, notAssessed.assessed)).toBe(notAssessed.label);
    expect(riskChipGlyph(notAssessed.level, notAssessed.assessed)).toBe('—');
  });

  it('still shows the band abbreviation for an asset that WAS assessed (the other polarity)', () => {
    const clean = assetRisk({ risk_score: 0, risk_assessed_by: ['crypto'] });
    expect(clean.assessed).toBe(true);
    expect(riskChipGlyph(clean.level, clean.assessed)).toBe('I');

    const high = assetRisk({ risk_score: 72, risk_level: 'High' });
    expect(riskChipGlyph(high.level, high.assessed)).toBe('H');
  });

  it('defaults to assessed, so every other caller is unchanged', () => {
    expect(riskChipGlyph('Critical')).toBe(riskChipGlyph('Critical', true));
  });
});
