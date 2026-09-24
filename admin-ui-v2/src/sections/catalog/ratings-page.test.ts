import { describe, expect, it } from 'vitest';
import { RISK_BANDS } from '@vistasecurity/primitives/ratings';
import {
  OBSOLETE_RISK_FLOOR, algorithmUpdateBody, catalogueRiskLevel, compareCatalogueRisk, deprecateDescription,
  explicitRiskScore, obsoleteRiskScore,
} from './ratings-page';

const editFields = {
  strength: 'weak',
  risk: '',
  deprecationStatus: 'deprecated',
  deprecationDate: '2026-09-17',
  isPqc: false,
  pqcStatus: 'none',
  migrationGuidance: 'Replace it',
  recommendedAlternatives: 'AES-256-GCM',
};

describe('algorithm catalogue risk score input', () => {
  it('requires a deliberate integer score instead of coercing blank to zero', () => {
    expect(explicitRiskScore('')).toBeNull();
    expect(explicitRiskScore('   ')).toBeNull();
    expect(explicitRiskScore('0.5')).toBeNull();
  });

  it('accepts the complete 0–100 range including explicit zero', () => {
    expect(explicitRiskScore('0')).toBe(0);
    expect(explicitRiskScore('1')).toBe(1);
    expect(explicitRiskScore('100')).toBe(100);
  });

  it('rejects scores outside the catalogue range', () => {
    expect(explicitRiskScore('-1')).toBeNull();
    expect(explicitRiskScore('101')).toBeNull();
    expect(explicitRiskScore('not a score')).toBeNull();
  });
});

describe('algorithm catalogue update payload', () => {
  it('keeps a historical unassessed row editable without fabricating a score', () => {
    const body = algorithmUpdateBody(null, editFields);
    expect(body).toMatchObject({ strength: 'weak', deprecation_status: 'deprecated' });
    expect(body).not.toHaveProperty('risk_score');
  });

  it('preserves an explicit zero assessment', () => {
    expect(algorithmUpdateBody(null, { ...editFields, risk: '0' })).toMatchObject({ risk_score: 0 });
  });

  it('does not allow a known score to be cleared or replaced with invalid input', () => {
    expect(algorithmUpdateBody(50, editFields)).toBeNull();
    expect(algorithmUpdateBody(null, { ...editFields, risk: '0.5' })).toBeNull();
  });
});

describe('catalogue risk presentation', () => {
  it('keeps explicit zero distinct from an unknown score', () => {
    expect(catalogueRiskLevel(0)).toBe('Informational');
    expect(catalogueRiskLevel(null)).toBeNull();
  });

  it('sorts unknown scores after every numeric score, including zero', () => {
    const rows = [
      { name: 'unknown', risk_score: null },
      { name: 'zero', risk_score: 0 },
      { name: 'high', risk_score: 100 },
    ].sort(compareCatalogueRisk);
    expect(rows.map((row) => row.name)).toEqual(['high', 'zero', 'unknown']);
  });
});

// Decision 12 (RC-38): Deprecate makes the algorithm grade Critical, and the
// console must say exactly what the server does.
describe('obsolete grades Critical', () => {
  it('takes the floor from the shared Critical band, not a literal', () => {
    const critical = RISK_BANDS.find((b) => b.label === 'Critical');
    expect(OBSOLETE_RISK_FLOOR).toBe(critical?.min);
    expect(catalogueRiskLevel(OBSOLETE_RISK_FLOOR)).toBe('Critical');
    expect(catalogueRiskLevel(OBSOLETE_RISK_FLOOR - 1)).not.toBe('Critical');
  });

  it('raises a lower score to the floor and keeps a higher one', () => {
    expect(obsoleteRiskScore(30)).toBe(OBSOLETE_RISK_FLOOR);
    expect(obsoleteRiskScore(null)).toBe(OBSOLETE_RISK_FLOOR);
    expect(obsoleteRiskScore(OBSOLETE_RISK_FLOOR + 5)).toBe(OBSOLETE_RISK_FLOOR + 5);
  });

  it('describes the score change and the restore', () => {
    const text = deprecateDescription(30);
    expect(text).toContain(`from 30 to ${OBSOLETE_RISK_FLOOR}`);
    expect(text).toContain('Critical');
    expect(text).toContain('restores its 30 score');
    expect(deprecateDescription(null)).toContain('restores it to unassessed');
    expect(deprecateDescription(OBSOLETE_RISK_FLOOR + 3)).toContain(`stays ${OBSOLETE_RISK_FLOOR + 3}`);
  });

  it('does not echo an unchanged score, so leaving obsolete restores the remembered one', () => {
    const body = algorithmUpdateBody(OBSOLETE_RISK_FLOOR, {
      ...editFields, deprecationStatus: 'current', risk: String(OBSOLETE_RISK_FLOOR),
    });
    expect(body).not.toBeNull();
    expect(body).not.toHaveProperty('risk_score');
    expect(body).toMatchObject({ deprecation_status: 'current' });
  });

  it('still sends a score the admin actually changed', () => {
    expect(algorithmUpdateBody(40, { ...editFields, risk: '55' })).toMatchObject({ risk_score: 55 });
  });

  it('refuses a below-floor score while the algorithm stays obsolete', () => {
    expect(algorithmUpdateBody(OBSOLETE_RISK_FLOOR, {
      ...editFields, deprecationStatus: 'obsolete', risk: String(OBSOLETE_RISK_FLOOR - 10),
    })).toBeNull();
    expect(algorithmUpdateBody(OBSOLETE_RISK_FLOOR, {
      ...editFields, deprecationStatus: 'obsolete', risk: String(OBSOLETE_RISK_FLOOR + 1),
    })).toMatchObject({ risk_score: OBSOLETE_RISK_FLOOR + 1 });
  });
});
