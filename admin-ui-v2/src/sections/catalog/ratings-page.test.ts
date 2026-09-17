import { describe, expect, it } from 'vitest';
import { algorithmUpdateBody, catalogueRiskLevel, compareCatalogueRisk, explicitRiskScore } from './ratings-page';

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
