import { describe, expect, it } from 'vitest';
import { levelFromScore } from '../../components/ui';
import {
  atRestState, protectionRung, rungLevel, rungColor, rowRiskLevel,
  RUNG_META, RUNG_ORDER, dataProtectionCsvRow, DATA_PROTECTION_CSV_HEADER,
  determinedParam, resourceTypeParam, encryptionTypeLabel, resourceTypeLabel, originLabel,
  type CryptoApplication,
} from './data-protection';

const app = (over: Partial<CryptoApplication> = {}): CryptoApplication => ({
  id: 'a1', resource_type: 'cloud_storage', resource_name: 'bucket', ...over,
});

// ---------------------------------------------------------------------------
// THE thing that must never regress: three states, never two. An AccessDenied
// on the encryption read must not render as either verdict.
// ---------------------------------------------------------------------------
describe('atRestState — three states', () => {
  it('is encrypted only when determined AND encrypted', () => {
    expect(atRestState({ encryption_determined: true, encrypted: true })).toBe('encrypted');
  });

  it('is unencrypted only when determined AND not encrypted', () => {
    expect(atRestState({ encryption_determined: true, encrypted: false })).toBe('unencrypted');
  });

  it('is not-assessed when determination failed, whatever `encrypted` says', () => {
    // Both polarities: an undetermined row must not inherit either verdict.
    expect(atRestState({ encryption_determined: false, encrypted: false })).toBe('not-assessed');
    expect(atRestState({ encryption_determined: false, encrypted: true })).toBe('not-assessed');
  });

  it('is not-assessed when the determination flag is absent or null', () => {
    expect(atRestState({})).toBe('not-assessed');
    expect(atRestState({ encrypted: true })).toBe('not-assessed');
    expect(atRestState({ encryption_determined: null, encrypted: false })).toBe('not-assessed');
  });

  it('is not-assessed when determined but `encrypted` is missing (incoherent → honest)', () => {
    expect(atRestState({ encryption_determined: true })).toBe('not-assessed');
    expect(atRestState({ encryption_determined: true, encrypted: null })).toBe('not-assessed');
  });

  it('never maps a not-assessed row onto an encrypted or unencrypted render', () => {
    const undetermined = [
      app({ encryption_determined: false, encrypted: true, key_manager: 'customer', encryption_type: 'sse-kms' }),
      app({ encryption_determined: false, encrypted: false }),
      app({}),
    ];
    for (const a of undetermined) {
      expect(atRestState(a)).toBe('not-assessed');
      expect(protectionRung(a)).toBe('not-assessed');
      expect(RUNG_META[protectionRung(a)].filled).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// The ladder: unencrypted → provider key → customer key. SSE-S3 must NOT look
// like SSE-KMS-with-a-customer-key.
// ---------------------------------------------------------------------------
describe('protectionRung — the ladder', () => {
  it('puts an unencrypted resource on the bottom rung', () => {
    expect(protectionRung(app({ encryption_determined: true, encrypted: false }))).toBe('unencrypted');
  });

  it('reads explicit key_manager custody', () => {
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, key_manager: 'provider', encryption_type: 'sse-s3' }))).toBe('provider-managed');
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, key_manager: 'customer', encryption_type: 'sse-kms' }))).toBe('customer-managed');
  });

  it('treats SSE-S3 with no custody attribution as provider-managed', () => {
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, encryption_type: 'sse-s3' }))).toBe('provider-managed');
  });

  it('does NOT promote an unattributed KMS key to customer-managed', () => {
    // "SSE-KMS" alone does not say whose key (aws/s3 is SSE-KMS too).
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, encryption_type: 'sse-kms' }))).toBe('custody-unknown');
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, encryption_type: 'sse-kms-dsse' }))).toBe('custody-unknown');
    expect(protectionRung(app({ encryption_determined: true, encrypted: true, encryption_type: 'unknown' }))).toBe('custody-unknown');
  });

  it('gives SSE-S3 and customer-KMS visibly different rungs and tones', () => {
    const sseS3 = app({ encryption_determined: true, encrypted: true, encryption_type: 'sse-s3', key_manager: 'provider' });
    const kms = app({ encryption_determined: true, encrypted: true, encryption_type: 'sse-kms', key_manager: 'customer' });
    // Both are "encrypted"…
    expect(atRestState(sseS3)).toBe('encrypted');
    expect(atRestState(kms)).toBe('encrypted');
    // …but they must never present identically.
    expect(protectionRung(sseS3)).not.toBe(protectionRung(kms));
    expect(rungColor(protectionRung(sseS3))).not.toBe(rungColor(protectionRung(kms)));
    expect(RUNG_META[protectionRung(sseS3)].filled).toBeLessThan(RUNG_META[protectionRung(kms)].filled);
  });

  it('fills the meter monotonically up the ladder', () => {
    const filled = RUNG_ORDER.map((r) => RUNG_META[r].filled);
    expect(filled).toEqual([0, 1, 2, 2, 3]);
  });
});

// The rung severities come from the SHARED band ladder, not a local colour
// table — pin them against levelFromScore so a band change moves both together.
describe('rungLevel uses the shared risk bands', () => {
  it('bands unencrypted Critical, provider-managed Medium, customer-managed Low', () => {
    expect(rungLevel('unencrypted')).toBe(levelFromScore(90));
    expect(rungLevel('unencrypted')).toBe('Critical');
    expect(rungLevel('provider-managed')).toBe(levelFromScore(40));
    expect(rungLevel('provider-managed')).toBe('Medium');
    expect(rungLevel('customer-managed')).toBe(levelFromScore(10));
    expect(rungLevel('customer-managed')).toBe('Low');
  });

  it('bands a not-assessed rung Informational — not Low, not "safe"', () => {
    expect(rungLevel('not-assessed')).toBe('Informational');
  });
});

describe('rowRiskLevel', () => {
  it("prefers the server's banded level", () => {
    expect(rowRiskLevel(app({ risk_level: 'High', risk_score: 10 }))).toBe('High');
  });

  it('falls back to the shared band ladder when the server sends only a score', () => {
    expect(rowRiskLevel(app({ risk_score: 90 }))).toBe(levelFromScore(90));
    expect(rowRiskLevel(app({ risk_score: 40 }))).toBe(levelFromScore(40));
  });

  it('bands a missing/zero score as Informational (0 == NOT ASSESSED, not safe)', () => {
    expect(rowRiskLevel(app({}))).toBe('Informational');
    expect(rowRiskLevel(app({ risk_score: 0 }))).toBe('Informational');
  });
});

describe('filter params', () => {
  it('maps the assessment filter onto the API tri-state', () => {
    expect(determinedParam('All')).toBeUndefined();
    expect(determinedParam('Assessed')).toBe(true);
    expect(determinedParam('Not assessed')).toBe(false);
  });

  it('maps resource-type labels onto API values', () => {
    expect(resourceTypeParam('All')).toBeUndefined();
    expect(resourceTypeParam('Object storage')).toBe('cloud_storage');
    expect(resourceTypeParam('Database')).toBe('database');
  });
});

describe('labels', () => {
  it('humanises resource and encryption types without inventing values', () => {
    expect(resourceTypeLabel('cloud_storage')).toBe('Object storage');
    expect(resourceTypeLabel('database')).toBe('Database');
    expect(resourceTypeLabel(null)).toBe('—');
    expect(resourceTypeLabel('some_new_type')).toBe('some new type');
    expect(encryptionTypeLabel('sse-kms-dsse')).toBe('DSSE-KMS');
    expect(encryptionTypeLabel(null)).toBe('—');
  });

  it('shows provider and region so a finding is actionable', () => {
    expect(originLabel(app({ cloud_provider: 'aws', cloud_region: 'us-east-1' }))).toBe('aws · us-east-1');
    expect(originLabel(app({}))).toBe('—');
  });
});

describe('CSV export', () => {
  it('emits one cell per header column', () => {
    expect(dataProtectionCsvRow(app({})).length).toBe(DATA_PROTECTION_CSV_HEADER.length);
  });

  it('exports not_assessed as its own value, never as encrypted/unencrypted', () => {
    const row = dataProtectionCsvRow(app({ encryption_determined: false, encrypted: true }));
    expect(row[DATA_PROTECTION_CSV_HEADER.indexOf('encryption_state')]).toBe('not_assessed');
    expect(row[DATA_PROTECTION_CSV_HEADER.indexOf('key_custody')]).toBe('not_assessed');
  });

  it('carries the ARN and the custody rung', () => {
    const row = dataProtectionCsvRow(app({
      encryption_determined: true, encrypted: true, key_manager: 'customer', encryption_type: 'sse-kms',
      resource_identifier: 'arn:aws:s3:::example-bucket', kms_key_id: 'arn:aws:kms:us-east-1:1:key/abc',
    }));
    expect(row[DATA_PROTECTION_CSV_HEADER.indexOf('resource_identifier')]).toBe('arn:aws:s3:::example-bucket');
    expect(row[DATA_PROTECTION_CSV_HEADER.indexOf('key_custody')]).toBe(RUNG_META['customer-managed'].label);
    expect(row[DATA_PROTECTION_CSV_HEADER.indexOf('encryption_state')]).toBe('encrypted');
  });
});
