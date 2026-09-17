import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { connectionStrengthFilter, connectionStrengthLabel, connectionStrengthTone } from './connection-strength';

describe('external connection strength', () => {
  it.each(['weak', 'acceptable', 'strong', 'recommended'] as const)('preserves the canonical %s label and filter', (grade) => {
    const label = connectionStrengthLabel(grade);
    expect(label.toLowerCase()).toBe(grade);
    expect(connectionStrengthFilter(label)).toBe(grade);
  });
  it('keeps unknown and unresolved historical weakness visible', () => {
    expect(connectionStrengthLabel(null)).toBe('Not assessed');
    expect(connectionStrengthLabel(null, ['Prior weak key evidence unavailable'])).toBe('Reassessment required');
    expect(connectionStrengthTone(null)).toBe('var(--app-t3)');
    expect(connectionStrengthFilter('Not assessed')).toBe('unassessed');
    expect(connectionStrengthFilter('All')).toBeUndefined();
  });
  it('keeps known weakness visible alongside a reassessment gap', () => {
    expect(connectionStrengthLabel('weak', ['Previous weak assessment requires fresh cryptographic evidence'])).toBe('Weak');
    expect(connectionStrengthTone('weak')).toBe('var(--danger)');
  });
  it('wires canonical filtering and explicit labels into the table and export', () => {
    const source = readFileSync(new URL('./inventory-page.tsx', import.meta.url), 'utf8');
    expect(source.includes('...(strength ? { strength } : {})')).toBe(true);
    expect(source).toContain('connectionStrengthLabel(cn.strength, cn.weak_reasons)');
    expect(source).toContain('connectionStrengthLabel(strength, cn.weak_reasons)');
    expect(source).not.toContain('cn.crypto_strength');
    expect(source).toContain("weakReasons.join('; ')");
    expect(source).toContain('title={reasonsTitle}');
    const dashboard = readFileSync(new URL('../dashboard/dashboard-page.tsx', import.meta.url), 'utf8');
    expect(dashboard.includes("['Reassessment required', cx?.reassessment_required ?? 0]")).toBe(true);
  });
});
