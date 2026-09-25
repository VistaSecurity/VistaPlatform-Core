// Explicit external scan targets ( W5.13b): how the wizard reads the
// API's target verdicts, plus the reachability of the wizard from Active Scan.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { describeExternal, describeExternalAsset, externalConfirmTitle, targetVerdict } from './discover-targets';

describe('targetVerdict', () => {
  it('reads 422 external_targets_unconfirmed as a question with its targets', () => {
    const v = targetVerdict(422, {
      error: 'external_targets_unconfirmed',
      details: '2 scan target(s) are outside your registered networks',
      external_targets: [{ target: '93.184.216.34', addresses: ['93.184.216.34'] }, { target: 'www.example.com', addresses: ['93.184.216.34'] }],
    });
    expect(v.kind).toBe('unconfirmed');
    if (v.kind === 'unconfirmed') expect(v.targets.map((t) => t.target)).toEqual(['93.184.216.34', 'www.example.com']);
  });

  it('reads 403 external_targets_disabled as the operator switch, not a permission problem', () => {
    const v = targetVerdict(403, { error: 'external_targets_disabled', details: 'off', external_targets: [{ target: '93.184.216.34', addresses: [] }] });
    expect(v.kind).toBe('disabled');
  });

  it('reads 400 targets_refused with every target and its reason', () => {
    const v = targetVerdict(400, {
      error: 'targets_refused',
      details: 'refused',
      refused_targets: [{ target: '169.254.169.254', reason: 'link-local addresses include the cloud instance-metadata service' }, { target: 'metadata.example.com', reason: 'it resolves to 169.254.169.254' }],
    });
    expect(v.kind).toBe('refused');
    if (v.kind === 'refused') expect(v.refused).toHaveLength(2);
  });

  it('falls back to an error with the server sentence, then a status line — never the internal validation_error code', () => {
    expect(targetVerdict(409, { error: 'validation_error', details: 'sensor offline' })).toEqual({ kind: 'error', message: 'sensor offline' });
    expect(targetVerdict(400, { error: 'validation_error' })).toEqual({ kind: 'error', message: 'Failed to start discovery (400)' });
    expect(targetVerdict(500, undefined)).toEqual({ kind: 'error', message: 'Failed to start discovery (500)' });
    // A code with no list is not a verdict the dialog can render.
    expect(targetVerdict(422, { error: 'external_targets_unconfirmed' }).kind).toBe('error');
  });
});

describe('confirmation wording', () => {
  it('is the sentence the owner asked for, singular and plural', () => {
    expect(externalConfirmTitle(1)).toBe('1 target is outside your registered networks. Only scan systems you are authorized to test.');
    expect(externalConfirmTitle(3)).toBe('3 targets are outside your registered networks. Only scan systems you are authorized to test.');
  });

  it('shows where a name points, and not a literal twice', () => {
    expect(describeExternal({ target: 'https://www.example.com/', addresses: ['93.184.216.34'] })).toBe('https://www.example.com/ → 93.184.216.34');
    expect(describeExternal({ target: '93.184.216.0/28', addresses: ['93.184.216.0/28'] })).toBe('93.184.216.0/28');
  });
});

describe('reachability', () => {
  const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
  it('Active Scan opens the target wizard, gated on discovery.create like the endpoint', () => {
    const page = read('./active-scan-page.tsx');
    expect(page).toMatch(/<DiscoverAssetsModal open=\{targetsOpen\}/);
    expect(page).toMatch(/permission=\{TENANT_PERMISSIONS\.discovery\.create\}>\s*<button[^>]*onClick=\{\(\) => setTargetsOpen\(true\)\}/);
  });
  it('Active Scan sends the confirmation only from its "Scan anyway"', () => {
    const page = read('./active-scan-page.tsx');
    expect(page.match(/confirmed: true \}\)/g)).toHaveLength(1);
    expect(page).toMatch(/Scan anyway/);
    expect(page.match(/confirmed: false \}\)/g)?.length).toBeGreaterThanOrEqual(2);
  });
  it('names the asset beside the address it would be scanned at', () => {
    expect(describeExternalAsset({ target: '93.184.216.34', addresses: ['93.184.216.34'], asset_name: 'partner-portal' })).toBe('partner-portal (93.184.216.34)');
    expect(describeExternalAsset({ target: '93.184.216.34', addresses: ['93.184.216.34'] })).toBe('93.184.216.34');
  });
  it('the wizard sends the confirmation only from the confirmation', () => {
    const modal = read('./discover-modal.tsx');
    expect(modal).toMatch(/create\.mutate\(true\)/);
    expect(modal.match(/create\.mutate\(true\)/g)).toHaveLength(1);
    expect(modal).toMatch(/external_targets_confirmed: true/);
  });
});
