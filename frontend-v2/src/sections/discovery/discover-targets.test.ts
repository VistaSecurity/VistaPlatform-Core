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

  it('reads 422 scan_target_too_large with the server sentence and each oversize target', () => {
    const v = targetVerdict(422, {
      error: 'scan_target_too_large',
      details: 'scan target too large: "10.20.0.0/19" names 8192 addresses',
      oversize_targets: [{ target: '10.20.0.0/19', addresses: '8192' }],
      target_limit: 4096,
    });
    expect(v).toEqual({ kind: 'too_large', oversize: [{ target: '10.20.0.0/19', addresses: '8192' }], message: 'scan target too large: "10.20.0.0/19" names 8192 addresses' });
    // The job-total flavour has no target list but is still this verdict.
    const total = targetVerdict(422, { error: 'scan_target_too_large', details: 'together 16640 addresses', job_addresses: '16640', job_limit: 16384 });
    expect(total).toEqual({ kind: 'too_large', oversize: [], message: 'together 16640 addresses' });
  });

  it('reads 422 scan_budget_exceeded with the server sentence and the largest target (#2170)', () => {
    const largest = { target: '10.0.0.0/22', addresses: 1024, tcp_port_count: 65535, udp_port_count: 11, estimated_probes: 67119104 };
    expect(targetVerdict(422, { error: 'scan_budget_exceeded', details: 'scan too large: 67119104 probes', estimated_probes: 67119104, probe_limit: 25000000, largest_target: largest }))
      .toEqual({ kind: 'budget', largest, message: 'scan too large: 67119104 probes' });
    expect(targetVerdict(422, { error: 'scan_budget_exceeded' })).toMatchObject({ kind: 'budget', largest: undefined });
  });

  it('reads 422 scan_plan_unavailable as a calm notice in its own words, not the raw code (#2170)', () => {
    const v = targetVerdict(422, { error: 'scan_plan_unavailable', details: 'scan depth is not available yet on this deployment; use protocols and ports' });
    expect(v.kind).toBe('plan_unavailable');
    expect(v.message).not.toMatch(/scan_plan_unavailable|protocols and ports/);
    expect(v.message).toMatch(/not available on this installation/);
  });

  it('reads 409 sensor_scan_plan_unsupported as its own refusal, in the server\'s words (#2194)', () => {
    const details = "sensor edge-a's software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned";
    expect(targetVerdict(409, { error: 'sensor_scan_plan_unsupported', details })).toEqual({ kind: 'sensor_unsupported', message: details });
    expect(targetVerdict(409, { error: 'sensor_scan_plan_unsupported' }).message).toMatch(/does not support scan depth/);
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
  it('Active Scan sends the confirmation only from its "Scan anyway", and only for the assets still pending', () => {
    // The scan dialog builds every body through scanBody; `true` is
    // passed from exactly one place, the confirmation, with what the server
    // says is still pending rather than the whole selection (the retired
    // page's C.4) or only the held assets (which dropped the rest).
    const dialog = read('../inventory/scan-dialog.tsx');
    expect(dialog.match(/confirmed: true \}\)/g)).toHaveLength(1);
    expect(dialog).toMatch(/sel: confirmSelection\(confirm\), confirmed: true/);
    expect(dialog).toMatch(/Scan anyway/);
    expect(dialog.match(/confirmed: false \}\)/g)).toHaveLength(1);
  });
  it('names the asset beside the address it would be scanned at', () => {
    expect(describeExternalAsset({ target: '93.184.216.34', addresses: ['93.184.216.34'], asset_name: 'partner-portal' })).toBe('partner-portal (93.184.216.34)');
    expect(describeExternalAsset({ target: '93.184.216.34', addresses: ['93.184.216.34'] })).toBe('93.184.216.34');
  });
  it('the wizard sends the confirmation only from the confirmation', () => {
    // WP4a: the body is built by discover-plan.ts's buildJobRequest, which
    // sets the flag only for `confirmed`; the dialog passes true from exactly
    // one place, the confirmation's "Scan anyway".
    const modal = read('./discover-modal.tsx');
    expect(modal.match(/start\(true\)/g)).toHaveLength(1);
    expect(modal).toMatch(/onClick=\{\(\) => start\(true\)\}>\s*\{create\.isPending \? 'Starting…' : 'Scan anyway'\}/);
    expect(modal).not.toMatch(/external_targets_confirmed/);
    const plan = read('./discover-plan.ts');
    expect(plan.match(/external_targets_confirmed = true/g)).toHaveLength(1);
    expect(plan).toMatch(/else if \(opts\.confirmed\) body\.external_targets_confirmed = true/);
  });
});
