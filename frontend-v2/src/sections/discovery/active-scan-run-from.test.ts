import { describe, expect, it } from 'vitest';
import {
  type ActiveScanResponse, type SensorRow,
  AUTO, PLATFORM, choiceFromValue, describeScanResult, isPlatformSensor, runFromOptions, scanRequestBody, tenantSensors,
} from './active-scan-run-from';

// The "Run from" control's decisions, one spec-table state at a time.

const now = Date.now();
function sensor(over: Partial<SensorRow>): SensorRow {
  return {
    id: 'id', tenant_id: 't', name: 'sensor', platform: 'linux', version: '1', profile: 'datacenter_host',
    sensor_type: 'network', status: 'active', air_gapped: false, network_interfaces: [], available_interfaces: [],
    tags: [], ip_address: '198.51.100.173', last_heartbeat: new Date(now - 20_000).toISOString(),
    reporting_interval: 30, created_at: '', updated_at: '',
    ...over,
  } as SensorRow;
}
const xps = sensor({ id: 'xps', name: 'xps16-sensor' });
const stale = sensor({ id: 'branch', name: 'branch-sensor', last_heartbeat: new Date(now - 3_600_000).toISOString() });
const platform = sensor({ id: 'plat', name: 'Platform Discovery Sensor', tags: ['system', 'platform', 'discovery'], platform: 'platform' });
const gapped = sensor({ id: 'vault', name: 'vault-sensor', air_gapped: true });

describe('isPlatformSensor / tenantSensors', () => {
  it('excludes the platform sensors and air-gapped ones, live first then by name', () => {
    expect(isPlatformSensor(platform)).toBe(true);
    expect(isPlatformSensor(xps)).toBe(false);
    expect(tenantSensors([stale, platform, xps, gapped]).map((s) => s.name)).toEqual(['xps16-sensor', 'branch-sensor']);
  });
});

describe('runFromOptions', () => {
  it('default: Auto · Platform sensor · each tenant sensor, defaulting to Auto', () => {
    const r = runFromOptions([xps, platform], { loading: false, error: false });
    expect(r.options.map((o) => o.value)).toEqual([AUTO, PLATFORM, 'sensor:xps']);
    expect(r.options[0].label).toMatch(/observing sensor/i);
    expect(r.defaultValue).toBe(AUTO);
    expect(r.noTenantSensors).toBe(false);
  });

  it('an offline sensor is listed but disabled, with the reason', () => {
    const r = runFromOptions([xps, stale], { loading: false, error: false });
    const off = r.options.find((o) => o.value === 'sensor:branch');
    expect(off?.disabled).toBe(true);
    expect(off?.label).toMatch(/offline/);
    expect(off?.hint).toMatch(/sensor offline/);
    expect(r.options.find((o) => o.value === 'sensor:xps')?.disabled).toBeFalsy();
  });

  it('empty: no tenant sensors → Platform sensor only, with the hint flag', () => {
    const r = runFromOptions([platform], { loading: false, error: false });
    expect(r.options.map((o) => o.value)).toEqual([PLATFORM]);
    expect(r.defaultValue).toBe(PLATFORM);
    expect(r.noTenantSensors).toBe(true);
  });

  it('loading: disabled, Platform placeholder', () => {
    const r = runFromOptions(undefined, { loading: true, error: false });
    expect(r.loading).toBe(true);
    expect(r.options.map((o) => o.value)).toEqual([PLATFORM]);
  });

  it('error: falls back to Platform with the notice flag', () => {
    const r = runFromOptions(undefined, { loading: false, error: true });
    expect(r.error).toBe(true);
    expect(r.options.map((o) => o.value)).toEqual([PLATFORM]);
    expect(r.defaultValue).toBe(PLATFORM);
  });
});

describe('scanRequestBody', () => {
  it('maps the select value onto run_from / sensor_id', () => {
    expect(choiceFromValue(AUTO)).toEqual({ run_from: 'auto' });
    expect(choiceFromValue(PLATFORM)).toEqual({ run_from: 'platform' });
    expect(choiceFromValue('sensor:xps')).toEqual({ run_from: 'sensor', sensor_id: 'xps' });
    expect(scanRequestBody(['a'], 'sensor:xps')).toEqual({ asset_ids: ['a'], run_from: 'sensor', sensor_id: 'xps' });
    expect(scanRequestBody(['a', 'b'], AUTO)).toEqual({ asset_ids: ['a', 'b'], run_from: 'auto' });
    expect(scanRequestBody(['a'], AUTO)).not.toHaveProperty('sensor_id');
  });
});

describe('describeScanResult', () => {
  const base: ActiveScanResponse = { message: 'Active scan started', job_id: 'j1', count: 3, jobs: [], skipped: [] };

  it('names the executor', () => {
    const d = describeScanResult({ ...base, jobs: [{ job_id: 'j1', executor: 'sensor', sensor_name: 'xps16-sensor', count: 3 }] });
    expect(d.tone).toBe('success');
    expect(d.text).toBe('Active scan started for 3 assets from xps16-sensor');
  });

  it('names every executor when the scan was split', () => {
    const d = describeScanResult({ ...base, jobs: [
      { job_id: 'j1', executor: 'sensor', sensor_name: 'xps16-sensor', count: 2 },
      { job_id: 'j2', executor: 'platform', count: 1 },
    ] });
    expect(d.text).toMatch(/from 2 executors \(xps16-sensor, the platform sensor\)/);
  });

  it('says what was NOT scanned', () => {
    const d = describeScanResult({ ...base, count: 2, jobs: [{ job_id: 'j1', executor: 'platform', count: 2 }],
      skipped: [{ asset_id: 'a', reason: 'observing sensor branch-sensor is offline; 10.0.0.9 was not scanned this pass' }] });
    expect(d.tone).toBe('warning');
    expect(d.text).toMatch(/1 not scanned: observing sensor branch-sensor is offline/);
  });

  it('a scan that started nothing is an error, with the reason', () => {
    const d = describeScanResult({ ...base, count: 0, job_id: '', skipped: [{ asset_id: 'a', reason: 'observing sensor xps16-sensor is offline; 10.0.0.9 was not scanned this pass' }] });
    expect(d.tone).toBe('error');
    expect(d.text).toMatch(/Nothing was scanned — observing sensor xps16-sensor is offline/);
  });
});
