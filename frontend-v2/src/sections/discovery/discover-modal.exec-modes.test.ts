import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { buildJobRequest, checkForm, initialForm, type DiscoverForm } from './discover-plan';
import { runFromOptions, type SensorRow } from './active-scan-run-from';

// "Run from" in the Discover wizard ( WP4a). The wizard used to offer
// `execution_mode: "cloud"` labelled "Cloud — platform sensor"; the job
// processor reads a stored "cloud" as a cloud-ACCOUNT discovery and failed the
// job (hole H37). The server now maps a legacy "cloud" to the platform, but the
// wizard must not send it at all: it sends `run_from` (auto · platform ·
// sensor + sensor_id) — the same choices, and the same tested logic, as
// Discovery → Active Scan.

const form = (runFrom: string): DiscoverForm => ({ ...initialForm(null), targets: '10.0.0.0/24', runFrom });
const body = (runFrom: string) => {
  const f = form(runFrom);
  return buildJobRequest(f, checkForm(f, false), { otAvailable: false });
};

const now = new Date().toISOString();
const sensor = (id: string, name: string, extra: Partial<SensorRow> = {}) =>
  ({ id, name, status: 'active', last_heartbeat: now, tags: [], platform: 'linux', ...extra }) as SensorRow;

describe('Run from → the request', () => {
  it('Auto is run_from auto', () => {
    expect(body('auto')).toMatchObject({ run_from: 'auto' });
    expect(body('auto')).not.toHaveProperty('sensor_id');
  });

  it('Platform sensor is run_from platform — never the legacy "cloud"', () => {
    expect(body('platform')).toMatchObject({ run_from: 'platform' });
    expect(body('platform')).not.toHaveProperty('sensor_id');
  });

  it('a named tenant sensor is run_from sensor with its id', () => {
    expect(body('sensor:6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d')).toMatchObject({ run_from: 'sensor', sensor_id: '6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d' });
  });

  it('never sends the legacy dispatch fields, whatever is chosen', () => {
    for (const v of ['auto', 'platform', 'sensor:abc']) {
      const b = body(v);
      expect(b).not.toHaveProperty('execution_mode');
      expect(b).not.toHaveProperty('preferred_sensor_ids');
      expect(JSON.stringify(b)).not.toContain('cloud');
    }
  });
});

describe('Run from → the choices', () => {
  it('offers Auto, the platform sensor and each tenant sensor — and no "cloud"', () => {
    const r = runFromOptions([sensor('s1', 'edge-a'), sensor('p1', 'platform', { tags: ['system'] })], { loading: false, error: false });
    expect(r.options.map((o) => o.value)).toEqual(['auto', 'platform', 'sensor:s1']);
    expect(r.defaultValue).toBe('auto');
  });

  it('the wizard source names no legacy execution mode', () => {
    const src = readFileSync(fileURLToPath(new URL('./discover-modal.tsx', import.meta.url)), 'utf8');
    expect(src).not.toMatch(/execution_mode|EXEC_MODES|'cloud'/);
  });
});
