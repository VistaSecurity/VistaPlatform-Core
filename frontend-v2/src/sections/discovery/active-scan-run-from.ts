// The Active Scan page's "Run from" decisions, out of the component so
// they can be tested without rendering: which executors to offer given the
// sensor fleet (and whether it loaded), what the scan request looks like for
// the chosen one, and how to say what the scan did.
//
// The permission follows the ACTION, not the executor: dispatching to a tenant
// sensor is gated by the same assets.update the platform scan is, so nothing
// here consults RBAC.
import type { inventoryComponents, sensorManagerComponents } from '@vistasecurity/api-contract';
import { sensorOnline } from './kit';

export type SensorRow = sensorManagerComponents['schemas']['Sensor'];
export type ActiveScanResponse = inventoryComponents['schemas']['ActiveScanResponse'];
export type ActiveScanRequest = inventoryComponents['schemas']['ActiveScanRequest'];

/** One choice in the "Run from" select. */
export interface RunFromOption {
  /** `auto`, `platform`, or `sensor:<id>`. */
  value: string;
  label: string;
  disabled?: boolean;
  /** For a sensor entry: why it is disabled (offline), shown as the title. */
  hint?: string;
}

export interface RunFromChoice {
  run_from: 'auto' | 'platform' | 'sensor';
  sensor_id?: string;
}

export const AUTO = 'auto';
export const PLATFORM = 'platform';

/** The platform's own in-cluster sensors carry the `system` tag; they are the "Platform sensor" entry, never listed by name. */
export function isPlatformSensor(s: Pick<SensorRow, 'tags' | 'platform'>): boolean {
  return (s.tags ?? []).some((t) => t.toLowerCase() === 'system') || (s.platform ?? '').toLowerCase() === 'platform';
}

/** Tenant sensors a scan could run from, live ones first, then by name. */
export function tenantSensors(sensors: SensorRow[]): SensorRow[] {
  return sensors
    .filter((s) => !isPlatformSensor(s) && !s.air_gapped)
    .sort((a, b) => {
      const ao = sensorOnline(a.status, a.last_heartbeat) ? 0 : 1;
      const bo = sensorOnline(b.status, b.last_heartbeat) ? 0 : 1;
      return ao - bo || a.name.localeCompare(b.name);
    });
}

/**
 * The select's options for the fleet as loaded.
 *
 * Every state the spec table names:
 *   - sensors still loading → the control is disabled (caller reads `loading`);
 *   - the list failed → Platform only, with an inline notice (caller reads `error`);
 *   - no tenant sensors registered → Platform only, with the hint to Sensors & Agents;
 *   - otherwise Auto (default) · Platform sensor · one entry per tenant sensor,
 *     offline ones present but disabled so the operator can see WHY a host
 *     cannot be scanned from where it was observed.
 */
export function runFromOptions(sensors: SensorRow[] | undefined, state: { loading: boolean; error: boolean }): {
  options: RunFromOption[];
  defaultValue: string;
  loading: boolean;
  error: boolean;
  noTenantSensors: boolean;
} {
  const platform: RunFromOption = { value: PLATFORM, label: 'Platform sensor' };
  if (state.loading) {
    return { options: [platform], defaultValue: PLATFORM, loading: true, error: false, noTenantSensors: false };
  }
  if (state.error || sensors === undefined) {
    return { options: [platform], defaultValue: PLATFORM, loading: false, error: true, noTenantSensors: false };
  }
  const fleet = tenantSensors(sensors);
  if (fleet.length === 0) {
    return { options: [platform], defaultValue: PLATFORM, loading: false, error: false, noTenantSensors: true };
  }
  const options: RunFromOption[] = [
    { value: AUTO, label: 'Auto (observing sensor)' },
    platform,
    ...fleet.map((s) => {
      const on = sensorOnline(s.status, s.last_heartbeat);
      return {
        value: `sensor:${s.id}`,
        label: on ? s.name : `${s.name} (offline)`,
        disabled: !on,
        hint: on ? undefined : 'This sensor has not checked in recently; a scan sent to it would fail as "sensor offline".',
      };
    }),
  ];
  return { options, defaultValue: AUTO, loading: false, error: false, noTenantSensors: false };
}

/** The select value → the request's executor fields. */
export function choiceFromValue(value: string): RunFromChoice {
  if (value === PLATFORM) return { run_from: 'platform' };
  if (value.startsWith('sensor:')) return { run_from: 'sensor', sensor_id: value.slice('sensor:'.length) };
  return { run_from: 'auto' };
}

/** The POST body for a scan of these assets from this executor. */
export function scanRequestBody(assetIds: string[], value: string): ActiveScanRequest {
  const choice = choiceFromValue(value);
  const body: ActiveScanRequest = { asset_ids: assetIds, run_from: choice.run_from };
  if (choice.sensor_id) body.sensor_id = choice.sensor_id;
  return body;
}

/**
 * The toast after a scan: names the executor(s), and says what was NOT
 * scanned. "Active scan started" alone would hide a job that went to the
 * wrong place or an asset that went nowhere.
 */
export function describeScanResult(r: ActiveScanResponse): { text: string; tone: 'success' | 'warning' | 'error' } {
  const jobs = r.jobs ?? [];
  const skipped = r.skipped ?? [];
  const executors = Array.from(new Set(jobs.map((j) => (j.executor === 'sensor' ? j.sensor_name ?? 'a tenant sensor' : 'the platform sensor'))));
  const n = r.count ?? 0;
  const assets = `${n} asset${n === 1 ? '' : 's'}`;

  if (jobs.length === 0) {
    const reason = skipped[0]?.reason ? ` — ${skipped[0].reason}` : '';
    return { text: `Nothing was scanned${reason}`, tone: 'error' };
  }
  const from = executors.length === 1 ? `from ${executors[0]}` : `from ${executors.length} executors (${executors.join(', ')})`;
  if (skipped.length > 0) {
    return {
      text: `Active scan started for ${assets} ${from}; ${skipped.length} not scanned: ${skipped[0].reason}`,
      tone: 'warning',
    };
  }
  return { text: `Active scan started for ${assets} ${from}`, tone: 'success' };
}
