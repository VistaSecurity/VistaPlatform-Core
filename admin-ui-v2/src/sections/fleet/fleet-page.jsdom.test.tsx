// @vitest-environment jsdom
//
// Fleet ▸ Agent estate, MOUNTED THROUGH THE REAL PAGE over a real QueryClient
// and the real typed clients, with only fetch stubbed (admin-ui review RC-16,
// tenants-overview-fleet-7 / -8).
//
// The fixture is one tenant's estate as the owner saw it: the two platform
// rows every tenant is given (both in sensor-manager's /admin/sensors), one
// customer sensor, and one discovery agent (device-interrogation /admin/agents).
//
//   - The Platform Device Interrogation Agent is a `sensors` row but an agent:
//     the Sensors chip used to read 3 (both platform rows + the customer
//     sensor) and label it "Platform Sensor".
//   - The discovery agent's stored status is 'active' forever; the row must
//     show effective_status (here: offline — its heartbeat is stale).
//
// Mutations run (each red, then restored green):
//   - sensorFleetRow always kind 'sensor' → chips Sensors 3 / Agents 1; red.
//   - isPlatformInterrogationAgent ignores is_platform_sensor → the customer
//     device_interrogation sensor moves to Agents; red.
//   - agentFleetRow reads a.status → the stale agent shows Active; red.
//   - chips counted from the per-endpoint arrays again → red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const TENANT = '55555555-5555-4555-8555-555555555555';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const sensorRow = (over: Record<string, unknown>) => ({
  id: crypto.randomUUID(), tenant_id: TENANT, tenant_name: 'Northwind', tenant_slug: 'northwind',
  name: 'x', description: null, sensor_type: 'network', platform: 'linux', version: '1.0.0', profile: 'discovery',
  status: 'active', air_gapped: false, network_interfaces: [], available_interfaces: [], tags: [], ip_address: null,
  is_platform_sensor: false, last_heartbeat: '2026-09-23T00:00:00Z', created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
  ...over,
});

const sensors = [
  sensorRow({ name: 'Platform Discovery Sensor', platform: 'platform', version: 'system', tags: ['system', 'platform', 'discovery'], is_platform_sensor: true }),
  sensorRow({ name: 'Platform Device Interrogation Agent', platform: 'platform', version: 'system', profile: 'device_interrogation', sensor_type: 'api', tags: ['system', 'platform', 'device_interrogation'], is_platform_sensor: true }),
  // A customer may deploy a sensor with the interrogation profile: still a sensor.
  sensorRow({ name: 'customer-sensor-1', platform: 'windows', profile: 'device_interrogation' }),
];
const agents = [{
  id: crypto.randomUUID(), tenant_id: TENANT, tenant_name: 'Northwind', tenant_slug: 'northwind',
  name: 'customer-agent-1', platform: 'windows', profile: null, version: '1.0.0',
  status: 'active', effective_status: 'offline', ip_address: null,
  last_heartbeat: '2026-09-22T00:00:00Z', created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
}];

const fetchStub = vi.fn(async (req: Request) => {
  const path = new URL(req.url).pathname;
  if (path.endsWith('/admin/sensors')) return json({ sensors, count: sensors.length });
  if (path.endsWith('/admin/agents')) return json({ agents, count: agents.length });
  if (path.endsWith('/admin/metrics')) return json({});
  return json({ error: 'not stubbed' }, 404);
});
class RelativeUrlRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(typeof input === 'string' && input.startsWith('/') ? `http://gateway.test${input}` : input, init);
  }
}
const realFetch = globalThis.fetch;
const realRequest = globalThis.Request;

type PageModule = typeof import('./fleet-page');
type ScopeModule = typeof import('../../app/scope');
let page: PageModule;
let scope: ScopeModule;

beforeAll(async () => {
  vi.stubGlobal('fetch', fetchStub);
  vi.stubGlobal('Request', RelativeUrlRequest);
  page = await import('./fleet-page');
  scope = await import('../../app/scope');
});
afterAll(() => {
  vi.stubGlobal('fetch', realFetch);
  vi.stubGlobal('Request', realRequest);
  vi.unstubAllGlobals();
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
afterEach(() => {
  act(() => root?.unmount());
  root = null;
  host?.remove();
});

async function settle() {
  for (let i = 0; i < 10; i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  }
}
async function until<T>(read: () => T | null | undefined, what: string): Promise<T> {
  for (let i = 0; i < 50; i++) {
    const v = read();
    if (v) return v;
    await settle();
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(
    <QueryClientProvider client={qc}>
      <scope.ScopeProvider><page.FleetPage /></scope.ScopeProvider>
    </QueryClientProvider>,
  ));
  await until(() => host.textContent?.includes('customer-agent-1') && host.textContent?.includes('customer-sensor-1'), 'both endpoints to render');
}

const chip = (label: string) =>
  Array.from(host.querySelectorAll<HTMLButtonElement>('button.op-chip')).find((b) => b.textContent?.startsWith(label))!;
const rowFor = (name: string) =>
  Array.from(host.querySelectorAll('tbody tr')).find((tr) => tr.textContent?.includes(name));

describe('Fleet agent estate classifies by kind, not by store', () => {
  it('counts the platform interrogation agent as an agent', async () => {
    await mount();
    expect(chip('All').textContent).toBe('All4');
    expect(chip('sensors').textContent).toBe('sensors2');
    expect(chip('agents').textContent).toBe('agents2');

    expect(rowFor('Platform Device Interrogation Agent')?.textContent).toContain('Platform Interrogation Agent');
    expect(rowFor('Platform Discovery Sensor')?.textContent).toContain('Platform Sensor');

    act(() => chip('agents').click());
    await settle();
    const names = Array.from(host.querySelectorAll('tbody tr')).map((tr) => tr.textContent ?? '');
    expect(names.some((t) => t.includes('Platform Device Interrogation Agent'))).toBe(true);
    expect(names.some((t) => t.includes('customer-agent-1'))).toBe(true);
    expect(names.some((t) => t.includes('customer-sensor-1'))).toBe(false);
  });

  it("shows a discovery agent's heartbeat-derived status, not the stored one", async () => {
    await mount();
    const row = rowFor('customer-agent-1');
    expect(row?.textContent).toContain('Offline');
    expect(row?.textContent).not.toContain('Active');
  });
});
