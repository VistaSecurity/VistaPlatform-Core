// @vitest-environment jsdom
//
// Which SECTION the platform device-interrogation agent renders in, MOUNTED.
//
// The agent has a row in `sensors` only because the interrogation pipeline
// needs something to attribute discoveries to (ResultProcessor.lookupSystemSensor
// resolves it as `sensor_discoveries.sensor_id`). It is not a sensor, and it
// arrived on the sensors query, so it rendered in the Sensors table — under a
// Type column reading "api", with an empty Segment.
//
// agent-fleet.test.ts pins what the PREDICATE decides. This pins that the page
// actually consults it: delete the `partitionSensorFleet` call from
// sensors-page.tsx and every assertion below goes red, while the helper's own
// suite stays green. That is the repo's "test the WIRING, not just the helper"
// rule — the same shape as select_tier_gate_test.go.
//
// Follows rail-drawer.jsdom.test.tsx: jsdom + React's own `act`, no
// testing-library, and the docblock opts this file in so the node-env suites
// are untouched.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const PLATFORM_AGENT = 'Platform Device Interrogation Agent';
const PLATFORM_SENSOR = 'Platform Discovery Sensor';
const CUSTOMER_SENSOR = 'edge-sensor-01';
const CUSTOMER_AGENT = 'agent-on-jump-host';

// The two rows the provisioning trigger gives every tenant, plus one
// customer-deployed sensor that carries the interrogation profile — the row
// that must NOT move (see isPlatformInterrogationAgent).
const SENSORS = [
  { id: 's-platform', name: PLATFORM_SENSOR, platform: 'platform', profile: 'discovery', sensor_type: 'network', tags: ['system', 'platform', 'discovery'], status: 'active', version: '1.0.0', last_heartbeat: new Date().toISOString(), network_interfaces: [] },
  { id: 's-interrogation', name: PLATFORM_AGENT, platform: 'platform', profile: 'device_interrogation', sensor_type: 'api', tags: ['system', 'platform', 'device_interrogation'], status: 'active', version: '1.0.0', last_heartbeat: new Date().toISOString(), network_interfaces: [] },
  { id: 's-customer', name: CUSTOMER_SENSOR, platform: 'linux', profile: 'device_interrogation', sensor_type: 'network', tags: ['edge'], status: 'active', version: '0.9.0', last_heartbeat: new Date().toISOString(), network_interfaces: ['10.0.0.0/24'] },
];

const AGENTS = [
  { id: 'a-1', name: CUSTOMER_AGENT, platform: 'linux', profile: 'device_interrogation', status: 'active', version: '1.0.0', last_heartbeat: new Date().toISOString(), job_count: 3, last_job_at: new Date().toISOString(), addresses: [] },
];

vi.mock('./queries', () => ({
  useSensors: () => ({ data: SENSORS, isLoading: false, isError: false }),
  useDeviceAgents: () => ({ data: AGENTS, isLoading: false, isError: false }),
  useDiscoveryCounts: () => ({ data: { 's-interrogation': 42 }, isLoading: false, isError: false }),
}));

// The write surface and the drawers are not what is under test, and each one
// opens its own queries.
vi.mock('./sensor-modals', () => ({
  RegisterSensorModal: () => null,
  DeleteSensorModal: () => null,
  DeleteAgentModal: () => null,
  PendingRegistrationsSection: () => null,
}));
// The drawers are stubbed to a marker rather than to null: which one a row
// opens is the point. The platform row's data is a SENSOR row, so it must open
// the sensor drawer — the agent drawer would call device-interrogation-service's
// per-agent config endpoints with a sensor id and 404.
vi.mock('./sensor-detail-drawer', () => ({
  SensorDetailDrawer: ({ sensor }: { sensor: { name: string } }) => <div data-testid="sensor-drawer">{sensor.name}</div>,
}));
vi.mock('./agent-detail-drawer', () => ({
  AgentDetailDrawer: ({ agent }: { agent: { name: string } }) => <div data-testid="agent-drawer">{agent.name}</div>,
}));
vi.mock('./agent-fleet-defaults-modal', () => ({ AgentFleetDefaultsModal: () => null }));
vi.mock('./sensor-fleet-defaults-modal', () => ({ SensorFleetDefaultsModal: () => null }));

vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
  usePermissions: () => ({ hasPermission: () => true, hasAnyPermission: () => true }),
}));

const { SensorsPage } = await import('./sensors-page');

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => { root.render(<SensorsPage />); });
});

afterEach(() => {
  act(() => { root.unmount(); });
  host.remove();
});

/** The two tables, located the way a reader would: by the heading between them. */
function tables() {
  const heading = [...host.querySelectorAll('h3')].find((h) => h.textContent === 'Discovery agents');
  if (!heading) throw new Error('no "Discovery agents" heading rendered');
  const agentsSection = heading.parentElement!.parentElement!;
  const panels = [...host.querySelectorAll('.panel')];
  const agentsTable = panels.find((p) => agentsSection.contains(p));
  const sensorsTable = panels.find((p) => !agentsSection.contains(p));
  if (!agentsTable || !sensorsTable) throw new Error('expected a table in each section');
  return { sensorsTable, agentsTable, heading };
}

describe('Sensors & Agents — which section each row lands in', () => {
  it('renders the platform interrogation agent in the Discovery agents section', () => {
    const { agentsTable } = tables();
    expect(agentsTable.textContent).toContain(PLATFORM_AGENT);
  });

  it('no longer renders it in the Sensors table', () => {
    const { sensorsTable } = tables();
    expect(sensorsTable.textContent).not.toContain(PLATFORM_AGENT);
  });

  it('leaves the platform DISCOVERY sensor in the Sensors table', () => {
    // Same trigger, same platform markers, same `system` tag — only the profile
    // separates them, and this one really is a sensor.
    const { sensorsTable, agentsTable } = tables();
    expect(sensorsTable.textContent).toContain(PLATFORM_SENSOR);
    expect(agentsTable.textContent).not.toContain(PLATFORM_SENSOR);
  });

  it('leaves a customer sensor carrying the interrogation profile in the Sensors table', () => {
    const { sensorsTable, agentsTable } = tables();
    expect(sensorsTable.textContent).toContain(CUSTOMER_SENSOR);
    expect(agentsTable.textContent).not.toContain(CUSTOMER_SENSOR);
  });

  it('keeps the enrolled agents alongside it, not instead of it', () => {
    const { agentsTable } = tables();
    expect(agentsTable.textContent).toContain(CUSTOMER_AGENT);
  });

  it('counts the moved row in both the section count and the page total', () => {
    // Moving a row between tables must not change how many things the tenant
    // has. The page header counted sensors + agents; dropping the platform
    // agent from the sensor list without adding it back would silently
    // decrement it.
    const { heading } = tables();
    expect(heading.nextElementSibling?.textContent).toBe('2');
    const pageCount = host.querySelector('h2')!.nextElementSibling;
    expect(pageCount?.textContent).toBe('4');
  });

  it('offers no delete for it — it is platform-managed', () => {
    const { agentsTable } = tables();
    const row = [...agentsTable.children].find((r) => r.textContent?.includes(PLATFORM_AGENT));
    expect(row).toBeTruthy();
    expect(row!.querySelector('button')).toBeNull();
  });

  it('opens the SENSOR drawer for it, and the agent drawer for an enrolled agent', () => {
    const { agentsTable } = tables();
    const rowFor = (name: string) => [...agentsTable.children].find((r) => r.textContent?.includes(name)) as HTMLElement;

    act(() => { rowFor(PLATFORM_AGENT).click(); });
    expect(host.querySelector('[data-testid="sensor-drawer"]')?.textContent).toBe(PLATFORM_AGENT);
    expect(host.querySelector('[data-testid="agent-drawer"]')).toBeNull();
  });

  it('opens the agent drawer for an enrolled agent', () => {
    const { agentsTable } = tables();
    const row = [...agentsTable.children].find((r) => r.textContent?.includes(CUSTOMER_AGENT)) as HTMLElement;
    act(() => { row.click(); });
    expect(host.querySelector('[data-testid="agent-drawer"]')?.textContent).toBe(CUSTOMER_AGENT);
    expect(host.querySelector('[data-testid="sensor-drawer"]')).toBeNull();
  });
});
