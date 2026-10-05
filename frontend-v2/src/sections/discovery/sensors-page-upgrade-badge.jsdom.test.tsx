// @vitest-environment jsdom
//
// Discovery → Sensors & Agents, MOUNTED: a tenant sensor whose heartbeat does
// not report `scan_plan_v1` carries the "needs upgrading" indicator (
// D3); one that does, and the platform's own sensor, do not. agent-fleet.test.ts
// pins the predicate; this pins that the page renders it — delete the
// indicator from sensors-page.tsx and this goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const OLD = 'edge-old';
const NEW = 'edge-new';
const PLATFORM = 'Platform Discovery Sensor';
const BADGE = 'Needs upgrading to run scans on the current engine';
const now = new Date().toISOString();

const SENSORS = [
  { id: 's-platform', name: PLATFORM, platform: 'platform', profile: 'discovery', sensor_type: 'network', tags: ['system', 'platform', 'discovery'], status: 'active', version: '1.0.0', last_heartbeat: now, network_interfaces: [], reported_capabilities: [] },
  { id: 's-old', name: OLD, platform: 'linux', profile: 'datacenter_host', sensor_type: 'network', tags: [], status: 'active', version: '4.3.0', last_heartbeat: now, network_interfaces: ['eth0'], reported_capabilities: ['identity_dns_v1'] },
  { id: 's-new', name: NEW, platform: 'linux', profile: 'datacenter_host', sensor_type: 'network', tags: [], status: 'active', version: '4.5.0', last_heartbeat: now, network_interfaces: ['eth0'], reported_capabilities: ['identity_dns_v1', 'scan_plan_v1'] },
];

vi.mock('./queries', () => ({
  useSensors: () => ({ data: SENSORS, isLoading: false, isError: false }),
  useDeviceAgents: () => ({ data: [], isLoading: false, isError: false }),
  useDiscoveryCounts: () => ({ data: {}, isLoading: false, isError: false }),
}));
vi.mock('./sensor-modals', () => ({
  RegisterSensorModal: () => null,
  DeleteSensorModal: () => null,
  DeleteAgentModal: () => null,
  PendingRegistrationsSection: () => null,
}));
vi.mock('./sensor-detail-drawer', () => ({ SensorDetailDrawer: () => null }));
vi.mock('./agent-detail-drawer', () => ({ AgentDetailDrawer: () => null }));
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

/** The sensor name of the row an element sits in. */
function rowNameOf(el: Element): string | null {
  for (let n: Element | null = el; n; n = n.parentElement) {
    const text = n.textContent ?? '';
    const names = [OLD, NEW, PLATFORM].filter((name) => text.includes(name));
    if (names.length === 1) return names[0];
    if (names.length > 1) return null;
  }
  return null;
}

describe('Sensors & Agents — scan engine upgrade indicator', () => {
  it('marks only the tenant sensor without scan_plan_v1', () => {
    const badges = [...host.querySelectorAll('span')].filter((s) => s.children.length === 0 && s.textContent === BADGE);
    expect(badges.length).toBe(1);
    expect(rowNameOf(badges[0])).toBe(OLD);
  });
});
