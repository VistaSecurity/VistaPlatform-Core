// @vitest-environment jsdom
//
// The Sensors & Agents page on a failed read, MOUNTED. sensor-manager answers
// 503 when its store errors; the page must say the read failed (with a retry),
// not render "no sensors" — a database blip must not look like an empty fleet.
// And the page-level "nothing registered" claim spans both fleets, so a failed
// agents read with zero sensors must not make it either.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({
  sensors: { data: undefined as unknown, isLoading: false, isError: false, error: undefined as unknown, refetch: vi.fn() },
  agents: { data: undefined as unknown, isLoading: false, isError: false, error: undefined as unknown, refetch: vi.fn() },
}));

vi.mock('./queries', () => ({
  useSensors: () => state.sensors,
  useDeviceAgents: () => state.agents,
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

function mount() {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => { root.render(<SensorsPage />); });
}

beforeEach(() => {
  state.sensors = { data: [], isLoading: false, isError: false, error: undefined, refetch: vi.fn() };
  state.agents = { data: [], isLoading: false, isError: false, error: undefined, refetch: vi.fn() };
});
afterEach(() => {
  act(() => { root.unmount(); });
  host.remove();
});

describe('Sensors & Agents — failed reads', () => {
  it('a failed sensors read shows the error and a working Retry, not "no sensors"', () => {
    state.sensors = { data: undefined, isLoading: false, isError: true, error: new Error('Failed to load sensors'), refetch: vi.fn() };
    mount();
    expect(host.textContent).toContain("Couldn't load sensors");
    expect(host.textContent).not.toMatch(/No sensors or agents|No network sensors/);
    const retry = [...host.querySelectorAll('button')].find((b) => b.textContent === 'Retry');
    expect(retry).toBeTruthy();
    act(() => { retry!.click(); });
    expect(state.sensors.refetch).toHaveBeenCalledTimes(1);
  });

  it('a failed agents read with zero sensors does not claim nothing is registered', () => {
    state.agents = { data: undefined, isLoading: false, isError: true, error: new Error('Failed to load device agents'), refetch: vi.fn() };
    mount();
    expect(host.textContent).toContain("Couldn't load discovery agents");
    expect(host.textContent).not.toContain('No sensors or agents are registered');
  });

  it('keeps the empty state for a SUCCESSFUL empty fleet', () => {
    mount();
    expect(host.textContent).toContain('No sensors or agents are registered');
    expect(host.textContent).not.toContain("Couldn't load");
  });
});
