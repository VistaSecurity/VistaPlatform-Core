// @vitest-environment jsdom
//
// "Additional TLS ports" ( WP5), MOUNTED where a person reaches it:
// Discovery → Sensors & Agents → Sensor defaults (the fleet dialog, against a
// stubbed sensor-manager), and the same SettingsPanel the sensor drawer's
// Control tab renders, in device scope, for the states only a device has —
// pending restart and applied.
//
// The setting is not special-cased by key: the panel renders the platform's
// `port_list` kind. So what is pinned is that THIS registry entry comes out as
// a usable control in every state — loading, load error, default (empty),
// entry with junk refused and named, built-in ports noted, saving, save error,
// saved with the restart called out, read-only, pending restart, applied.
//
// Follows sensor-fleet-defaults-third-party.jsdom.test.tsx: jsdom + React's
// own `act`, no testing-library.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Setting } from './agent-config';

const LABEL = 'Additional TLS ports';
const DESCRIPTION =
  'Ports where your organisation runs TLS on a non-standard port. Sensors will decode TLS handshakes seen on them. ' +
  'Built-in ports such as 443 and 8443 are always watched. Each added port slightly increases capture load.';

// The registry entry as sensor-manager serves it for a tenant that has never
// touched it (built_in_ports trimmed to what the cases use).
const PORTS: Setting = {
  key: 'extra_tls_ports',
  value: '',
  origin: 'built_in',
  kind: 'port_list',
  apply: 'restart',
  label: LABEL,
  description: DESCRIPTION,
  built_in_ports: { '443': 'HTTPS', '8443': 'HTTPS (alternate port)', '22': 'SSH' },
};

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  canEdit: true,
}));

vi.mock('../../lib/clients', () => ({ clients: { sensors: { GET: mocks.get, PUT: mocks.put } } }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  usePermissions: () => ({ hasPermission: () => mocks.canEdit, hasAnyPermission: () => mocks.canEdit }),
}));

const { SensorFleetDefaultsModal } = await import('./sensor-fleet-defaults-modal');
const { SettingsPanel } = await import('./settings-panel');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mocks.get.mockReset();
  mocks.put.mockReset();
  mocks.canEdit = true;
  mocks.get.mockResolvedValue({ data: { settings: [PORTS] }, error: undefined, response: { status: 200 } });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  host.remove();
});

async function settled(done: () => boolean) {
  for (let i = 0; i < 100 && !done(); i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 5));
    });
  }
  expect(done()).toBe(true);
}

const body = () => document.body.textContent ?? '';
const entry = () => document.body.querySelector<HTMLInputElement>(`input[aria-label="Add to ${LABEL}"]`);
const button = (text: string | RegExp) =>
  [...document.body.querySelectorAll('button')].find((b) =>
    typeof text === 'string' ? b.textContent === text : text.test(b.textContent ?? ''),
  );
const chips = () =>
  [...document.body.querySelectorAll('button[aria-label^="Remove port "]')].map((b) =>
    Number(b.getAttribute('aria-label')!.replace('Remove port ', '')),
  );
const alertText = () => document.body.querySelector('[role="alert"]')?.textContent ?? '';

async function mountFleet() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <SensorFleetDefaultsModal onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}

async function typeAndAdd(text: string) {
  const input = entry()!;
  await act(async () => {
    // React tracks the value through the prototype setter; assigning
    // `input.value` directly is invisible to its onChange.
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, text);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => {
    button('Add')!.click();
  });
}

describe('Additional TLS ports in the sensor fleet defaults', () => {
  it('loading: says so while the defaults are fetched', async () => {
    mocks.get.mockReturnValue(new Promise(() => {}));
    await mountFleet();
    expect(body()).toContain('Loading defaults…');
    expect(entry()).toBeNull();
  });

  it('load error: says the defaults could not be loaded', async () => {
    mocks.get.mockResolvedValue({ data: undefined, error: { error: 'boom' }, response: { status: 500 } });
    await mountFleet();
    await settled(() => body().includes("Couldn't load the sensor fleet defaults."));
  });

  it('default: labelled, explained, empty, and nothing sent', async () => {
    await mountFleet();
    await settled(() => entry() !== null);
    expect(body()).toContain(LABEL);
    expect(body()).toContain(DESCRIPTION);
    expect(body()).toContain('No additional ports — sensors watch their built-in ports only.');
    expect(body()).toContain('takes effect on restart');
    expect(chips()).toEqual([]);
    expect(button(/^Save/)!.disabled).toBe(true);
    expect(mocks.put).not.toHaveBeenCalled();
  });

  it('entry: junk is refused and every bad value named; a range is refused as a range', async () => {
    await mountFleet();
    await settled(() => entry() !== null);

    await typeAndAdd('9443, abc, 70000');
    expect(alertText()).toBe('"abc" is not a port number; 70000 is outside the port range 1-65535');
    expect(chips()).toEqual([]);

    await typeAndAdd('9000-9010');
    expect(alertText()).toBe('"9000-9010" is a range; list each port on its own');
    expect(chips()).toEqual([]);
    expect(button(/^Save/)!.disabled).toBe(true);
  });

  it('entry: ports become sorted chips; a built-in port is accepted and noted; a chip can be removed', async () => {
    await mountFleet();
    await settled(() => entry() !== null);

    await typeAndAdd('10443 9443');
    expect(chips()).toEqual([9443, 10443]);
    expect(entry()!.value).toBe('');

    await typeAndAdd('443');
    expect(chips()).toEqual([443, 9443, 10443]);
    expect(body()).toContain('443 is already monitored as HTTPS; listing it here changes nothing.');

    await act(async () => {
      document.body.querySelector<HTMLButtonElement>('button[aria-label="Remove port 443"]')!.click();
    });
    expect(chips()).toEqual([9443, 10443]);
    expect(body()).not.toContain('already monitored as HTTPS');
    expect(button(/^Save/)!.textContent).toBe('Save (1)');
  });

  it('saving, then saved: the canonical list is sent, the control locks, and the restart is called out', async () => {
    let finish: (v: unknown) => void = () => {};
    mocks.put.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    await mountFleet();
    await settled(() => entry() !== null);
    await typeAndAdd('10443, 9443');
    await act(async () => {
      button(/^Save/)!.click();
    });
    await settled(() => button(/^Saving/) !== undefined);

    expect(mocks.put).toHaveBeenCalledWith('/sensors/config/defaults', {
      body: { values: { extra_tls_ports: '9443,10443' }, confirmed: false },
    });
    expect(entry()!.disabled).toBe(true);

    await act(async () => {
      finish({
        data: { changed: ['extra_tls_ports: none → 9443,10443'], adjusted: [], needs_restart: ['extra_tls_ports'] },
        error: undefined,
        response: { status: 200 },
      });
    });
    await settled(() => body().includes('Saved:'));
    expect(body()).toContain('Saved: extra_tls_ports: none → 9443,10443');
    expect(body()).toContain(`Takes effect on restart: ${LABEL}`);
  });

  it('save error: the platform\'s reason is shown and nothing is reported saved', async () => {
    mocks.put.mockResolvedValue({
      data: undefined,
      error: { error: 'Some settings could not be accepted', problems: ['extra_tls_ports: 70000 is outside the port range 1-65535'] },
      response: { status: 400 },
    });
    await mountFleet();
    await settled(() => entry() !== null);
    await typeAndAdd('9443');
    await act(async () => {
      button(/^Save/)!.click();
    });
    await settled(() => body().includes('extra_tls_ports: 70000 is outside the port range 1-65535'));
    expect(body()).not.toContain('Saved:');
  });

  it('read-only: without Update sensors the list is shown but cannot change', async () => {
    mocks.canEdit = false;
    mocks.get.mockResolvedValue({
      data: { settings: [{ ...PORTS, value: '9443', origin: 'fleet' }] },
      error: undefined,
      response: { status: 200 },
    });
    await mountFleet();
    await settled(() => entry() !== null);
    expect(chips()).toEqual([9443]);
    expect(entry()!.disabled).toBe(true);
    expect(document.body.querySelector<HTMLButtonElement>('button[aria-label="Remove port 9443"]')!.disabled).toBe(true);
    expect(button(/^Save/)).toBeUndefined();
  });
});

describe('Additional TLS ports on one sensor (Control tab panel)', () => {
  async function mountDevice(status: Parameters<typeof SettingsPanel>[0]['status']) {
    await act(async () => {
      root.render(
        <SettingsPanel
          settings={[{ ...PORTS, value: '9443', origin: 'device' }]}
          status={status}
          scope="device"
          canEdit
          saving={false}
          save={vi.fn()}
        />,
      );
    });
  }

  it('pending restart: shown until the sensor reports the list in effect', async () => {
    await mountDevice({ state: 'awaiting_restart', desired_revision: 'r1', pending_restart: ['extra_tls_ports'] });
    expect(body()).toContain('Awaiting restart');
    expect(body()).toContain('Pending restart — accepted, and adopted when the device restarts.');
    expect(body()).not.toContain('In effect on this sensor.');
    expect(body()).toContain('Set on this device');
  });

  it('applied: the sensor reported the list in effect', async () => {
    await mountDevice({ state: 'applied', desired_revision: 'r1' });
    expect(body()).toContain('In effect on this sensor.');
    expect(body()).not.toContain('Pending restart');
  });

  // The two statuses agentconfig.Reconcile produces for a sensor older than
  // the setting (strings pinned in shared/agentconfig/unsupported_test.go and
  // the sensor-manager integration test that drives the real exchange).
  async function mountOlderSensor(value: string, status: Parameters<typeof SettingsPanel>[0]['status']) {
    await act(async () => {
      root.render(
        <SettingsPanel
          settings={[{ ...PORTS, value, origin: value === '' ? 'built_in' : 'device' }]}
          status={status}
          scope="device"
          canEdit
          saving={false}
          save={vi.fn()}
        />,
      );
    });
  }

  it('older sensor, nobody set it: no failure, the sensor reads as applied', async () => {
    await mountOlderSensor('', { state: 'applied', desired_revision: 'r1' });
    expect(body()).toContain('Applied');
    expect(body()).not.toContain('Failed');
    expect(body()).not.toContain('does not support');
  });

  it('older sensor, an operator set ports: failed, saying to upgrade the sensor', async () => {
    const reason = "This sensor's version (v4.1.0) does not support this setting — upgrade the sensor to apply it.";
    await mountOlderSensor('9443', { state: 'failed', desired_revision: 'r1', failures: { extra_tls_ports: reason } });
    expect(body()).toContain('Failed');
    expect(body()).toContain(reason);
    expect(body()).not.toContain('In effect on this sensor.');
  });
});
