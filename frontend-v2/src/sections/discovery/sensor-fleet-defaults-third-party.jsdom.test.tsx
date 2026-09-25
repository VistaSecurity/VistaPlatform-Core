// @vitest-environment jsdom
//
// The third-party TLS enrichment opt-in ( W5.13, owner decision Q10),
// MOUNTED in the real Sensor fleet defaults dialog (Discovery → Sensors &
// Agents → Sensor defaults) against a stubbed sensor-manager.
//
// The setting is not special-cased in the frontend: the panel renders whatever
// the platform's registry sends. So what is pinned here is that the platform's
// shape for THIS setting — its label, its explanation, its confirmation — comes
// out as the consent control the owner asked for, in each of its states:
// default (off), saving, error, success, and read-only without the permission.
//
// Follows settings-panel.jsdom.test.tsx: jsdom + React's own `act`, no
// testing-library.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const LABEL = 'Actively enrich third-party TLS connections';
const DESCRIPTION =
  'Off by default. When on, sensors actively connect to external TLS services your network talks to, ' +
  'to read their certificates. Third parties may see these connections.';
const CONFIRM =
  'Sensors will open their own TLS connections to external services your network talks to — ' +
  'vendors, SaaS and other third parties — to read their certificates. Those third parties may see these connections.';

// The registry entry exactly as sensor-manager serves it for a tenant that has
// never touched it.
const SETTING = {
  key: 'third_party_tls_enrichment',
  value: false,
  origin: 'built_in',
  kind: 'bool',
  apply: 'immediate',
  label: LABEL,
  description: DESCRIPTION,
  confirm: CONFIRM,
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

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mocks.get.mockReset();
  mocks.put.mockReset();
  mocks.canEdit = true;
  mocks.get.mockResolvedValue({ data: { settings: [SETTING] }, error: undefined, response: { status: 200 } });
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

const flush = async () => {
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
  }
};

// Waits for the dialog to render its settings, rather than for a fixed number
// of ticks: the query resolves on its own schedule.
async function settled(done: () => boolean) {
  for (let i = 0; i < 100 && !done(); i++) {
    await act(async () => {
      await new Promise((r) => setTimeout(r, 5));
    });
  }
  expect(done()).toBe(true);
}

async function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <SensorFleetDefaultsModal onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
  await settled(() => toggle() !== null);
}

const body = () => document.body.textContent ?? '';
const toggle = () => document.body.querySelector<HTMLInputElement>(`input[type="checkbox"][aria-label="${LABEL}"]`);
const button = (text: string | RegExp) =>
  [...document.body.querySelectorAll('button')].find((b) =>
    typeof text === 'string' ? b.textContent === text : text.test(b.textContent ?? ''),
  );

async function turnOnAndConfirm() {
  await act(async () => {
    toggle()!.click();
  });
  await act(async () => {
    button(/^Save/)!.click();
  });
  // Turning it on asks first, naming who experiences the consequence.
  expect(body()).toContain(CONFIRM);
  await act(async () => {
    button('Yes, turn it on')!.click();
  });
}

describe('Sensor fleet defaults: third-party TLS enrichment opt-in', () => {
  it('default: off, with its name and the explanation of what turning it on does', async () => {
    await mount();
    expect(toggle()).not.toBeNull();
    expect(toggle()!.checked).toBe(false);
    expect(toggle()!.disabled).toBe(false);
    expect(body()).toContain(LABEL);
    expect(body()).toContain(DESCRIPTION);
    expect(body()).toContain('Built-in default');
    // Nothing is sent until the operator changes something and confirms.
    expect(mocks.put).not.toHaveBeenCalled();
  });

  it('saving: the write carries the confirmation, and the control is locked while it runs', async () => {
    let finish: (v: unknown) => void = () => {};
    mocks.put.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    await mount();
    await turnOnAndConfirm();

    expect(mocks.put).toHaveBeenCalledWith('/sensors/config/defaults', {
      body: { values: { third_party_tls_enrichment: true }, confirmed: true },
    });
    expect(button(/^Saving/)).toBeTruthy();
    expect(toggle()!.disabled).toBe(true);

    await act(async () => {
      finish({ data: { changed: ['third_party_tls_enrichment: false → true'], adjusted: [], needs_restart: [] }, error: undefined, response: { status: 200 } });
    });
    await flush();
  });

  it('error: a failed save says so and leaves the setting as it was', async () => {
    mocks.put.mockResolvedValue({ data: undefined, error: { error: 'sensor-manager is unavailable' }, response: { status: 503 } });
    await mount();
    await turnOnAndConfirm();
    await settled(() => body().includes('sensor-manager is unavailable'));
    expect(body()).not.toContain('Saved:');
  });

  it('success: the save is reported', async () => {
    mocks.put.mockResolvedValue({
      data: { changed: ['third_party_tls_enrichment: false → true'], adjusted: null, needs_restart: null },
      error: undefined,
      response: { status: 200 },
    });
    await mount();
    await turnOnAndConfirm();
    await settled(() => body().includes('Saved:'));

    expect(body()).toContain('Saved: third_party_tls_enrichment: false → true');
    expect(body()).not.toContain('sensor-manager is unavailable');
  });

  it('read-only: without the Update sensors permission the control is shown but cannot change', async () => {
    mocks.canEdit = false;
    await mount();

    expect(toggle()).not.toBeNull();
    expect(toggle()!.disabled).toBe(true);
    expect(button(/^Save/)).toBeUndefined();
    expect(body()).toContain('Changing fleet defaults needs the Update sensors permission.');
    expect(body()).toContain(DESCRIPTION);
  });
});
