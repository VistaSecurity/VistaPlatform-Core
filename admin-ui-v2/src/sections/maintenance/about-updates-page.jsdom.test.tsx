// @vitest-environment jsdom
//
// Maintenance ▸ About & Updates: every state of the versions card from spec
// §1 (default, empty, loading, error with retry, success), the four-state
// alignment badge ported from the tenant About page, and the plain-language
// management notices (not_kubernetes, gitops). The update card's own states
// are in about-updates-card.jsdom.test.tsx.
import { act } from 'react';
import { MemoryRouter } from 'react-router';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MaintenanceStatus } from './maintenance-queries';

interface QueryState { isLoading: boolean; isError: boolean; data?: MaintenanceStatus; refetch: () => void }

const q = vi.hoisted(() => {
  const value: QueryState = { isLoading: false, isError: false, refetch: vi.fn() };
  return { value };
});
// The update card has its own test file; here it only has to render quietly.
vi.mock('./maintenance-queries', () => ({
  useMaintenanceStatus: () => q.value,
  useUpdateStatus: () => ({ isLoading: true, isError: false, data: undefined, refetch: vi.fn() }),
  useCheckForUpdates: () => ({ isPending: false, error: null, mutate: vi.fn() }),
  useMaintenanceRuns: () => ({ isLoading: false, isError: false, data: [], refetch: vi.fn() }),
  UpdateCheckConflictError: class extends Error {},
}));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: () => false }) };
});

import { AboutUpdatesPage } from './about-updates-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function status(over: Partial<MaintenanceStatus> = {}, caps: Partial<MaintenanceStatus['capabilities']> = {}): MaintenanceStatus {
  return {
    service: 'maintenance-service',
    capabilities: { helm_managed: true, gitops: false, backups: true, updates: true, reason: '', ...caps },
    release: { name: 'vista', namespace: 'vista' },
    single_node: false,
    versions: {
      self: { service: 'v4.5.0', chart: '4.5.0', app_version: '4.5.0' },
      services: [
        { service: 'auth-service', tag: 'v4.5.0', chart: '4.5.0', app_version: '4.5.0', status: 'healthy' },
        { service: 'inventory-service', tag: 'v4.5.0', chart: '4.5.0', app_version: '4.5.0', status: 'unreachable' },
      ],
      status: 'aligned',
      summary: { total: 2, reachable: 2, unreachable: 0, reporting: 2 },
      aligned: true,
    },
    ...over,
  };
}

let root: Root | null = null;
let host: HTMLDivElement;

function mount(value: Partial<QueryState>) {
  q.value = { isLoading: false, isError: false, data: undefined, refetch: vi.fn(), ...value };
  act(() => root!.render(<MemoryRouter><AboutUpdatesPage /></MemoryRouter>));
}
const $ = (id: string) => host.querySelector(`[data-testid="${id}"]`);

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
});

describe('About & Updates — versions card', () => {
  it('loading: skeleton rows, no conclusions', () => {
    mount({ isLoading: true });
    expect(host.querySelectorAll('[data-testid="skeleton-row"]').length).toBeGreaterThan(0);
    expect($('maintenance-alignment')).toBeNull();
  });

  it('error: a retry row that refetches', () => {
    mount({ isError: true });
    const err = $('maintenance-versions-error');
    expect(err?.textContent).toContain('Couldn’t load');
    act(() => err!.querySelector('button')!.click());
    expect(q.value.refetch).toHaveBeenCalledTimes(1);
  });

  it('error: the status answered but the versions could not be read', () => {
    mount({ data: status({ versions: null, versions_error: 'could not read running versions' }) });
    expect($('maintenance-versions-error')?.textContent).toContain('monitoring service');
    expect($('maintenance-management')).not.toBeNull();
  });

  it('empty: "No services reported"', () => {
    const s = status();
    s.versions!.services = [];
    mount({ data: s });
    expect($('maintenance-versions-empty')?.textContent).toBe('No services reported');
  });

  it('success: one row per service with its version and health', () => {
    mount({ data: status() });
    const rows = host.querySelectorAll('[data-testid="maintenance-version-row"]');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('auth-service');
    expect(rows[0].textContent).toContain('v4.5.0');
    expect(rows[0].textContent).toContain('Healthy');
    expect(rows[1].textContent).toContain('Unreachable');
    expect($('maintenance-alignment')?.textContent).toContain('Vista Platform 4.5.0');
  });

  it.each([
    ['aligned', 'All services aligned'],
    ['skew', 'Version skew detected'],
    ['degraded', 'Degraded'],
    ['unknown', 'Version unknown'],
  ] as const)('badge: %s', (st, label) => {
    const s = status();
    s.versions!.status = st;
    if (st === 'skew') s.versions!.skew = [{ field: 'tag', values: ['v4.5.0', 'v4.4.0'] }];
    mount({ data: s });
    expect($('maintenance-alignment')?.getAttribute('data-status')).toBe(st);
    expect($('maintenance-alignment')?.textContent).toContain(label);
    expect(Boolean($('maintenance-skew'))).toBe(st === 'skew');
  });
});

describe('About & Updates — how the install is managed', () => {
  it('Helm-managed: names the release and namespace', () => {
    mount({ data: status() });
    expect($('maintenance-management')?.textContent).toContain('Managed by Helm');
    expect($('maintenance-management')?.textContent).toContain('release vista in namespace vista');
  });

  it('not_kubernetes: says the console cannot back up or update this deployment', () => {
    mount({ data: status({}, { helm_managed: false, backups: false, updates: false, reason: 'not_kubernetes' }) });
    const t = $('maintenance-management')?.textContent ?? '';
    expect(t).toContain('Not available in this deployment');
    expect(t).toContain('Docker Compose is for evaluation only');
  });

  it('gitops: points the operator at their values repository', () => {
    mount({ data: status({}, { gitops: true, updates: false, reason: 'gitops' }) });
    const t = $('maintenance-management')?.textContent ?? '';
    expect(t).toContain('Managed by GitOps');
    expect(t).toContain('values repository');
  });

  it('single node: warns that an upgrade briefly takes services down', () => {
    mount({ data: status({ single_node: true }) });
    expect($('maintenance-single-node')).not.toBeNull();
  });

  it('uses the product name, never the squashed identifier', () => {
    mount({ data: status() });
    expect(host.textContent).not.toMatch(/VistaPlatform/);
  });
});
