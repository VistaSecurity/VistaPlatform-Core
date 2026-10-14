// @vitest-environment jsdom
//
// Maintenance ▸ About & Updates: the update card, every state from spec §1 —
// up to date, check disabled, checking, registry error, update available (with
// the notes link and the Update button — live for a platform.maintenance
// holder on a Helm-managed install, disabled with its reason otherwise — that
// opens the confirmation dialog), plus "Check now" being offered only to an
// operator holding platform.maintenance.
import { act } from 'react';
import { MemoryRouter } from 'react-router';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { MaintenanceStatus, UpdateStatus } from './maintenance-queries';

interface UpdateQuery { isLoading: boolean; isError: boolean; data?: UpdateStatus; refetch: () => void }
interface Mutation { isPending: boolean; error: unknown; mutate: () => void }

const h = vi.hoisted(() => {
  const initial: { update: UpdateQuery; mutation: Mutation; perms: Set<string>; caps: MaintenanceStatus['capabilities'] } = {
    update: { isLoading: false, isError: false, refetch: () => {} },
    mutation: { isPending: false, error: null, mutate: () => {} },
    perms: new Set<string>(),
    caps: { helm_managed: true, gitops: false, backups: true, updates: true, reason: '' },
  };
  return initial;
});

vi.mock('./maintenance-queries', () => {
  class UpdateCheckConflictError extends Error {
    reason: string;
    constructor(reason: string) {
      super(reason === 'check_in_progress' ? 'An update check is already running.' : 'The update check is turned off for this install.');
      this.reason = reason;
    }
  }
  return {
    useMaintenanceStatus: () => ({
      isLoading: false,
      isError: false,
      refetch: () => {},
      data: { service: 'maintenance-service', capabilities: h.caps, release: { name: 'vista', namespace: 'vista' }, single_node: false, versions: null },
    }),
    useUpdateStatus: () => h.update,
    useCheckForUpdates: () => h.mutation,
    useMaintenanceRuns: () => ({ isLoading: false, isError: false, data: [], refetch: () => {} }),
    UpdateCheckConflictError,
  };
});
// The dialog has its own tests; here it only has to say it opened, and for
// which version.
vi.mock('./update-dialog', () => ({
  UpdateDialog: ({ version }: { version: string }) => <div data-testid="update-dialog-stub">{version}</div>,
}));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => h.perms.has(p) }) };
});

import { AboutUpdatesPage, relativeTime, updateButtonState, updateCardState } from './about-updates-page';
import { UpdateCheckConflictError } from './maintenance-queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const row = (over: Partial<UpdateStatus> = {}): UpdateStatus => ({
  checked_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
  source: 'oci://ghcr.io/vistasecurity/vistaplatform',
  current_version: '4.5.0',
  latest_version: null,
  notes_url: null,
  error: null,
  prereleases_seen: [],
  update_available: false,
  check_enabled: true,
  ...over,
});

let root: Root | null = null;
let host: HTMLDivElement;
const $ = (id: string) => host.querySelector(`[data-testid="${id}"]`);
const card = () => $('maintenance-updates')!;

function mount(update: Partial<UpdateQuery>) {
  h.update = { isLoading: false, isError: false, data: undefined, refetch: vi.fn(), ...update };
  act(() => root!.render(<MemoryRouter><AboutUpdatesPage /></MemoryRouter>));
}

beforeEach(() => {
  h.perms = new Set();
  h.mutation = { isPending: false, error: null, mutate: vi.fn() };
  h.caps = { helm_managed: true, gitops: false, backups: true, updates: true, reason: '' };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
});

describe('About & Updates — update card states', () => {
  it('up to date: "Up to date · checked 2 hours ago"', () => {
    mount({ data: row() });
    expect(card().getAttribute('data-state')).toBe('current');
    expect(card().textContent).toContain('Up to date');
    expect(card().textContent).toContain('checked 2 hours ago');
  });

  it('check disabled: says the check is off and offers no Check now', () => {
    h.perms.add('platform.maintenance');
    mount({ data: row({ check_enabled: false }) });
    expect(card().getAttribute('data-state')).toBe('disabled');
    expect(card().textContent).toContain('Update check is off');
    expect(card().textContent).toContain('maintenance.updateCheck.enabled=false');
    expect($('maintenance-check-now')).toBeNull();
  });

  it('checking: "Checking…" while the mutation runs or the first read loads', () => {
    h.mutation.isPending = true;
    mount({ data: row() });
    expect(card().getAttribute('data-state')).toBe('loading');
    expect(card().textContent).toContain('Checking…');
    act(() => root!.unmount());
    root = createRoot(host);
    h.mutation.isPending = false;
    mount({ isLoading: true });
    expect(card().textContent).toContain('Checking…');
  });

  it('error: "Could not reach the chart registry: …" with Check now', () => {
    h.perms.add('platform.maintenance');
    mount({ data: row({ error: 'registry request https://ghcr.io/v2/x/tags/list returned HTTP 503' }) });
    expect(card().getAttribute('data-state')).toBe('error');
    expect(card().textContent).toContain('Could not reach the chart registry: registry request https://ghcr.io/v2/x/tags/list returned HTTP 503');
    expect($('maintenance-check-now')).not.toBeNull();
  });

  it('available: version, notes link in a new tab, and a disabled Update button with its reason', () => {
    mount({ data: row({ update_available: true, latest_version: '4.6.0', notes_url: 'https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0' }) });
    expect(card().getAttribute('data-state')).toBe('available');
    expect(card().textContent).toContain('Vista Platform 4.6.0 available');
    const notes = $('maintenance-update-notes') as HTMLAnchorElement;
    expect(notes.getAttribute('href')).toBe('https://github.com/VistaSecurity/VistaPlatform-Core/releases/tag/v4.6.0');
    expect(notes.getAttribute('target')).toBe('_blank');
    expect(notes.getAttribute('rel')).toContain('noopener');
    // A platform.health viewer sees the button, disabled, with the reason.
    const update = $('maintenance-update-button') as HTMLButtonElement;
    expect(update.disabled).toBe(true);
    expect(update.title).toContain('platform.maintenance');
    expect($('maintenance-update-reason')?.textContent).toContain('platform.maintenance');
  });

  it('available + platform.maintenance: Update is live and opens the confirmation dialog for that version', () => {
    h.perms.add('platform.maintenance');
    mount({ data: row({ update_available: true, latest_version: '4.6.0' }) });
    const update = $('maintenance-update-button') as HTMLButtonElement;
    expect(update.disabled).toBe(false);
    expect($('maintenance-update-reason')).toBeNull();
    expect($('update-dialog-stub')).toBeNull();
    act(() => update.click());
    expect($('update-dialog-stub')?.textContent).toBe('4.6.0');
  });

  it('check disabled + platform.maintenance: a version can be typed to update from a mirror', () => {
    h.perms.add('platform.maintenance');
    mount({ data: row({ check_enabled: false }) });
    const input = $('manual-version') as HTMLInputElement;
    const form = $('maintenance-manual-update') as HTMLFormElement;
    act(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
      setter.call(input, 'v4.6.1');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    act(() => { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
    expect($('update-dialog-stub')?.textContent).toBe('4.6.1');
  });

  it('available but the last check failed: still offers the version and says the last check failed', () => {
    mount({ data: row({ update_available: true, latest_version: '4.6.0', error: 'timeout' }) });
    expect(card().getAttribute('data-state')).toBe('available');
    expect($('maintenance-update-stale-error')?.textContent).toContain('timeout');
  });

  it('never checked: says so', () => {
    mount({ data: row({ checked_at: null }) });
    expect(card().textContent).toContain('No update check has run yet');
  });

  it('read failed: a retry row that refetches', () => {
    const refetch = vi.fn();
    mount({ isError: true, refetch });
    expect(card().textContent).toContain('Couldn’t load the update status');
    act(() => card().querySelector('button')!.click());
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it('not Kubernetes: no check content at all, the management notice carries the reason', () => {
    h.caps = { helm_managed: false, gitops: false, backups: false, updates: false, reason: 'not_kubernetes' };
    mount({ data: row({ error: 'chart source not configured' }) });
    expect(card().getAttribute('data-state')).toBe('unsupported');
    expect(card().textContent).not.toContain('Could not reach');
    expect($('maintenance-check-now')).toBeNull();
  });

  it('GitOps: the available version is still shown, Update disabled with the GitOps reason', () => {
    h.perms.add('platform.maintenance');
    h.caps = { helm_managed: true, gitops: true, backups: true, updates: false, reason: 'gitops' };
    mount({ data: row({ update_available: true, latest_version: '4.6.0' }) });
    expect(card().textContent).toContain('4.6.0 available');
    const update = $('maintenance-update-button') as HTMLButtonElement;
    expect(update.disabled).toBe(true);
    expect(update.title).toContain('GitOps');
    act(() => update.click());
    expect($('update-dialog-stub')).toBeNull();
  });
});

describe('About & Updates — Check now', () => {
  it('is hidden without platform.maintenance (a platform.health viewer)', () => {
    h.perms.add('platform.health');
    mount({ data: row() });
    expect($('maintenance-check-now')).toBeNull();
  });

  it('is shown to a platform.maintenance holder and runs the check', () => {
    h.perms.add('platform.maintenance');
    mount({ data: row() });
    const btn = $('maintenance-check-now') as HTMLButtonElement;
    expect(btn).not.toBeNull();
    act(() => btn.click());
    expect(h.mutation.mutate).toHaveBeenCalledTimes(1);
  });

  it('a check already in progress is reported inline', () => {
    h.perms.add('platform.maintenance');
    h.mutation.error = new UpdateCheckConflictError('check_in_progress');
    mount({ data: row() });
    expect($('maintenance-update-check-error')?.textContent).toContain('already running');
  });

  it('any other failure reads as a failed check', () => {
    h.perms.add('platform.maintenance');
    h.mutation.error = new Error('boom');
    mount({ data: row() });
    expect($('maintenance-update-check-error')?.textContent).toContain('The update check failed');
  });
});

describe('pure helpers', () => {
  it('relativeTime', () => {
    const now = Date.parse('2026-10-14T12:00:00Z');
    expect(relativeTime('2026-10-14T11:59:40Z', now)).toBe('just now');
    expect(relativeTime('2026-10-14T11:59:00Z', now)).toBe('1 minute ago');
    expect(relativeTime('2026-10-14T11:15:00Z', now)).toBe('45 minutes ago');
    expect(relativeTime('2026-10-14T09:00:00Z', now)).toBe('3 hours ago');
    expect(relativeTime('2026-10-12T12:00:00Z', now)).toBe('2 days ago');
    expect(relativeTime('garbage', now)).toBe('at an unknown time');
  });

  it('available beats a failed check; disabled beats an error', () => {
    const caps = { helm_managed: true, gitops: false, backups: true, updates: true, reason: '' } as const;
    expect(updateCardState({ isLoading: false, isError: false, data: row({ update_available: true, latest_version: '4.6.0', error: 'x' }) }, caps, false).kind).toBe('available');
    expect(updateCardState({ isLoading: false, isError: false, data: row({ check_enabled: false, error: 'x' }) }, caps, false).kind).toBe('disabled');
  });

  it('updateButtonState: needs capabilities.updates AND platform.maintenance', () => {
    const caps = { helm_managed: true, gitops: false, backups: true, updates: true, reason: '' } as const;
    expect(updateButtonState(caps, true)).toEqual({ enabled: true, reason: null });
    expect(updateButtonState(caps, false).enabled).toBe(false);
    expect(updateButtonState({ ...caps, updates: false, reason: 'gitops' }, true).reason).toContain('GitOps');
    expect(updateButtonState(undefined, true).enabled).toBe(false);
  });

  it('uses the product name, never the squashed identifier', () => {
    mount({ data: row({ update_available: true, latest_version: '4.6.0' }) });
    expect(host.textContent).not.toMatch(/VistaPlatform/);
  });
});
