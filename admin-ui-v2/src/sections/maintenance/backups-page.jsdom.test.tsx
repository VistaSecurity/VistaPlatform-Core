// @vitest-environment jsdom
//
// Maintenance ▸ Backups: every state from spec §1 (default, empty, loading,
// error + retry, storage unavailable), the platform.maintenance gate on
// Create / Download / Delete, the Create backup dialog's passphrase rule, and
// the Run history card.
import { act } from 'react';
import { MemoryRouter } from 'react-router';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Backup, BackupList, MaintenanceRun, MaintenanceStatus } from './maintenance-queries';

interface Q<T> { isLoading: boolean; isError: boolean; data?: T; refetch: () => void }

interface State {
  status: Q<MaintenanceStatus>;
  list: Q<BackupList>;
  runs: Q<MaintenanceRun[]>;
  create: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
}
const state: State = vi.hoisted(() => ({
  status: { isLoading: false, isError: false, refetch: () => {} },
  list: { isLoading: false, isError: false, refetch: () => {} },
  runs: { isLoading: false, isError: false, refetch: () => {} },
  create: vi.fn(),
  remove: vi.fn(),
}));
const perms = vi.hoisted(() => ({ set: new Set<string>() }));

vi.mock('./maintenance-queries', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    useMaintenanceStatus: () => state.status,
    useBackups: () => state.list,
    useMaintenanceRuns: () => state.runs,
    useBackupMutations: () => ({
      create: { mutate: state.create, isPending: false },
      remove: { mutate: state.remove, isPending: false },
    }),
  };
});
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => perms.set.has(p) }) };
});

import { BackupsPage, formatSize } from './backups-page';
import { createBackupFormError, createBackupRequest } from './create-backup-dialog';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const status = (caps: Partial<MaintenanceStatus['capabilities']> = {}): MaintenanceStatus => ({
  service: 'maintenance-service',
  capabilities: { helm_managed: true, gitops: false, backups: true, updates: true, reason: '', ...caps },
  release: { name: 'vista', namespace: 'vista' },
  single_node: false,
  versions: null,
});

const backup = (over: Partial<Backup> = {}): Backup => ({
  id: '0b6f1c1e-1111-4222-8333-444455556666',
  run_id: null,
  created_at: '2026-10-14T03:12:00Z',
  size_bytes: Math.round(1.8 * 1024 ** 3),
  contents: { database: true, secrets: false },
  encrypted: false,
  manifest: null,
  status: 'ready',
  ...over,
});

const run = (over: Partial<MaintenanceRun> = {}): MaintenanceRun => ({
  id: 'run-1',
  kind: 'backup',
  status: 'succeeded',
  started_by: '7d1c2b3a-0000-4000-8000-000000000000',
  started_at: '2026-10-14T03:12:00Z',
  finished_at: '2026-10-14T03:14:00Z',
  steps: [],
  ...over,
});

let root: Root | null = null;
let host: HTMLDivElement;

function mount(opts: { status?: Partial<Q<MaintenanceStatus>>; list?: Partial<Q<BackupList>>; runs?: Partial<Q<MaintenanceRun[]>> } = {}) {
  state.status = { isLoading: false, isError: false, data: status(), refetch: vi.fn(), ...opts.status };
  state.list = { isLoading: false, isError: false, data: { backups: [], available: true, retention: 5 }, refetch: vi.fn(), ...opts.list };
  state.runs = { isLoading: false, isError: false, data: [], refetch: vi.fn(), ...opts.runs };
  act(() => root!.render(<MemoryRouter><BackupsPage /></MemoryRouter>));
}
const panel = () => document.querySelector('[data-testid="maintenance-backups"]');
const button = (label: string) => [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);
const click = (el: Element | undefined | null) => act(() => { (el as HTMLElement).click(); });

function type(el: HTMLInputElement, value: string) {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

beforeEach(() => {
  perms.set = new Set();
  state.create.mockReset();
  state.remove.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
});

describe('Backups page states', () => {
  it('loading: a skeleton', () => {
    mount({ status: { isLoading: true, data: undefined } });
    expect(panel()?.getAttribute('data-state')).toBe('loading');
    expect(document.querySelector('[data-testid="skeleton"]')).not.toBeNull();
  });

  it('error: retry refetches', () => {
    mount({ status: { isError: true, data: undefined } });
    click(button('Retry'));
    expect(state.status.refetch).toHaveBeenCalledTimes(1);
  });

  it('list error: retry refetches the list too', () => {
    mount({ list: { isError: true, data: undefined } });
    expect(panel()?.getAttribute('data-state')).toBe('error');
    click(button('Retry'));
    expect(state.list.refetch).toHaveBeenCalledTimes(1);
  });

  it('compose: not available in this deployment', () => {
    mount({ status: { data: status({ helm_managed: false, backups: false, updates: false, reason: 'not_kubernetes' }) } });
    expect(panel()?.textContent).toContain('Not available in this deployment');
  });

  it('storage off: names the chart value', () => {
    mount({ status: { data: status({ backups: false }) } });
    expect(panel()?.textContent).toContain('Backup storage is not configured for this install');
    expect(panel()?.textContent).toContain('maintenance.backups.enabled=false');
  });

  it('empty: "No backups yet" and Create backup for platform.maintenance holders', () => {
    perms.set.add('platform.maintenance');
    mount();
    expect(panel()?.textContent).toContain('No backups yet');
    expect(button('Create backup')?.disabled).toBe(false);
  });

  it('empty without platform.maintenance: no Create button', () => {
    perms.set.add('platform.health');
    mount();
    expect(panel()?.textContent).toContain('No backups yet');
    expect(button('Create backup')).toBeUndefined();
  });

  it('default: rows with size, contents, status and the encrypted badge; Download only when ready', () => {
    perms.set.add('platform.maintenance');
    mount({ list: { data: { available: true, retention: 5, backups: [
      backup({ id: 'aaaa', contents: { database: true, secrets: true }, encrypted: true }),
      backup({ id: 'bbbb', status: 'running', size_bytes: null }),
    ] } } });
    const rows = document.querySelectorAll('[data-testid="backup-row"]');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('1.8 GB');
    expect(rows[0].textContent).toContain('Encrypted');
    expect(rows[0].textContent).toContain('encryption keys and install secrets');
    expect(rows[0].querySelector('[data-testid="download"]')?.getAttribute('href')).toBe('/api/v1/maintenance-service/admin/maintenance/backups/aaaa/download');
    expect(rows[1].textContent).toContain('Running…');
    expect(rows[1].querySelector('[data-testid="download"]')).toBeNull();
    expect(rows[1].querySelector('button[aria-label="Delete backup"]')).toBeNull();
    // A backup is running: no second one.
    expect(button('Create backup')?.disabled).toBe(true);
  });

  it('default without platform.maintenance: no Download, no Delete, no Create', () => {
    perms.set.add('platform.health');
    mount({ list: { data: { available: true, retention: 5, backups: [backup()] } } });
    expect(document.querySelector('[data-testid="download"]')).toBeNull();
    expect(document.querySelector('button[aria-label="Delete backup"]')).toBeNull();
    expect(button('Create backup')).toBeUndefined();
  });

  it('Delete asks first, then deletes that backup', () => {
    perms.set.add('platform.maintenance');
    mount({ list: { data: { available: true, retention: 5, backups: [backup({ id: 'cccc' })] } } });
    click(document.querySelector('button[aria-label="Delete backup"]'));
    expect(document.body.textContent).toContain('Delete this backup?');
    expect(state.remove).not.toHaveBeenCalled();
    click(button('Delete backup'));
    expect(state.remove).toHaveBeenCalledWith('cccc', expect.anything());
  });
});

describe('Create backup dialog', () => {
  function openDialog() {
    perms.set.add('platform.maintenance');
    mount();
    click(button('Create backup'));
  }
  const primary = () => [...document.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent === 'Create backup') as HTMLButtonElement;
  const input = (label: string) => document.querySelector(`input[aria-label="${label}"]`) as HTMLInputElement;

  it('database only: no passphrase asked, the request carries none', () => {
    openDialog();
    expect(input('Passphrase')).toBeNull();
    expect(primary().disabled).toBe(false);
    click(primary());
    expect(state.create).toHaveBeenCalledWith({ include_secrets: false }, expect.anything());
  });

  it('including the keys reveals the warning and the passphrase rule gates Create', () => {
    openDialog();
    click(document.querySelector('[data-testid="include-secrets"]'));
    expect(document.querySelector('[data-testid="secrets-warning"]')?.textContent).toContain('the only way to open the file');
    expect(primary().disabled).toBe(true);

    type(input('Passphrase'), 'too short');
    expect(document.querySelector('[data-testid="form-error"]')?.textContent).toContain('at least 12 characters');
    expect(primary().disabled).toBe(true);

    type(input('Passphrase'), 'correct horse battery');
    type(input('Confirm passphrase'), 'correct horse battery!');
    expect(document.querySelector('[data-testid="form-error"]')?.textContent).toContain('do not match');
    expect(primary().disabled).toBe(true);

    type(input('Confirm passphrase'), 'correct horse battery');
    expect(document.querySelector('[data-testid="form-error"]')).toBeNull();
    expect(primary().disabled).toBe(false);
    click(primary());
    expect(state.create).toHaveBeenCalledWith({ include_secrets: true, passphrase: 'correct horse battery' }, expect.anything());
  });

  it('a refusal from the service is shown inline', () => {
    state.create.mockImplementation((_body: unknown, opts: { onError: (e: unknown) => void }) => opts.onError(new Error('another maintenance run is in progress; wait for it to finish')));
    openDialog();
    click(primary());
    expect(document.querySelector('[data-testid="create-error"]')?.textContent).toContain('another maintenance run is in progress');
  });

  it('the pure rule matches the service (12 characters, secrets only)', () => {
    expect(createBackupFormError({ includeSecrets: false, passphrase: '', confirm: '' })).toBeNull();
    expect(createBackupFormError({ includeSecrets: true, passphrase: '', confirm: '' })).toContain('Enter a passphrase');
    expect(createBackupFormError({ includeSecrets: true, passphrase: '12345678901', confirm: '12345678901' })).toContain('12 characters');
    expect(createBackupFormError({ includeSecrets: true, passphrase: '123456789012', confirm: '123456789012' })).toBeNull();
    expect(createBackupRequest({ includeSecrets: false, passphrase: 'leftover', confirm: 'leftover' })).toEqual({ include_secrets: false });
  });
});

describe('Run history', () => {
  it('empty: "No maintenance runs yet"', () => {
    mount();
    expect(document.querySelector('[data-testid="run-history"]')?.textContent).toContain('No maintenance runs yet');
  });

  it('loading and error states', () => {
    mount({ runs: { isLoading: true, data: undefined } });
    expect(document.querySelector('[data-testid="runs-skeleton"]')).not.toBeNull();
    mount({ runs: { isError: true, data: undefined } });
    click([...document.querySelectorAll('[data-testid="run-history"] button')].find((b) => b.textContent?.includes('Retry')));
    expect(state.runs.refetch).toHaveBeenCalledTimes(1);
  });

  it('rows: kind, who, outcome and the failed step', () => {
    mount({ runs: { data: [
      run({ id: 'r1' }),
      run({ id: 'r2', status: 'failed', error: 'BackoffLimitExceeded', steps: [
        { name: 'dump', executor: 'job', status: 'failed', error: 'pg_dump: connection refused' },
        { name: 'package', executor: 'service', status: 'skipped' },
      ] }),
    ] } });
    const rows = document.querySelectorAll('[data-testid="run-row"]');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('Backup');
    expect(rows[0].textContent).toContain('Succeeded');
    expect(rows[0].textContent).toContain('7d1c2b3a');
    expect(rows[1].querySelector('[data-testid="failed-step"]')?.textContent).toBe('dump: pg_dump: connection refused');
  });
});

describe('formatSize', () => {
  it('reads like the spec ("1.8 GB")', () => {
    expect(formatSize(Math.round(1.8 * 1024 ** 3))).toBe('1.8 GB');
    expect(formatSize(512 * 1024 ** 2)).toBe('512 MB');
    expect(formatSize(900)).toBe('900 B');
    expect(formatSize(null)).toBe('—');
  });
});
