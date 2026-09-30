// @vitest-environment jsdom
//
// CMDB sync engine, as a tenant sees it (integrations W11):
//
//  - which buttons a card offers follows the platform's REGISTRY direction —
//    SolarWinds is pull-only, so it has Pull and no Sync;
//  - Test / Sync / Pull show the server's reason, not a fixed sentence;
//  - the Pull toast says what failed and what is held for identity review;
//  - the profile form sends the egress settings, has no conflict policy (it
//    was a no-op), and offers push-only settings only to push platforms;
//  - the sync history shows direction and the per-item errors.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: api,
    notifications: api,
  },
}));
vi.mock('react-hot-toast', () => ({ default: toast }));
vi.mock('@vistasecurity/primitives/features', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/features')>()),
  useFeature: () => true,
  editionAwareRetry: () => false,
}));
vi.mock('@vistasecurity/primitives/rbac', async (orig) => ({
  ...(await orig<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: unknown }) => children,
}));

const { IntegrationsPage, pullSummary } = await import('./pages-integrations');
const { CmdbProfileModal, CmdbJobsModal, canPushTo, canPullFrom } = await import('./cmdb-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function profile(platform: string, name: string) {
  return {
    id: `id-${platform}`, tenant_id: 't', name, platform_type: platform,
    connection_config: { base_url: 'https://cmdb.example.test', auth_type: 'basic', username: 'svc' },
    field_mapping_config: {}, sync_config: { schedule: 'daily', batch_size: 250 }, ci_type_mapping: {},
    is_enabled: true, has_password: true, has_api_token: false, has_client_secret: false,
    created_at: '2026-09-29T00:00:00Z', updated_at: '2026-09-29T00:00:00Z',
  };
}

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset();
  toast.success.mockReset(); toast.error.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } });
  await act(async () => { root.render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>); });
}
async function settle(done: () => boolean) {
  for (let i = 0; i < 60 && !done(); i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
  }
}
const text = () => document.body.textContent ?? '';

function card(name: string): HTMLElement {
  const title = [...document.body.querySelectorAll('div')].find((d) => d.textContent === name);
  let el: HTMLElement | null | undefined = title;
  // Walk up to the card: the element that also holds the action buttons.
  while (el && !el.querySelector('button[title="Sync history"]')) el = el.parentElement;
  if (!el) throw new Error(`no card for ${name}`);
  return el;
}
const buttonIn = (el: HTMLElement, label: string) =>
  [...el.querySelectorAll('button')].find((b) => b.textContent === label);

async function renderPage(profiles: unknown[]) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/cmdb/profiles') return { data: { profiles }, response: { ok: true, status: 200 } };
    if (path === '/connectors') return { data: { groups: [] }, response: { ok: true, status: 200 } };
    if (path === '/connectors/netbox/connections') return { data: { connections: [] }, response: { ok: true, status: 200 } };
    return { data: [], response: { ok: true, status: 200 } };
  });
  await render(<IntegrationsPage meta={{ key: 'integrations', label: 'Integrations', icon: 'plug', job: '' }} />);
  await settle(() => text().includes('Orion'));
}

it('derives direction from the connector registry', () => {
  expect(canPushTo('solarwinds')).toBe(false);
  expect(canPullFrom('solarwinds')).toBe(true);
  for (const p of ['servicenow', 'device42', 'oomnitza']) {
    expect(canPushTo(p)).toBe(true);
    expect(canPullFrom(p)).toBe(true);
  }
  expect(canPushTo('jira')).toBe(false); // an ITSM key, not a CMDB
});

// MUTATION (goes red): render CmdbSyncButton unconditionally.
it('offers Sync only to push-capable platforms', async () => {
  await renderPage([profile('solarwinds', 'Orion'), profile('servicenow', 'Prod SN')]);
  const orion = card('Orion');
  expect(buttonIn(orion, 'Pull')).toBeTruthy();
  expect(buttonIn(orion, 'Sync'), 'SolarWinds is pull-only; Sync pushed certs and keys into Orion as nodes').toBeFalsy();
  const sn = card('Prod SN');
  expect(buttonIn(sn, 'Pull')).toBeTruthy();
  expect(buttonIn(sn, 'Sync')).toBeTruthy();
});

// A profile paused for an invalid field mapping says so, and why — the
// server refuses its runs, and a card that looked healthy would leave the
// tenant guessing (platform ADR-0002 D10 rule 4).
// MUTATION (goes red): drop the mapping_error banner.
it('shows a profile paused for an invalid mapping', async () => {
  const paused = { ...profile('oomnitza', 'Assets'), mapping_error: 'field_mapping_config.hostname: unknown field "hostname"' };
  await renderPage([paused, profile('solarwinds', 'Orion')]);
  const c = card('Assets');
  expect(c.textContent).toContain('Mapping invalid');
  expect(c.textContent).toContain('field_mapping_config.hostname');
  expect(card('Orion').textContent).not.toContain('Mapping invalid');
});

// MUTATION (goes red): throw the fixed 'Failed to start sync' / 'Connection failed'.
it('Sync and Test show the server reason', async () => {
  await renderPage([profile('servicenow', 'Prod SN')]);
  api.POST.mockImplementation(async (path: string) => {
    if (path.endsWith('/sync')) return { data: undefined, error: { error: 'a sync for this profile is already running' }, response: { ok: false, status: 409 } };
    return { data: undefined, error: { success: false, error: 'The CMDB\'s TLS certificate is not trusted. If an internal CA issued it, paste that CA certificate into "CA bundle" in the profile' }, response: { ok: false, status: 400 } };
  });
  const sn = card('Prod SN');
  await act(async () => { buttonIn(sn, 'Sync')!.click(); });
  await settle(() => toast.error.mock.calls.length > 0);
  expect(toast.error).toHaveBeenLastCalledWith('a sync for this profile is already running');
  await act(async () => { buttonIn(sn, 'Test')!.click(); });
  await settle(() => toast.error.mock.calls.length > 1);
  expect(toast.error).toHaveBeenLastCalledWith(expect.stringContaining('CA bundle'));
});

// MUTATION (goes red): go back to "Pulled N new assets (M already present)".
it('the Pull toast says what failed and what is held for review', () => {
  expect(pullSummary({ created: 2, skipped: 5, failed: 0 })).toBe('Pulled 2 new assets, 5 already present');
  const msg = pullSummary({ created: 1, skipped: 0, failed: 3, unresolved: 4 });
  expect(msg).toContain('3 failed');
  expect(msg).toContain('4 held for identity review');
});

it('a pull with failures toasts as an error', async () => {
  await renderPage([profile('solarwinds', 'Orion')]);
  api.POST.mockResolvedValue({ data: { created: 0, skipped: 1, failed: 2, unresolved: 0, results: [] }, error: undefined, response: { ok: true, status: 200 } });
  await act(async () => { buttonIn(card('Orion'), 'Pull')!.click(); });
  await settle(() => toast.error.mock.calls.length > 0);
  expect(String(toast.error.mock.calls[0][0])).toContain('2 failed');
});

type Body = { connection_config: Record<string, unknown>; sync_config: Record<string, unknown> };
async function saveEdit(p: ReturnType<typeof profile>, before?: () => Promise<void>): Promise<Body> {
  api.PUT.mockResolvedValue({ data: p, error: undefined, response: { ok: true, status: 200 } });
  await render(<CmdbProfileModal open profile={p} onClose={() => {}} />);
  if (before) await before();
  const save = [...document.body.querySelectorAll('button')].find((b) => b.textContent === 'Save changes')!;
  await act(async () => { save.click(); });
  await settle(() => api.PUT.mock.calls.length > 0);
  return (api.PUT.mock.calls[0] as [string, { body: Body }])[1].body;
}

// MUTATION (goes red): drop allow_private_endpoint / ca_bundle_pem from the
// connection_config the form sends.
it('sends the egress settings', async () => {
  const body = await saveEdit(profile('device42', 'D42'), async () => {
    const toggle = [...document.body.querySelectorAll('label')].find((l) => l.textContent?.includes('CMDB is on our own network'))!
      .querySelector('button')!;
    await act(async () => { toggle.click(); });
    const ta = document.body.querySelector('textarea[aria-label="CA bundle (PEM)"]') as HTMLTextAreaElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!;
    await act(async () => { setter.call(ta, '-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----'); ta.dispatchEvent(new Event('input', { bubbles: true })); });
  });
  expect(body.connection_config.allow_private_endpoint).toBe(true);
  expect(body.connection_config.ca_bundle_pem).toContain('BEGIN CERTIFICATE');
  expect(body.sync_config).toEqual({ schedule: 'daily', batch_size: 250, include_crypto_summary: false });
  expect(text()).not.toContain('On conflict');
});

it('a pull-only platform has no push settings', async () => {
  const body = await saveEdit(profile('solarwinds', 'Orion'));
  expect(body.sync_config).toEqual({ schedule: 'daily' });
  expect(document.body.querySelector('input[aria-label="Push batch size"]')).toBeNull();
  expect(text()).not.toContain('Include cryptographic summary');
  expect(text()).toContain('pull-only');
});

it('refuses a batch size outside 1–1000', async () => {
  await render(<CmdbProfileModal open profile={profile('servicenow', 'SN')} onClose={() => {}} />);
  const input = document.body.querySelector('input[aria-label="Push batch size"]') as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  await act(async () => { setter.call(input, '5000'); input.dispatchEvent(new Event('input', { bubbles: true })); });
  const save = [...document.body.querySelectorAll('button')].find((b) => b.textContent === 'Save changes')!;
  expect(save.disabled).toBe(true);
});

// MUTATION (goes red): stop rendering summary.errors in the history.
it('the history shows direction and the per-item errors', async () => {
  api.GET.mockResolvedValue({
    data: { jobs: [
      { id: 'j1', tenant_id: 't', profile_id: 'p', status: 'partial', trigger_type: 'scheduled', items_pushed: 1,
        items_reconciled: 0, items_failed: 1, items_skipped: 0, error_log: [], created_at: '2026-09-29T00:00:00Z',
        summary: { direction: 'push', created: 1, updated: 0, errors: [{ local_id: 'asset-1', error: 'ServiceNow returned HTTP 403: ACL' }], errors_total: 1, errors_omitted: 0 } },
      { id: 'j2', tenant_id: 't', profile_id: 'p', status: 'failed', trigger_type: 'manual', items_pushed: 0,
        items_reconciled: 0, items_failed: 0, items_skipped: 0, created_at: '2026-09-29T00:00:00Z',
        error_log: [{ error: 'pull failed: The CMDB did not answer in time' }], summary: { direction: 'pull' } },
    ] }, error: undefined, response: { ok: true, status: 200 },
  });
  await render(<CmdbJobsModal open profile={profile('servicenow', 'SN')} onClose={() => {}} />);
  await settle(() => text().includes('Push · scheduled'));
  expect(text()).toContain('Pull · manual');
  const rows = [...document.body.querySelectorAll('tr[aria-expanded]')];
  expect(rows.length).toBe(2);
  await act(async () => { (rows[0] as HTMLElement).click(); });
  expect(text()).toContain('HTTP 403: ACL');
  await act(async () => { (rows[1] as HTMLElement).click(); });
  expect(text()).toContain('did not answer in time');
});
