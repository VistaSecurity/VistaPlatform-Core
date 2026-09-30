// @vitest-environment jsdom
//
// Integrations review M16: ServiceNow's REST APIs take Basic auth or an OAuth
// access token. The profile dialog offered an "API token" for ServiceNow that
// was sent as a bearer token ServiceNow never issued — it could not work, and
// the API now refuses it. The dialog must not offer it, and a profile stored
// with it must open on an option that works.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const { CmdbProfileModal, CMDB_PLATFORMS } = await import('./cmdb-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(profile: Parameters<typeof CmdbProfileModal>[0]['profile']) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <CmdbProfileModal open profile={profile} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}

function authSelect(): HTMLSelectElement {
  const selects = [...document.body.querySelectorAll('select')];
  const s = selects.find((el) => [...el.options].some((o) => o.value === 'basic'));
  if (!s) throw new Error('no authentication select');
  return s;
}

it('offers ServiceNow only Basic and OAuth2 client credentials', async () => {
  const sn = CMDB_PLATFORMS.find((p) => p.value === 'servicenow');
  expect(sn?.auth).toEqual(['basic', 'oauth2']);

  await render(null); // a new profile opens on ServiceNow
  const options = [...authSelect().options].map((o) => o.value);
  expect(options).toEqual(['basic', 'oauth2']);
  expect(document.body.textContent).not.toContain('API token');
});

it('opens a ServiceNow profile stored with an API token on Basic, asking for credentials', async () => {
  await render({
    id: 'p-1', tenant_id: 't', name: 'Old ServiceNow', platform_type: 'servicenow',
    connection_config: { base_url: 'https://cmdb.example.test', auth_type: 'api_token' },
    field_mapping_config: {}, sync_config: { schedule: 'manual' }, ci_type_mapping: {},
    is_enabled: true, has_password: false, has_api_token: true, has_client_secret: false,
    created_at: '2026-09-29T00:00:00Z', updated_at: '2026-09-29T00:00:00Z',
  });
  expect(authSelect().value).toBe('basic');
  const save = [...document.body.querySelectorAll('button')].find((b) => b.textContent === 'Save changes');
  expect(save?.disabled).toBe(true); // no username / password yet
});
