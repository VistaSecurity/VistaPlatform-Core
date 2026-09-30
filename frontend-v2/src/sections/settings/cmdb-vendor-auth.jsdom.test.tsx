// @vitest-environment jsdom
//
// The authentication choices a CMDB profile offers must be the ones the
// connector implements (integrations review M16, work package W13):
//
//  - Device42 and SolarWinds Orion authenticate with HTTP Basic (a Device42
//    user / an Orion account). Their connectors used to offer an "API token"
//    that was sent as a Bearer header neither service accepts;
//  - Oomnitza takes its API token (Authorization2) or Basic, both real.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api, notifications: api } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

const { CmdbProfileModal, CMDB_PLATFORMS } = await import('./cmdb-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement; let root: Root;
beforeEach(() => { host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); });
afterEach(() => { act(() => root.unmount()); host.remove(); });

function stored(platform: string, authType: string) {
  return {
    id: `id-${platform}`, tenant_id: 't', name: platform, platform_type: platform,
    connection_config: { base_url: 'https://cmdb.example.test', auth_type: authType, username: 'svc' },
    field_mapping_config: {}, sync_config: { schedule: 'daily', batch_size: 250 }, ci_type_mapping: {},
    is_enabled: true, has_password: false, has_api_token: true, has_client_secret: false,
    created_at: '2026-09-30T00:00:00Z', updated_at: '2026-09-30T00:00:00Z',
  };
}

async function authOptions(p: ReturnType<typeof stored>): Promise<string[]> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><CmdbProfileModal open profile={p} onClose={() => {}} /></QueryClientProvider>);
  });
  const selects = [...document.body.querySelectorAll('select')];
  const auth = selects.find((s) => [...s.options].some((o) => o.textContent === 'Username & password'))!;
  return [...auth.options].map((o) => o.textContent ?? '');
}

// MUTATION (goes red): add 'api_token' back to Device42's or SolarWinds's auth list.
it('Device42 and SolarWinds offer Username & password only', () => {
  const by = Object.fromEntries(CMDB_PLATFORMS.map((p) => [p.value, p.auth]));
  expect(by.device42).toEqual(['basic']);
  expect(by.solarwinds).toEqual(['basic']);
  expect(by.oomnitza).toEqual(['api_token', 'basic']);
});

it('the form for a profile stored with the retired API-token scheme shows Basic, not a token field', async () => {
  for (const platform of ['device42', 'solarwinds']) {
    expect(await authOptions(stored(platform, 'api_token'))).toEqual(['Username & password']);
    expect(document.body.textContent).toContain('Username');
    expect(document.body.textContent).not.toContain('API token');
    act(() => root.render(<div />));
  }
});

it('Oomnitza still offers its API token and Basic', async () => {
  expect(await authOptions(stored('oomnitza', 'api_token'))).toEqual(['API token', 'Username & password']);
});
