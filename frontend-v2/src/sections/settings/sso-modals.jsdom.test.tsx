// @vitest-environment jsdom
// A Microsoft/Azure tenant SSO provider with allowed email domains is refused
// by the server unless both OAuth endpoints name one Entra directory.
// The modal prefills Microsoft with the multi-tenant `common` authority, so it
// must say so before saving — otherwise every save (including an unrelated
// edit of an existing provider, since the PUT always sends the domains and
// URLs) comes back as a bare 400.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';
import { SsoProviderModal } from './sso-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { auth: api } }));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ tenant: { id: 't-1' } }) }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { users: { manage: 'users.manage' } },
  usePermissions: () => ({ hasPermission: () => false }),
}));

const DIR = '11111111-2222-4333-8444-555555555555';
const common = (leaf: string) => `https://login.microsoftonline.com/common/oauth2/v2.0/${leaf}`;
const pinned = (leaf: string) => `https://login.microsoftonline.com/${DIR}/oauth2/v2.0/${leaf}`;

function provider(authUrl: string, tokenUrl: string, domains: string[]) {
  return {
    id: 'p-1', provider_type: 'microsoft', provider_name: 'Entra', is_enabled: true, is_default: false,
    auto_provision_users: true, allowed_domains: domains, client_id: 'client', auth_url: authUrl,
    token_url: tokenUrl, group_role_mappings: [],
  } as unknown as AuthC['schemas']['SSOProvider'];
}

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.PUT.mockReset().mockResolvedValue({ response: { ok: true } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(p: AuthC['schemas']['SSOProvider'] | null) {
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><SsoProviderModal provider={p} open onClose={() => {}} /></QueryClientProvider>);
  });
}
const saveButton = () => [...document.querySelectorAll('button')].find((b) => b.textContent === 'Save changes')!;
const alertText = () => document.querySelector('[role="alert"]')?.textContent ?? '';

it('blocks saving a Microsoft provider on `common` that carries allowed domains, and names the fix', async () => {
  await render(provider(common('authorize'), common('token'), ['example.com']));
  expect(saveButton().disabled).toBe(true);
  expect(alertText()).toContain('name your Entra directory');
  expect(alertText()).toContain('or clear the domains');
});

it('blocks it when only one endpoint is pinned', async () => {
  await render(provider(pinned('authorize'), common('token'), ['example.com']));
  expect(saveButton().disabled).toBe(true);
});

it('saves once both endpoints name one directory', async () => {
  await render(provider(pinned('authorize'), pinned('token'), ['example.com']));
  expect(alertText()).toBe('');
  expect(saveButton().disabled).toBe(false);
  await act(async () => saveButton().click());
  expect(api.PUT).toHaveBeenCalledTimes(1);
});

it('leaves a `common` provider with no allowed domains alone', async () => {
  await render(provider(common('authorize'), common('token'), []));
  expect(alertText()).toBe('');
  expect(saveButton().disabled).toBe(false);
});
