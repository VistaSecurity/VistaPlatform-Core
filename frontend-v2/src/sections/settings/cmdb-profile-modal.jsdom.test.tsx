// @vitest-environment jsdom
//
// The CMDB profile dialog after credentials became write-only (integrations
// review: the API returns has_password / has_api_token /
// has_client_secret instead of the secret values, so editing a profile must
// let the operator leave a stored secret blank (the server keeps it) — before,
// the form pre-filled the plaintext secret the API handed back. And a refused
// save shows the server's reason (duplicate name, unknown platform) instead of
// a generic "Failed to save".
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const { CmdbProfileModal } = await import('./cmdb-modals');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const profile = {
  id: 'p-1', tenant_id: 't', name: 'Production ServiceNow', platform_type: 'servicenow',
  connection_config: { base_url: 'https://cmdb.example.test', instance_url: 'https://cmdb.example.test', auth_type: 'basic', username: 'svc' },
  field_mapping_config: {}, sync_config: { schedule: 'manual' }, ci_type_mapping: {},
  is_enabled: true, has_password: true, has_api_token: false, has_client_secret: false,
  created_at: '2026-09-29T00:00:00Z', updated_at: '2026-09-29T00:00:00Z',
};

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  api.PUT.mockReset(); api.POST.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(p: typeof profile | null) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <CmdbProfileModal open profile={p} onClose={() => {}} />
      </QueryClientProvider>,
    );
  });
}

function button(label: string) {
  return [...document.body.querySelectorAll('button')].find((b) => b.textContent === label);
}

async function settle(done: () => boolean) {
  for (let i = 0; i < 40 && !done(); i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 5)); });
  }
}

it('lets a stored password stay blank on edit, and sends no secret back', async () => {
  api.PUT.mockResolvedValue({ data: profile, error: undefined, response: { ok: true, status: 200 } });
  await render(profile);

  const pw = document.body.querySelector('input[type="password"]') as HTMLInputElement;
  expect(pw.value).toBe('');
  expect(pw.placeholder).toBe('Leave blank to keep the current secret');

  const save = button('Save changes');
  expect(save?.disabled).toBe(false);
  await act(async () => { save!.click(); });
  await settle(() => api.PUT.mock.calls.length > 0);

  type PutCall = [string, { body: { connection_config: Record<string, unknown> } }];
  const { body } = (api.PUT.mock.calls[0] as PutCall)[1];
  expect(body.connection_config.password).toBe('');
  expect(body.connection_config.username).toBe('svc');
});

it('still requires a password when none is stored', async () => {
  await render({ ...profile, has_password: false });
  expect(button('Save changes')?.disabled).toBe(true);
});

it('shows the server reason when a save is refused', async () => {
  const reason = 'A CMDB profile named "Production ServiceNow" already exists';
  api.PUT.mockResolvedValue({ data: undefined, error: { error: reason }, response: { ok: false, status: 409 } });
  await render(profile);
  await act(async () => { button('Save changes')!.click(); });
  await settle(() => !!document.body.textContent?.includes('already exists'));
  expect(document.body.textContent).toContain(reason);
});
