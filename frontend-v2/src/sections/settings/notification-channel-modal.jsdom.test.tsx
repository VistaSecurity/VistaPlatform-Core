// @vitest-environment jsdom
// The API no longer returns channel credentials — a Slack webhook URL, a
// PagerDuty routing key, a webhook's tokens and header values arrive masked
// (`https://hooks.example.test/••••`, `••••1234`). The edit modal used to prefill the
// field from config and PUT it back, which would now overwrite the stored
// secret with its own mask. Editing must therefore work WITHOUT re-entering the
// secret: blank means "keep the current value", and the credential is left out
// of the request so the server keeps what it has.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';
import { ChannelModal, buildChannelConfig } from './notification-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications: api, complianceEngine: api } }));
vi.mock('./alert-sources', () => ({
  alertSourceOptions: () => [],
  fetchAlertCatalogSources: async () => [],
}));

type Channel = NC['schemas']['TenantNotificationChannel'];
const MASKED_URL = 'https://hooks.example.test/••••';

/** The request body of the first PUT the modal made. */
function sentConfig(): Record<string, unknown> {
  const call = api.PUT.mock.calls[0] as [string, { body: { config: Record<string, unknown> } }];
  return call[1].body.config;
}

function channel(type: string, config: Record<string, unknown>): Channel {
  return {
    id: 'c-1', tenant_id: 't-1', channel_name: 'Ops', channel_type: type, config,
    enabled: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  };
}

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  api.PUT.mockReset().mockResolvedValue({ response: { ok: true } });
  api.POST.mockReset().mockResolvedValue({ response: { ok: true } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(c: Channel | null) {
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><ChannelModal channel={c} open onClose={() => {}} /></QueryClientProvider>);
  });
}
const button = (label: string) => [...document.querySelectorAll('button')].find((b) => b.textContent === label)!;
const monoInput = () => document.querySelector('input.mono') as HTMLInputElement;

async function typeInto(input: HTMLInputElement, value: string) {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

it('never prefills the credential; shows the masked form as a placeholder and says blank keeps it', async () => {
  await render(channel('slack', { webhook_url: MASKED_URL, channel: '#alerts' }));
  expect(monoInput().value).toBe('');
  expect(monoInput().placeholder).toContain(MASKED_URL);
  expect(document.body.textContent).toContain('Leave blank to keep the current value');
});

it('saves an edit with the credential left blank, and omits it from the request', async () => {
  await render(channel('slack', { webhook_url: MASKED_URL, channel: '#alerts' }));
  expect(button('Save changes').disabled).toBe(false);
  await act(async () => button('Save changes').click());

  expect(api.PUT).toHaveBeenCalledTimes(1);
  expect(sentConfig()).not.toHaveProperty('webhook_url');
  expect(sentConfig().channel).toBe('#alerts'); // unexposed keys still carried through
});

it('sends a newly typed credential', async () => {
  await render(channel('slack', { webhook_url: MASKED_URL }));
  await typeInto(monoInput(), 'https://hooks.example.test/services/NEW');
  await act(async () => button('Save changes').click());
  expect(sentConfig().webhook_url).toBe('https://hooks.example.test/services/NEW');
});

it('still requires the credential when creating a connection', async () => {
  await render(null);
  await typeInto(document.querySelector('input[data-autofocus]') as HTMLInputElement, 'New');
  await act(async () => {
    const select = document.querySelector('select') as HTMLSelectElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!;
    setter.call(select, 'slack');
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect(button('Add connection').disabled).toBe(true);
  await typeInto(monoInput(), 'https://hooks.example.test/services/NEW');
  expect(button('Add connection').disabled).toBe(false);
});

it('keeps email recipients prefilled — addresses are not secrets', async () => {
  await render(channel('email', { recipients: ['a@example.test', 'b@example.test'] }));
  expect(monoInput().value).toBe('a@example.test, b@example.test');
  expect(document.body.textContent).not.toContain('Leave blank');
});

it('buildChannelConfig: blank credential on edit is omitted, on create it is not', () => {
  const def = { value: 'webhook', label: 'w', configKey: 'url' as const, configLabel: 'URL', hint: '' };
  expect(buildChannelConfig({ url: 'https://x/••••', auth: { type: 'bearer', token: '••••1234' } }, def, '', true))
    .toEqual({ auth: { type: 'bearer', token: '••••1234' } });
  expect(buildChannelConfig({}, def, ' https://y ', false)).toEqual({ url: 'https://y' });
});

// --- generic webhook: authentication + signing secret -------------------------

async function selectValue(select: HTMLSelectElement, value: string) {
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!;
    setter.call(select, value);
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
}
const selects = () => [...document.querySelectorAll('select')] as HTMLSelectElement[];
const authSelect = () => selects().find((s) => [...s.options].some((o) => o.value === 'bearer'))!;
const inputByLabel = (label: string) => {
  const field = [...document.querySelectorAll('label, div')].find((n) => n.children.length > 0 && n.textContent?.startsWith(label) && n.querySelector('input'));
  return field!.querySelector('input') as HTMLInputElement;
};
const lastPostBody = () => (api.POST.mock.calls[0] as [string, { body: { config: Record<string, unknown> } }])[1].body;

async function fillNewWebhook(url: string) {
  await render(null);
  await typeInto(document.querySelector('input[data-autofocus]') as HTMLInputElement, 'Receiver');
  await selectValue(selects()[0], 'webhook');
  await typeInto(monoInput(), url);
}

it('a new webhook can authenticate with a bearer token, which is sent in auth', async () => {
  await fillNewWebhook('https://hooks.example.test/in');
  await selectValue(authSelect(), 'bearer');
  // The chosen mode's credential is required before saving.
  expect(button('Add connection').disabled).toBe(true);
  expect(document.body.textContent).toContain('Enter the bearer token');
  await typeInto(inputByLabel('Bearer token'), 'tok_test_only');
  expect(button('Add connection').disabled).toBe(false);

  await act(async () => button('Add connection').click());
  expect(lastPostBody().config).toEqual({ url: 'https://hooks.example.test/in', auth: { type: 'bearer', token: 'tok_test_only' } });
});

it('a new webhook can send one custom header', async () => {
  await fillNewWebhook('https://hooks.example.test/in');
  await selectValue(authSelect(), 'header');
  await typeInto(inputByLabel('Header name'), 'X-Api-Key');
  await typeInto(inputByLabel('Header value'), 'k_test_only');
  await act(async () => button('Add connection').click());
  expect(lastPostBody().config).toEqual({ url: 'https://hooks.example.test/in', headers: { 'X-Api-Key': 'k_test_only' } });
});

// The signing secret is generated by the server and shown once. Closing over it
// would lose the only copy.
it('shows a server-generated signing secret once, and stays open until dismissed', async () => {
  api.POST.mockResolvedValue({ data: { id: 'c-9', signing_secret: 'whsec_generated_test_only' }, response: { ok: true } });
  const onClose = vi.fn();
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><ChannelModal channel={null} open onClose={onClose} /></QueryClientProvider>);
  });
  await typeInto(document.querySelector('input[data-autofocus]') as HTMLInputElement, 'Receiver');
  await selectValue(selects()[0], 'webhook');
  await typeInto(monoInput(), 'https://hooks.example.test/in');
  // No secret typed: none is sent, so the server generates one.
  await act(async () => button('Add connection').click());
  expect(lastPostBody().config).not.toHaveProperty('webhook_secret');

  const shown = document.querySelector('[data-testid="signing-secret"]') as HTMLInputElement;
  expect(shown.value).toBe('whsec_generated_test_only');
  expect(document.body.textContent).toContain('only time the secret is shown');
  expect(onClose).not.toHaveBeenCalled();

  await act(async () => button('Done').click());
  expect(onClose).toHaveBeenCalledTimes(1);
});

it('a channel created with no generated secret just closes', async () => {
  api.POST.mockResolvedValue({ data: { id: 'c-9' }, response: { ok: true } });
  const onClose = vi.fn();
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><ChannelModal channel={null} open onClose={onClose} /></QueryClientProvider>);
  });
  await typeInto(document.querySelector('input[data-autofocus]') as HTMLInputElement, 'Slacky');
  await selectValue(selects()[0], 'slack');
  await typeInto(monoInput(), 'https://hooks.example.test/services/NEW');
  await act(async () => button('Add connection').click());
  expect(onClose).toHaveBeenCalledTimes(1);
  expect(document.querySelector('[data-testid="signing-secret"]')).toBeNull();
});

it('editing a webhook: nothing re-entered keeps every stored credential, and the masked secret is not resent', async () => {
  await render(channel('webhook', {
    url: 'https://hooks.example.test/••••',
    auth: { type: 'bearer', token: '••••wxyz' },
    webhook_secret: '••••abcd',
  }));
  expect(authSelect().value).toBe('bearer');
  expect(document.body.textContent).toContain('Leave blank to keep the current value');
  await act(async () => button('Save changes').click());

  const config = sentConfig();
  expect(config).toEqual({ auth: { type: 'bearer' } }); // url, token and secret all omitted => kept server-side
});

it('editing a webhook: a newly entered signing secret rotates it', async () => {
  await render(channel('webhook', { url: 'https://hooks.example.test/••••', webhook_secret: '••••abcd' }));
  await typeInto(inputByLabel('Signing secret'), 'whsec_rotated_test_only');
  await act(async () => button('Save changes').click());
  expect(sentConfig().webhook_secret).toBe('whsec_rotated_test_only');
});

it('editing a webhook: switching to a mode with nothing stored demands the new credential', async () => {
  await render(channel('webhook', { url: 'https://hooks.example.test/••••', auth: { type: 'bearer', token: '••••wxyz' } }));
  await selectValue(authSelect(), 'basic');
  expect(button('Save changes').disabled).toBe(true);
  await typeInto(inputByLabel('Username'), 'svc');
  await typeInto(inputByLabel('Password'), 'pw_test_only');
  expect(button('Save changes').disabled).toBe(false);
  await act(async () => button('Save changes').click());
  expect(sentConfig().auth).toEqual({ type: 'basic', username: 'svc', password: 'pw_test_only' });
});
