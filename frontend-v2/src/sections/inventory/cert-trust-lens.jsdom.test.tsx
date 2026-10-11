// @vitest-environment jsdom
//
// The Certificates lens's Trust filter, chip and "Untrusted certificates" view
// ( slice 3), through the REAL InventoryPage so the wiring is what is
// tested: the URL's `trust` selection must reach `GET /certificates` as the
// pinned `trust_status` parameter, and each row must carry its trust chip
// beside (not instead of) the expiry dot.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UNTRUSTED_CERTIFICATES_HREF } from './builtin-views';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const untrusted = {
  id: '22222222-0000-4000-8000-000000000001', common_name: 'netbox.corp.example', subject_dn: 'CN=netbox.corp.example',
  issuer_dn: 'CN=Corp Issuing CA', public_key_algorithm: 'RSA', public_key_size: 2048, not_after: '2027-06-01T00:00:00Z',
  certificate_state: 'active', data_source: 'discovery', deployment_count: 1, trust_status: 'untrusted',
};
const fresh = {
  id: '22222222-0000-4000-8000-000000000002', common_name: 'new.example.org', subject_dn: 'CN=new.example.org',
  issuer_dn: 'CN=Example CA', public_key_algorithm: 'ECDSA', public_key_size: 256, not_after: '2027-06-01T00:00:00Z',
  certificate_state: 'active', data_source: 'discovery', deployment_count: 1,
};

const PROBE_FLAG = 'Certificate signed by an untrusted certificate authority (not in the system trust store — may be a private or pinned CA)';
const conn = (id: string, dest: string, extra: Record<string, unknown>) => ({
  id, dest_hostname: dest, dest_ip: '203.0.113.7', dest_port: 443, source_hostname: 'app-1', source_ip: '10.0.0.5',
  protocol: 'TLS', protocol_version: 'TLS 1.3', cipher_suite: 'TLS_AES_128_GCM_SHA256', strength: 'strong',
  cert_hygiene_flags: [PROBE_FLAG], cert_not_after: '2027-01-01T00:00:00Z', last_seen_at: '2026-10-01T00:00:00Z', ...extra,
});
const CONNECTIONS = [
  conn('c1', 'evaluated.example.com', { trust_status: 'untrusted' }),
  conn('c2', 'legacy.example.com', {}),
];

const inventoryGet = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: { GET: inventoryGet, POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() },
    compliance: { GET: vi.fn() },
  },
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: () => null,
  usePermissions: () => ({ hasPermission: () => false, hasAnyPermission: () => false, permissions: [] }),
}));

import { InventoryPage } from './inventory-page';

const ok = (data: unknown) => ({ data, error: undefined, response: { ok: true, status: 200 } });
const certCalls: Record<string, unknown>[] = [];

beforeEach(() => {
  certCalls.length = 0;
  inventoryGet.mockReset().mockImplementation(async (path: string, init?: { params?: { query?: Record<string, unknown> } }) => {
    if (path === '/external-connections') {
      return ok({ connections: CONNECTIONS, pagination: { total: CONNECTIONS.length, page: 1, page_size: 50 } });
    }
    if (path === '/certificates') {
      certCalls.push(init?.params?.query ?? {});
      return ok({ certificates: [untrusted, fresh], pagination: { total: 2, page: 1, page_size: 50 } });
    }
    return ok({ assets: [], items: [], total: 0, pagination: { total: 0, page: 1, page_size: 50 } });
  });
});

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function settle() {
  for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}
async function show(entry: string) {
  await act(async () => {
    root.render(<MemoryRouter initialEntries={[entry]}>
      <QueryClientProvider client={cache}>
        <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
      </QueryClientProvider>
    </MemoryRouter>);
  });
  await settle();
}
const last = () => certCalls[certCalls.length - 1];
const row = (name: string) => [...host.querySelectorAll('[data-testid="cert-row"]')].find((r) => r.textContent?.includes(name));

describe('Certificates lens · Trust', () => {
  it('asks for every certificate when no trust filter is set', async () => {
    await show('/inventory?lens=certificate');
    expect(last().trust_status).toBeUndefined();
  });

  it('the built-in view link sends trust_status=untrusted,distrusted and names the view', async () => {
    expect(UNTRUSTED_CERTIFICATES_HREF).toBe('/inventory?lens=certificate&trust=untrusted,distrusted');
    await show(UNTRUSTED_CERTIFICATES_HREF);
    expect(last().trust_status).toBe('untrusted,distrusted');
    expect(host.textContent).toContain('Untrusted certificates');
    expect(host.querySelector('[data-testid="cert-trust-filter"]')?.textContent).toContain('Trust · 2');
  });

  it('a row carries its trust chip, and an unevaluated certificate says so — never trusted', async () => {
    await show('/inventory?lens=certificate');
    expect(row('netbox.corp.example')?.querySelector('[data-testid="cert-trust-chip"]')?.textContent).toBe('Untrusted CA');
    expect(row('new.example.org')?.querySelector('[data-testid="cert-trust-chip"]')?.textContent).toBe('Not yet evaluated');
  });

  it('ticking a value in the filter refetches with it, including "Not yet evaluated" as `unevaluated`', async () => {
    await show('/inventory?lens=certificate');
    await act(async () => { (host.querySelector('[data-testid="cert-trust-filter"]') as HTMLButtonElement).click(); });
    const box = (label: string) => host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
    await act(async () => { box('Not yet evaluated').click(); });
    await settle();
    expect(last().trust_status).toBe('unevaluated');
    await act(async () => { box('Self-signed').click(); });
    await settle();
    expect(last().trust_status).toBe('self_signed,unevaluated');
  });

  it('picking the view from the Views menu applies it', async () => {
    await show('/inventory?lens=certificate');
    const views = [...host.querySelectorAll('button')].find((b) => b.getAttribute('title') === 'Views')!;
    await act(async () => { views.click(); });
    const item = [...host.querySelectorAll('[role="menuitem"]')].find((b) => b.textContent?.includes('Untrusted certificates')) as HTMLButtonElement;
    await act(async () => { item.click(); });
    await settle();
    expect(last().trust_status).toBe('untrusted,distrusted');
  });
});

describe('3rd Party lens · Trust', () => {
  const rowOf = (dest: string) => [...host.querySelectorAll('.row-hover')].find((r) => r.textContent?.includes(dest)) as HTMLElement;
  const hygieneTitle = (dest: string) => rowOf(dest).querySelector('[title^="Certificate hygiene"]')?.getAttribute('title') ?? '';

  it('shows the platform trust chip when the connection carries trust_status, and drops the probe\'s CA verdict', async () => {
    await show('/inventory?lens=connections');
    expect(rowOf('evaluated.example.com').querySelector('[data-testid="cert-trust-chip"]')?.textContent).toBe('Untrusted CA');
    expect(hygieneTitle('evaluated.example.com')).toBe('');
  });

  it('without trust_status: no chip, and the probe flag says whose trust and where to change it', async () => {
    await show('/inventory?lens=connections');
    expect(rowOf('legacy.example.com').querySelector('[data-testid="cert-trust-chip"]')).toBeNull();
    const t = hygieneTitle('legacy.example.com');
    expect(t).toContain('not trusted by your organisation');
    expect(t).toContain('Settings → Policies → Trusted CAs');
    expect(t).not.toContain('untrusted certificate authority');
  });
});
