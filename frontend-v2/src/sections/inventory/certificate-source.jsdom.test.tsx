// @vitest-environment jsdom
//
// The CONSUMER for slice C of.
//
// A tenant adds an AWS account; the account's ACM certificate must appear in
// Inventory → Certificates with a correct expiry and be distinguishable from a
// certificate observed on the wire. Two things have to be true on the page, and
// neither is provable from the producer side:
//
//   1. nothing in the lens filters a cloud-managed certificate out, and
//   2. the row says where the certificate came from.
//
// So this renders the REAL InventoryPage at ?lens=certificate against a
// /certificates response holding one of each. Deleting the source badge from
// CertRow turns it red; a filter that hid provider-API certificates would too.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// The ACM certificate from the live demo discovery. No PEM and no fingerprint —
// DescribeCertificate returns metadata about a certificate, not the certificate
// — which is exactly the shape the lens has to render without complaint.
const cloudCert = {
  id: '11111111-0000-4000-8000-000000000001',
  common_name: 'shop.example.com',
  subject_dn: 'CN=shop.example.com',
  issuer_dn: 'Amazon',
  public_key_algorithm: 'RSA',
  public_key_size: 2048,
  signature_algorithm: 'SHA256WITHRSA',
  not_after: '2026-12-18T23:59:59Z',
  certificate_state: 'active',
  data_source: 'cloud_api',
  deployment_count: 1,
};

const observedCert = {
  id: '11111111-0000-4000-8000-000000000002',
  common_name: '*.cloudfront.net',
  subject_dn: 'CN=*.cloudfront.net',
  issuer_dn: 'CN=Amazon RSA 2048 M01,O=Amazon,C=US',
  public_key_algorithm: 'RSA',
  public_key_size: 2048,
  not_after: '2027-03-10T00:00:00Z',
  certificate_state: 'active',
  data_source: 'discovery',
  deployment_count: 1,
};

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

function ok(data: unknown) {
  return { data, error: undefined, response: { ok: true, status: 200 } };
}

let certificatesQueryParams: Record<string, unknown> | undefined;

beforeEach(() => {
  certificatesQueryParams = undefined;
  inventoryGet.mockReset().mockImplementation(async (path: string, init?: { params?: { query?: Record<string, unknown> } }) => {
    switch (path) {
      case '/certificates':
        certificatesQueryParams = init?.params?.query;
        return ok({ certificates: [cloudCert, observedCert], pagination: { total: 2, page: 1, page_size: 50 } });
      case '/identity/summary':
        return ok({ established: 0, operator_confirmed: 0, legacy: 0, unresolved: 0, conflicted: 0, provisional: 0, admission_mode: 'enforce' });
      case '/saved-views':
        return ok({ saved_views: [] });
      default:
        return ok({ assets: [], items: [], total: 0, pagination: { total: 0, page: 1, page_size: 50 } });
    }
  });
});

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function show(entry: string) {
  await act(async () => {
    root.render(<MemoryRouter key={entry} initialEntries={[entry]}>
      <QueryClientProvider client={cache}>
        <Routes><Route path="/inventory" element={<InventoryPage />} /></Routes>
      </QueryClientProvider>
    </MemoryRouter>);
  });
  for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  return host.textContent ?? '';
}

it('lists the cloud-managed certificate beside the observed one, and says which is which', async () => {
  const page = await show('/inventory?lens=certificate');

  // 1. It is THERE. The ACM record has no PEM and no fingerprint; nothing in
  //    the lens may treat that as a reason to drop it.
  expect(page).toContain('shop.example.com');
  expect(page).toContain('*.cloudfront.net');

  // 2. The lens asks for all certificates. A default ownership or source scope
  //    here would hide cloud-managed ones exactly the way a bare /facets call
  //    hides pending assets.
  expect(certificatesQueryParams?.ownership).toBeUndefined();

  // 3. The two are distinguishable, and the badge is on the right row.
  expect(page).toContain('cloud-managed');
  expect(page).toContain('observed');

  const rowFor = (name: string) => {
    const el = [...host.querySelectorAll('div')].find(
      (d) => d.textContent?.startsWith(name) && d.textContent.length < name.length + 40,
    );
    if (!el) throw new Error(`no row found for ${name}`);
    return el.textContent ?? '';
  };
  expect(rowFor('shop.example.com')).toContain('cloud-managed');
  expect(rowFor('*.cloudfront.net')).toContain('observed');

  // 4. The expiry is the one ACM stated — the whole point of the slice. The
  //    row renders days remaining from not_after, never a stored derivation.
  const remaining = (Date.parse(cloudCert.not_after) - Date.now()) / 86_400_000;
  const shown = [Math.floor(remaining), Math.ceil(remaining)].map((d) => `${d}d`);
  expect(shown.some((d) => rowFor('shop.example.com').includes(d))).toBe(true);
  // …and NOT the certificate's total validity period, which is what the
  // deleted expires_in_days computed and called time remaining (D5).
  const totalValidity = Math.round((Date.parse(cloudCert.not_after) - Date.parse('2025-11-19T00:00:00Z')) / 86_400_000);
  expect(rowFor('shop.example.com')).not.toContain(`${totalValidity}d`);
});
