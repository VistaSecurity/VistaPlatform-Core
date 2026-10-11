// @vitest-environment jsdom
//
// Settings → Policies → Trusted CAs ( slice 1). Renders the REAL page
// against a mocked inventory client and checks every Section 1 state plus the
// gating split: the table is readable by anyone who can see the inventory, and
// every write control needs `certificates.trust`.
//
// The RBAC mock below answers from `granted`, so deleting a <PermissionGate>
// from the page turns the "viewer" test red (mutation-checked when written).
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(), authGET: vi.fn() }));
const granted = vi.hoisted(() => new Set<string>());
vi.mock('../../lib/clients', () => ({
  clients: { inventory: { GET: api.GET, POST: api.POST, PUT: api.PUT, DELETE: api.DELETE }, auth: { GET: api.authGET } },
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));
vi.mock('@vistasecurity/primitives/auth', () => ({ useAuth: () => ({ tenant: { id: 'tenant-1' }, user: { id: 'u1' } }) }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => {
  const real = await importOriginal<typeof import('@vistasecurity/primitives/rbac')>();
  return {
    ...real,
    usePermissions: () => ({
      isLoading: false,
      permissions: [...granted],
      hasPermission: (p: string) => granted.has(p),
      hasAnyPermission: (ps: string[]) => ps.some((p) => granted.has(p)),
      hasAllPermissions: (ps: string[]) => ps.every((p) => granted.has(p)),
    }),
    PermissionGate: ({ permission, children, fallback = null }: { permission?: string; children: ReactNode; fallback?: ReactNode }) =>
      <>{permission && granted.has(permission) ? children : fallback}</>,
  };
});

const { TrustedCAsPage } = await import('./pages-trusted-cas');
const { settingsPageMeta } = await import('./nav');

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----';

const anchor = {
  id: 'anchor-1',
  tenant_id: 'tenant-1',
  certificate_id: 'cert-ca-1',
  decision: 'trusted' as const,
  note: 'internal issuing root',
  decided_by: 'u1',
  decided_at: '2026-10-09T12:00:00Z',
  created_at: '2026-10-09T12:00:00Z',
  updated_at: '2026-10-09T12:00:00Z',
  certificate: {
    id: 'cert-ca-1',
    subject_dn: 'CN=Example Internal Root CA,O=Example',
    issuer_dn: 'CN=Example Internal Root CA,O=Example',
    common_name: 'Example Internal Root CA',
    fingerprint_sha256: 'aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44',
    is_self_signed: true,
    is_ca_certificate: true,
  },
  affected_certificates: 3,
  affected_assets: 2,
};

const ok = (data: unknown, status = 200) => ({ data, error: undefined, response: { ok: true, status } });
const fail = (status: number, error: unknown) => ({ data: undefined, error, response: { ok: false, status } });

function serve(anchors: unknown[] | 'error') {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/trust-anchors') return anchors === 'error' ? fail(500, { error: 'boom' }) : ok({ anchors, total: anchors.length });
    if (path === '/trust-anchors/public-roots') return ok({ version: '2026-09-01', root_count: 150, source: 'Mozilla NSS' });
    return ok({});
  });
}

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  granted.clear();
  granted.add('assets.read');
  for (const f of [api.GET, api.POST, api.PUT, api.DELETE]) f.mockReset();
  api.authGET.mockReset().mockResolvedValue(ok({ users: [{ id: 'u1', first_name: 'Ada', last_name: 'Admin', email: 'ada@example.test', is_active: true }] }));
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <TrustedCAsPage meta={settingsPageMeta('trusted-cas')} />
      </QueryClientProvider>,
    );
  });
}

const text = () => document.body.textContent ?? '';
const buttons = (label: string | RegExp) =>
  [...document.body.querySelectorAll('button')].filter((b) => (typeof label === 'string' ? b.textContent?.trim() === label : label.test(b.textContent ?? '')));

async function click(label: string | RegExp) {
  const [btn] = buttons(label);
  expect(btn, `no "${String(label)}" button`).toBeTruthy();
  await act(async () => { btn.click(); });
}

function type(el: HTMLTextAreaElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')!.set!;
  act(() => { setter.call(el, value); el.dispatchEvent(new window.Event('input', { bubbles: true })); });
}
const field = (label: string) => document.body.querySelector<HTMLTextAreaElement>(`textarea[aria-label="${label}"]`)!;

describe('states', () => {
  it('empty: says public roots are trusted by default, and shows the bundle', async () => {
    serve([]);
    await render();
    await vi.waitFor(() => expect(text()).toContain('No CA decisions yet.'));
    expect(text()).toContain('Public roots are trusted by default.');
    expect(document.body.querySelector('[data-testid="public-roots"]')?.textContent)
      .toBe('Public roots · Mozilla bundle 2026-09-01 · 150 roots · trusted by default');
  });

  it('default: one row per decision with name, chip, decider, note and affected counts', async () => {
    serve([anchor]);
    await render();
    await vi.waitFor(() => expect(text()).toContain('Example Internal Root CA'));
    const row = document.body.querySelector('[data-anchor-row="anchor-1"]')!;
    expect(row.textContent).toContain('Trusted');
    expect(row.textContent).toContain('internal issuing root');
    expect(row.textContent).toContain('3 certificates on 2 assets');
    // The fingerprint is truncated in the cell and whole in its title, for copying.
    const fp = row.querySelector<HTMLButtonElement>('button[title^="SHA-256"]')!;
    expect(fp.title).toContain(anchor.certificate.fingerprint_sha256);
    expect(fp.textContent).toContain('…');
  });

  it('error: a load failure renders a card with Retry, which refetches', async () => {
    serve('error');
    await render();
    await vi.waitFor(() => expect(text()).toContain("Couldn't load trust decisions"));
    const before = api.GET.mock.calls.filter(([p]) => p === '/trust-anchors').length;
    serve([]);
    await click(/Retry/);
    await vi.waitFor(() => expect(text()).toContain('No CA decisions yet.'));
    expect(api.GET.mock.calls.filter(([p]) => p === '/trust-anchors').length).toBeGreaterThan(before);
  });
});

describe('gating', () => {
  it('a viewer sees the table but no write control', async () => {
    serve([anchor]);
    await render();
    await vi.waitFor(() => expect(text()).toContain('Example Internal Root CA'));
    expect(buttons(/Add CA/)).toHaveLength(0);
    expect(buttons('Change decision')).toHaveLength(0);
    expect(buttons(/Remove/)).toHaveLength(0);
  });

  it('a viewer on an empty page gets no Add CA either', async () => {
    serve([]);
    await render();
    await vi.waitFor(() => expect(text()).toContain('No CA decisions yet.'));
    expect(buttons(/Add CA/)).toHaveLength(0);
  });

  it('certificates.trust brings Add CA, Change decision and Remove', async () => {
    granted.add('certificates.trust');
    serve([anchor]);
    await render();
    await vi.waitFor(() => expect(text()).toContain('Example Internal Root CA'));
    expect(buttons(/Add CA/).length).toBeGreaterThan(0);
    expect(buttons('Change decision')).toHaveLength(1);
    expect(buttons(/Remove/)).toHaveLength(1);
  });
});

describe('Add CA', () => {
  beforeEach(() => { granted.add('certificates.trust'); });

  it('sends the PEM, the decision and the note, trimmed', async () => {
    serve([]);
    api.POST.mockResolvedValue(ok({ ...anchor, decision: 'distrusted' }, 201));
    await render();
    await vi.waitFor(() => expect(buttons(/Add CA/).length).toBeGreaterThan(0));
    await click(/Add CA/);
    type(field('CA certificate (PEM)'), `\n  ${PEM}\n\n`);
    await click('Distrusted');
    type(field('Note'), '  retiring, see ticket 42  ');
    await click('Distrust this CA');

    expect(api.POST).toHaveBeenCalledTimes(1);
    const [path, init] = api.POST.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/trust-anchors');
    expect(init.body).toEqual({ certificate_pem: PEM, decision: 'distrusted', note: 'retiring, see ticket 42' });
    expect(init.body).not.toHaveProperty('certificate_id');
  });

  it('defaults to Trusted and omits an empty note', async () => {
    serve([]);
    api.POST.mockResolvedValue(ok(anchor, 201));
    await render();
    await vi.waitFor(() => expect(buttons(/Add CA/).length).toBeGreaterThan(0));
    await click(/Add CA/);
    type(field('CA certificate (PEM)'), PEM);
    await click('Trust this CA');
    const init = api.POST.mock.calls[0][1] as { body: Record<string, unknown> };
    expect(init.body.decision).toBe('trusted');
    expect(init.body.note).toBeUndefined();
  });

  it('refuses text that is not a PEM certificate before sending it', async () => {
    serve([]);
    await render();
    await vi.waitFor(() => expect(buttons(/Add CA/).length).toBeGreaterThan(0));
    await click(/Add CA/);
    type(field('CA certificate (PEM)'), 'MIIBnotapem');
    const [submit] = buttons('Trust this CA');
    expect(submit.disabled).toBe(true);
    expect(text()).toContain('-----BEGIN CERTIFICATE-----');
    expect(api.POST).not.toHaveBeenCalled();
  });

  it('409: shows the server error and points at the existing decision', async () => {
    serve([anchor]);
    api.POST.mockResolvedValue(fail(409, { error: 'A decision already exists for Example Internal Root CA (trusted)' }));
    await render();
    await vi.waitFor(() => expect(text()).toContain('Example Internal Root CA'));
    await click(/Add CA/);
    type(field('CA certificate (PEM)'), PEM);
    await click('Trust this CA');
    await vi.waitFor(() => expect(text()).toContain('A decision already exists for Example Internal Root CA (trusted)'));
    await click('Show existing decision');
    expect(document.body.querySelector('[role="dialog"]')).toBeNull();
    expect(document.body.querySelector('[data-anchor-row="anchor-1"]')?.getAttribute('data-highlighted')).toBe('true');
  });
});

describe('Change decision / Remove', () => {
  beforeEach(() => { granted.add('certificates.trust'); });

  it('Change decision starts flipped and PUTs the new decision with the note', async () => {
    serve([anchor]);
    api.PUT.mockResolvedValue(ok({ ...anchor, decision: 'distrusted' }));
    await render();
    await vi.waitFor(() => expect(buttons('Change decision')).toHaveLength(1));
    await click('Change decision');
    expect(text()).toContain('Affects 3 certificates on 2 assets.');
    await click('Save decision');
    const [path, init] = api.PUT.mock.calls[0] as [string, { params: { path: { id: string } }; body: Record<string, unknown> }];
    expect(path).toBe('/trust-anchors/{id}');
    expect(init.params.path.id).toBe('anchor-1');
    expect(init.body).toEqual({ decision: 'distrusted', note: 'internal issuing root' });
  });

  it('a 403 says so in words', async () => {
    serve([anchor]);
    api.PUT.mockResolvedValue(fail(403, { error: 'forbidden' }));
    await render();
    await vi.waitFor(() => expect(buttons('Change decision')).toHaveLength(1));
    await click('Change decision');
    await click('Save decision');
    await vi.waitFor(() => expect(text()).toContain("You don't have permission to change trust"));
  });

  it('Remove confirms what happens, then DELETEs', async () => {
    serve([anchor]);
    api.DELETE.mockResolvedValue({ data: undefined, error: undefined, response: { ok: true, status: 204 } });
    await render();
    await vi.waitFor(() => expect(buttons(/Remove/)).toHaveLength(1));
    await click(/Remove/);
    expect(text()).toContain('The CA stays in your inventory');
    expect(text()).toContain('return to Untrusted CA');
    await click('Remove decision');
    expect(api.DELETE).toHaveBeenCalledWith('/trust-anchors/{id}', { params: { path: { id: 'anchor-1' } } });
  });
});
