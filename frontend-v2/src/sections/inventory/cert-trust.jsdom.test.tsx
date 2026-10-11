// @vitest-environment jsdom
//
// The certificate drawer's Trust section ( slice 1), rendered through the
// REAL CertDrawer so deleting its wiring (the chip in the header, the rows in
// Trust & revocation) turns these red, not just the helper's tests.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
const granted = vi.hoisted(() => new Set<string>());
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));
vi.mock('react-router', () => ({ Link: ({ children }: { children: ReactNode }) => <a>{children}</a>, useNavigate: () => vi.fn() }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ permission, children, fallback = null }: { permission?: string; children: ReactNode; fallback?: ReactNode }) =>
    <>{permission && granted.has(permission) ? children : fallback}</>,
}));
vi.mock('../../components/ui', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../components/ui')>()),
  DrawerShell: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

const { CertDrawer } = await import('./drawers');
const { trustAnchorName } = await import('./cert-trust');

const root_ca = {
  id: 'ca-root', common_name: 'Example Root CA', subject_dn: 'CN=Example Root CA', issuer_dn: 'CN=Example Root CA',
  is_ca_certificate: true, is_self_signed: true, certificate_state: 'active', fingerprint_sha256: 'ff', data_completeness: 'full',
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};
const leaf = {
  id: 'leaf-1', common_name: 'app.example.test', subject_dn: 'CN=app.example.test', issuer_dn: 'CN=Example Root CA',
  is_ca_certificate: false, is_self_signed: false, certificate_state: 'active', fingerprint_sha256: 'aa', data_completeness: 'full',
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};

const ok = (data: unknown, status = 200) => ({ data, error: undefined, response: { ok: true, status } });
const fail = (status: number, error: unknown) => ({ data: undefined, error, response: { ok: false, status } });

function serve(cert: Record<string, unknown>, opts: { chain?: unknown[]; anchors?: unknown[] } = {}) {
  api.GET.mockImplementation(async (path: string) => {
    if (path === '/certificates/{id}') return ok({ certificate: cert });
    if (path === '/certificates/{id}/chain') return ok({ chain: opts.chain ?? [cert], chain_length: 1, is_complete: true });
    if (path === '/trust-anchors') return ok({ anchors: opts.anchors ?? [], total: (opts.anchors ?? []).length });
    return ok({});
  });
}

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  granted.clear();
  for (const f of Object.values(api)) f.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(certId: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><CertDrawer certId={certId} onClose={() => {}} /></QueryClientProvider>);
  });
}

const text = () => document.body.textContent ?? '';
const chip = () => document.body.querySelector('[data-testid="cert-trust-chip"]')?.textContent;
const buttons = (label: string) => [...document.body.querySelectorAll('button')].filter((b) => b.textContent?.trim() === label);
async function click(label: string) {
  const [b] = buttons(label);
  expect(b, `no "${label}" button`).toBeTruthy();
  await act(async () => { b.click(); });
}

describe('chip', () => {
  it('shows the trust status in the header and explains it in Trust & revocation', async () => {
    serve({ ...leaf, trust_status: 'untrusted', trust_anchor_certificate_id: 'ca-root' }, { chain: [leaf, root_ca] });
    await render('leaf-1');
    await vi.waitFor(() => expect(chip()).toBe('Untrusted CA'));
    expect(text()).toContain('nobody in your organisation has trusted');
    // The anchor is named from the chain already loaded, not shown as an id.
    expect(text()).toContain('Chain ends at');
    expect(text()).toContain('Example Root CA');
  });

  it('an unevaluated certificate reads "Not yet evaluated", never trusted', async () => {
    serve({ ...leaf });
    await render('leaf-1');
    await vi.waitFor(() => expect(chip()).toBe('Not yet evaluated'));
  });

  it('names the anchor from the chain, and falls back to its id', () => {
    const chain = [leaf, root_ca] as never[];
    expect(trustAnchorName({ id: 'leaf-1', trust_anchor_certificate_id: 'ca-root' }, chain)).toBe('Example Root CA');
    expect(trustAnchorName({ id: 'leaf-1', trust_anchor_certificate_id: 'ca-gone' }, chain)).toBe('ca-gone');
    expect(trustAnchorName({ id: 'ca-root', trust_anchor_certificate_id: 'ca-root' }, chain)).toBe('this certificate');
    expect(trustAnchorName({ id: 'leaf-1' }, chain)).toBeNull();
  });
});

describe('Trust this CA', () => {
  it('appears on a CA certificate for someone with certificates.trust', async () => {
    granted.add('certificates.trust');
    serve({ ...root_ca, trust_status: 'untrusted' });
    await render('ca-root');
    await vi.waitFor(() => expect(buttons('Trust this CA')).toHaveLength(1));
    expect(buttons('Distrust this CA')).toHaveLength(1);
    expect(buttons('Remove decision')).toHaveLength(0);
  });

  it('does not appear on a leaf certificate, even with the permission', async () => {
    granted.add('certificates.trust');
    serve({ ...leaf, trust_status: 'untrusted' });
    await render('leaf-1');
    await vi.waitFor(() => expect(chip()).toBe('Untrusted CA'));
    expect(buttons('Trust this CA')).toHaveLength(0);
    expect(api.GET.mock.calls.some(([p]) => p === '/trust-anchors')).toBe(false);
  });

  it('does not appear on a CA certificate without the permission', async () => {
    serve({ ...root_ca, trust_status: 'untrusted' });
    await render('ca-root');
    await vi.waitFor(() => expect(chip()).toBe('Untrusted CA'));
    expect(buttons('Trust this CA')).toHaveLength(0);
    expect(buttons('Distrust this CA')).toHaveLength(0);
  });

  it('confirms in words, POSTs the certificate id, then refetches so the chip can flip', async () => {
    granted.add('certificates.trust');
    serve({ ...root_ca, trust_status: 'untrusted' });
    api.POST.mockResolvedValue(ok({ id: 'anchor-1', certificate_id: 'ca-root', decision: 'trusted' }, 201));
    await render('ca-root');
    await vi.waitFor(() => expect(buttons('Trust this CA')).toHaveLength(1));
    await click('Trust this CA');
    expect(text()).toContain('Trusting Example Root CA marks every certificate that chains to it as trusted by your organisation.');

    const detailCalls = () => api.GET.mock.calls.filter(([p]) => p === '/certificates/{id}').length;
    const before = detailCalls();
    serve({ ...root_ca, trust_status: 'private_trusted' }, { anchors: [{ id: 'anchor-1', certificate_id: 'ca-root', decision: 'trusted' }] });
    // Two "Trust this CA" buttons now: the drawer's and the dialog's primary.
    const confirm = [...document.body.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent === 'Trust this CA')!;
    await act(async () => { (confirm as HTMLButtonElement).click(); });

    expect(api.POST).toHaveBeenCalledWith('/trust-anchors', { body: { certificate_id: 'ca-root', decision: 'trusted', note: undefined } });
    await vi.waitFor(() => expect(detailCalls()).toBeGreaterThan(before));
    await vi.waitFor(() => expect(chip()).toBe('Trusted (your CA)'));
  });

  it('with an existing trust decision offers Distrust (PUT) and Remove, not Trust', async () => {
    granted.add('certificates.trust');
    serve({ ...root_ca, trust_status: 'private_trusted' }, { anchors: [{ id: 'anchor-1', certificate_id: 'ca-root', decision: 'trusted', note: 'n' }] });
    api.PUT.mockResolvedValue(ok({ id: 'anchor-1', certificate_id: 'ca-root', decision: 'distrusted' }));
    await render('ca-root');
    await vi.waitFor(() => expect(buttons('Remove decision')).toHaveLength(1));
    expect(buttons('Trust this CA')).toHaveLength(0);
    await click('Distrust this CA');
    expect(text()).toContain('Distrusting Example Root CA marks every certificate that chains to it as distrusted');
    const confirm = [...document.body.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent === 'Distrust this CA')!;
    await act(async () => { (confirm as HTMLButtonElement).click(); });
    expect(api.PUT).toHaveBeenCalledWith('/trust-anchors/{id}', { params: { path: { id: 'anchor-1' } }, body: { decision: 'distrusted', note: 'n' } });
  });

  it('a 403 is said in words inside the dialog', async () => {
    granted.add('certificates.trust');
    serve({ ...root_ca, trust_status: 'untrusted' });
    api.POST.mockResolvedValue(fail(403, { error: 'forbidden' }));
    await render('ca-root');
    await vi.waitFor(() => expect(buttons('Trust this CA')).toHaveLength(1));
    await click('Trust this CA');
    const confirm = [...document.body.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent === 'Trust this CA')!;
    await act(async () => { (confirm as HTMLButtonElement).click(); });
    await vi.waitFor(() => expect(text()).toContain("You don't have permission to change trust"));
  });
});
