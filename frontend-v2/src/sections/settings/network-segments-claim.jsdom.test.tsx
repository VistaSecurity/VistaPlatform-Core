// @vitest-environment jsdom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NetworkSegmentsPage } from './pages-infra';

// "Claim as mine" on a learned public range: the WIRING of the page to
// the claim endpoints, every state of the confirmation, and the permission
// gate. The helpers are pinned by segment-provenance.test.ts; this fails if the
// row stops offering the action, the dialog stops saying what a claim means,
// or the button calls the wrong endpoint.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
const gate = vi.hoisted(() => ({ granted: true, asked: [] as string[] }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { settings: { update: 'settings.update' } },
  PermissionGate: ({ permission, children, fallback }: { permission: string; children: ReactNode; fallback?: ReactNode }) => {
    gate.asked.push(permission);
    return gate.granted ? children : (fallback ?? null);
  },
}));

const base = {
  tenant_id: 't', segment_type: 'cidr', environment: 'production', location_id: null, is_active: true,
  auto_approve_discoveries: false, tags: null, created_at: '2026-09-24T00:00:00Z', updated_at: '2026-09-24T00:00:00Z',
};
const learned = { source: 'interrogation', source_device_type: 'fortinet', source_asset_id: 'a1', dhcp: 'unknown' };
const unclaimed = { ...base, id: 'dmz', name: 'dmz', value: '93.184.216.0/28', network_type: 'public', metadata: { ...learned } };
const claimed = {
  ...base, id: 'web', name: 'web', value: '93.184.216.16/28', network_type: 'public',
  metadata: { ...learned, claimed: { by: 'u1', by_name: 'Ada Admin', at: '2026-10-01T12:00:00Z' } },
};
const segments = [
  unclaimed,
  claimed,
  { ...base, id: 'lan', name: 'lan', value: '10.20.30.0/24', network_type: 'private', metadata: { ...learned } },
  { ...base, id: 'ours', name: 'Our estate', value: '93.184.217.0/24', network_type: 'public', metadata: {} },
];

let host: HTMLDivElement; let root: Root; let cache: QueryClient;
beforeEach(() => {
  gate.granted = true; gate.asked = [];
  api.GET.mockReset().mockResolvedValue({ data: { network_segments: segments }, response: { ok: true } });
  api.POST.mockReset().mockResolvedValue({ data: claimed, response: { ok: true } });
  api.DELETE.mockReset().mockResolvedValue({ data: unclaimed, response: { ok: true } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); document.body.innerHTML = ''; });

async function flush() { await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); }); }
async function render() {
  const meta = { key: 'network-segments', label: 'Network Segments', icon: 'network', job: 'Segments' };
  await act(async () => { root.render(<QueryClientProvider client={cache}><NetworkSegmentsPage meta={meta} /></QueryClientProvider>); });
  await flush();
}

// The name cell of one row (its outermost column span).
function row(name: string): HTMLElement {
  const label = [...host.querySelectorAll('span')].find((s) => s.textContent === name);
  expect(label, `no row named ${name}`).toBeTruthy();
  return label!.parentElement!;
}
function button(scope: ParentNode, text: string): HTMLButtonElement | undefined {
  return [...scope.querySelectorAll('button')].find((b) => b.textContent === text) as HTMLButtonElement | undefined;
}
async function click(el: HTMLElement) { await act(async () => { el.click(); }); await flush(); }

it('offers "Claim as mine" only on a learned public range, and shows who claimed one', async () => {
  await render();
  expect(button(row('dmz'), 'Claim as mine')).toBeTruthy();
  expect(row('dmz').textContent).toContain('not treated as yours');
  expect(row('web').querySelector('[data-testid="segment-claim-chip"]')?.textContent).toMatch(/^Claimed by Ada Admin · .*2026$/);
  expect(button(row('web'), 'Revoke claim')).toBeTruthy();
  expect(button(row('web'), 'Claim as mine')).toBeUndefined();
  // Learned private and declared public: nothing to claim, no claim UI.
  for (const name of ['lan', 'Our estate']) {
    expect(button(row(name), 'Claim as mine'), name).toBeUndefined();
    expect(row(name).textContent, name).not.toContain('Claim');
  }
});

it('hides the claim actions without settings.update, but still shows the claim', async () => {
  gate.granted = false;
  await render();
  expect(gate.asked).toContain('settings.update');
  expect(button(row('dmz'), 'Claim as mine')).toBeUndefined();
  expect(button(row('web'), 'Revoke claim')).toBeUndefined();
  expect(row('web').textContent).toContain('Claimed by Ada Admin');
});

it('confirms in plain words, then claims the range and refreshes the list', async () => {
  await render();
  await click(button(row('dmz'), 'Claim as mine')!);
  expect(api.POST).not.toHaveBeenCalled(); // the click opens the confirmation; it does not claim
  const dialog = document.body;
  expect(dialog.textContent).toContain('Claim 93.184.216.0/28 as yours?');
  expect(dialog.textContent).toContain('learned this public range from Fortinet');
  const consequences = dialog.querySelector('[data-testid="claim-consequences"]')?.textContent ?? '';
  expect(consequences).toContain('You are stating that this range belongs to your organization');
  expect(consequences).toContain('scan it when someone in your organization asks');
  expect(consequences).toContain('Sensors will treat it as yours');
  expect(consequences).toContain("Do not claim a range you don't control");
  expect(consequences).toContain('does not verify the claim');

  const gets = api.GET.mock.calls.length;
  const confirm = [...dialog.querySelectorAll('button')].filter((b) => b.textContent === 'Claim as mine').pop()!;
  await click(confirm);
  expect(api.POST).toHaveBeenCalledWith('/network-segments/{id}/claim', { params: { path: { id: 'dmz' } } });
  expect(api.GET.mock.calls.length).toBeGreaterThan(gets);
  expect(document.body.textContent).not.toContain('as yours?');
});

it('shows the loading state while the claim is saving', async () => {
  let release!: (v: unknown) => void;
  api.POST.mockReturnValueOnce(new Promise((resolve) => { release = resolve; }));
  await render();
  await click(button(row('dmz'), 'Claim as mine')!);
  await click([...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Claim as mine').pop()!);
  const pending = button(document.body, 'Claiming…');
  expect(pending?.disabled).toBe(true);
  expect(button(document.body, 'Cancel')?.disabled).toBe(true);
  await act(async () => { release({ data: claimed, response: { ok: true } }); });
  await flush();
  expect(button(document.body, 'Claiming…')).toBeUndefined();
});

it('keeps the dialog open and says why when the server refuses', async () => {
  api.POST.mockResolvedValueOnce({
    error: { error: 'segment cannot be claimed: a private segment already counts as yours' },
    response: { ok: false, status: 409 },
  });
  await render();
  await click(button(row('dmz'), 'Claim as mine')!);
  await click([...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Claim as mine').pop()!);
  expect(document.body.querySelector('[role="alert"]')?.textContent).toContain('already counts as yours');
  expect(document.body.textContent).toContain('Claim 93.184.216.0/28 as yours?');
});

it('revokes a claim after confirming', async () => {
  await render();
  await click(button(row('web'), 'Revoke claim')!);
  expect(document.body.textContent).toContain('Revoke your claim on 93.184.216.16/28?');
  expect(api.DELETE).not.toHaveBeenCalled();
  await click([...document.body.querySelectorAll('button')].filter((b) => b.textContent === 'Revoke claim').pop()!);
  expect(api.DELETE).toHaveBeenCalledWith('/network-segments/{id}/claim', { params: { path: { id: 'web' } } });
  expect(api.POST).not.toHaveBeenCalled();
});
