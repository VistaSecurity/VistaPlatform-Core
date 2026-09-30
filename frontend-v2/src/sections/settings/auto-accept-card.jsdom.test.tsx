// @vitest-environment jsdom
//
// Settings → Identification rules → the rule-merge switch ( Phase 4, owner
// decision D1): "Merge records the rules are sure are one device".
//
// The WIRING test, in the shape of network-segment-modal-dhcp.jsdom.test.tsx:
// the state table in the spec names a state per row, and this drives the real
// card and the real hooks over a mocked client to see each one.
//
// MUTATIONS (recorded in the PR):
//   - send `auto_accept_threshold` along with the toggle: the "only" assertion
//     fails, because an unsaved threshold draft would be written by an unrelated
//     switch;
//   - send `!enabled` inverted (or omit a falsy value): the PUT-body tests fail;
//   - render a default when the read has not answered: the skeleton test fails;
//   - drop the toast: the "Saved" test fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
const gate = vi.hoisted(() => ({ allowed: true }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('react-hot-toast', () => ({ default: toast }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  // The gate is exercised for real elsewhere; here it is a switch the test flips,
  // so the read-only branch can be seen.
  PermissionGate: ({ children, fallback }: { children: React.ReactNode; fallback?: React.ReactNode }) =>
    gate.allowed ? children : (fallback ?? null),
  TENANT_PERMISSIONS: { settings: { update: 'settings.update' }, assets: { update: 'assets.update' } },
}));

const { AutoAcceptCard, RULE_MERGE_LABEL, RULE_MERGE_READ_ERROR } = await import('./auto-accept-card');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const settings = (over: Record<string, unknown> = {}) => ({
  identification: { auto_accept_threshold: 0.9, auto_merge_existing: true, matcher_model_id: 'matcher-logreg-v1', ...over },
});
const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });

// The "server": what GET returns is what the last PUT stored, as it would be.
let stored: Record<string, unknown>;

let host: HTMLDivElement; let root: Root; let qc: QueryClient;
beforeEach(() => {
  gate.allowed = true;
  toast.success.mockReset(); toast.error.mockReset();
  stored = {};
  api.GET.mockReset().mockImplementation(async () => ok(settings(stored)));
  api.PUT.mockReset().mockImplementation(async (_path: string, init: { body: Record<string, unknown> }) => {
    stored = { ...stored, ...init.body };
    return ok(settings(stored));
  });
  qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); qc.clear(); });

async function render() {
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><AutoAcceptCard /></QueryClientProvider>);
  });
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}
const toggle = () => host.querySelector<HTMLButtonElement>('[data-testid="rule-merge-toggle"]');
const putBody = (call = 0) => (api.PUT.mock.calls[call][1] as { body: Record<string, unknown> }).body;
async function click(el: Element | null) {
  await act(async () => { (el as HTMLElement).click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
}

it('shows the effective value: ON when the server says so (an absent setting reads ON there)', async () => {
  await render();
  expect(toggle()!.getAttribute('aria-checked')).toBe('true');
  expect(toggle()!.getAttribute('aria-label')).toBe(RULE_MERGE_LABEL);
  expect(host.textContent).toContain('Merge records the rules are sure are one device');
});

it('shows OFF when the tenant turned it off', async () => {
  stored = { auto_merge_existing: false };
  await render();
  expect(toggle()!.getAttribute('aria-checked')).toBe('false');
});

it('turning it off PUTs auto_merge_existing: false — and ONLY that field', async () => {
  await render();
  await click(toggle());
  expect(api.PUT).toHaveBeenCalledTimes(1);
  expect(api.PUT.mock.calls[0][0]).toBe('/settings/identification');
  // Exactly one key. The threshold is 0.9 on screen and must not ride along: it
  // is a permission of a different kind, and a draft of it must never be saved
  // by an unrelated switch.
  expect(putBody()).toEqual({ auto_merge_existing: false });
});

it('turning it back on PUTs true — falsy-vs-absent is not confused in either direction', async () => {
  stored = { auto_merge_existing: false };
  await render();
  await click(toggle());
  expect(putBody()).toEqual({ auto_merge_existing: true });
});

it('does not send the toggle when the THRESHOLD is saved', async () => {
  await render();
  // Move the threshold to 95% and save it.
  await click(host.querySelector('[data-testid="threshold-95"]'));
  await click(host.querySelector('[data-testid="save-threshold"]'));
  expect(api.PUT).toHaveBeenCalledTimes(1);
  expect(putBody()).toEqual({ auto_accept_threshold: 0.95 });
});

it('toasts "Saved" and shows the value the server now holds', async () => {
  await render();
  await click(toggle());
  expect(toast.success).toHaveBeenCalledWith('Saved');
  expect(toggle()!.getAttribute('aria-checked')).toBe('false');
});

it('is disabled while saving, so a double click cannot send two writes', async () => {
  let release!: (v: unknown) => void;
  api.PUT.mockReturnValue(new Promise((r) => { release = r; }));
  await render();
  await act(async () => { toggle()!.click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  expect(toggle()!.disabled).toBe(true);
  await click(toggle());
  expect(api.PUT).toHaveBeenCalledTimes(1);
  await act(async () => { release(ok(settings({ auto_merge_existing: false }))); });
});

it('shows a skeleton beside the threshold while the read is in flight — never a default', async () => {
  api.GET.mockReturnValue(new Promise(() => {}));
  await render();
  expect(host.querySelector('[data-testid="rule-merge-skeleton"]')).not.toBeNull();
  expect(toggle(), 'a switch rendered before the server answered would show a value nobody chose').toBeNull();
});

it('says exactly what the spec says when the read fails, and offers no switch', async () => {
  api.GET.mockResolvedValue({ data: undefined, error: { error: 'boom' }, response: { ok: false, status: 500 } });
  await render();
  const err = host.querySelector('[data-testid="rule-merge-error"]');
  expect(err?.textContent).toBe(
    'Could not read this setting. Nothing has changed — rule merges keep running with the last saved value.',
  );
  expect(RULE_MERGE_READ_ERROR).toBe(err?.textContent);
  expect(toggle()).toBeNull();
});

it('a failed save toasts the error and leaves the switch where the server has it', async () => {
  api.PUT.mockResolvedValue({ data: undefined, error: { error: 'Failed to save the identification settings' }, response: { ok: false, status: 500 } });
  await render();
  await click(toggle());
  expect(toast.error).toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toggle()!.getAttribute('aria-checked')).toBe('true');
});

it('explains what "sure" means, in plain words, and where the merges are listed', async () => {
  await render();
  const text = host.querySelector('[data-testid="rule-merge"]')!.textContent;
  expect(text).not.toBeNull();
  expect(text).toContain('same MAC address or serial number');
  expect(text).toContain('seen directly');
  expect(text).toContain('an address alone never counts');
  // The survivor, stated accurately: typed values always win; a pending record
  // you entered yields the survivor slot to an already-approved one.
  expect(text).toContain('Values you typed always win');
  expect(text).toContain('unless it is still waiting for');
  expect(text).toContain('same network segment');
  expect(text).toContain('nothing contradicts');
  expect(text).toContain('“keep separate”');
  expect(text).toContain('never overridden');
  expect(text).toContain('Discovery → Approvals → Merged automatically');
  expect(text).toContain('Vista Platform');
  // Shown whether the switch is on or off: someone deciding to turn it OFF needs it most.
  stored = { auto_merge_existing: false };
  qc.clear();
  await render();
  expect(host.querySelector('[data-testid="rule-merge"]')!.textContent).toContain('same network segment');
});

it('renders read-only, with the current value, for a role without both permissions', async () => {
  gate.allowed = false;
  await render();
  expect(toggle()).toBeNull();
  expect(host.querySelector('[data-testid="rule-merge-readonly"]')!.textContent).toContain('On');
});
