// @vitest-environment jsdom
// Inventory change notifications (DCIM gap 5) in the routing-rule editor:
// "Inventory changes" is offered as a source; choosing it swaps the severity
// filter for the object-kind / action pickers and the two include toggles, and
// the rule is saved as alert_source inventory-service + alert_type
// object_changed with a change_filter. Five states: default, empty, loading,
// error, success — plus the edit round trip.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi, type Mock } from 'vitest';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';
import { RuleModal } from './notification-modals';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const notifications = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }));
const compliance = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { notifications, compliance } }));

type Channel = NC['schemas']['TenantNotificationChannel'];
type Rule = NC['schemas']['TenantNotificationRule'];

const channel: Channel = {
  id: 'c-1', tenant_id: 't-1', channel_name: 'Ops webhook', channel_type: 'webhook', config: {},
  enabled: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
};

let host: HTMLDivElement; let root: Root; let cache: QueryClient; let onClose: Mock<() => void>;
beforeEach(() => {
  notifications.POST.mockReset().mockResolvedValue({ response: { ok: true, status: 201 } });
  notifications.PUT.mockReset().mockResolvedValue({ response: { ok: true, status: 200 } });
  compliance.GET.mockReset().mockResolvedValue({ data: { catalog: [{ source: 'inventory-service' }, { source: 'sensor-manager' }] }, response: { ok: true } });
  onClose = vi.fn<() => void>();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function render(rule: Rule | null = null) {
  await act(async () => {
    root.render(<QueryClientProvider client={cache}><RuleModal rule={rule} channels={[channel]} open onClose={onClose} /></QueryClientProvider>);
  });
}
const buttons = () => [...document.querySelectorAll('button')];
const button = (label: string) => buttons().find((b) => b.textContent === label)!;
const sourceSelect = () => [...document.querySelectorAll('select')][0];
const filterFields = () => document.querySelector('[data-testid="change-filter-fields"]');
const text = () => document.body.textContent ?? '';

async function setInput(el: HTMLInputElement | HTMLSelectElement, value: string) {
  await act(async () => {
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
  });
}
const click = async (el: Element) => act(async () => { (el as HTMLElement).click(); });

/** TanStack Query notifies observers on a timer, so a mutation's pending /
 *  error / success render can land after the click's act() returns. */
async function waitFor(check: () => boolean, what: string) {
  for (let i = 0; i < 50; i++) {
    if (check()) return;
    await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function fillNewInventoryRule() {
  await render();
  await setInput(document.querySelector('input[data-autofocus]') as HTMLInputElement, 'Cable changes');
  await setInput(sourceSelect(), 'inventory-changes');
  await click(button('Ops webhook'));
}

it('default: offers Inventory changes as a source; the change pickers appear only for it', async () => {
  await render();
  const options = [...sourceSelect().options].map((o) => o.textContent);
  expect(options).toContain('Inventory changes');
  expect(filterFields()).toBeNull();
  expect(text()).toContain('Severity filter');

  await setInput(sourceSelect(), 'inventory-changes');
  expect(filterFields()).not.toBeNull();
  expect(text()).not.toContain('Severity filter');
  expect(text()).toContain('Include changes made by discovery');
  expect(text()).toContain('Include changes made by a sync connection');

  await setInput(sourceSelect(), 'sensor-manager');
  expect(filterFields()).toBeNull();
});

it('empty: no kind or action chosen reads as "all", and a kind search that matches nothing says so', async () => {
  await fillNewInventoryRule();
  expect(text()).toContain('None selected — changes to every kind of object are delivered.');
  expect(text()).toContain('None selected — creates, updates and deletes are all delivered.');
  await setInput(document.querySelector('input[aria-label="Filter object kinds"]') as HTMLInputElement, 'zzzz');
  expect(text()).toContain('No object kind matches');
});

it('loading: the save button is disabled and says Saving… while the request is in flight', async () => {
  let resolve!: (v: unknown) => void;
  notifications.POST.mockReturnValue(new Promise((r) => { resolve = r; }));
  await fillNewInventoryRule();
  await click(button('Add rule'));
  await waitFor(() => !!button('Saving…'), 'the pending state');
  expect(button('Saving…').disabled).toBe(true);
  await act(async () => { resolve({ response: { ok: true, status: 201 } }); });
});

it('error: a refused save shows the server reason and keeps the modal open', async () => {
  notifications.POST.mockResolvedValue({ error: { error: 'change_filter.object_kinds: unknown object kind "cables"' }, response: { ok: false, status: 400 } });
  await fillNewInventoryRule();
  await click(button('Add rule'));
  await waitFor(() => text().includes('unknown object kind'), 'the error message');
  expect(text()).toContain('unknown object kind');
  expect(onClose).not.toHaveBeenCalled();
});

it('success: saves alert_source inventory-service + alert_type object_changed with the chosen filter', async () => {
  await fillNewInventoryRule();
  await setInput(document.querySelector('input[aria-label="Filter object kinds"]') as HTMLInputElement, 'cable');
  await click(button('Cable'));
  await click(button('Deleted'));
  const [intake] = [...document.querySelectorAll<HTMLInputElement>('[data-testid="change-filter-fields"] input[type="checkbox"]')];
  await click(intake);
  expect(text()).toContain('1 selected: Cable');

  await click(button('Add rule'));
  await waitFor(() => onClose.mock.calls.length > 0, 'the modal to close');
  expect(notifications.POST).toHaveBeenCalledTimes(1);
  const body = (notifications.POST.mock.calls[0] as [string, { body: Record<string, unknown> }])[1].body;
  expect(body.alert_source).toBe('inventory-service');
  expect(body.alert_type).toBe('object_changed');
  expect(body.change_filter).toEqual({ object_kinds: ['cable'], actions: ['delete'], include_intake: true, include_sync: false });
  expect(body.severity_filter).toBeUndefined();
  expect(onClose).toHaveBeenCalled();
});

it('edit: an Inventory-changes rule opens with its filter and saves changes to it', async () => {
  await render({
    id: 'r-1', tenant_id: 't-1', rule_name: 'Prefix changes', alert_source: 'inventory-service', alert_type: 'object_changed',
    channel_ids: ['c-1'], frequency: 'immediate', enabled: true, priority: 0,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    change_filter: { object_kinds: ['prefix'], include_intake: false, include_sync: true },
  });
  expect(sourceSelect().value).toBe('inventory-changes');
  expect(sourceSelect().disabled).toBe(true);
  expect(text()).toContain('1 selected: Prefix');
  await click(button('Updated'));
  await click(button('Save changes'));
  await waitFor(() => notifications.PUT.mock.calls.length > 0, 'the PUT');
  const body = (notifications.PUT.mock.calls[0] as [string, { body: Record<string, unknown> }])[1].body;
  expect(body.alert_type).toBe('object_changed');
  expect(body.change_filter).toEqual({ object_kinds: ['prefix'], actions: ['update'], include_intake: false, include_sync: true });
});
