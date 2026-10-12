// @vitest-environment jsdom
//
// Plans ▸ plan builder, MOUNTED: a labelled dialog that survives a stray scrim
// click once the admin has typed into it.
//
// Mutations run (each red, then restored green): dropping `dirty` from the
// builder's <Dialog>; dropping `canAssign` from the Assign button.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PlanBuilder } from './plan-builder';

const perms = vi.hoisted(() => ({ granted: new Set<string>() }));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => perms.granted.has(p) }) };
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
afterEach(() => { perms.granted.clear(); act(() => root?.unmount()); root = null; host?.remove(); });

function open(onClose: () => void) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  act(() => root!.render(<QueryClientProvider client={qc}><PlanBuilder items={[]} onClose={onClose} /></QueryClientProvider>));
}
const scrim = () => host.querySelector('[data-dialog-scrim]') as HTMLElement;

describe('plan builder dialog', () => {
  it('is a labelled modal dialog with a named close button', () => {
    open(() => {});
    const d = host.querySelector('[role="dialog"]')!;
    expect(d.getAttribute('aria-modal')).toBe('true');
    expect(document.getElementById(d.getAttribute('aria-labelledby')!)?.textContent).toBe('New plan');
    expect(d.querySelector('button[aria-label="Close"]')).not.toBeNull();
  });

  it('closes on a scrim click while untouched', () => {
    const onClose = vi.fn();
    open(onClose);
    act(() => scrim().click());
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps a half-filled plan open on a scrim click and asks first', () => {
    const onClose = vi.fn();
    open(onClose);
    const input = host.querySelector('input[placeholder="Pro"]') as HTMLInputElement;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    act(() => { set.call(input, 'Gold'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    act(() => scrim().click());
    expect(onClose).not.toHaveBeenCalled();
    expect(host.textContent).toContain('Discard changes?');
  });
});

describe('plan builder: Assign to tenant follows the API gate', () => {
  // POST /admin/tiers/{id}/assign needs platform.billing, not platform.settings.
  const tier = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'gold', display_name: 'Gold', price_cents: 1000, billing_interval: 'month', billing_method: 'invoice', is_active: true, is_custom: false, features: {}, limits: {}, addon_pricing: {}, metadata: {} };
  const openEdit = () => {
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    act(() => root!.render(<QueryClientProvider client={qc}><PlanBuilder tier={tier as any} items={[]} onClose={() => {}} /></QueryClientProvider>));
  };
  const assignButton = () => Array.from(host.querySelectorAll('button')).find((b) => /Assign to tenant/.test(b.textContent ?? ''));

  it('is offered with platform.billing', () => {
    perms.granted.add('platform.billing');
    openEdit();
    expect(assignButton()).toBeDefined();
  });
  it('is not offered with platform.settings alone', () => {
    perms.granted.add('platform.settings');
    openEdit();
    expect(assignButton()).toBeUndefined();
  });
});
