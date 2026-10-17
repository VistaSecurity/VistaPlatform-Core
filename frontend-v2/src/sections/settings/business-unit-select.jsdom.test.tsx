// @vitest-environment jsdom
// The asset form's Business unit control: pick one of the tenant's units, none,
// or create a new one by name; and what each choice sends.
import { act, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { BusinessUnitSelect, NO_BUSINESS_UNIT, businessUnitFields, type BusinessUnitChoice } from './business-unit-select';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));

const unit = (id: string, name: string, parent_id: string | null) => ({
  id, tenant_id: 't', name, slug: name.toLowerCase(), parent_id, external_ids: {}, source_kind: 'declared',
  custom_fields: {}, created_at: '', updated_at: '', asset_count: 0,
});

let host: HTMLDivElement; let root: Root; let cache: QueryClient; let latest: BusinessUnitChoice = NO_BUSINESS_UNIT;
function Harness() {
  const [v, setV] = useState<BusinessUnitChoice>(NO_BUSINESS_UNIT);
  // Recorded from the change handler, not during render, so the harness does
  // not reassign a module variable while React is rendering.
  const onChange = (next: BusinessUnitChoice) => { latest = next; setV(next); };
  return <BusinessUnitSelect value={v} onChange={onChange} />;
}
beforeEach(() => {
  api.GET.mockReset().mockResolvedValue({ data: { business_units: [unit('f', 'Finance', 'c'), unit('c', 'Corporate', null)], total: 2 } });
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function mount() {
  await act(async () => { root.render(<QueryClientProvider client={cache}><Harness /></QueryClientProvider>); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}
const select = () => host.querySelector('select[aria-label="Business unit"]') as HTMLSelectElement;
const choose = (v: string) => act(async () => {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!.call(select(), v);
  select().dispatchEvent(new Event('change', { bubbles: true }));
});

it('lists the tree (parent first, child indented), None, and Create new', async () => {
  await mount();
  const labels = [...select().options].map((o) => (o.textContent ?? '').replace(/\u00a0/g, '_'));
  expect(labels).toEqual(['None', 'Corporate', '__Finance', 'Create new…']);
});

it('a chosen unit sends its id; None sends nothing on create and a clear on edit', async () => {
  await mount();
  await choose('f');
  expect(businessUnitFields(latest, false)).toEqual({ business_unit_id: 'f' });
  await choose('');
  expect(businessUnitFields(latest, false)).toEqual({});
  expect(businessUnitFields(latest, true)).toEqual({ business_unit_id: '' });
});

it('Create new reveals a name box and sends the name', async () => {
  await mount();
  await choose('__new__');
  const input = host.querySelector('input[aria-label="New business unit name"]') as HTMLInputElement;
  expect(input).not.toBeNull();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, ' Legal ');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(businessUnitFields(latest, true)).toEqual({ business_unit: 'Legal' });
});
