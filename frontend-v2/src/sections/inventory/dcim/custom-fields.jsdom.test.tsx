// @vitest-environment jsdom
//
// Custom fields (DCIM BUILD_PLAN row 5.1): <CustomFieldsPanel> in all five
// states — default, empty, loading, error, success — over a faked inventory
// client and the REAL permission gate; its wiring onto the asset page; and
// Settings → Custom Fields, reachable from the settings nav.
//
// Mutations: delete the <CustomFieldsPanel kind="asset"> mount from
// asset-page.tsx → "the asset Overview carries the panel" goes red; delete the
// `custom-fields` entry from settings/nav.ts or its case in settings-page.tsx
// → "Settings → Custom Fields is registered" goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), del: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: mocks.put, PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { CustomFieldsPanel } from './custom-fields-panel';
import { AssetPage } from '../asset-page';
import { CustomFieldsSettingsPage } from '../../settings/pages-custom-fields';
import { SETTINGS_NAV, settingsPageMeta } from '../../settings/nav';

const ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const base = {
  tenant_id: 't', required: false, default: null, choice_set_id: null, related_object_kind: null,
  validation_minimum: null, validation_maximum: null, validation_regex: null, ui_visible: 'always', ui_editable: 'yes',
  weight: 100, group_name: null, is_cloneable: false, description: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const OWNER = { ...base, id: 'f1', name: 'owner_team', label: 'Owner team', type: 'text', object_kinds: ['asset', 'prefix'], required: true };
const TIER = { ...base, id: 'f2', name: 'tier', label: 'Tier', type: 'select', object_kinds: ['asset'], choice_set_id: 's1' };
const HIDDEN = { ...base, id: 'f3', name: 'secret_note', label: 'Hidden', type: 'text', object_kinds: ['asset'], ui_visible: 'hidden' };
const TIERS = { id: 's1', tenant_id: 't', name: 'Tiers', description: null, choices: [['gold', 'Gold'], ['silver', 'Silver']], order_alphabetically: false, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null };

const page = <T,>(rows: T[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

function answer(routes: Record<string, () => unknown>) {
  mocks.get.mockImplementation(async (path: string) => {
    const fn = routes[path];
    return fn ? fn() : { data: { data: [] } };
  });
}

async function mount(ui: React.ReactNode, permissions: string[], path = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/" element={ui} />
              <Route path="/inventory/assets/:id/:tab?" element={<AssetPage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}

const text = () => host.textContent ?? '';
const byTest = (id: string) => host.querySelectorAll(`[data-testid="${id}"]`);
const field = (label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement & HTMLSelectElement;
function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}
const click = async (el: Element) => { await act(async () => { (el as HTMLElement).click(); }); };
const MANAGE = ['dcim.read', 'assets.update'];

describe('<CustomFieldsPanel>', () => {
  const defs = () => {
    answer({ '/dcim/custom-fields': () => page([OWNER, TIER, HIDDEN]), '/dcim/custom-field-choice-sets': () => page([TIERS]) });
  };

  it('default: each visible field with its value, choices by label, hidden fields left out', async () => {
    defs();
    await mount(<CustomFieldsPanel kind="asset" id={ID} values={{ owner_team: 'Payments', tier: 'gold', secret_note: 'x' }} permission="assets.update" onChange={vi.fn()} />, ['dcim.read']);
    await vi.waitFor(() => expect(byTest('custom-field-owner_team')).toHaveLength(1));
    expect(byTest('custom-field-owner_team')[0].textContent).toContain('Payments');
    await vi.waitFor(() => expect(byTest('custom-field-tier')[0].textContent).toContain('Gold'));
    expect(byTest('custom-field-secret_note')).toHaveLength(0);
    expect(mocks.get).toHaveBeenCalledWith('/dcim/custom-fields', { params: { query: { limit: 1000, object_kind: 'asset' } } });
    // Without the kind's manage permission there is no editor.
    expect(byTest('custom-fields-edit')).toHaveLength(0);
  });

  it('empty: says no field applies and where they are defined', async () => {
    answer({ '/dcim/custom-fields': () => page([]) });
    await mount(<CustomFieldsPanel kind="prefix" id={ID} values={{}} permission="ipam.manage" onChange={vi.fn()} />, ['dcim.read']);
    await vi.waitFor(() => expect(byTest('custom-fields-empty')).toHaveLength(1));
    expect(text()).toContain('Settings → Custom Fields');
  });

  it('loading: a skeleton while the definitions load', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<CustomFieldsPanel kind="asset" id={ID} values={{}} permission="assets.update" onChange={vi.fn()} />, ['dcim.read']);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: the server reason and a working retry', async () => {
    mocks.get.mockResolvedValue({ error: { error: { message: 'You do not have dcim.read.' } } });
    await mount(<CustomFieldsPanel kind="asset" id={ID} values={{}} permission="assets.update" onChange={vi.fn()} />, ['dcim.read']);
    await vi.waitFor(() => expect(byTest('substrate-error')).toHaveLength(1));
    expect(text()).toContain('You do not have dcim.read.');
    defs();
    await click([...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Retry'))!);
    await vi.waitFor(() => expect(byTest('custom-field-owner_team')).toHaveLength(1));
  });

  it('success: an edit sends only the changed fields and says it saved', async () => {
    defs();
    const onChange = vi.fn().mockResolvedValue(undefined);
    await mount(<CustomFieldsPanel kind="asset" id={ID} values={{ owner_team: 'Payments' }} permission="assets.update" onChange={onChange} />, MANAGE);
    await vi.waitFor(() => expect(byTest('custom-fields-edit')).toHaveLength(1));
    await click(byTest('custom-fields-edit')[0]);
    await vi.waitFor(() => expect(field('Tier')).not.toBeNull());
    await act(async () => { setValue(field('Tier'), 'silver'); });
    await click(byTest('custom-fields-save')[0]);
    await vi.waitFor(() => expect(onChange).toHaveBeenCalledWith({ tier: 'silver' }));
    await vi.waitFor(() => expect(byTest('custom-fields-saved')).toHaveLength(1));
  });

  it('a refused save shows the server reason and keeps the editor open', async () => {
    defs();
    const onChange = vi.fn().mockRejectedValue(new Error('custom field "owner_team" is required'));
    await mount(<CustomFieldsPanel kind="asset" id={ID} values={{ owner_team: 'Payments' }} permission="assets.update" onChange={onChange} />, MANAGE);
    await vi.waitFor(() => expect(byTest('custom-fields-edit')).toHaveLength(1));
    await click(byTest('custom-fields-edit')[0]);
    await act(async () => { setValue(field('Owner team'), ''); });
    await click(byTest('custom-fields-save')[0]);
    await vi.waitFor(() => expect(byTest('custom-fields-error')).toHaveLength(1));
    expect(text()).toContain('is required');
    expect(onChange).toHaveBeenCalledWith({ owner_team: null });
    expect(byTest('custom-fields-save')).toHaveLength(1);
  });
});

describe('asset page wiring', () => {
  const ASSET = { id: ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null, custom_fields: { owner_team: 'Payments' } };

  it('the asset Overview carries the panel for kind=asset, and a save PUTs the asset', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/custom-fields': () => page([OWNER, TIER]),
      '/dcim/custom-field-choice-sets': () => page([TIERS]),
    });
    mocks.put.mockResolvedValue({ data: { asset: ASSET }, response: { ok: true } });
    await mount(null, MANAGE, `/inventory/assets/${ID}`);
    await vi.waitFor(() => expect(byTest('custom-fields-panel')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('custom-field-owner_team')[0]?.textContent).toContain('Payments'));
    const call = mocks.get.mock.calls.find(([p]) => p === '/dcim/custom-fields') as [string, { params: { query: Record<string, unknown> } }];
    expect(call[1].params.query.object_kind).toBe('asset');
    await click(byTest('custom-fields-edit')[0]);
    await act(async () => { setValue(field('Tier'), 'gold'); });
    await click(byTest('custom-fields-save')[0]);
    await vi.waitFor(() => expect(mocks.put).toHaveBeenCalledWith('/infrastructure-assets/{id}', { params: { path: { id: ID } }, body: { custom_fields: { tier: 'gold' } } }));
  });
});

describe('Settings → Custom Fields', () => {
  const META = { key: 'custom-fields', label: 'Custom Fields', icon: 'list-checks', built: true, job: 'job', section: 'Infrastructure' };

  it('is registered in the settings nav behind dcim.read and routed by the settings page', () => {
    const item = SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'custom-fields');
    expect(item?.built).toBe(true);
    expect(item?.permission).toBe('dcim.read');
    expect(settingsPageMeta('custom-fields').label).toBe('Custom Fields');
    const routing = readFileSync(resolve(__dirname, '../../settings/settings-page.tsx'), 'utf8');
    expect(routing).toMatch(/case 'custom-fields': return <CustomFieldsSettingsPage/);
  });

  it('default: the definitions table, read-only without custom_fields.manage', async () => {
    answer({ '/dcim/custom-fields': () => page([OWNER, TIER]), '/dcim/custom-field-choice-sets': () => page([TIERS]) });
    await mount(<CustomFieldsSettingsPage meta={META} />, ['dcim.read']);
    await vi.waitFor(() => expect(text()).toContain('cf.owner_team'));
    expect(text()).toContain('Required');
    expect(text()).toContain('Tiers');
    expect(byTest('add-custom-field')).toHaveLength(0);
  });

  it('empty, then a create posts the definition', async () => {
    answer({ '/dcim/custom-fields': () => page([]), '/dcim/custom-field-choice-sets': () => page([]) });
    mocks.post.mockResolvedValue({ data: { data: OWNER } });
    await mount(<CustomFieldsSettingsPage meta={META} />, ['dcim.read', 'custom_fields.manage']);
    await vi.waitFor(() => expect(text()).toContain('No custom fields yet'));
    await click(byTest('add-custom-field')[0]);
    await act(async () => { setValue(field('Name'), 'owner_team'); });
    const prefix = [...host.querySelectorAll('[data-testid="custom-field-kinds"] label')].find((l) => l.textContent === 'Prefix')!;
    await click(prefix.querySelector('input')!);
    await click(byTest('custom-field-save')[0]);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalled());
    const [path, init] = mocks.post.mock.calls[0] as [string, { body: Record<string, unknown> }];
    expect(path).toBe('/dcim/custom-fields');
    expect(init.body).toMatchObject({ name: 'owner_team', type: 'text', object_kinds: ['prefix'], required: false });
  });

  it('loading and error states', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<CustomFieldsSettingsPage meta={META} />, ['dcim.read']);
    expect(byTest('substrate-loading').length).toBeGreaterThan(0);
    mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'boom' } } });
    act(() => root.unmount());
    root = createRoot(host);
    await mount(<CustomFieldsSettingsPage meta={META} />, ['dcim.read']);
    await vi.waitFor(() => expect(byTest('substrate-error').length).toBeGreaterThan(0));
    expect(text()).toContain('boom');
  });

  it('the Choice sets tab creates a set from value|Label lines', async () => {
    answer({ '/dcim/custom-fields': () => page([]), '/dcim/custom-field-choice-sets': () => page([]) });
    mocks.post.mockResolvedValue({ data: { data: TIERS } });
    await mount(<CustomFieldsSettingsPage meta={META} />, ['dcim.read', 'custom_fields.manage']);
    await click(byTest('tab-sets')[0]);
    await vi.waitFor(() => expect(byTest('add-choice-set')).toHaveLength(1));
    await click(byTest('add-choice-set')[0]);
    await act(async () => { setValue(field('Name'), 'Tiers'); });
    const ta = field('Choices') as unknown as HTMLTextAreaElement;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(ta, 'gold|Gold\nsilver');
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await click(byTest('choice-set-save')[0]);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledWith('/dcim/custom-field-choice-sets', { body: { name: 'Tiers', choices: [['gold', 'Gold'], ['silver', 'silver']], order_alphabetically: false, description: null } }));
  });
});
