// @vitest-environment jsdom
//
// The Config Context tab and Settings → Config Contexts (BUILD_PLAN row 5.3) in
// all five states over a faked inventory client and the REAL permission gate,
// and their registration (asset tab, settings nav, page route).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));

// The init argument of the n-th POST: `mocks.post` is untyped, so name its shape once.
interface PostInit { body?: unknown }
const postInit = (n: number): PostInit => (mocks.post.mock.calls[n] as [string, PostInit])[1];
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ConfigContextTab } from './config-context-tab';
import { AssetPage } from '../asset-page';
import { ASSET_TABS } from '../asset-tabs';
import { SETTINGS_NAV } from '../../settings/nav';
import { WorkspacePage } from '../../settings/settings-page';
import { ConfigContextsSettingsPage, parseContextData } from '../../settings/pages-config-contexts';

const ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const CTX = {
  id: 'cc1', tenant_id: 't', name: 'Corporate NTP', weight: 500, is_active: true, data: { ntp: '10.0.0.1' },
  regions: [], site_groups: [], sites: [], locations: [], device_types: [], device_roles: ['r1'], platforms: [], cluster_types: [], cluster_groups: [], clusters: [], business_units: [], tags: [],
  description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const RENDERED = { data: { data: { data: { ntp: '10.0.0.1', dns: { search: 'corp' } }, contributing: [{ id: 'cc0', name: 'Base', weight: 100 }, { id: 'cc1', name: 'Corporate NTP', weight: 500 }] } } };
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
    return fn ? fn() : { data: {} };
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
              <Route path="/inventory/manage/:page" element={<WorkspacePage />} />
            </Routes>
          </MemoryRouter>
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}



const READ = ['dcim.read'];
const MANAGE = ['dcim.read', 'dcim.manage'];
const text = () => host.textContent ?? '';
const byTest = (id: string) => host.querySelectorAll(`[data-testid="${id}"]`);
function setValue(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}
const field = (label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement & HTMLTextAreaElement;
const click = async (el: HTMLElement) => { await act(async () => { el.click(); }); };

describe('<ConfigContextTab>', () => {
  const asset = { id: ID } as never;

  it('success: renders the merged JSON and the contributors in merge order', async () => {
    answer({ '/dcim/assets/{id}/config-context': () => RENDERED });
    await mount(<ConfigContextTab asset={asset} />, READ);
    await vi.waitFor(() => expect(byTest('config-context-json')).toHaveLength(1));
    expect(JSON.parse(byTest('config-context-json')[0].textContent ?? '')).toEqual({ ntp: '10.0.0.1', dns: { search: 'corp' } });
    expect([...host.querySelectorAll('[data-testid="config-context-contributors"] li')].map((l) => l.textContent)).toEqual(['Base · weight 100', 'Corporate NTP · weight 500']);
    expect(mocks.get).toHaveBeenCalledWith('/dcim/assets/{id}/config-context', { params: { path: { id: ID } } });
  });

  it('empty: says no context applies, not that the asset has no config', async () => {
    answer({ '/dcim/assets/{id}/config-context': () => ({ data: { data: { data: {}, contributing: [] } } }) });
    await mount(<ConfigContextTab asset={asset} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No config context applies to this asset'));
    expect(byTest('config-context-json')).toHaveLength(0);
  });

  it('loading, error and the permission fallback', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ConfigContextTab asset={asset} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'render failed' } } });
    await mount(<ConfigContextTab asset={asset} />, READ);
    await vi.waitFor(() => expect(text()).toContain('render failed'));
    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockReset();
    await mount(<ConfigContextTab asset={asset} />, ['assets.read']);
    expect(text()).toContain("You can't view the config context");
    expect(mocks.get).not.toHaveBeenCalled();
  });
});

describe('registration', () => {
  const ASSET = { id: ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

  it('the asset page has a live Config Context tab that mounts the tab component', async () => {
    const tab = ASSET_TABS.find((t) => t.key === 'config-context');
    expect(tab?.label).toBe('Config Context');
    expect(tab?.placeholder).toBeUndefined();
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/assets/{id}/config-context': () => RENDERED,
    });
    await mount(null, READ, `/inventory/assets/${ID}/config-context`);
    await vi.waitFor(() => expect(byTest('config-context-tab')).toHaveLength(1));
  });

  it('the workspace router serves /inventory/manage/config-contexts with the page', async () => {
    answer({ '/dcim/config-contexts': () => page([CTX]) });
    await mount(null, READ, '/inventory/manage/config-contexts');
    await vi.waitFor(() => expect(byTest('config-contexts-settings')).toHaveLength(1));
    await vi.waitFor(() => expect(text()).toContain('Corporate NTP'));
  });

  it('Settings lists Config Contexts, behind dcim.read', () => {
    const item = SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'config-contexts');
    expect(item?.built).toBe(true);
    expect(item?.permission).toBe('dcim.read');
  });
});

describe('Settings → Config Contexts', () => {
  const META = { key: 'config-contexts', label: 'Config Contexts', icon: 'braces', built: true, job: 'job', section: 'Infrastructure' };

  it('default: a row per context with weight, status and what it applies to', async () => {
    answer({ '/dcim/config-contexts': () => page([CTX, { ...CTX, id: 'cc2', name: 'Off', is_active: false, device_roles: [] }]) });
    await mount(<ConfigContextsSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('Corporate NTP'));
    expect(text()).toContain('1 device roles');
    expect(text()).toContain('All assets');
    expect(text()).toContain('Inactive');
    expect(byTest('add-config-context')).toHaveLength(1);
  });

  it('read-only users get no write controls', async () => {
    answer({ '/dcim/config-contexts': () => page([CTX]) });
    await mount(<ConfigContextsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('Corporate NTP'));
    expect(byTest('add-config-context')).toHaveLength(0);
    expect(host.querySelector('[aria-label="Edit Corporate NTP"]')).toBeNull();
  });

  it('empty, loading and error', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ConfigContextsSettingsPage meta={META} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockReset();
    answer({ '/dcim/config-contexts': () => page([]) });
    await mount(<ConfigContextsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No config contexts yet'));
    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'down' } } });
    await mount(<ConfigContextsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('down'));
  });

  it('refuses non-object JSON in the dialog without posting, then creates with the JSON and weight', async () => {
    answer({ '/dcim/config-contexts': () => page([]), '/dcim/device-roles': () => page([]) });
    mocks.post.mockResolvedValueOnce({ data: { data: CTX } });
    await mount(<ConfigContextsSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(byTest('add-config-context')).toHaveLength(1));
    await click(byTest('add-config-context')[0] as HTMLElement);
    await vi.waitFor(() => expect(field('Name')).not.toBeNull());
    expect((byTest('config-context-save')[0] as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { setValue(field('Name'), 'Corporate NTP'); setValue(field('Data'), '[1]'); });
    await click(byTest('config-context-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(byTest('config-context-form-error')).toHaveLength(1));
    expect(mocks.post).not.toHaveBeenCalled();
    await act(async () => { setValue(field('Data'), '{"ntp":"10.0.0.1"}'); setValue(field('Weight'), '500'); });
    await click(byTest('config-context-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
    expect(postInit(0).body).toMatchObject({ name: 'Corporate NTP', weight: 500, is_active: true, data: { ntp: '10.0.0.1' }, device_roles: [], tags: [] });
  });

  it('parseContextData accepts objects only', () => {
    expect(parseContextData('')).toEqual({ ok: true, value: {} });
    expect(parseContextData('{"a":1}').ok).toBe(true);
    expect(parseContextData('[1]').ok).toBe(false);
    expect(parseContextData('null').ok).toBe(false);
    expect(parseContextData('{').ok).toBe(false);
  });
});
