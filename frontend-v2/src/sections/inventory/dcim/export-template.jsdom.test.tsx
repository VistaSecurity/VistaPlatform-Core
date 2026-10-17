// @vitest-environment jsdom
//
// Settings → Export Templates and the Export button's template menu (BUILD_PLAN
// row 5.5) in all five states over a faked inventory client and the REAL
// permission gate, and their registration (settings nav, page route, menu).
//
// Mutations: drop the nav entry / the settings-page case / the TemplateMenu
// render in export-button.tsx -> the matching test goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));
interface PostInit { body?: unknown }
const postInit = (n: number): PostInit => (mocks.post.mock.calls[n] as [string, PostInit])[1];
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ExportButton } from './export-button';
import { SETTINGS_NAV } from '../../settings/nav';
import { SettingsPage } from '../../settings/settings-page';
import { ExportTemplatesSettingsPage } from '../../settings/pages-export-templates';

const NOW = new Date().toISOString();
const TPL = {
  id: 'et1', tenant_id: 't', name: 'Hosts file', object_kinds: ['prefix'], template: '{{range .Rows}}{{.name}}\n{{end}}',
  mime_type: 'text/plain', file_extension: 'hosts', description: null, comments: null, source_kind: 'declared', source_ref: null,
  custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
};
const KINDS = [{ kind: 'prefix', label: 'Prefix', plural: 'Prefixes', permission: 'ipam.manage', read_permission: 'ipam.read', columns: [], preview: false },
  { kind: 'vlan', label: 'VLAN', plural: 'VLANs', permission: 'ipam.manage', read_permission: 'ipam.read', columns: [], preview: false }];
const page = <T,>(rows: T[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 1000, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() });
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

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
              <Route path="/settings/:page" element={<SettingsPage />} />
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
const click = async (el: Element) => { await act(async () => { (el as HTMLElement).click(); }); };

describe('registration', () => {
  it('Settings lists Export Templates, behind dcim.read', () => {
    const item = SETTINGS_NAV.flatMap((s) => s.items).find((i) => i.key === 'export-templates');
    expect(item?.built).toBe(true);
    expect(item?.permission).toBe('dcim.read');
  });
  it('the settings router serves /settings/export-templates with the page', async () => {
    answer({ '/dcim/export-templates': () => page([TPL]) });
    await mount(null, READ, '/settings/export-templates');
    await vi.waitFor(() => expect(byTest('export-templates-settings')).toHaveLength(1));
    await vi.waitFor(() => expect(text()).toContain('Hosts file'));
  });
});

describe('Settings → Export Templates', () => {
  const META = { key: 'export-templates', label: 'Export Templates', icon: 'file-code', built: true, job: 'job', section: 'Infrastructure' };

  it('default: a row per template with its kinds and file type; writers get the controls', async () => {
    answer({ '/dcim/export-templates': () => page([TPL]) });
    await mount(<ExportTemplatesSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('Hosts file'));
    expect(text()).toContain('prefix');
    expect(text()).toContain('.hosts');
    expect(byTest('add-export-template')).toHaveLength(1);
    expect(host.querySelector('[aria-label="Edit Hosts file"]')).not.toBeNull();
  });

  it('read-only users get no write controls', async () => {
    answer({ '/dcim/export-templates': () => page([TPL]) });
    await mount(<ExportTemplatesSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('Hosts file'));
    expect(byTest('add-export-template')).toHaveLength(0);
    expect(host.querySelector('[aria-label="Edit Hosts file"]')).toBeNull();
  });

  it('loading, empty and error', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ExportTemplatesSettingsPage meta={META} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    act(() => root.unmount()); root = createRoot(host); mocks.get.mockReset();
    answer({ '/dcim/export-templates': () => page([]) });
    await mount(<ExportTemplatesSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No export templates yet'));
    act(() => root.unmount()); root = createRoot(host); mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'down' } } });
    await mount(<ExportTemplatesSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('down'));
  });

  it('creates with the kinds and file settings, and previews on five rows', async () => {
    answer({ '/dcim/export-templates': () => page([]), '/dcim/import/kinds': () => ({ data: { data: KINDS } }) });
    mocks.post.mockImplementation(async (path: string) => (path === '/dcim/export/preview'
      ? { data: { data: { output: 'a\nb\n', rows: 2 } } } : { data: { data: TPL } }));
    await mount(<ExportTemplatesSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(byTest('add-export-template')).toHaveLength(1));
    await click(byTest('add-export-template')[0]);
    await vi.waitFor(() => expect(host.querySelector('[aria-label="Kind: Prefixes"]')).not.toBeNull());
    expect((byTest('export-template-save')[0] as HTMLButtonElement).disabled).toBe(true);
    expect((byTest('export-template-preview')[0] as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { setValue(field('Name'), 'Hosts file'); setValue(field('File extension'), '.hosts'); });
    await click(host.querySelector('[aria-label="Kind: Prefixes"]')!);
    await click(byTest('export-template-preview')[0]);
    await vi.waitFor(() => expect(byTest('export-template-preview-output')).toHaveLength(1));
    expect(byTest('export-template-preview-output')[0].textContent).toBe('a\nb\n');
    expect(postInit(0).body).toEqual({ kind: 'prefix', template: '{{range .Rows}}{{.name}}\n{{end}}' });
    await click(byTest('export-template-save')[0]);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(2));
    expect(postInit(1).body).toMatchObject({ name: 'Hosts file', object_kinds: ['prefix'], file_extension: 'hosts', mime_type: 'text/plain' });
  });

  it('shows the server refusal of a template that leaves the sandbox, and a failed preview', async () => {
    answer({ '/dcim/export-templates': () => page([]), '/dcim/import/kinds': () => ({ data: { data: KINDS } }) });
    mocks.post.mockResolvedValue({ error: { error: { message: 'template: function "exec" not defined' } } });
    await mount(<ExportTemplatesSettingsPage meta={META} />, MANAGE);
    await click(byTest('add-export-template')[0]);
    await vi.waitFor(() => expect(host.querySelector('[aria-label="Kind: Prefixes"]')).not.toBeNull());
    await act(async () => { setValue(field('Name'), 'Bad'); setValue(field('Template'), '{{exec "id"}}'); });
    await click(host.querySelector('[aria-label="Kind: Prefixes"]')!);
    await click(byTest('export-template-preview')[0]);
    await vi.waitFor(() => expect(byTest('export-template-preview-error')).toHaveLength(1));
    expect(byTest('export-template-preview-error')[0].textContent).toContain('exec');
    await click(byTest('export-template-save')[0]);
    await vi.waitFor(() => expect(byTest('export-template-form-error')).toHaveLength(1));
  });
});

describe('<ExportButton> template menu', () => {
  const open = async () => {
    await click(byTest('export-with-template-prefix')[0]);
  };

  it('lists the templates for its kind and downloads through the one picked', async () => {
    answer({ '/dcim/export-templates': () => page([TPL]), '/dcim/export': () => ({ data: new Blob(['x']), response: { ok: true } }) });
    await mount(<ExportButton kind="prefix" filters={{ vrf_id: 'v1' }} />, READ);
    expect(byTest('export-templates-prefix')).toHaveLength(0);
    await open();
    await vi.waitFor(() => expect(byTest('export-template-et1')).toHaveLength(1));
    expect(mocks.get).toHaveBeenCalledWith('/dcim/export-templates', { params: { query: { limit: 1000, object_kind: 'prefix' } } });
    await click(byTest('export-template-et1')[0]);
    await vi.waitFor(() => expect(URL.createObjectURL).toHaveBeenCalled());
    const call = mocks.get.mock.calls.find((c) => c[0] === '/dcim/export') as [string, { params: { query: Record<string, unknown> } }];
    expect(call[1].params.query).toMatchObject({ kind: 'prefix', format: 'template', template_id: 'et1', vrf_id: 'v1' });
  });

  it('empty, loading and error states of the menu', async () => {
    answer({ '/dcim/export-templates': () => page([]) });
    await mount(<ExportButton kind="prefix" />, READ);
    await open();
    await vi.waitFor(() => expect(byTest('export-templates-prefix-empty')).toHaveLength(1));
    act(() => root.unmount()); root = createRoot(host); mocks.get.mockReset();
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ExportButton kind="prefix" />, READ);
    await open();
    expect(byTest('export-templates-prefix-loading')).toHaveLength(1);
    act(() => root.unmount()); root = createRoot(host); mocks.get.mockReset();
    mocks.get.mockResolvedValue({ error: { error: { message: 'no' } } });
    await mount(<ExportButton kind="prefix" />, READ);
    await open();
    await vi.waitFor(() => expect(byTest('export-templates-prefix-error')).toHaveLength(1));
  });
});
