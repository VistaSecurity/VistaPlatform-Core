// @vitest-environment jsdom
//
// <ObjectContacts> and <ObjectImages> (BUILD_PLAN row 2.8) in all five states —
// default, empty, loading, error, success — over a faked inventory client and
// the REAL permission gate, their wiring onto the asset page, and Settings →
// Contacts.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));

// The init argument of the n-th POST: `mocks.post` is untyped, so name its shape once.
interface PostInit { body?: unknown; bodySerializer?: () => FormData }
const postInit = (n: number): PostInit => (mocks.post.mock.calls[n] as [string, PostInit])[1];
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: vi.fn(), PATCH: mocks.patch, DELETE: mocks.del }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ObjectContacts } from './object-contacts';
import { ObjectImages } from './object-images';
import { AssetPage } from '../asset-page';
import { ContactsSettingsPage } from '../../settings/pages-contacts';

const ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const ROLE_ONCALL = { id: 'r1', tenant_id: null, name: 'On-call', slug: 'on-call', description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null };
const ROLE_OWN = { ...ROLE_ONCALL, id: 'r2', tenant_id: 't', name: 'Escalation', slug: 'escalation' };
const NOC = { id: 'c1', tenant_id: 't', name: 'NOC', title: null, phone: '+1 555 0100', email: 'noc@example.test', address: null, link: null, group_id: null, external_ids: {}, description: null, comments: null, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null };
const ASSIGNMENT = {
  id: 'a1', tenant_id: 't', object_kind: 'asset', object_id: ID, contact_id: 'c1', role_id: 'r1', priority: 'primary',
  source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null,
  contact: { id: 'c1', name: 'NOC', title: null, phone: '+1 555 0100', email: 'noc@example.test' },
  role: { id: 'r1', name: 'On-call', slug: 'on-call' },
};
const IMAGE = { id: 'i1', tenant_id: 't', object_kind: 'asset', object_id: ID, storage_ref: 'local:x/y.png', name: 'R12 front.png', width: 400, height: 300, size_bytes: 1234, description: null, source_kind: 'declared', source_ref: null, custom_fields: {}, created_at: NOW, updated_at: NOW, created_by: null };

const page = <T,>(rows: T[]) => ({ data: { data: rows, pagination: { total: rows.length, limit: 200, offset: 0, next_offset: null } } });

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

function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}
const field = (label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement & HTMLSelectElement;
function button(label: string): HTMLButtonElement {
  const b = [...host.querySelectorAll('button')].find((x) => x.textContent?.includes(label) || x.getAttribute('aria-label')?.includes(label));
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}
const click = async (el: HTMLElement) => { await act(async () => { el.click(); }); };

describe('<ObjectContacts>', () => {
  it('default: one row per assignment with contact, role and priority', async () => {
    answer({ '/dcim/objects/{kind}/{id}/contacts': () => page([ASSIGNMENT]) });
    await mount(<ObjectContacts kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('contact-row')).toHaveLength(1));
    expect(text()).toContain('NOC');
    expect(text()).toContain('noc@example.test');
    expect(byTest('contact-role')[0].textContent).toBe('On-call');
    expect(byTest('contact-priority')[0].textContent).toBe('primary');
    expect(mocks.get).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/contacts', { params: { path: { kind: 'asset', id: ID }, query: { limit: 200 } } });
    // Read-only: no assign, no remove.
    expect(byTest('assign-contact')).toHaveLength(0);
    expect(host.querySelector('[aria-label="Remove NOC"]')).toBeNull();
  });

  it('empty: says nobody is assigned', async () => {
    answer({ '/dcim/objects/{kind}/{id}/contacts': () => page([]) });
    await mount(<ObjectContacts kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No contacts assigned'));
    expect(byTest('substrate-empty')).toHaveLength(1);
  });

  it('loading: a skeleton while the request is in flight', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ObjectContacts kind="asset" id={ID} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: the server reason and a working retry', async () => {
    mocks.get.mockResolvedValueOnce({ error: { error: { message: 'No such object for this organisation.' } } });
    await mount(<ObjectContacts kind="site" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('substrate-error')).toHaveLength(1));
    expect(text()).toContain('No such object for this organisation.');
    mocks.get.mockResolvedValue(page([ASSIGNMENT]));
    await click(button('Retry'));
    await vi.waitFor(() => expect(byTest('contact-row')).toHaveLength(1));
  });

  it('success: assign an existing contact in a role, then the list refreshes', async () => {
    let assigned = false;
    answer({
      '/dcim/objects/{kind}/{id}/contacts': () => page(assigned ? [ASSIGNMENT] : []),
      '/dcim/contacts': () => page([NOC]),
      '/dcim/contact-roles': () => page([ROLE_ONCALL, ROLE_OWN]),
    });
    mocks.post.mockImplementation(async () => { assigned = true; return { data: { data: ASSIGNMENT } }; });
    await mount(<ObjectContacts kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('assign-contact')).toHaveLength(1));
    await click(byTest('assign-contact')[0] as HTMLElement);
    await vi.waitFor(() => expect(field('Contact')).not.toBeNull());
    expect((byTest('assign-save')[0] as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { setValue(field('Contact'), 'c1'); setValue(field('Role'), 'r1'); setValue(field('Priority'), 'primary'); });
    await click(byTest('assign-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(byTest('contact-row')).toHaveLength(1));
    expect(mocks.post).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/contacts', {
      params: { path: { kind: 'asset', id: ID } }, body: { contact_id: 'c1', role_id: 'r1', priority: 'primary' },
    });
  });

  it('success: a new contact is created inline, then assigned', async () => {
    answer({
      '/dcim/objects/{kind}/{id}/contacts': () => page([]),
      '/dcim/contacts': () => page([]),
      '/dcim/contact-roles': () => page([ROLE_ONCALL]),
    });
    mocks.post.mockImplementation(async (path: string) => (path === '/dcim/contacts' ? { data: { data: NOC } } : { data: { data: ASSIGNMENT } }));
    await mount(<ObjectContacts kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('assign-contact')).toHaveLength(1));
    await click(byTest('assign-contact')[0] as HTMLElement);
    await vi.waitFor(() => expect(field('Contact')).not.toBeNull());
    await act(async () => { setValue(field('Contact'), '__new__'); });
    await act(async () => { setValue(field('New contact name'), 'NOC'); setValue(field('New contact email'), 'noc@example.test'); setValue(field('Role'), 'r1'); });
    await click(byTest('assign-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(2));
    expect(mocks.post.mock.calls[0]).toEqual(['/dcim/contacts', { body: { name: 'NOC', email: 'noc@example.test' } }]);
    expect(postInit(1).body).toEqual({ contact_id: 'c1', role_id: 'r1' });
  });

  it('a refused assignment shows the server reason in the form', async () => {
    answer({
      '/dcim/objects/{kind}/{id}/contacts': () => page([]),
      '/dcim/contacts': () => page([NOC]),
      '/dcim/contact-roles': () => page([ROLE_ONCALL]),
    });
    mocks.post.mockResolvedValue({ error: { error: { message: 'an object with the same identity already exists' } } });
    await mount(<ObjectContacts kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('assign-contact')).toHaveLength(1));
    await click(byTest('assign-contact')[0] as HTMLElement);
    await vi.waitFor(() => expect(field('Contact')).not.toBeNull());
    await act(async () => { setValue(field('Contact'), 'c1'); setValue(field('Role'), 'r1'); });
    await click(byTest('assign-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(byTest('assign-error')).toHaveLength(1));
    expect(text()).toContain('same identity already exists');
  });

  it('remove deletes the assignment', async () => {
    answer({ '/dcim/objects/{kind}/{id}/contacts': () => page([ASSIGNMENT]) });
    mocks.del.mockResolvedValue({});
    await mount(<ObjectContacts kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('contact-row')).toHaveLength(1));
    await click(button('Remove NOC'));
    await vi.waitFor(() => expect(mocks.del).toHaveBeenCalledWith('/dcim/contact-assignments/{id}', { params: { path: { id: 'a1' } } }));
  });
});

describe('<ObjectImages>', () => {
  const file = (name: string, type: string, size = 10) => {
    const f = new File(['x'], name, { type });
    Object.defineProperty(f, 'size', { value: size });
    return f;
  };
  const choose = async (f: File) => {
    const input = byTest('image-file')[0] as HTMLInputElement;
    Object.defineProperty(input, 'files', { value: [f], configurable: true });
    await act(async () => { input.dispatchEvent(new Event('change', { bubbles: true })); });
  };

  it('default: a card per image loading from the download route', async () => {
    answer({ '/dcim/objects/{kind}/{id}/images': () => page([IMAGE]) });
    await mount(<ObjectImages kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('image-card')).toHaveLength(1));
    const img = host.querySelector('img') as HTMLImageElement;
    expect(img.getAttribute('src')).toBe('/api/v2/inventory-service/dcim/images/i1/download');
    expect(img.alt).toBe('R12 front.png');
    expect(byTest('upload-image')).toHaveLength(0);
  });

  it('empty', async () => {
    answer({ '/dcim/objects/{kind}/{id}/images': () => page([]) });
    await mount(<ObjectImages kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No images'));
  });

  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ObjectImages kind="asset" id={ID} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: reason and retry', async () => {
    mocks.get.mockResolvedValueOnce({ error: { error: { message: 'boom' } } });
    await mount(<ObjectImages kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(text()).toContain('boom'));
    mocks.get.mockResolvedValue(page([IMAGE]));
    await click(button('Retry'));
    await vi.waitFor(() => expect(byTest('image-card')).toHaveLength(1));
  });

  it('success: uploads a multipart file (with the device-type slot) and refreshes', async () => {
    let n = 0;
    answer({ '/dcim/objects/{kind}/{id}/images': () => page(n ? [IMAGE] : []) });
    mocks.post.mockImplementation(async () => { n = 1; return { data: { data: IMAGE } }; });
    await mount(<ObjectImages kind="device_type" id={ID} slot="front" />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('Upload front image'));
    await choose(file('f.png', 'image/png'));
    await vi.waitFor(() => expect(byTest('image-card')).toHaveLength(1));
    expect((mocks.post.mock.calls[0] as [string])[0]).toBe('/dcim/objects/{kind}/{id}/images');
    const fd = postInit(0).bodySerializer!();
    expect(fd.get('slot')).toBe('front');
    expect((fd.get('file') as File).name).toBe('f.png');
  });

  it('a file over 5 MB is refused before any request is sent', async () => {
    answer({ '/dcim/objects/{kind}/{id}/images': () => page([]) });
    await mount(<ObjectImages kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('upload-image')).toHaveLength(1));
    await choose(file('big.png', 'image/png', 6 * 1024 * 1024));
    await vi.waitFor(() => expect(byTest('image-error')).toHaveLength(1));
    expect(text()).toContain('larger than 5 MB');
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('a server refusal is shown', async () => {
    answer({ '/dcim/objects/{kind}/{id}/images': () => page([]) });
    mocks.post.mockResolvedValue({ error: { error: { message: 'only png, jpeg, webp and svg images are accepted' } } });
    await mount(<ObjectImages kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('upload-image')).toHaveLength(1));
    await choose(file('tool.exe', 'application/octet-stream'));
    await vi.waitFor(() => expect(byTest('image-error')).toHaveLength(1));
    expect(text()).toContain('only png, jpeg, webp and svg');
  });

  it('delete removes the image', async () => {
    answer({ '/dcim/objects/{kind}/{id}/images': () => page([IMAGE]) });
    mocks.del.mockResolvedValue({});
    await mount(<ObjectImages kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('image-card')).toHaveLength(1));
    await click(button('Delete R12 front.png'));
    await vi.waitFor(() => expect(mocks.del).toHaveBeenCalledWith('/dcim/images/{id}', { params: { path: { id: 'i1' } } }));
  });
});

describe('asset page wiring', () => {
  const ASSET = { id: ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

  it('the Overview carries the Contacts and Images panels for kind=asset', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/objects/{kind}/{id}/contacts': () => page([ASSIGNMENT]),
      '/dcim/objects/{kind}/{id}/images': () => page([IMAGE]),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }),
    });
    await mount(null, READ, `/inventory/assets/${ID}`);
    await vi.waitFor(() => expect(byTest('object-contacts')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('object-images')).toHaveLength(1));
    await vi.waitFor(() => expect(byTest('contact-row')).toHaveLength(1));
    const call = mocks.get.mock.calls.find(([p]) => p === '/dcim/objects/{kind}/{id}/contacts') as [string, { params: { path: Record<string, string> } }];
    expect(call[1].params.path).toEqual({ kind: 'asset', id: ID });
  });

  it('without dcim.read neither panel is mounted or fetched', async () => {
    answer({ '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }) });
    await mount(null, ['assets.read'], `/inventory/assets/${ID}`);
    await vi.waitFor(() => expect(text()).toContain('sw-1.example.test'));
    expect(byTest('object-contacts')).toHaveLength(0);
    expect(byTest('object-images')).toHaveLength(0);
    expect(mocks.get.mock.calls.some(([p]) => String(p).startsWith('/dcim/'))).toBe(false);
  });
});

describe('Settings → Contacts', () => {
  const META = { key: 'contacts', label: 'Contacts', icon: 'users', built: true, job: 'job', section: 'Infrastructure' };

  it('default: contacts table, with the built-in roles read-only on the Roles tab', async () => {
    answer({ '/dcim/contacts': () => page([NOC]), '/dcim/contact-roles': () => page([ROLE_ONCALL, ROLE_OWN]) });
    await mount(<ContactsSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('noc@example.test'));
    expect(byTest('add-contact')).toHaveLength(1);
    await click(byTest('tab-roles')[0] as HTMLElement);
    await vi.waitFor(() => expect(text()).toContain('Escalation'));
    expect(text()).toContain('Built in');
    expect(host.querySelector('[aria-label="Edit On-call"]')).toBeNull();
    expect(host.querySelector('[aria-label="Edit Escalation"]')).not.toBeNull();
  });

  it('read-only users get no write controls', async () => {
    answer({ '/dcim/contacts': () => page([NOC]) });
    await mount(<ContactsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('noc@example.test'));
    expect(byTest('add-contact')).toHaveLength(0);
    expect(host.querySelector('[aria-label="Edit NOC"]')).toBeNull();
  });

  it('empty, loading and error', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ContactsSettingsPage meta={META} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
    act(() => root.unmount());
    root = createRoot(host);
    answer({ '/dcim/contacts': () => page([]) });
    await mount(<ContactsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No contacts yet'));
    act(() => root.unmount());
    root = createRoot(host);
    mocks.get.mockResolvedValue({ error: { error: { message: 'down' } } });
    await mount(<ContactsSettingsPage meta={META} />, READ);
    await vi.waitFor(() => expect(text()).toContain('down'));
  });

  it('creates a contact and shows the server refusal in the dialog', async () => {
    answer({ '/dcim/contacts': () => page([]) });
    mocks.post.mockResolvedValueOnce({ error: { error: { message: 'email "x" is not an address' } } });
    await mount(<ContactsSettingsPage meta={META} />, MANAGE);
    await vi.waitFor(() => expect(byTest('add-contact')).toHaveLength(1));
    await click(byTest('add-contact')[0] as HTMLElement);
    await vi.waitFor(() => expect(field('Name')).not.toBeNull());
    expect((byTest('contact-save')[0] as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { setValue(field('Name'), 'NOC'); setValue(field('Email'), 'x'); });
    await click(byTest('contact-save')[0] as HTMLElement);
    await vi.waitFor(() => expect(byTest('contact-form-error')).toHaveLength(1));
    expect(postInit(0).body).toMatchObject({ name: 'NOC', email: 'x', title: null, group_id: null });
  });
});
