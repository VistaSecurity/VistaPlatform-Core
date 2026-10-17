// @vitest-environment jsdom
//
// The DCIM substrate readers (BUILD_PLAN row 0.3): <ObjectChanges>,
// <ObjectJournal> and <ObjectTags> in all five states — default, empty,
// loading, error, success — over a faked inventory client and the REAL
// permission gate, and their wiring onto the asset page (the Changes tab and
// the header tag editor).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }));
vi.mock('../../../lib/clients', () => ({
  clients: new Proxy({}, {
    get: () => ({ GET: mocks.get, POST: mocks.post, PUT: mocks.put, PATCH: vi.fn(), DELETE: vi.fn() }),
  }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import { ObjectChanges } from './object-changes';
import { ObjectJournal } from './object-journal';
import { ObjectTags } from './object-tags';
import { AssetPage } from '../asset-page';

const ID = '11111111-1111-4111-8111-111111111111';
const NOW = new Date().toISOString();
const USER = '22222222-2222-4222-8222-222222222222';

const CHANGE = {
  id: 'c1', object_kind: 'asset', object_id: ID, action: 'update',
  prechange_data: { tags: [] }, postchange_data: { tags: ['core'] }, changed_fields: ['tags'],
  user_id: USER, user_name: 'op@example.test', request_id: null, source: 'ui', created_at: NOW,
};
const ENTRY = {
  id: 'j1', object_kind: 'asset', object_id: ID, kind: 'warning', comments: 'fan tray replaced',
  created_by: USER, created_by_name: 'Olive Operator', created_at: NOW,
};
const TAG_CORE = { id: 't1', name: 'Core', slug: 'core', color: 'aa1100', description: null, object_kinds: [], created_at: NOW, updated_at: NOW };
const TAG_PCI = { id: 't2', name: 'PCI scope', slug: 'pci-scope', color: null, description: null, object_kinds: ['asset'], created_at: NOW, updated_at: NOW };
const TAG_RACK = { id: 't3', name: 'Rack only', slug: 'rack-only', color: null, description: null, object_kinds: ['rack'], created_at: NOW, updated_at: NOW };

const page = <T,>(rows: T[], total = rows.length) => ({ data: { data: rows, pagination: { total, limit: 25, offset: 0, next_offset: null } } });

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  mocks.get.mockReset();
  mocks.post.mockReset();
  mocks.put.mockReset();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

type Routes = Record<string, () => unknown>;
function answer(routes: Routes) {
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

function setValue(el: HTMLTextAreaElement | HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
    : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true }));
}

function button(label: string): HTMLButtonElement {
  const b = [...host.querySelectorAll('button')].find((x) => x.textContent?.includes(label));
  if (!b) throw new Error(`no button "${label}" in: ${text()}`);
  return b;
}

describe('<ObjectChanges>', () => {
  it('default: one row per change with action, fields, actor, source and time', async () => {
    answer({ '/dcim/changes': () => page([CHANGE, { ...CHANGE, id: 'c2', action: 'create', changed_fields: ['name'], user_id: null, user_name: null, source: 'intake:lldp' }], 7) });
    await mount(<ObjectChanges kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('change-row')).toHaveLength(2));
    expect(text()).toContain('Updated');
    expect(text()).toContain('tags');
    expect(text()).toContain('op@example.test');
    expect(text()).toContain('Web UI');
    expect(text()).toContain('Discovery (lldp)');
    expect(text()).toContain('Showing the latest 2 of 7 changes');
    expect(mocks.get).toHaveBeenCalledWith('/dcim/changes', { params: { query: { object_kind: 'asset', object_id: ID, limit: 25 } } });
  });

  it('empty: says nothing is recorded yet, not that nothing changed', async () => {
    answer({ '/dcim/changes': () => page([]) });
    await mount(<ObjectChanges kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(text()).toContain('No changes recorded yet'));
    expect(byTest('substrate-empty')).toHaveLength(1);
    // Every DCIM writer records changes now (phase 1 moved them); the empty
    // state says so plainly and no longer points at the History tab.
    expect(text()).not.toMatch(/edits made from now on/i);
    expect(text()).toContain('who made them and when');
  });

  it('loading: a skeleton while the request is in flight', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ObjectChanges kind="asset" id={ID} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: the server reason and a retry that refetches', async () => {
    let fail = true;
    answer({ '/dcim/changes': () => (fail ? { error: { error: { code: 'internal_error', message: 'The request could not be completed.' } } } : page([CHANGE])) });
    await mount(<ObjectChanges kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('substrate-error')).toHaveLength(1));
    expect(text()).toContain('The request could not be completed.');
    fail = false;
    await act(async () => { button('Retry').click(); });
    await vi.waitFor(() => expect(byTest('change-row')).toHaveLength(1));
  });

  it('success: a journal entry added on the same object refreshes the change log', async () => {
    let changes: unknown[] = [];
    answer({ '/dcim/changes': () => page(changes), '/dcim/objects/{kind}/{id}/journal': () => page([]) });
    mocks.post.mockImplementation(async () => {
      changes = [{ ...CHANGE, object_kind: 'journal_entry', action: 'create', changed_fields: ['comments'] }];
      return { data: { data: ENTRY } };
    });
    await mount(<><ObjectChanges kind="asset" id={ID} /><ObjectJournal kind="asset" id={ID} /></>, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No changes recorded yet'));
    await act(async () => { setValue(host.querySelector('textarea')!, 'moved'); });
    await act(async () => { button('Add entry').click(); });
    await vi.waitFor(() => expect(byTest('change-row')).toHaveLength(1));
  });
});

describe('<ObjectJournal>', () => {
  it('default: entries with kind, author and text; the add form is for dcim.manage only', async () => {
    answer({ '/dcim/objects/{kind}/{id}/journal': () => page([ENTRY]) });
    await mount(<ObjectJournal kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('journal-row')).toHaveLength(1));
    expect(text()).toContain('Warning');
    expect(text()).toContain('Olive Operator');
    expect(text()).toContain('fan tray replaced');
    expect(host.querySelector('form[aria-label="Add journal entry"]')).toBeNull();
  });

  it('empty: explains what a journal entry is', async () => {
    answer({ '/dcim/objects/{kind}/{id}/journal': () => page([]) });
    await mount(<ObjectJournal kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No journal entries yet'));
    expect(host.querySelector('form[aria-label="Add journal entry"]')).not.toBeNull();
  });

  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ObjectJournal kind="asset" id={ID} />, READ);
    expect(byTest('substrate-loading')).toHaveLength(1);
  });

  it('error: a 404 for an object this organisation cannot see reads as an error, not as empty', async () => {
    answer({ '/dcim/objects/{kind}/{id}/journal': () => ({ error: { error: { code: 'object_not_found', message: 'No such object for this organisation.' } } }) });
    await mount(<ObjectJournal kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('substrate-error')).toHaveLength(1));
    expect(text()).toContain('No such object for this organisation.');
    expect(text()).not.toContain('No journal entries yet');
  });

  it('success: posts kind and trimmed text, clears the form, shows the new entry', async () => {
    let rows: unknown[] = [];
    answer({ '/dcim/objects/{kind}/{id}/journal': () => page(rows) });
    mocks.post.mockImplementation(async () => {
      rows = [{ ...ENTRY, kind: 'danger', comments: 'PSU failed' }];
      return { data: { data: rows[0] } };
    });
    await mount(<ObjectJournal kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('No journal entries yet'));
    const ta = host.querySelector('textarea')!;
    await act(async () => {
      setValue(ta, '  PSU failed  ');
      setValue(host.querySelector('select[aria-label="Entry kind"]')!, 'danger');
    });
    await act(async () => { button('Add entry').click(); });
    expect(mocks.post).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/journal', {
      params: { path: { kind: 'asset', id: ID } },
      body: { kind: 'danger', comments: 'PSU failed' },
    });
    await vi.waitFor(() => expect(text()).toContain('PSU failed'));
    expect(host.querySelector('textarea')!.value).toBe('');
  });
});

describe('<ObjectTags>', () => {
  it('default: chips for the object\'s tags and an editor button for dcim.manage', async () => {
    answer({ '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [TAG_CORE] } }) });
    await mount(<ObjectTags kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(byTest('tag-chip')).toHaveLength(1));
    expect(text()).toContain('Core');
    expect(text()).toContain('Edit tags');
  });

  it('a read-only role sees the chips and no editor', async () => {
    answer({ '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [TAG_CORE] } }) });
    await mount(<ObjectTags kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('tag-chip')).toHaveLength(1));
    expect(text()).not.toContain('Edit tags');
  });

  it('empty', async () => {
    answer({ '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [] } }) });
    await mount(<ObjectTags kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(byTest('tags-empty')).toHaveLength(1));
  });

  it('loading', async () => {
    mocks.get.mockImplementation(() => new Promise(() => {}));
    await mount(<ObjectTags kind="asset" id={ID} />, READ);
    expect(byTest('tags-loading')).toHaveLength(1);
  });

  it('error: says the tags are unavailable rather than "No tags"', async () => {
    answer({ '/dcim/objects/{kind}/{id}/tags': () => ({ error: { error: { code: 'internal_error', message: 'x' } } }) });
    await mount(<ObjectTags kind="asset" id={ID} />, READ);
    await vi.waitFor(() => expect(text()).toContain('Tags unavailable'));
    expect(byTest('tags-empty')).toHaveLength(0);
  });

  it('success: the editor offers only applicable tags and PUTs the new set', async () => {
    answer({
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [TAG_CORE] } }),
      '/dcim/tags': () => ({ data: { data: [TAG_CORE, TAG_PCI, TAG_RACK] } }),
    });
    mocks.put.mockResolvedValue({ data: { data: [TAG_PCI] } });
    await mount(<ObjectTags kind="asset" id={ID} />, MANAGE);
    await vi.waitFor(() => expect(text()).toContain('Edit tags'));
    await act(async () => { button('Edit tags').click(); });
    await vi.waitFor(() => expect(host.querySelectorAll('[role="dialog"] input[type="checkbox"]')).toHaveLength(2));
    expect(host.querySelector('[role="dialog"]')!.textContent).not.toContain('Rack only');
    const [core, pci] = [...host.querySelectorAll<HTMLInputElement>('[role="dialog"] input[type="checkbox"]')];
    expect(core.checked).toBe(true);
    await act(async () => { core.click(); pci.click(); });
    await act(async () => { button('Save tags').click(); });
    expect(mocks.put).toHaveBeenCalledWith('/dcim/objects/{kind}/{id}/tags', {
      params: { path: { kind: 'asset', id: ID } },
      body: { tag_ids: ['t2'] },
    });
    await vi.waitFor(() => expect(host.querySelector('[role="dialog"]')).toBeNull());
    expect(text()).toContain('PCI scope');
    expect(text()).not.toContain('Core');
  });
});

describe('asset page wiring', () => {
  const ASSET = { id: ID, hostname: 'sw-1.example.test', display_name: 'sw-1.example.test', class_key: 'switch', asset_status: 'monitoring', risk_score: 0, deleted_at: null };

  it('the Changes tab is registered and renders the change log and journal for kind=asset', async () => {
    answer({
      '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }),
      '/dcim/changes': () => page([]),
      '/dcim/objects/{kind}/{id}/journal': () => page([]),
      '/dcim/objects/{kind}/{id}/tags': () => ({ data: { data: [TAG_CORE] } }),
    });
    await mount(null, MANAGE, `/inventory/assets/${ID}/changes`);
    await vi.waitFor(() => expect(text()).toContain('No changes recorded yet'));
    expect([...host.querySelectorAll('[role="tab"]')].some((t) => t.textContent === 'Changes' && t.getAttribute('aria-selected') === 'true')).toBe(true);
    expect(text()).toContain('No journal entries yet');
    // The header carries the substrate tag editor.
    await vi.waitFor(() => expect(byTest('tag-chip')).toHaveLength(1));
    const call = mocks.get.mock.calls.find(([p]) => p === '/dcim/changes') as [string, { params: { query: Record<string, unknown> } }] | undefined;
    // 5.2: the asset's tab also lists its interfaces', addresses' and journal changes.
    expect(call?.[1].params.query).toMatchObject({ object_kind: 'asset', object_id: ID, include_related: true });
  });

  it('without dcim.read the tab explains the permission and nothing is fetched', async () => {
    answer({ '/infrastructure-assets/{id}': () => ({ data: { asset: ASSET } }) });
    await mount(null, ['assets.read'], `/inventory/assets/${ID}/changes`);
    await vi.waitFor(() => expect(text()).toContain("You can't view changes"));
    expect(mocks.get.mock.calls.some(([p]) => String(p).startsWith('/dcim/'))).toBe(false);
    expect(byTest('object-tags')).toHaveLength(0);
  });
});
