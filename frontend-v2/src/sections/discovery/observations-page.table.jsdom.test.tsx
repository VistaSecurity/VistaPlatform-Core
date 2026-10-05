// @vitest-environment jsdom
//
// Discovery → Observations as the review table, driven through the
// REAL page, table, bulk bar, dialogs and single-row form. Only the transport
// and the permission source are faked.
//
// The guards that matter, each mutation-tested (see the PR):
//   - bulk Confirm only for an all-ready selection, judged on the CURRENT rows (D4)
//   - names, never ids, for the network and the source
//   - the reason is prefilled — single row and batch (D1)
//   - failed bulk rows stay on screen with their own reason
//   - read-only without assets.update
//   - "Treat this network as stable…" is a link and nothing more (D2)
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Observation } from './observation-review';
import { ObservationsPage } from './observations-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn() }));
const perm = vi.hoisted(() => ({ can: true }));
vi.mock('../../lib/clients', () => ({ clients: { inventory: api } }));
vi.mock('@vistasecurity/primitives/rbac', () => ({
  TENANT_PERMISSIONS: { assets: { update: 'assets.update' } },
  PermissionGate: ({ children }: { children: ReactNode }) => (perm.can ? children : null),
  usePermissions: () => ({ hasPermission: (p: string) => perm.can && p === 'assets.update' }),
}));
vi.mock('../inventory/asset-queries', () => ({ useAssetsQuery: () => ({ data: { assets: [], total: 0, pageSize: 50 }, isPending: false, isError: false }) }));

const SCOPE_ID = '7d1c2b3a-0000-4000-8000-00000000beef';
const SENSOR_ID = '0b9f8e7d-0000-4000-8000-00000000cafe';

function obs(id: string, over: Partial<Observation> = {}): Observation {
  return {
    id, source_kind: 'measured', source_ref: `sensor:${SENSOR_ID}`, collector_version: '4.3.0',
    network_scope: SCOPE_ID, network_name: 'Office LAN', source_name: 'edge-sensor',
    evidence: { endpoints: [{ address: `192.0.2.${id.length}`, port: 22, protocol: 'ssh', transport: 'tcp' }] },
    summary: [{ kind: 'ip_address', label: 'IP address', value: `192.0.2.${id.length}` }],
    admission_reasons: ['dynamic_address_without_device_binding'], state: 'unresolved', asset_id: null, proposal_id: null,
    first_seen_at: '2026-09-28T10:00:00Z', last_seen_at: '2026-10-01T10:00:00Z', occurrence_count: 3,
    enrichment_state: 'completed', enrichment_reason: '', last_attempt_at: null, next_attempt_at: null,
    needs: 'ready_to_confirm', suggested_action: 'confirm', explanation_code: 'dynamic_address_answered',
    suggested_reason: `Confirmed from Observations: SSH 22 seen at host-${id} on Office LAN (edge-sensor).`,
    link_asset: null, evidence_held: false,
    ...over,
  };
}
const sensorRow = (id: string) => obs(id, {
  needs: 'needs_sensor', suggested_action: 'sensor_options', explanation_code: 'relayed_advertisement',
  admission_reasons: ['unverified_relayed_advertisement'],
  suggested_reason: `Dismissed from Observations: A device seen as ${id}.local (edge-sensor) — advertised by another device; nothing here saw the device itself.`,
});

const COUNTS = { ready_to_confirm: 2, link_existing: 0, needs_review: 0, needs_network: 1, needs_sensor: 1, likely_noise: 4, all: 9 };
let page: { rows: Observation[]; counts: typeof COUNTS; total?: number };
let detail: Record<string, Observation | 'error'>;
let listPending: boolean;
let listFails: boolean;

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
function Where() { return <span id="where">{useLocation().search}</span>; }

beforeEach(() => {
  perm.can = true;
  page = { rows: [obs('a1'), obs('b22')], counts: COUNTS };
  detail = {};
  listPending = false;
  listFails = false;
  window.localStorage.clear();
  api.GET.mockReset().mockImplementation(async (path: string, init?: { params?: { path?: { id?: string } } }) => {
    if (path === '/identity/summary') return { response: { ok: true }, data: { established: 0, operator_confirmed: 0, legacy: 0, unresolved: 9, conflicted: 0, provisional: 0, admission_mode: 'enforce' } };
    if (path === '/discovery/observations/{id}') {
      const id = init?.params?.path?.id ?? '';
      const found = detail[id] ?? page.rows.find((r) => r.id === id);
      return found && found !== 'error' ? { response: { ok: true }, data: found } : { response: { ok: false, status: 404 } };
    }
    if (listPending) return new Promise(() => {});
    if (listFails) return { response: { ok: false, status: 500 } };
    return { response: { ok: true }, data: { observations: page.rows, total: page.total ?? page.rows.length, page: 1, page_size: 50, counts: page.counts } };
  });
  api.POST.mockReset();
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); document.body.innerHTML = ''; });

async function flush(n = 3) { for (let i = 0; i < n; i++) await act(async () => { await new Promise((r) => setTimeout(r, 5)); }); }
async function render(entry = '/discovery/observations') {
  await act(async () => {
    root.render(<MemoryRouter initialEntries={[entry]}><QueryClientProvider client={cache}>
      <Routes><Route path="/discovery/observations" element={<><ObservationsPage /><Where /></>} /></Routes>
    </QueryClientProvider></MemoryRouter>);
  });
  await flush();
}
const text = () => document.body.textContent ?? '';
const listCalls = () => api.GET.mock.calls.filter(([p]) => p === '/discovery/observations').map(([, init]) => (init as { params: { query: Record<string, unknown> } }).params.query);
const lastQuery = () => { const calls = listCalls(); return calls[calls.length - 1]; };
function button(label: string | RegExp, scope: ParentNode = document.body) {
  const found = [...scope.querySelectorAll('button')].find((b) => (typeof label === 'string' ? b.textContent?.trim() === label : label.test(b.textContent ?? '')));
  expect(found, `button ${String(label)}`).toBeTruthy();
  return found!;
}
async function click(el: HTMLElement) { await act(async () => { el.click(); }); await flush(); }
const row = (id: string) => host.querySelector<HTMLTableRowElement>(`tr[data-observation="${id}"]`)!;
const checkbox = (id: string) => row(id).querySelector<HTMLInputElement>('input[type="checkbox"]')!;
const bar = () => document.querySelector('[role="region"][aria-label="Bulk actions"]');
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
async function typeInto(el: HTMLTextAreaElement | HTMLInputElement, value: string) {
  await act(async () => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
async function expand(id: string) {
  const toggle = row(id).querySelector<HTMLButtonElement>('button[aria-expanded]')!;
  if (toggle.getAttribute('aria-expanded') === 'false') await click(toggle);
  return document.getElementById(toggle.getAttribute('aria-controls')!)!;
}

describe('chips', () => {
  it('opens on Ready to confirm, with every chip counted from the response', async () => {
    await render();
    expect(lastQuery()).toMatchObject({ state: 'unresolved', needs: ['ready_to_confirm'], page: 1, page_size: 50, sort: 'last_seen_desc' });
    const pressed = [...host.querySelectorAll('button[aria-pressed="true"]')].map((b) => b.textContent);
    expect(pressed).toEqual(['Ready to confirm2']);
    for (const label of ['Needs a network1', 'Needs a sensor1', 'Likely noise4', 'All9']) expect(button(label).getAttribute('aria-pressed')).toBe('false');
  });

  it('asks for the chip’s rows, remembers it, and keeps the state control under All', async () => {
    await render();
    await click(button('Likely noise4'));
    expect(lastQuery()).toMatchObject({ state: 'unresolved', needs: ['likely_noise'] });
    expect(JSON.parse(window.localStorage.getItem('vista.observations.view')!)).toEqual({ chip: 'likely_noise', pageSize: 50 });
    expect(host.querySelector('select[aria-label="Observation state"]')).toBeNull();
    await click(button('All9'));
    expect(lastQuery()).toMatchObject({ state: 'unresolved' });
    expect(lastQuery()).not.toHaveProperty('needs');
    const state = host.querySelector<HTMLSelectElement>('select[aria-label="Observation state"]')!;
    expect([...state.options].map((o) => o.value)).toEqual(['unresolved', 'conflict', 'linked', 'dismissed', 'expired', 'all']);
    await act(async () => { state.value = 'dismissed'; state.dispatchEvent(new Event('change', { bubbles: true })); });
    await flush();
    expect(lastQuery()).toMatchObject({ state: 'dismissed' });
  });

  it('starts from the remembered chip and page size', async () => {
    window.localStorage.setItem('vista.observations.view', JSON.stringify({ chip: 'needs_sensor', pageSize: 25 }));
    await render();
    expect(lastQuery()).toMatchObject({ needs: ['needs_sensor'], page_size: 25 });
  });

  it('clears the selection when the view changes', async () => {
    await render();
    await click(checkbox('a1'));
    expect(bar()?.textContent).toContain('1 selected');
    await click(button('Needs a network1'));
    await click(button('Ready to confirm2'));
    expect(bar()).toBeNull();
    expect(checkbox('a1').checked).toBe(false);
  });

  it('searches and sorts on the server', async () => {
    await render();
    await typeInto(host.querySelector<HTMLInputElement>('input[aria-label="Search observations"]')!, '192.0.2');
    await act(async () => { host.querySelector('form[role="search"]')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
    await flush();
    expect(lastQuery()).toMatchObject({ q: '192.0.2' });
    await click(button('Network'));
    expect(lastQuery()).toMatchObject({ sort: 'network', q: '192.0.2' });
    expect(button('Network').closest('th')?.getAttribute('aria-sort')).toBe('ascending');
    await click(button('Last seen'));
    expect(lastQuery()).toMatchObject({ sort: 'last_seen_desc' });
    await click(button('Last seen'));
    expect(lastQuery()).toMatchObject({ sort: 'last_seen_asc' });
  });
});

describe('rows', () => {
  it('shows host, services, network NAME, source NAME, last seen and the need — never an id', async () => {
    page.rows = [obs('a1'), obs('u9', { network_name: null, needs: 'needs_network', suggested_action: 'add_network', explanation_code: 'network_not_configured' })];
    await render();
    const cells = [...row('a1').children].map((td) => td.textContent?.trim());
    expect(cells.slice(1, 6)).toEqual(['192.0.2.2SSH 22', 'Office LAN', 'edge-sensor', expect.stringMatching(/ago$/), 'Ready to confirm']);
    expect(row('a1').querySelector('time')?.getAttribute('title')).toBe(new Date('2026-10-01T10:00:00Z').toLocaleString());
    expect(row('u9').children[2].textContent).toBe('No configured network');
    // Expanded too: the scope and the source ref are ids, and nowhere on the page.
    await expand('a1'); await expand('u9');
    expect(text()).not.toContain(SCOPE_ID);
    expect(text()).not.toContain(SENSOR_ID);
  });

  it('expands from the keyboard-operable toggle, wired to the panel it controls', async () => {
    await render();
    const toggle = row('a1').querySelector<HTMLButtonElement>('button[aria-expanded]')!;
    expect(toggle.tagName).toBe('BUTTON');
    const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!;
    expect(panel.hidden).toBe(true);
    toggle.focus();
    expect(document.activeElement).toBe(toggle);
    await click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(panel.hidden).toBe(false);
    expect(panel.querySelector('[aria-label="Evidence"]')?.textContent).toContain('IP address192.0.2.2');
    expect(panel.textContent).toContain('3 sightings');
    expect(panel.textContent).toContain('192.0.2.2:22 · SSH 22 · tcp');
    await click(toggle);
    expect(panel.hidden).toBe(true);
  });

  it('shows the details read inline, with a retry when it fails', async () => {
    detail.a1 = 'error';
    await render();
    const panel = await expand('a1');
    expect(panel.textContent).toContain('Couldn’t load details.');
    detail.a1 = obs('a1', { enrichment_jobs: [] });
    await click(button('Retry', panel));
    expect(panel.textContent).toContain('No enrichment attempts are recorded for this observation.');
  });
});

describe('what this needs', () => {
  it('explains a DHCP row and offers "Treat this network as stable…" as a plain link and nothing else (D2)', async () => {
    page.rows = [obs('a1', { summary: [{ kind: 'ssh_host_key_fingerprint', label: 'SSH host key', value: 'SHA256:abcd…wxyz' }] })];
    await render();
    const needs = (await expand('a1')).querySelector<HTMLElement>('[aria-label="What this needs"]')!;
    expect(needs.textContent).toContain('A real device answered at this address, but this network uses DHCP');
    expect(needs.textContent).toContain('Its ssh host key (SHA256:abcd…wxyz) will recognise it next time.');
    const stable = [...needs.querySelectorAll('a')].find((a) => a.textContent === 'Treat this network as stable…')!;
    expect(stable.getAttribute('href')).toBe('/settings/segments');
    expect(needs.textContent).toContain('Future scans can then create and approve assets there directly');
    // No review date, no reminder, no expiry: the owner ruled them out.
    expect(needs.querySelector('input[type="date"], input[type="datetime-local"], input[type="number"]')).toBeNull();
    expect(needs.textContent).not.toMatch(/review date|remind|expir|re-?evaluat/i);
  });

  it('sends a row outside every network to the segment settings', async () => {
    page.rows = [obs('n1', { network_name: null, needs: 'needs_network', suggested_action: 'add_network', explanation_code: 'network_not_configured' })];
    await render();
    const add = [...row('n1').querySelectorAll('a')].find((a) => a.textContent === 'Add network');
    expect(add?.getAttribute('href')).toBe('/settings/segments');
    const needs = (await expand('n1')).querySelector('[aria-label="What this needs"]')!;
    expect(needs.textContent).toContain('This address is not inside any network you have set up.');
    expect(needs.textContent).toContain('that covers 192.0.2.2');
  });

  it('opens a sensor row on its options: a sensor, a link or a dismissal', async () => {
    page.rows = [sensorRow('s1')];
    await render();
    await click(button('See options', row('s1')));
    const needs = document.getElementById(row('s1').querySelector('button[aria-expanded]')!.getAttribute('aria-controls')!)!.querySelector('[aria-label="What this needs"]')!;
    expect(needs.textContent).toContain('Another device advertised this name; nothing here saw the device itself.');
    expect([...needs.querySelectorAll('a')].find((a) => a.textContent === 'Install a sensor on that network')?.getAttribute('href')).toBe('/discovery/sensors');
    expect(button('Link to an asset', needs)).toBeTruthy();
    expect(button('Dismiss', needs)).toBeTruthy();
  });

  it('prefills a single row’s decision with the server’s reason, editable and still required (D1)', async () => {
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 } });
    await render();
    await click(button('Confirm…', row('a1')));
    const field = document.querySelector<HTMLTextAreaElement>('[aria-label="What this needs"] textarea')!;
    expect(field.value).toBe('Confirmed from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor).');
    await typeInto(field, '');
    expect(button('Save decision').disabled).toBe(true);
    await typeInto(field, 'Seen it on the rack');
    await click(button('Save decision'));
    expect(api.POST).toHaveBeenCalledWith('/discovery/observations/{id}/confirm', { params: { path: { id: 'a1' } }, body: { reason: 'Seen it on the rack' } });
  });

  it('turns the proposed reason around when the person dismisses a ready row', async () => {
    await render();
    await click(button('Dismiss…', row('a1')));
    expect(document.querySelector<HTMLTextAreaElement>('[aria-label="What this needs"] textarea')!.value)
      .toBe('Dismissed from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor).');
  });
});

// item 9: a dynamic address an existing asset already owns is not
// "Ready to confirm" (the server refuses Confirm on it). The row offers
// "Link to <asset>" and the bulk bar links instead of confirming.
describe('rows an existing asset already owns (#2205)', () => {
  const ROUTER = '5a1f0c52-0000-4000-8000-0000000000aa';
  const linkRow = (id: string, name = 'dream-router') => obs(id, {
    needs: 'link_existing', suggested_action: 'link', explanation_code: 'owned_by_asset',
    link_asset: { id: ROUTER, name, linkable: true },
    suggested_reason: `Linked from Observations: SSH 22 seen at host-${id} on Office LAN (edge-sensor) — already belongs to ${name}.`,
  });
  const reviewRow = (id: string) => obs(id, { needs: 'needs_review', suggested_action: 'none', explanation_code: 'owned_by_several_assets',
    suggested_reason: `Dismissed from Observations: SSH 22 seen at host-${id} — its identifiers already belong to assets that need comparing first.` });

  it('shows "Link to <asset>" on the row, never Confirm', async () => {
    page.rows = [linkRow('a1')];
    await render();
    expect(button('Link to dream-router…', row('a1')).disabled).toBe(false);
    expect([...row('a1').querySelectorAll('button')].some((b) => /^Confirm/.test(b.textContent ?? ''))).toBe(false);
    expect(row('a1').textContent).toContain('Matches an asset');
  });

  it('opens the existing Link form on the owner, with the link reason prefilled', async () => {
    page.rows = [linkRow('a1')];
    await render();
    await click(button('Link to dream-router…', row('a1')));
    const form = document.querySelector<HTMLElement>('[aria-label="What this needs"]')!;
    expect(form.querySelector('textarea')!.value).toBe('Linked from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor) — already belongs to dream-router.');
    expect(form.querySelector<HTMLSelectElement>('select')!.value).toBe(ROUTER);
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 }, data: {} });
    await click(button('Save decision', form));
    expect(api.POST).toHaveBeenCalledExactlyOnceWith('/discovery/observations/{id}/link', { params: { path: { id: 'a1' } }, body: expect.objectContaining({ asset_id: ROUTER }) });
  });

  it('a needs-review row has no one-click action but Dismiss, and says why', async () => {
    page.rows = [reviewRow('r1')];
    await render();
    const actions = [...row('r1').querySelectorAll('button')].map((b) => b.textContent?.trim()).filter((t) => t?.endsWith('…'));
    expect(actions).toEqual(['Dismiss…']);
    expect(row('r1').textContent).toContain('Several match');
    expect((await expand('r1')).textContent).toContain('More than one existing asset owns identifiers');
  });

  it('bulk Link links a homogeneous selection; Confirm is off for it', async () => {
    page.rows = [linkRow('a1'), linkRow('b22')];
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 }, data: { batch_id: 'b', results: [
      { id: 'a1', outcome: 'ok', status: 200, message: 'Linked', asset_id: ROUTER },
      { id: 'b22', outcome: 'ok', status: 200, message: 'Linked', asset_id: ROUTER },
    ] } });
    await render();
    await click(checkbox('a1')); await click(checkbox('b22'));
    expect(button('Confirm', bar()!).disabled).toBe(true);
    expect(button('Link to existing', bar()!).disabled).toBe(false);
    await click(button('Link to existing', bar()!));
    expect(dialog()?.getAttribute('aria-label')).toBe('Link 2 observations to existing assets');
    expect(dialog()!.querySelector('textarea')!.value).toBe('Linked from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor), and 1 more like it.');
    await click(button('Link 2', dialog()!));
    expect(api.POST).toHaveBeenCalledExactlyOnceWith('/discovery/observations/bulk', { body: { action: 'link', ids: ['a1', 'b22'], reason: expect.stringContaining('Linked from Observations') } });
    expect(text()).toContain('2 linked.');
  });

  it('bulk Link is off when the selection mixes in a row that is not a link suggestion', async () => {
    page.rows = [linkRow('a1'), obs('b22')];
    await render();
    await click(checkbox('a1')); await click(checkbox('b22'));
    expect(button('Link to existing', bar()!).disabled).toBe(true);
    expect(button('Confirm', bar()!).disabled).toBe(true);
  });
});

describe('bulk (D4)', () => {
  it('stays hidden until a row is ticked', async () => {
    await render();
    expect(bar()).toBeNull();
    await click(checkbox('a1'));
    expect(bar()?.textContent).toContain('1 selected');
    expect(document.querySelector('[role="status"]')?.textContent).toContain('1 selected');
  });

  it('offers Confirm for an all-ready selection and Dismiss for any; Link only for matched rows', async () => {
    page.rows = [obs('a1'), obs('b22'), sensorRow('s1')];
    await render();
    await click(checkbox('a1')); await click(checkbox('b22'));
    expect(button('Confirm', bar()!).disabled).toBe(false);
    await click(checkbox('s1'));
    expect(bar()?.textContent).toContain('3 selected');
    expect(button('Confirm', bar()!).disabled).toBe(true);
    expect(button('Dismiss', bar()!).disabled).toBe(false);
    // Rows nothing owns are not link suggestions, so bulk Link stays off.
    expect(button('Link to existing', bar()!).disabled).toBe(true);
  });

  it('selects every selectable row on the page, and only those', async () => {
    page.rows = [obs('a1'), obs('l1', { state: 'linked', needs: 'none', suggested_action: 'none', explanation_code: 'not_awaiting_review', suggested_reason: '' })];
    await render();
    expect(row('l1').querySelector('input[type="checkbox"]')).toBeNull();
    await click(host.querySelector<HTMLInputElement>('input[aria-label="Select every observation on this page"]')!);
    expect(bar()?.textContent).toContain('1 selected');
  });

  it('re-judges Confirm on the CURRENT rows when a refetch changes one', async () => {
    await render();
    await click(checkbox('a1')); await click(checkbox('b22'));
    expect(button('Confirm', bar()!).disabled).toBe(false);
    // Somebody else's change lands: b22 now needs a network.
    page.rows = [obs('a1'), obs('b22', { needs: 'needs_network', suggested_action: 'add_network', explanation_code: 'network_not_configured' })];
    await act(async () => { await cache.invalidateQueries({ queryKey: ['identity-observations'] }); });
    await flush();
    expect(checkbox('b22').checked).toBe(true);
    expect(button('Confirm', bar()!).disabled).toBe(true);
  });

  it('confirms in one call with a prefilled, editable batch reason, and reports per row', async () => {
    page.rows = [obs('a1'), obs('b22'), obs('c333')];
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 }, data: { batch_id: 'batch', results: [
      { id: 'a1', outcome: 'ok', status: 200, message: 'ok', asset_id: 'x' },
      { id: 'b22', outcome: 'failed', status: 402, code: 'asset_allowance_reached', message: 'allowance' },
      { id: 'c333', outcome: 'failed', status: 409, code: 'observation_changed', message: 'changed' },
    ] } });
    await render();
    for (const id of ['a1', 'b22', 'c333']) await click(checkbox(id));
    await click(button('Confirm', bar()!));
    expect(dialog()?.getAttribute('aria-label')).toBe('Create 3 assets');
    expect(dialog()?.textContent).toContain('Each then follows its network’s approval rules.');
    const reason = dialog()!.querySelector('textarea')!;
    expect(reason.value).toBe('Confirmed from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor), and 2 more like it.');
    await typeInto(reason, 'Walked the floor');
    // After the decision a refreshed page holds b22 still (allowance) and no
    // longer holds c333 (it changed state) — both must stay on screen.
    page.rows = [obs('b22')];
    await click(button('Confirm 3', dialog()!));
    expect(api.POST).toHaveBeenCalledExactlyOnceWith('/discovery/observations/bulk', { body: { action: 'confirm', ids: ['a1', 'b22', 'c333'], reason: 'Walked the floor' } });
    expect(dialog()).toBeNull();
    expect(text()).toContain('1 confirmed, 2 need another look.');
    expect(row('b22').querySelector('[data-row-failure]')?.textContent).toBe('The asset allowance has been reached. This observation is still saved; you can link it to an existing asset.');
    expect(row('c333')?.querySelector('[data-row-failure]')?.textContent).toBe('This changed since you looked — review it.');
    expect(row('a1')).toBeNull();
    // The refresh after a decision covers what it changed.
    const keys = (api.GET.mock.calls as unknown[][]).map(([p]) => p);
    expect(keys.filter((p) => p === '/identity/summary').length).toBeGreaterThan(1);
  });

  it.each([
    ['not_found', 404, 'This observation is gone — it was removed or decided elsewhere.'],
    ['provisional_item_requires_merge_review', 409, 'This observation already backs a provisional inventory item. To combine it with another asset, use merge review from Inventory.'],
    ['not_ready_to_confirm', 422, 'This one is not ready for that in bulk — review it on its own.'],
    ['cancelled', 503, 'The request ended before this one was reached. Try again.'],
    ['internal_error', 500, 'The decision could not be saved. Try again.'],
  ])('says a %s failure in the row’s own words', async (code, status, words) => {
    page.rows = [obs('a1')];
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 }, data: { batch_id: 'b', results: [{ id: 'a1', outcome: 'failed', status, code, message: 'x' }] } });
    await render();
    await click(checkbox('a1'));
    await click(button('Dismiss', bar()!));
    await click(button('Dismiss 1', dialog()!));
    expect(text()).toContain('0 dismissed, 1 needs another look.');
    expect(row('a1').querySelector('[data-row-failure]')?.textContent).toBe(words);
  });

  it('prefills a plain dismissal and keeps the dialog open on a refused request', async () => {
    page.rows = [obs('a1'), sensorRow('s1')];
    api.POST.mockResolvedValue({ response: { ok: false, status: 403 } });
    await render();
    await click(checkbox('a1')); await click(checkbox('s1'));
    await click(button('Dismiss', bar()!));
    expect(dialog()?.getAttribute('aria-label')).toBe('Dismiss 2 observations');
    expect(dialog()!.querySelector('textarea')!.value).toBe('Dismissed from Observations: SSH 22 seen at host-a1 on Office LAN (edge-sensor), and 1 more.');
    await click(button('Dismiss 2', dialog()!));
    expect(dialog()?.querySelector('[role="alert"]')?.textContent).toBe('You do not have permission to decide observations.');
  });

  it('disables the bar and shows progress while a decision is saving', async () => {
    let settle: (v: unknown) => void = () => {};
    api.POST.mockReturnValue(new Promise((r) => { settle = r; }));
    await render();
    await click(checkbox('a1'));
    await click(button('Confirm', bar()!));
    await click(button('Confirm 1', dialog()!));
    expect(bar()?.getAttribute('aria-busy')).toBe('true');
    expect(bar()?.textContent).toContain('Saving 1 decision…');
    for (const b of bar()!.querySelectorAll('button')) expect(b.disabled).toBe(true);
    await act(async () => { settle({ response: { ok: true, status: 200 }, data: { batch_id: 'b', results: [{ id: 'a1', outcome: 'ok', status: 200, message: 'ok' }] } }); });
    await flush();
    expect(text()).toContain('1 confirmed.');
  });
});

describe('states', () => {
  it('shows skeleton rows while loading', async () => {
    listPending = true;
    await render();
    expect(host.querySelector('table[aria-busy="true"]')).not.toBeNull();
    expect(host.querySelectorAll('tr[data-skeleton]').length).toBeGreaterThan(0);
  });

  it('says nothing needs you, and suggests the next chip with rows', async () => {
    page = { rows: [], counts: { ready_to_confirm: 0, link_existing: 0, needs_review: 0, needs_network: 0, needs_sensor: 3, likely_noise: 2, all: 5 } };
    await render();
    expect(host.querySelector('[data-empty]')?.textContent).toContain('Nothing needs you right now');
    await click(button('Show Needs a sensor (3)'));
    expect(lastQuery()).toMatchObject({ needs: ['needs_sensor'] });
  });

  it('says a search matched nothing, and offers to clear it', async () => {
    await render();
    page.rows = [];
    await typeInto(host.querySelector<HTMLInputElement>('input[aria-label="Search observations"]')!, 'nope');
    await act(async () => { host.querySelector('form[role="search"]')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
    await flush();
    expect(host.querySelector('[data-empty]')?.textContent).toContain('No observations match “nope”.');
  });

  it('says it could not load, and retries', async () => {
    listFails = true;
    await render();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain('Couldn’t load observations');
    listFails = false;
    await click(button('Retry'));
    expect(row('a1')).not.toBeNull();
  });
});

describe('deep links', () => {
  it('?asset_id= reads that asset’s evidence across every state, as a filter you can clear', async () => {
    await render('/discovery/observations?asset_id=asset-7');
    expect(document.getElementById('where')?.textContent).toBe('?asset_id=asset-7');
    expect(lastQuery()).toMatchObject({ asset_id: 'asset-7', state: 'all' });
    expect(text()).toContain('Evidence for one asset');
    expect(host.querySelector('a[href="/inventory/assets/asset-7"]')?.textContent).toBe('Back to asset');
    await click(host.querySelector<HTMLButtonElement>('button[aria-label="Clear the asset filter"]')!);
    expect(document.getElementById('where')?.textContent).toBe('');
    expect(lastQuery()).not.toHaveProperty('asset_id');
  });

  it('?observation_id= opens that observation expanded from the detail read', async () => {
    page.rows = [];
    detail['obs-9'] = obs('obs-9', { needs: 'needs_sensor', suggested_action: 'sensor_options', explanation_code: 'no_collector_in_network' });
    await render('/discovery/observations?observation_id=obs-9');
    expect(listCalls()).toHaveLength(0);
    expect(api.GET).toHaveBeenCalledWith('/discovery/observations/{id}', { params: { path: { id: 'obs-9' } } });
    expect(row('obs-9').querySelector('button[aria-expanded]')?.getAttribute('aria-expanded')).toBe('true');
    expect(text()).toContain('No sensor can reach the network this was seen on');
    expect(host.querySelector('a[href="/discovery/observations"]')?.textContent).toBe('View all observations');
    // One observation: no bulk selection here.
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
  });
});

describe('RBAC', () => {
  it('without assets.update the table is read-only: no checkboxes, no decisions', async () => {
    perm.can = false;
    await render();
    expect(row('a1')).not.toBeNull();
    expect(host.querySelector('input[type="checkbox"]')).toBeNull();
    expect([...host.querySelectorAll('button')].filter((b) => /Confirm|Dismiss|Link to an asset/.test(b.textContent ?? ''))).toEqual([]);
    const needs = (await expand('a1')).querySelector('[aria-label="What this needs"]')!;
    // The explanation is for everyone; the decision is not.
    expect(needs.textContent).toContain('A real device answered at this address');
    expect(needs.querySelector('button')).toBeNull();
  });
});

// Platform ADR-0003 D2: supporting evidence is linked to an
// established asset but its endpoints are held off it. The row is decidable,
// and its one action links it to THAT asset, which attaches the endpoints.
describe('supporting evidence whose endpoints were held (#2205)', () => {
  const GATEWAY = '5a1f0c52-0000-4000-8000-0000000000bb';
  const heldRow = (id: string) => obs(id, {
    state: 'linked', asset_id: GATEWAY, evidence_held: true,
    needs: 'none', suggested_action: 'none', explanation_code: 'not_awaiting_review', suggested_reason: '',
  });

  it('offers "Attach endpoints…" and links to the asset it already names', async () => {
    page.rows = [heldRow('h1')];
    await render();
    expect([...row('h1').querySelectorAll('button')].map((b) => b.textContent?.trim()).filter((t) => t?.endsWith('…'))).toEqual(['Attach endpoints…']);
    await click(button('Attach endpoints…', row('h1')));
    const form = document.querySelector<HTMLElement>('[aria-label="What this needs"]')!;
    expect(form.querySelector('select')).toBeNull();
    api.POST.mockResolvedValue({ response: { ok: true, status: 200 }, data: {} });
    await click(button('Attach endpoints', form));
    expect(api.POST).toHaveBeenCalledExactlyOnceWith('/discovery/observations/{id}/link', { params: { path: { id: 'h1' } }, body: expect.objectContaining({ asset_id: GATEWAY }) });
  });

  it('an ordinary linked row offers nothing', async () => {
    page.rows = [obs('l1', { state: 'linked', asset_id: GATEWAY, needs: 'none', suggested_action: 'none', explanation_code: 'not_awaiting_review', suggested_reason: '' })];
    await render();
    expect([...row('l1').querySelectorAll('button')].filter((b) => b.textContent?.trim().endsWith('…'))).toHaveLength(0);
  });
});
