// @vitest-environment jsdom
// The bulk action bar: which actions a person sees, what each sends,
// and the edit form's rules. The REAL PermissionProvider decides what renders,
// seeded through its own query, so a dropped gate turns a test red.
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { PermissionProvider } from '@vistasecurity/primitives/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type Init = { body: Record<string, unknown>; params: { query: Record<string, unknown> } };
const mocks = vi.hoisted(() => ({
  post: vi.fn<(path: string, init: Init) => Promise<unknown>>(),
  get: vi.fn<(path: string, init: Init) => Promise<unknown>>(),
  toastSuccess: vi.fn(),
}));
// Every service client answers through the same mocks; the permission
// provider's own read is served from the seeded cache.
vi.mock('../../lib/clients', () => ({
  clients: new Proxy({}, { get: () => ({ POST: mocks.post, GET: mocks.get }) }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: mocks.toastSuccess }) }));
vi.mock('./scan-dialog', () => ({ ScanDialog: () => <div data-testid="scan-dialog" /> }));
vi.mock('../findings/export-csv', () => ({ downloadCsv: vi.fn() }));
vi.mock('../../components/ui', () => ({
  Icon: () => null,
  ModalField: ({ children, label }: { children: ReactNode; label: string }) => <label>{label}{children}</label>,
  ModalInput: (p: React.InputHTMLAttributes<HTMLInputElement>) => <input {...p} />,
  ModalSelect: (p: React.SelectHTMLAttributes<HTMLSelectElement>) => <select {...p} />,
  Modal: ({ open, title, children, primary, secondary, footerNote }: { open: boolean; title: string; children?: ReactNode; primary: ReactNode; secondary: ReactNode; footerNote?: ReactNode }) =>
    open ? <div data-testid="modal"><h2>{title}</h2>{children}{footerNote}{secondary}{primary}</div> : null,
}));

import { BulkActionBar, buildChanges, parseTagPairs, selectionRows } from './bulk-action-bar';
import type { AssetSelection } from './asset-selection';

let host: HTMLDivElement;
let root: Root;
let onChange: Mock<(s: AssetSelection) => void>;
beforeEach(() => {
  mocks.post.mockReset(); mocks.get.mockReset(); mocks.toastSuccess.mockReset();
  onChange = vi.fn<(s: AssetSelection) => void>();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

async function render(selection: AssetSelection, permissions: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  qc.setQueryData(['user-permissions'], permissions);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <PermissionProvider>
          <BulkActionBar selection={selection} onChange={onChange} seen={new Map()} onScanStarted={vi.fn()} />
        </PermissionProvider>
      </QueryClientProvider>,
    );
  });
}
const labels = () => [...host.querySelectorAll('[role="toolbar"] button')].map((b) => b.textContent?.trim());
const button = (re: RegExp) => [...host.querySelectorAll('button')].find((b) => re.test(b.textContent?.trim() ?? ''));
async function click(re: RegExp) {
  const b = button(re);
  if (!b) throw new Error(`no ${re} button in: ${host.textContent}`);
  await act(async () => { b.click(); });
}

describe('what a person sees', () => {
  it('a reader can select and export, and nothing else', async () => {
    await render({ kind: 'ids', ids: new Set(['a']) }, ['assets.read']);
    expect(labels()).toEqual(['Export', 'Clear']);
    expect(host.textContent).toContain('1 asset selected');
  });

  it('an editor can scan, edit, archive and restore, but not delete', async () => {
    await render({ kind: 'ids', ids: new Set(['a']) }, ['assets.read', 'assets.update']);
    expect(labels()).toEqual(['Scan', 'Edit', 'Archive', 'Restore', 'Export', 'Clear']);
  });

  it('delete needs assets.delete', async () => {
    await render({ kind: 'ids', ids: new Set(['a']) }, ['assets.read', 'assets.update', 'assets.delete']);
    expect(labels()).toContain('Delete');
  });

  it('nothing selected, no bar', async () => {
    await render({ kind: 'none' }, ['assets.update']);
    expect(host.querySelector('[role="toolbar"]')).toBeNull();
  });
});

describe('lifecycle actions', () => {
  it('archive confirms, sends the query selection, reports the counts and clears', async () => {
    mocks.post.mockResolvedValueOnce({ data: { action: 'archive', matched: 40, changed: 38, unchanged: 2 }, response: { ok: true, status: 200 } });
    await render({ kind: 'query', query: 'environment:test', count: 40 }, ['assets.update']);
    await click(/^Archive$/);
    expect(host.textContent).toContain('Archive 40 assets?');
    expect(mocks.post).not.toHaveBeenCalled();
    await click(/^Archive 40 assets$/);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
    expect(mocks.post.mock.calls[0][0]).toBe('/infrastructure-assets/bulk-actions/archive');
    expect(mocks.post.mock.calls[0][1].body).toEqual({ query: 'environment:test', expected_count: 40 });
    await vi.waitFor(() => expect(mocks.toastSuccess).toHaveBeenCalledWith('38 assets archived; 2 already archived or not changed'));
    expect(onChange).toHaveBeenCalledWith({ kind: 'none' });
  });

  it('a changed selection is refused in words, and the selection is kept', async () => {
    mocks.post.mockResolvedValueOnce({ error: { error: 'selection_changed', expected_count: 40, count: 44 }, response: { ok: false, status: 409 } });
    await render({ kind: 'query', query: '', count: 40 }, ['assets.update', 'assets.delete']);
    await click(/^Delete$/);
    await click(/^Delete 40 assets$/);
    await vi.waitFor(() => expect(host.textContent).toContain('now matches 44 assets, more than the 40 you confirmed'));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('Scan opens the scan dialog', async () => {
    await render({ kind: 'ids', ids: new Set(['a']) }, ['assets.update']);
    await click(/^Scan$/);
    expect(host.querySelector('[data-testid="scan-dialog"]')).not.toBeNull();
  });

  it('over the bulk cap, the writes are disabled and say why', async () => {
    await render({ kind: 'query', query: '', count: 5001 }, ['assets.update']);
    expect(button(/^Archive$/)?.disabled).toBe(true);
    expect(button(/^Archive$/)?.title).toMatch(/at most 5,000/);
  });
});

describe('edit fields', () => {
  it('sends only what the person chose to change', async () => {
    mocks.post.mockResolvedValueOnce({ data: { action: 'update', matched: 2, changed: 2, unchanged: 0 }, response: { ok: true, status: 200 } });
    await render({ kind: 'ids', ids: new Set(['a', 'b']) }, ['assets.update']);
    await click(/^Edit$/);
    expect(button(/^Apply to 2 assets$/)?.disabled).toBe(true);
    const mode = host.querySelector('select[aria-label="Business unit: change"]') as HTMLSelectElement;
    await act(async () => { mode.value = 'set'; mode.dispatchEvent(new Event('change', { bubbles: true })); });
    const input = host.querySelector('input[aria-label="Business unit"]') as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    await act(async () => { setter.call(input, 'Payments'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await click(/^Apply to 2 assets$/);
    await vi.waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
    expect(mocks.post.mock.calls[0][0]).toBe('/infrastructure-assets/bulk-actions/update');
    expect(mocks.post.mock.calls[0][1].body).toEqual({ asset_ids: ['a', 'b'], changes: { business_unit: 'Payments' } });
  });

  it('clear sends an empty value; tags parse as name=value', () => {
    expect(buildChanges({ owner_email: 'clear' }, {}, '', '')).toEqual({ owner_email: '' });
    expect(buildChanges({ environment: 'set' }, { environment: 'production' }, 'zone=dmz, team = pay=ments, solo', 'legacy, ,temp'))
      .toEqual({ environment: 'production', add_tags: { zone: 'dmz', team: 'pay=ments', solo: '' }, remove_tags: ['legacy', 'temp'] });
    expect(buildChanges({ business_unit: 'set' }, { business_unit: '  ' }, '', '')).toBeNull();
    expect(buildChanges({}, {}, '', '')).toBeNull();
    expect(parseTagPairs(' , =x')).toEqual({});
  });
});

describe('export', () => {
  it('reads a query selection page by page through the list endpoint', async () => {
    const page = (n: number, from: number) => Array.from({ length: n }, (_, i) => ({ id: `a${from + i}` }));
    mocks.get
      .mockResolvedValueOnce({ data: { assets: page(100, 0) } })
      .mockResolvedValueOnce({ data: { assets: page(30, 100) } });
    const rows = await selectionRows({ kind: 'query', query: 'class:server', count: 130 }, new Map());
    expect(rows).toHaveLength(130);
    expect(mocks.get.mock.calls[1][1].params.query).toEqual({ query: 'class:server', page: 2, page_size: 100 });
  });

  it('ticked rows come from what the lens has shown', async () => {
    const seen = new Map([['a', { id: 'a' }], ['b', { id: 'b' }]]) as never;
    expect(await selectionRows({ kind: 'ids', ids: new Set(['b']) }, seen)).toEqual([{ id: 'b' }]);
  });
});
