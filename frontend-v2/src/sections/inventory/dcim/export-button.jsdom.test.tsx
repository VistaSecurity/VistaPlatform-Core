// @vitest-environment jsdom
// The Export button passes the page's filters to GET /dcim/export, saves the
// file, and says so when it fails.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ExportButton } from './export-button';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const api = vi.hoisted(() => ({ GET: vi.fn() }));
vi.mock('../../../lib/clients', () => ({ clients: { inventory: api } }));

let host: HTMLDivElement; let root: Root;
beforeEach(() => {
  api.GET.mockReset();
  host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host);
  Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() });
});
afterEach(() => { act(() => root.unmount()); host.remove(); });

const click = async () => {
  await act(async () => { (host.querySelector('button') as HTMLButtonElement).click(); });
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
};

it('sends the kind and the current filters, dropping blank ones', async () => {
  api.GET.mockResolvedValue({ data: new Blob(['a']), response: { ok: true } });
  await act(async () => { root.render(<ExportButton kind="prefix" filters={{ vrf_id: 'v1', group_id: '' }} />); });
  await click();
  const [path, opts] = api.GET.mock.calls[0] as [string, { parseAs: string; params: { query: Record<string, unknown> } }];
  expect(path).toBe('/dcim/export');
  expect(opts.parseAs).toBe('blob');
  expect(opts.params.query).toMatchObject({ kind: 'prefix', format: 'csv', vrf_id: 'v1' });
  expect(opts.params.query.group_id).toBeUndefined();
  expect(URL.createObjectURL).toHaveBeenCalled();
  expect(host.querySelector('[role="alert"]')).toBeNull();
});

it('shows the failure', async () => {
  api.GET.mockResolvedValue({ data: undefined, response: { ok: false }, error: { error: { message: 'no such filter' } } });
  await act(async () => { root.render(<ExportButton kind="vlan" />); });
  await click();
  expect(host.querySelector('[role="alert"]')!.textContent).toBe('no such filter');
});
