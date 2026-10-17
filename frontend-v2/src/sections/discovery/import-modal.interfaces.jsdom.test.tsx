// @vitest-environment jsdom
//
// DCIM row 1.5f, MOUNTED: a spreadsheet with interface columns, driven through
// the real wizard (upload → map → preview → import). The preview shows each
// row's interface, and the import posts it as a declared interface carrying
// the address at its prefix length. The upload step offers the template.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const post = vi.fn<(path: string, init: { body: unknown }) => Promise<unknown>>();
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: (path: string, init: { body: unknown }) => post(path, init) } } }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
}));
const sheet = vi.hoisted(() => ({
  fields: ['Class', 'Hostname', 'IP address', 'Prefix length', 'MAC address', 'Interface', 'VLAN'],
  data: [
    { Class: 'server', Hostname: 'app-01', 'IP address': '192.0.2.10', 'Prefix length': '24', 'MAC address': 'b4:96:91:0a:00:01', Interface: 'eth0', VLAN: '20' },
    { Class: 'server', Hostname: 'app-02', 'IP address': '192.0.2.11', 'Prefix length': '', 'MAC address': 'b4:96:91:0a:00:02', Interface: '', VLAN: '' },
  ],
}));
vi.mock('papaparse', () => ({
  default: {
    parse: (_f: File, opts: { complete: (r: { meta: { fields: string[] }; data: Record<string, string>[] }) => void }) =>
      opts.complete({ meta: { fields: sheet.fields }, data: sheet.data }),
  },
}));
const toast = vi.hoisted(() => Object.assign(() => undefined, { success: (_m: unknown) => undefined, error: (_m: unknown) => undefined }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import { ImportSpreadsheetModal } from './import-modal';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 20)); });
const text = () => document.body.textContent ?? '';
const button = (re: RegExp) => [...document.body.querySelectorAll('button')].find((b) => re.test(b.textContent ?? ''));
async function click(re: RegExp) {
  const b = button(re);
  expect(b, `button ${re}`).toBeTruthy();
  await act(async () => { b!.click(); });
  await flush();
}

beforeEach(() => {
  post.mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function openAndUpload() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <ImportSpreadsheetModal open onClose={() => undefined} lockedTarget="assets" />
      </QueryClientProvider>,
    );
  });
  await flush();
  expect(button(/Download a template/), 'the template download on the upload step').toBeTruthy();
  const input = document.body.querySelector('input[type="file"]') as HTMLInputElement;
  Object.defineProperty(input, 'files', { value: [new File(['x'], 'a.csv', { type: 'text/csv' })] });
  await act(async () => { input.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush();
}

describe('spreadsheet import — interface columns', () => {
  it('previews each row’s interface and imports it as a declared interface', async () => {
    post.mockResolvedValue({ data: { created: 2, skipped: 0, failed: 0, results: [] }, response: new Response(null, { status: 200 }) });
    await openAndUpload();
    await click(/^Review$/);
    expect(text()).toContain('eth0 · 192.0.2.10/24 · VLAN 20 · b4:96:91:0a:00:01');
    expect(text()).toContain('named by the platform');
    await click(/^Import 2 rows$/);
    const body = post.mock.calls[0][1].body as { rows: { interfaces?: unknown }[] };
    expect(body.rows[0].interfaces).toEqual([{
      name: 'eth0', mac_address: 'b4:96:91:0a:00:01', untagged_vlan: 20,
      addresses: [{ address: '192.0.2.10', prefix_length: 24 }],
    }]);
    expect(body.rows[1].interfaces).toBeUndefined();
  });

  it('flags a VLAN that is not one and skips the row', async () => {
    sheet.data[0].VLAN = '9999';
    try {
      await openAndUpload();
      await click(/^Review$/);
      expect(text()).toContain('is not a VLAN id');
      expect(button(/^Import 1 row$/)).toBeTruthy();
    } finally {
      sheet.data[0].VLAN = '20';
    }
  });
});
