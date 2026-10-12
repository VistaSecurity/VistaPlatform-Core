// @vitest-environment jsdom
//
// The spreadsheet import's post-import "Scan now" handoff, MOUNTED and driven
// through the real wizard (upload → map → preview → import → result).
//
// The scan endpoint answers 400 `{"error": "..."}` when it refuses a target
// (for example one that belongs to a collector). The mutation used to throw the
// fixed string 'Failed to start scan', so the person never learned WHY nothing
// was scanned. It must show the server's own sentence.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const post = vi.fn();
vi.mock('../../lib/clients', () => ({ clients: { inventory: { POST: (...a: unknown[]) => post(...a) } } }));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@vistasecurity/primitives/rbac')>()),
  PermissionGate: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('papaparse', () => ({
  default: {
    parse: (_f: File, opts: { complete: (r: { meta: { fields: string[] }; data: Record<string, string>[] }) => void }) =>
      opts.complete({ meta: { fields: ['hostname'] }, data: [{ hostname: 'web01.example.test' }] }),
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
  toast.error = vi.fn();
  toast.success = vi.fn();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function importOneAsset() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <ImportSpreadsheetModal open onClose={() => undefined} lockedTarget="assets" />
      </QueryClientProvider>,
    );
  });
  await flush();
  const input = document.body.querySelector('input[type="file"]') as HTMLInputElement;
  Object.defineProperty(input, 'files', { value: [new File(['hostname\nweb01.example.test'], 'a.csv', { type: 'text/csv' })] });
  await act(async () => { input.dispatchEvent(new Event('change', { bubbles: true })); });
  await flush();
  await click(/^Review$/);
  await click(/^Import 1 row$/);
  expect(text()).toContain('Scan 1 imported asset');
}

const created = { data: { created: 1, skipped: 0, failed: 0, results: [{ status: 'created', id: 'asset-1' }] }, response: new Response(null, { status: 200 }) };

describe('import → Scan now', () => {
  it("a 400 shows the server's reason, not a fixed string", async () => {
    const reason = 'scan dispatch is not authorized: probe target belongs to a collector';
    post.mockImplementation(async (path: string) => path === '/infrastructure-assets/scan'
      ? { error: { error: reason }, response: new Response(null, { status: 400 }) }
      : created);
    await importOneAsset();
    await click(/Scan now/);
    expect(toast.error).toHaveBeenCalledWith(reason);
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringContaining('Active scan started'));
  });

  it('a bodiless 500 is a failure, not "Active scan started"', async () => {
    post.mockImplementation(async (path: string) => path === '/infrastructure-assets/scan'
      ? { response: new Response(null, { status: 500 }) }
      : created);
    await importOneAsset();
    await click(/Scan now/);
    expect(toast.error).toHaveBeenCalledWith('Failed to start scan');
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringContaining('Active scan started'));
  });
});
