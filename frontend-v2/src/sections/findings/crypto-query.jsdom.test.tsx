// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CryptoRisk } from './model';

const { inventoryGet } = vi.hoisted(() => ({ inventoryGet: vi.fn() }));
vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: { GET: inventoryGet },
    compliance: { GET: vi.fn() },
  },
}));

import { RISK_PAGE_CAP, RISK_PAGE_SIZE, useCryptoRisks } from './queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

function risk(index: number): CryptoRisk {
  const id = `00000000-0000-0000-0000-${String(index).padStart(12, '0')}`;
  return {
    id,
    tenant_id: '10000000-0000-0000-0000-000000000000',
    asset_id: '20000000-0000-0000-0000-000000000000',
    crypto_implementation_id: id,
    severity: 'low',
    category: 'algorithm',
    issue_type: 'weak_cipher',
    current_value: `cipher-${index}`,
    description: 'Weak cipher',
    recommendation: 'Replace cipher',
    detected_at: '2026-09-17T00:00:00Z',
  };
}

function Probe() {
  const data = useCryptoRisks().data;
  return data ? (
    <output
      data-total={data.total}
      data-loaded={data.loaded}
      data-truncated={String(data.truncated)}
      data-risk-count={data.risks.length}
    />
  ) : null;
}

async function run(): Promise<HTMLOutputElement> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<QueryClientProvider client={qc}><Probe /></QueryClientProvider>);
  });
  for (let i = 0; i < 20 && !container.querySelector('output'); i++) {
    await act(async () => { await Promise.resolve(); });
  }
  const output = container.querySelector('output');
  if (!output) throw new Error('crypto query did not resolve');
  return output;
}

beforeEach(() => {
  inventoryGet.mockReset();
});

afterEach(() => {
  act(() => { root?.unmount(); });
  container?.remove();
});

describe('useCryptoRisks bounded prefix', () => {
  it('loads five real pages, then returns explicit truncation metadata', async () => {
    inventoryGet.mockImplementation(async (_path: string, options: { params: { query: { page: number; page_size: number } } }) => {
      const { page, page_size } = options.params.query;
      const first = (page - 1) * page_size;
      return {
        data: {
          risks: Array.from({ length: page_size }, (_, offset) => risk(first + offset + 1)),
          total: 600,
          page,
          page_size,
          total_pages: 6,
        },
      };
    });

    const output = await run();

    expect(inventoryGet).toHaveBeenCalledTimes(RISK_PAGE_CAP);
    expect((inventoryGet.mock.calls as unknown as [string, { params: { query: { page: number; page_size: number } } }][])
      .map(([, options]) => options.params.query.page)).toEqual([1, 2, 3, 4, 5]);
    expect(output.dataset).toMatchObject({ total: '600', loaded: '500', truncated: 'true' });
    expect(output.dataset.riskCount).toBe(String(RISK_PAGE_CAP * RISK_PAGE_SIZE));
  });

  it('reports a complete stream without a truncation warning', async () => {
    inventoryGet.mockResolvedValue({
      data: { risks: [risk(1)], total: 1, page: 1, page_size: RISK_PAGE_SIZE, total_pages: 1 },
    });

    const output = await run();

    expect(inventoryGet).toHaveBeenCalledTimes(1);
    expect(output.dataset).toMatchObject({ total: '1', loaded: '1', truncated: 'false' });
  });
});
