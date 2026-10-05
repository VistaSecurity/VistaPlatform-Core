// @vitest-environment jsdom
//
// The CONSUMER for W1.2: Inventory → a crypto configuration shows "Not
// measured" for a protocol version no collector read, and a "Partially
// assessed" note naming what was not measured — instead of an empty field
// beside a score that looks complete. Renders the REAL ConfigDrawer.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const inventoryGet = vi.hoisted(() => vi.fn());
vi.mock('../../lib/clients', () => ({
  clients: {
    inventory: { GET: inventoryGet, POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() },
    compliance: { GET: vi.fn() },
  },
}));

import { ConfigDrawer, type CryptoConfig } from './drawers';
import { NOT_MEASURED_TITLE, assessmentGaps } from './crypto-risk-presentation';

const base = {
  id: '22222222-0000-4000-8000-000000000002',
  protocol: 'TLS',
  cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384',
  risk_score: null,
  risk_score_assessed: false,
  risk_level: null,
};

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  inventoryGet.mockReset().mockResolvedValue({ data: { components: [] }, error: undefined, response: { ok: true, status: 200 } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function openDrawer(config: Record<string, unknown>) {
  await act(async () => {
    root.render(
      <MemoryRouter>
        <QueryClientProvider client={cache}>
          <ConfigDrawer config={config as unknown as CryptoConfig} onClose={() => {}} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  for (let i = 0; i < 5; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  return host.textContent ?? '';
}

describe('ConfigDrawer — unmeasured protocol version', () => {
  it('says "Not measured" and shows the Partially assessed note', async () => {
    const page = await openDrawer({ ...base, protocol_version: null, raw_data: { unmeasured_components: ['protocol_version'] } });
    expect(page).toContain('version not measured');
    expect(page).toContain('Not measured');
    expect(host.querySelector(`[title="${NOT_MEASURED_TITLE}"]`)).not.toBeNull();
    const note = host.querySelector('[role="note"]')?.textContent ?? '';
    expect(note).toContain('Partially assessed.');
    expect(note).toContain('protocol version');
    expect(note).toContain('never counted as safe');
  });

  it('shows a measured version and no note when the marker is stale', async () => {
    const page = await openDrawer({ ...base, protocol_version: 'TLS 1.2', risk_score: 25, risk_score_assessed: true, risk_level: 'Low', raw_data: { unmeasured_components: ['protocol_version'] } });
    expect(page).toContain('TLS 1.2');
    expect(page).not.toContain('Not measured');
    expect(host.querySelector('[role="note"]')).toBeNull();
  });

  it('shows no note for a fully measured configuration', async () => {
    await openDrawer({ ...base, protocol_version: 'TLS 1.3', raw_data: {} });
    expect(host.querySelector('[role="note"]')).toBeNull();
  });
});

describe('assessmentGaps', () => {
  it('names an unresolved cipher string as well', () => {
    expect(assessmentGaps({ protocol_version: null, raw_data: { unmeasured_components: ['protocol_version'], cipher_assessment: 'partial' } }).gaps)
      .toEqual(['protocol version', 'cipher set (the cipher string could not be fully resolved)']);
    expect(assessmentGaps({ protocol_version: null, raw_data: null })).toEqual({ versionUnmeasured: false, gaps: [] });
  });
});
