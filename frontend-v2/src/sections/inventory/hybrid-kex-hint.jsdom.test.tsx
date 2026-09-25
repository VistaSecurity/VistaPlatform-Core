// @vitest-environment jsdom
//
// The CONSUMER for W1.9: the "supports hybrid, negotiated classical" hint
// on the crypto-configuration drawer (Inventory → a configuration → Why this
// score → the key-exchange component).
//
// This renders the REAL ConfigDrawer, so the whole path is exercised: the
// drawer's "Why this score" query, the panel, and the component card. Each
// screen state the hint can be in is pinned: shown, not shown (support absent,
// or the key exchange already hybrid), and the loading / error states it
// inherits from the panel — where it must NOT appear, because nothing has been
// established yet.
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

const CONFIG_ID = '22222222-0000-4000-8000-000000000001';

const config = {
  id: CONFIG_ID,
  protocol: 'TLS',
  protocol_version: 'TLS 1.3',
  cipher_suite: 'TLS_AES_128_GCM_SHA256',
  key_exchange_algorithm: 'X25519',
  risk_score: 15,
  risk_score_assessed: true,
  risk_level: 'Low',
  raw_data: {},
} as unknown as CryptoConfig;

const aes = {
  algorithm_type: 'symmetric', algorithm_id: '00000000-0000-4000-8000-00000000000a', code: 'AES128-GCM', name: 'AES-128-GCM',
  category: 'symmetric', strength: 'strong', deprecation_status: 'current', risk_score: 10, risk_level: 'Low',
  sets_score: false, is_inferred: false, recommended_alternatives: [], is_pqc: false,
};
const x25519 = {
  algorithm_type: 'key_exchange', algorithm_id: '00000000-0000-4000-8000-00000000000b', code: 'X25519', name: 'X25519',
  category: 'key_exchange', strength: 'strong', deprecation_status: 'current', risk_score: 15, risk_level: 'Low',
  sets_score: true, is_inferred: false, recommended_alternatives: ['X25519MLKEM768'], is_pqc: false,
  migration_guidance: 'Strong classical key agreement; not quantum-resistant.',
};
const hybrid = {
  ...x25519, code: 'X25519MLKEM768', name: 'X25519MLKEM768', is_pqc: true, risk_score: 5, recommended_alternatives: [],
};

function ok(data: unknown) {
  return { data, error: undefined, response: { ok: true, status: 200 } };
}

function componentsRespond(respond: () => Promise<unknown>) {
  inventoryGet.mockReset().mockImplementation(async (path: string) => {
    if (path === '/crypto-configurations/{id}/components') return respond();
    return ok({});
  });
}

let host: HTMLDivElement;
let root: Root;
let cache: QueryClient;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
});
afterEach(() => { act(() => root.unmount()); cache.clear(); host.remove(); });

async function openDrawer() {
  await act(async () => {
    root.render(
      <MemoryRouter>
        <QueryClientProvider client={cache}>
          <ConfigDrawer config={config} onClose={() => {}} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  });
  for (let i = 0; i < 5; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)); });
  return host.textContent ?? '';
}

const hintEl = () => host.querySelector('[data-testid="hybrid-kex-hint"]');

describe('ConfigDrawer — hybrid key exchange hint', () => {
  it('shows the hint on the key-exchange component when the server supports hybrid but negotiated classical', async () => {
    componentsRespond(async () => ok({ components: [x25519, aes].map((c) => (c === x25519 ? { ...c, hybrid_kex_available: { groups: ['X25519MLKEM768'] } } : c)) }));
    const page = await openDrawer();

    expect(page).toContain('This server supports hybrid post-quantum key exchange (X25519MLKEM768), but negotiated X25519.');
    expect(page).toContain("Prefer the hybrid group in the server's configuration");
    expect(page).toContain('still counts as needing PQC migration');
    // Exactly once, and on the key-exchange card.
    expect(host.querySelectorAll('[data-testid="hybrid-kex-hint"]')).toHaveLength(1);
    const card = hintEl()?.parentElement?.textContent ?? '';
    expect(card).toContain('X25519');
    expect(card).toContain('Key exchange');
    // The assessment around it is untouched.
    expect(page).toContain('risk 15 (Low)');
  });

  it('shows it even when a different component sets the score', async () => {
    componentsRespond(async () => ok({ components: [{ ...aes, risk_score: 40, risk_level: 'Medium', sets_score: true }, { ...x25519, sets_score: false, hybrid_kex_available: { groups: [] } }] }));
    await openDrawer();
    expect(hintEl()?.textContent).toContain('supports hybrid post-quantum key exchange, but negotiated X25519.');
  });

  it('does not show the hint when hybrid support is absent or false', async () => {
    componentsRespond(async () => ok({ components: [x25519, aes] }));
    const page = await openDrawer();
    expect(page).toContain('X25519'); // the panel rendered
    expect(hintEl()).toBeNull();
    expect(page).not.toContain('supports hybrid post-quantum');
  });

  it('does not show the hint when the key exchange is already hybrid', async () => {
    componentsRespond(async () => ok({ components: [hybrid, aes] }));
    const page = await openDrawer();
    expect(page).toContain('X25519MLKEM768');
    expect(hintEl()).toBeNull();
  });

  it('shows nothing of the hint while the assessment is loading', async () => {
    componentsRespond(() => new Promise(() => {}));
    const page = await openDrawer();
    expect(page).toContain('Loading assessment…');
    expect(hintEl()).toBeNull();
  });

  it('shows the panel error, not the hint, when the assessment cannot be loaded', async () => {
    componentsRespond(async () => ({ data: undefined, error: { error: 'boom' }, response: { ok: false, status: 500 } }));
    const page = await openDrawer();
    expect(page).toContain("Couldn't load the assessment for this configuration.");
    expect(hintEl()).toBeNull();
  });
});
