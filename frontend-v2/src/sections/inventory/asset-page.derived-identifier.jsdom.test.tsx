// @vitest-environment jsdom
//
// Phase 2: a DERIVED identifier on the asset page says what it was
// derived from.
//
// The platform works some MACs out rather than seeing them — from an EUI-64
// IPv6 address, or from a serial that IS the MAC — and stores them
// `source_kind: inferred`, `source_ref: derived:<how>:<evidence>`. This renders
// the REAL AssetPage (overview tab, identifier list) with one derived MAC, one
// serial-derived MAC and one observed MAC. Rendering the plain source label for
// every row turns it red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset } from '@vistasecurity/api-contract';
import { AssetPage } from './asset-page';
import { identifierProvenanceLabel } from './asset-shape';
import { AddressPinToggle, type IdentifierDraft } from './class-picker';

// The page renders the Active Scan button, which reads the query client; none of
// these tests reads a query through it.
const queryClient = new QueryClient();

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const state = vi.hoisted(() => ({ asset: {} as Asset }));
vi.mock('./asset-queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('./asset-queries')>(),
  useAsset: () => ({ data: state.asset }),
  useAssetIdentifiers: () => ({ data: state.asset.identifiers }),
}));
vi.mock('../findings/queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('../findings/queries')>(),
  useAssetFindings: () => ({ data: [] }),
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: () => null,
}));

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function renderAsset(identifiers: NonNullable<Asset['identifiers']>) {
  state.asset = { id: 'asset-1', class_key: 'iot_device', identifiers } as Asset;
  act(() => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/inventory/assets/asset-1']}>
          <Routes><Route path="/inventory/assets/:id" element={<AssetPage />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  });
  return Array.from(container.querySelectorAll('[data-testid="identifier-provenance"]')).map((el) => ({
    text: el.textContent ?? '',
    title: el.getAttribute('title') ?? '',
  }));
}

describe('asset page — derived identifier provenance', () => {
  it('labels a derived MAC with the evidence it was derived from, and leaves an observed one alone', () => {
    const cells = renderAsset([
      { kind: 'mac_address', value: 'a0:b2:c3:d4:e5:f6', source_kind: 'inferred', source_ref: 'derived:eui64:fd00::a2b2:c3ff:fed4:e5f6', confidence: 0.9 },
      { kind: 'mac_address', value: '00:00:0c:7a:6b:5c', source_kind: 'inferred', source_ref: 'derived:serial:00000C7A6B5C', confidence: 0.9 },
      { kind: 'mac_address', value: '28:cf:da:11:22:40', source_kind: 'measured', source_ref: 'sensor', confidence: 1 },
    ] as NonNullable<Asset['identifiers']>);

    expect(cells.map((c) => c.text)).toEqual([
      'Derived from IPv6 address fd00::a2b2:c3ff:fed4:e5f6',
      'Derived from serial 00000C7A6B5C',
      'Measured',
    ]);
    // The raw provenance stays one hover away.
    expect(cells[0].title).toBe('Inferred · derived:eui64:fd00::a2b2:c3ff:fed4:e5f6');
  });
});

describe('identifierProvenanceLabel', () => {
  it.each([
    [{ source_kind: 'inferred', source_ref: 'derived:eui64:2001:db8::1' }, 'Derived from IPv6 address 2001:db8::1'],
    [{ source_kind: 'inferred', source_ref: 'derived:serial:ABC' }, 'Derived from serial ABC'],
    [{ source_kind: 'inferred', source_ref: 'derived:future-kind:x' }, 'Derived from future-kind:x'],
    // A model's inference (not a derivation) keeps the plain label.
    [{ source_kind: 'inferred', source_ref: 'model:matcher-v1' }, 'Inferred'],
    // "derived:" on a native row is not a claim this label makes.
    [{ source_kind: 'measured', source_ref: 'derived:eui64:2001:db8::1' }, 'Measured'],
    [{ source_kind: 'declared', source_ref: null }, 'Declared'],
    [{ source_kind: null, source_ref: null }, ''],
  ])('%o → %s', (ident, want) => {
    expect(identifierProvenanceLabel(ident)).toBe(want);
  });
});

describe('asset page — pinned address marker (#2205)', () => {
  it('marks an address its owner holds static, and nothing else', () => {
    renderAsset([
      { kind: 'ip_address', value: '192.0.2.1', source_kind: 'declared', address_assignment: 'static', confidence: 1 },
      { kind: 'ip_address', value: '192.0.2.2', source_kind: 'measured', address_assignment: 'dynamic', confidence: 1 },
      { kind: 'ip_address', value: '192.0.2.3', source_kind: 'measured', confidence: 1 },
    ] as NonNullable<Asset['identifiers']>);
    const pins = Array.from(container.querySelectorAll('[data-testid="identifier-address-pin"]'));
    expect(pins.map((el) => el.textContent)).toEqual(['static']);
    expect(pins[0].closest('div')?.textContent).toContain('192.0.2.1');
  });
});

describe('identifier editor — pin toggle (#2205)', () => {
  it('pins a measured address on request and shows an existing pin without a control', () => {
    const seen: IdentifierDraft[] = [];
    const row: IdentifierDraft = { kind: 'ip_address', value: '192.0.2.1', sourceKind: 'measured' };
    act(() => root.render(<AddressPinToggle row={row} onChange={(r) => seen.push(r)} />));
    const box = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
    expect(box.checked).toBe(false);
    act(() => box.click());
    expect(seen[seen.length - 1]?.addressAssignment).toBe('static');

    act(() => root.render(<AddressPinToggle row={{ ...row, storedAssignment: 'static' }} onChange={() => {}} />));
    expect(container.querySelector('input[type="checkbox"]')).toBeNull();
    expect(container.querySelector('[data-testid="identifier-pin-static"]')?.textContent).toBe('static');
  });
});
