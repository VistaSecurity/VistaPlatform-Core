import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Route, Routes } from 'react-router';
import { AssetPage } from './asset-page';
import type { Asset } from '@vistasecurity/api-contract';

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

function renderConfidence(confidence: number | null | undefined): string {
  state.asset = {
    id: 'asset-1', class_key: 'server', class_source_kind: 'declared',
    class_confidence: confidence,
    identifiers: [{ kind: 'hostname', value: 'host.example', source_kind: 'declared', confidence }],
  } as Asset;
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={['/inventory/assets/asset-1']}>
      <Routes><Route path="/inventory/assets/:id" element={<AssetPage />} /></Routes>
    </MemoryRouter>,
  );
}

describe('asset overview confidence contracts', () => {
  it.each([[0, '0%'], [0.01, '1%'], [1, '100%']])('renders class and identifier probability %s as %s', (value, label) => {
    const html = renderConfidence(value as number);
    expect(html).toContain(`title="Confidence ${label}"`);
    // The other occurrence is the class source annotation, rendered by OverviewTab.
    expect(html).toContain(`Declared ${label}`);
    expect(html).not.toContain('No confidence recorded for this identifier');
  });

  it.each([null, undefined])('keeps missing confidence %s absent in both actual consumers', (value) => {
    const html = renderConfidence(value);
    expect(html).toContain('title="No confidence recorded for this identifier">—</span>');
    expect(html).not.toContain('Declared 0%');
    expect(html).not.toContain('title="Confidence ');
  });
});
