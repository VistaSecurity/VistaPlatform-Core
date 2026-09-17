import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Route, Routes } from 'react-router';
import type { Asset } from '@vistasecurity/api-contract';
import { AssetPage } from './asset-page';
import type { ComplianceFinding } from '../findings/model';

const state = vi.hoisted(() => ({
  asset: {} as Asset,
  findings: [] as ComplianceFinding[],
}));

vi.mock('./asset-queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('./asset-queries')>(),
  useAsset: () => ({ data: state.asset }),
  useAssetIdentifiers: () => ({ data: state.asset.identifiers }),
}));
vi.mock('../findings/queries', async (importOriginal) => ({
  ...await importOriginal<typeof import('../findings/queries')>(),
  useAssetFindings: () => ({ data: state.findings }),
}));
vi.mock('@vistasecurity/primitives/rbac', async (importOriginal) => ({
  ...await importOriginal<typeof import('@vistasecurity/primitives/rbac')>(),
  PermissionGate: () => null,
}));

function vulnerability(cves: unknown[]): ComplianceFinding {
  return { producer: 'vulnerability', evidence: { cves } } as unknown as ComplianceFinding;
}

function renderOverview(): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={['/inventory/assets/asset-1']}>
      <Routes><Route path="/inventory/assets/:id" element={<AssetPage />} /></Routes>
    </MemoryRouter>,
  );
}

describe('asset overview assessment limitations', () => {
  beforeEach(() => {
    state.asset = {
      id: 'asset-1',
      class_key: 'server',
      display_name: 'Mixed evidence server',
      identifiers: [{ kind: 'hostname', value: 'mixed.example', source_kind: 'declared' }],
      risk_score: 90,
      risk_level: 'Critical',
      risk_assessed_by: ['vulnerability'],
    } as Asset;
    state.findings = [];
  });

  it('shows mixed scored and unscored CVE evidence beside the overview risk', () => {
    state.findings = [vulnerability([
      { cve_id: 'CVE-2026-1', cvss_score: 9.8 },
      { cve_id: 'CVE-2026-2', cvss_scored: false },
    ])];

    const html = renderOverview();
    expect(html).toContain('score 90');
    expect(html).toContain('data-testid="asset-assessment-limit"');
    expect(html).toContain('Assessment incomplete: 1 of 2 matching CVEs has no CVSS score.');
  });

  it('does not show an assessment limitation when every CVE is scored', () => {
    state.findings = [vulnerability([
      { cve_id: 'CVE-2026-1', cvss_score: 9.8 },
      { cve_id: 'CVE-2026-2', cvss_score: 0 },
    ])];

    const html = renderOverview();
    expect(html).toContain('score 90');
    expect(html).not.toContain('data-testid="asset-assessment-limit"');
    expect(html).not.toContain('Assessment incomplete');
  });
});
