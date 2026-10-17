// Inventory → Cloud (asset-inventory ADR-0009 D7; DCIM row 4.6).
//
// Every cloud resource the tenant's accounts hold, faceted by class, provider,
// account, region and the provider's own type, with an Account grouping
// toggle. The lens is the ordinary asset list under a fixed scope
// (`class:cloud_resource`): the query is still the state, each facet click
// writes a `provider:` / `account:` / `region:` / `cloud.type:` / `class=` term
// into it, and a row opens the same asset drawer the All assets lens opens.
import { useMemo, useState } from 'react';
import type { Asset } from '@vistasecurity/api-contract';
import { Icon } from '../../../components/ui';
import { ASSETS_PAGE_SIZE, useAssetFacets, useAssetsQuery } from '../asset-queries';
import { assetIdentity, classIcon, classLabel } from '../asset-shape';
import type { OpenAsset } from '../drawers';
import { QueryEditor } from '../query-editor';
import {
  CLOUD_FACETS, assetAccount, assetProvider, assetProviderType, assetRegion,
  facetTerm, groupByAccount, hasTerm, scopedCloudQuery, toggleTerm,
} from './cloud-model';

const GRID = 'minmax(220px, 2fr) minmax(130px, 1fr) 80px minmax(120px, 1fr) minmax(110px, 1fr) minmax(170px, 1.4fr)';

function Row({ asset, onOpen }: { asset: Asset; onOpen: OpenAsset }) {
  const ident = assetIdentity(asset);
  return (
    <div
      className="row-hover"
      role="row"
      data-testid="cloud-row"
      onClick={() => onOpen(asset.id, asset)}
      style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', minHeight: 42, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}
    >
      <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <Icon name={classIcon(asset.class_key)} size={14} style={{ color: 'var(--app-t3)', flex: 'none' }} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ident.primary}</span>
      </span>
      <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{classLabel(asset.class_key) || asset.class_key}</span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{assetProvider(asset) || '—'}</span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{assetAccount(asset) || '—'}</span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{assetRegion(asset) || '—'}</span>
      <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={assetProviderType(asset)}>{assetProviderType(asset) || '—'}</span>
    </div>
  );
}

export function CloudLens({ query, onQueryChange, page, onPageChange, onOpenAsset }: {
  query: string;
  onQueryChange: (q: string) => void;
  page: number;
  onPageChange: (p: number) => void;
  onOpenAsset: OpenAsset;
}) {
  const scoped = scopedCloudQuery(query);
  const assetsQ = useAssetsQuery(scoped, page);
  const facetsQ = useAssetFacets(scoped, CLOUD_FACETS.map((f) => f.level));
  const [byAccount, setByAccount] = useState(false);

  const assets = useMemo(() => assetsQ.data?.assets ?? [], [assetsQ.data]);
  const total = assetsQ.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / ASSETS_PAGE_SIZE));
  const groups = useMemo(() => (byAccount ? groupByAccount(assets) : [{ account: '', rows: assets }]), [byAccount, assets]);

  const set = (q: string) => { onQueryChange(q); onPageChange(1); };

  const body = () => {
    if (assetsQ.isError) {
      return (
        <div data-testid="cloud-error" style={{ padding: 40, textAlign: 'center', fontSize: 12.5, color: 'var(--danger-text)' }}>
          Couldn&apos;t load cloud resources. {assetsQ.error instanceof Error ? assetsQ.error.message : ''}
          <div style={{ marginTop: 10 }}><button className="ui-btn sm" onClick={() => { void assetsQ.refetch(); }}>Retry</button></div>
        </div>
      );
    }
    if (assetsQ.isLoading) return <div data-testid="cloud-loading" style={{ padding: 40, textAlign: 'center', fontSize: 12.5, color: 'var(--app-t3)' }}>Loading cloud resources…</div>;
    if (assets.length === 0) {
      return (
        <div data-testid="cloud-empty" style={{ padding: 48, textAlign: 'center', fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.6 }}>
          {query.trim()
            ? 'No cloud resource matches this query.'
            : 'No cloud resources yet. Connect an account under Discovery → Cloud and run a discovery; resources awaiting approval appear here once accepted.'}
        </div>
      );
    }
    return (
      <div role="table" aria-label="Cloud resources">
        <div role="row" style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 34, alignItems: 'center', borderBottom: '1px solid var(--app-border2)' }}>
          {['Resource', 'Class', 'Provider', 'Account', 'Region', 'Provider type'].map((h) => <span key={h} className="eyebrow-app">{h}</span>)}
        </div>
        {groups.map((g) => (
          <div key={g.account || '~none~'} data-testid={byAccount ? 'cloud-account-group' : undefined}>
            {byAccount && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', background: 'var(--app-panel2)', borderBottom: '1px solid var(--app-border)' }}>
                <Icon name="cloud" size={13} style={{ color: 'var(--accent)' }} />
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--app-t1)' }}>{g.account || 'Account not recorded'}</span>
                <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{g.rows.length} on this page</span>
              </div>
            )}
            {g.rows.map((a) => <Row key={a.id} asset={a} onOpen={onOpenAsset} />)}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div data-testid="cloud-lens" style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 26px 12px', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name="cloud" size={17} style={{ color: 'var(--accent)' }} />Cloud
        </h2>
        <QueryEditor value={query} onChange={set} busy={assetsQ.isFetching} />
        <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
          {assetsQ.isLoading ? 'loading…' : `${total} resource${total === 1 ? '' : 's'}`}
        </span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={byAccount} onChange={(e) => setByAccount(e.target.checked)} data-testid="cloud-group-by-account" />
          Group by account
        </label>
      </div>

      <div style={{ flex: 1, minHeight: 0, display: 'flex', margin: '0 26px 14px', borderRadius: 14, overflow: 'hidden', border: '1px solid var(--app-border)', background: 'var(--app-panel)' }}>
        <aside aria-label="Cloud facets" style={{ width: 230, flex: 'none', borderRight: '1px solid var(--app-border)', overflow: 'auto', padding: '10px 12px' }}>
          {facetsQ.isError && <div style={{ fontSize: 11, color: 'var(--danger-text)' }}>Facets could not be loaded.</div>}
          {CLOUD_FACETS.map((f) => {
            const buckets = facetsQ.data?.buckets[f.level] ?? [];
            const failed = facetsQ.data?.failed.includes(f.level);
            return (
              <div key={f.level} style={{ marginBottom: 12 }} data-testid={`cloud-facet-${f.level}`}>
                <div className="eyebrow-app" style={{ marginBottom: 5 }}>{f.label}</div>
                {failed && <div style={{ fontSize: 11, color: 'var(--danger-text)' }}>Could not be counted.</div>}
                {!failed && buckets.length === 0 && <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{facetsQ.isLoading ? '…' : 'None'}</div>}
                {buckets.map((b) => {
                  const term = facetTerm(f.field, b.value);
                  const on = hasTerm(query, term);
                  return (
                    <button
                      key={b.value}
                      onClick={() => set(toggleTerm(query, term))}
                      aria-pressed={on}
                      style={{ display: 'flex', width: '100%', alignItems: 'center', gap: 6, padding: '3px 6px', borderRadius: 6, border: 'none', background: on ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'none', cursor: 'pointer', textAlign: 'left' }}
                    >
                      <span style={{ flex: 1, minWidth: 0, fontSize: 11.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {f.level === 'class' ? classLabel(b.value) || b.value : b.label ?? b.value}
                      </span>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{b.count}</span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </aside>
        <div style={{ flex: 1, minWidth: 0, overflow: 'auto' }}>{body()}</div>
      </div>

      {!assetsQ.isLoading && !assetsQ.isError && total > ASSETS_PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, padding: '0 26px 18px' }}>
          <button className="ui-btn sm" disabled={page <= 1} onClick={() => onPageChange(Math.max(1, page - 1))}>Prev</button>
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{page} / {pages}</span>
          <button className="ui-btn sm" disabled={page >= pages} onClick={() => onPageChange(Math.min(pages, page + 1))}>Next</button>
        </div>
      )}
    </div>
  );
}
