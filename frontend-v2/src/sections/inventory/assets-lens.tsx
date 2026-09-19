// Inventory → All assets: the class-faceted list (ADR-0006 D2).
//
// One lens with a class facet replaces the idea of a lens per class — twelve
// classes would have meant twelve near-identical pages. The columns adapt to
// the selected class through the registry in `columns.ts`; the facets adapt to
// the tenant through the server's buckets; and the whole filter state is ONE
// query string in the URL, which is what makes a view shareable and a scope,
// an approval rule and a saved view all the same kind of thing.
import { useMemo } from 'react';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { Asset } from '@vistasecurity/api-contract';
import { Icon, RiskChip } from '../../components/ui';
import { ASSETS_PAGE_SIZE, AssetQueryError, useAssetFacets, useAssetsQuery } from './asset-queries';
import { assetIdentity, assetRisk, classIcon } from './asset-shape';
import { columnsForClass, gridTemplate, type AssetColumn } from './columns';
import { FACET_LEVELS, FacetRail } from './facet-rail';
import { applyFacetChange, queryToFacets, type FacetState } from './facet-query';
import { QueryChip, QueryEditor, ServerQueryErrors } from './query-editor';
import { SavedViews } from './saved-views';
import { IdentityStatus } from './identity-status';
import { IdentityCoverage } from '../discovery/observations-page';

function Header({ cols, grid }: { cols: AssetColumn[]; grid: string }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', height: 34, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
      <span />
      <span className="eyebrow-app">Asset</span>
      {cols.map((c) => (
        <span key={c.key} className="eyebrow-app" style={{ textAlign: c.numeric ? 'right' : 'left' }}>{c.label}</span>
      ))}
    </div>
  );
}

function AssetRow({ asset, cols, grid, onOpen }: {
  asset: Asset; cols: AssetColumn[]; grid: string; onOpen: (id: string) => void;
}) {
  const ident = assetIdentity(asset);
  const risk = assetRisk(asset);
  return (
    <div
      className="row-hover"
      role="button"
      tabIndex={0}
      onClick={() => onOpen(asset.id)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(asset.id); } }}
      style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}
    >
      <RiskChip level={risk.level} assessed={risk.assessed} size={22} title={risk.title} />
      <div style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name={classIcon(asset.class_key)} size={14} style={{ color: 'var(--app-t3)', flex: 'none' }} />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ident.primary}</div>
          <IdentityStatus asset={asset} />
          {ident.secondary && (
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ident.secondary}</div>
          )}
        </div>
      </div>
      {cols.map((c) => {
        const v = c.value(asset);
        return (
          <span
            key={c.key}
            className={c.mono ? 'mono' : undefined}
            title={v || undefined}
            style={{ fontSize: c.mono ? 12 : 12.5, color: v ? 'var(--app-t2)' : 'var(--app-t3)', textAlign: c.numeric ? 'right' : 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
          >
            {/* An em dash, not a blank, so an unknown value reads as "we do not
                know" rather than as a rendering slip. The primary-endpoint rule
                is why the Address cell is often one of these: an at-rest
                resource genuinely has no address, and inventing a port for it
                was the old model's bug. */}
            {v || '—'}
          </span>
        );
      })}
    </div>
  );
}

function Center({ icon, tone, title, message, detail, action }: {
  icon: string; tone: string; title: string; message: string;
  detail?: React.ReactNode;
  action?: { label: string; onClick: () => void }[];
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 9, padding: '58px 26px', textAlign: 'center' }}>
      <Icon name={icon} size={28} style={{ color: tone }} />
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 520, lineHeight: 1.6 }}>{message}</div>
      {detail}
      {action && action.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginTop: 5, flexWrap: 'wrap', justifyContent: 'center' }}>
          {action.map((a) => <button key={a.label} className="ui-btn" onClick={a.onClick}>{a.label}</button>)}
        </div>
      )}
    </div>
  );
}

function SkeletonRows({ grid, cols }: { grid: string; cols: number }) {
  return (
    <div data-testid="assets-skeleton">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)' }}>
          <span style={{ width: 18, height: 18, borderRadius: 6, background: 'var(--app-panel2)' }} />
          <span style={{ height: 11, borderRadius: 5, background: 'var(--app-panel2)', width: `${55 + (i % 4) * 9}%` }} />
          {Array.from({ length: cols }).map((__, j) => (
            <span key={j} style={{ height: 9, borderRadius: 5, background: 'var(--app-panel2)', opacity: 0.7 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * What the server actually ran, under the box the user typed in (ADR-0008 D4.4).
 *
 * The two strings are rarely identical. The read path AND-s in its own default
 * scope — `status:monitoring`, which steps aside only when the query names a
 * status itself — so `class:server` matches strictly fewer rows than
 * `class:server` alone would, and a user counting fewer assets than they
 * expected has no other way to find out why. (A pending-approval asset is not
 * inventory; the default is right. Being unable to SEE it is not.)
 *
 * It is shown whenever the server ran a predicate, and called out when that
 * predicate is not the one that was typed. Silence is the failure mode worth
 * avoiding here: a difference nobody is told about is the one that gets
 * debugged as "the inventory is wrong".
 */
export function AppliedQuery({ typed, applied }: { typed: string; applied: string }) {
  if (applied.trim() === '') return null;
  const differs = applied.trim() !== typed.trim();
  return (
    <div
      data-testid="applied-query"
      style={{ display: 'flex', alignItems: 'baseline', gap: 7, margin: '0 26px 9px', flexWrap: 'wrap' }}
    >
      <span className="eyebrow-app" style={{ flex: 'none' }}>Query applied</span>
      <QueryChip query={applied} />
      {differs && (
        <span
          title="Usually the default scope: only assets you are monitoring are listed, so anything still awaiting approval, denied or archived is excluded until your query names a status itself."
          style={{ fontSize: 10.5, fontWeight: 600, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn) 12%, transparent)', borderRadius: 40, padding: '1px 8px', flex: 'none' }}
        >
          not what you typed
        </span>
      )}
    </div>
  );
}

export function AssetsLens({ query, onQueryChange, page, onPageChange, pendingCount, onNewAsset, onImport }: {
  query: string;
  onQueryChange: (q: string) => void;
  page: number;
  onPageChange: (p: number) => void;
  pendingCount: number;
  onNewAsset: () => void;
  onImport?: () => void;
}) {
  const navigate = useNavigate();

  // The query is the state. Facets are DERIVED from it, and any term the rail
  // cannot express is carried through untouched — see facet-query.ts.
  const read = useMemo(() => queryToFacets(query), [query]);
  // A query that does not parse has no `extra` to carry it in, so writing the
  // rail's state would DELETE what the user typed. The rail is disabled in that
  // state and says so; the guard here is the one that cannot be clicked past.
  const setFacets = (next: FacetState) => {
    const q = applyFacetChange(read, next);
    if (q !== null) onQueryChange(q);
  };

  const assetsQ = useAssetsQuery(query, page);
  const facetsQ = useAssetFacets(query, FACET_LEVELS);

  const assets = assetsQ.data?.assets ?? [];
  const total = assetsQ.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / ASSETS_PAGE_SIZE));

  const cols = useMemo(() => columnsForClass(read.facets.class), [read.facets.class]);
  const grid = useMemo(() => gridTemplate(cols), [cols]);

  const openAsset = (id: string) => { void navigate(`/inventory/assets/${id}`); };

  const body = () => {
    if (assetsQ.isError) {
      // A query the SERVER refused gets the same treatment the editor gives one
      // this side refused: every diagnostic, with the caret under the offending
      // word. The two validators agree on almost everything, and the codes only
      // the server can raise (`untranslatable`, a value set the generated
      // catalogue is a release behind on) are precisely the ones a user has no
      // other way to understand.
      const diagnostics = assetsQ.error instanceof AssetQueryError ? assetsQ.error.diagnostics : null;
      return (
        <Center
          icon="alert-triangle"
          tone="var(--danger-text)"
          title={diagnostics ? 'The server refused this query' : "Couldn't load assets"}
          message={diagnostics
            ? 'It parsed here but not there. The problems are underlined below.'
            : (assetsQ.error instanceof Error ? assetsQ.error.message : 'The request failed.')}
          detail={diagnostics ? <ServerQueryErrors query={diagnostics.query} errors={diagnostics.errors} /> : undefined}
          action={[{ label: 'Retry', onClick: () => { void assetsQ.refetch(); } }]}
        />
      );
    }
    if (assetsQ.isLoading) return <SkeletonRows grid={grid} cols={cols.length} />;
    if (assets.length === 0) {
      // Two different empties, and conflating them is the trap: a filtered
      // no-match must not read as "you have no inventory", and an unfiltered
      // empty must not read as "your filter is too narrow".
      if (query.trim() !== '') {
        return (
          <Center
            icon="search-x"
            tone="var(--app-t3)"
            title="Nothing matches this query"
            message="No asset satisfies every term. Widen a filter in the rail, or edit the query directly."
            action={[{ label: 'Clear the query', onClick: () => onQueryChange('') }]}
          />
        );
      }
      return (
        <Center
          icon="inbox"
          tone="var(--app-t3)"
          title="No assets yet"
          message={pendingCount > 0
            ? `${pendingCount} discovered asset${pendingCount === 1 ? ' is' : 's are'} awaiting approval and will appear here once accepted. You can also import a spreadsheet or add one by hand.`
            : 'Discover, import, or add one. Discovery finds what is on your network; import brings a CMDB export or a spreadsheet; adding one by hand records something you already know about.'}
          action={[
            { label: 'Run a discovery', onClick: () => { void navigate('/discovery'); } },
            ...(onImport ? [{ label: 'Import a spreadsheet', onClick: onImport }] : []),
            { label: 'Add an asset', onClick: onNewAsset },
          ]}
        />
      );
    }
    return (
      <>
        <Header cols={cols} grid={grid} />
        {assets.map((a) => <AssetRow key={a.id} asset={a} cols={cols} grid={grid} onOpen={openAsset} />)}
      </>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 26px 12px', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name="database" size={17} style={{ color: 'var(--accent)' }} />All assets
        </h2>
        <QueryEditor value={query} onChange={(q) => { onQueryChange(q); onPageChange(1); }} busy={assetsQ.isFetching} />
        <SavedViews query={query} onApply={(q) => { onQueryChange(q); onPageChange(1); }} />
        <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
          {assetsQ.isLoading ? 'loading…' : `${total} asset${total === 1 ? '' : 's'}`}
          {assetsQ.isFetching && !assetsQ.isLoading ? ' · refreshing' : ''}
        </span>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.create}>
          <button onClick={onNewAsset} className="ui-btn accent" style={{ height: 33, padding: '0 11px', fontSize: 12.5 }}>
            <Icon name="plus" size={13} />New asset
          </button>
        </PermissionGate>
      </div>

      <AppliedQuery typed={query} applied={assetsQ.data?.appliedQuery ?? ''} />
      <IdentityCoverage />

      {pendingCount > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '0 26px 10px', padding: '8px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--warn) 35%, transparent)', background: 'color-mix(in srgb, var(--warn) 8%, transparent)' }}>
          <Icon name="inbox" size={15} style={{ color: 'var(--warn)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>
            <strong>{pendingCount}</strong> item{pendingCount === 1 ? '' : 's'} awaiting review — discovered assets, merge proposals and proposed relationships. Approved assets join Inventory with their certificates and crypto configurations.
          </span>
          <div style={{ flex: 1 }} />
          <button className="ui-btn sm" onClick={() => { void navigate('/discovery/approvals'); }}>
            Review<Icon name="chevron-right" size={13} />
          </button>
        </div>
      )}

      <div style={{ flex: 1, minHeight: 0, display: 'flex', margin: '0 26px 14px', borderRadius: 14, overflow: 'hidden', border: '1px solid var(--app-border)', background: 'var(--app-panel)' }}>
        <FacetRail
          facets={read.facets}
          data={facetsQ.data}
          extra={read.extra}
          unparsed={read.unparsed}
          onChange={(next) => { setFacets(next); onPageChange(1); }}
          onClear={() => { onQueryChange(''); onPageChange(1); }}
          onRetry={() => { void facetsQ.refetch(); }}
        />
        <div style={{ flex: 1, minWidth: 0, overflow: 'auto' }}>{body()}</div>
      </div>

      {!assetsQ.isLoading && !assetsQ.isError && total > ASSETS_PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, padding: '0 26px 18px' }}>
          <button className="ui-btn sm" disabled={page <= 1} onClick={() => onPageChange(Math.max(1, page - 1))} style={{ opacity: page <= 1 ? 0.5 : 1 }}>
            <Icon name="chevron-left" size={14} />Prev
          </button>
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{page} / {pages}</span>
          <button className="ui-btn sm" disabled={page >= pages} onClick={() => onPageChange(Math.min(pages, page + 1))} style={{ opacity: page >= pages ? 0.5 : 1 }}>
            Next<Icon name="chevron-right" size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
