// Inventory → All assets: the class-faceted list (ADR-0006 D2).
//
// One lens with a class facet replaces the idea of a lens per class — twelve
// classes would have meant twelve near-identical pages. The columns adapt to
// the selected class through the registry in `columns.ts`; the facets adapt to
// the tenant through the server's buckets; and the whole filter state is ONE
// query string in the URL, which is what makes a view shareable and a scope,
// an approval rule and a saved view all the same kind of thing.
import { useEffect, useMemo, useState } from 'react';
import { Link, useHref, useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { Asset } from '@vistasecurity/api-contract';
import { Icon, RiskChip } from '../../components/ui';
import { ASSETS_PAGE_SIZE, AssetQueryError, useAssetFacets, useAssetsQuery } from './asset-queries';
import { assetIdentity, assetRisk, classIcon } from './asset-shape';
import { columnsForClass, gridTemplate, type AssetColumn } from './columns';
import type { OpenAsset } from './drawers';
import { FACET_LEVELS, FacetRail } from './facet-rail';
import { applyFacetChange, queryToFacets, type FacetState } from './facet-query';
import { QueryChip, QueryEditor, ServerQueryErrors } from './query-editor';
import { SavedViews } from './saved-views';
import { IdentityStatus } from './identity-status';
import { IdentityCoverage } from '../discovery/observations-page';
import { NO_SELECTION, isSelected, pageState, toggleRow, togglePage, type AssetSelection } from './asset-selection';
import { activeScanView } from '../discovery/active-scan-row-state';
import { ActiveScanJobsPanel, BulkActionBar, SelectAllBanner, SelectBox, nameFrom, useScanFeed } from './bulk-action-bar';

// The checkbox column sits in front of the class-dependent grid.
const SELECT_COL = '18px';

function Header({ cols, grid, selectState, onSelectPage }: {
  cols: AssetColumn[]; grid: string; selectState: 'none' | 'some' | 'all'; onSelectPage: () => void;
}) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', height: 34, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
      <SelectBox state={selectState} onChange={onSelectPage} label="Select every asset on this page" />
      <span />
      <span className="eyebrow-app">Asset</span>
      {cols.map((c) => (
        <span key={c.key} className="eyebrow-app" style={{ textAlign: c.numeric ? 'right' : 'left' }}>{c.label}</span>
      ))}
    </div>
  );
}

/** A person's scan of this asset that is running, or whose last run failed —
 * the two states the retired Active Scan page showed per row. A
 *  completed scan needs no badge: its results are the row. */
function ScanBadge({ asset }: { asset: Asset }) {
  const view = activeScanView(asset);
  if (view.kind !== 'scanning' && view.kind !== 'failed') return null;
  const scanning = view.kind === 'scanning';
  return (
    <span
      title={scanning ? 'An active scan of this asset is running' : 'The last active scan did not reach this asset'}
      style={{ flex: 'none', fontSize: 10.5, fontWeight: 600, borderRadius: 40, padding: '1px 7px', color: scanning ? 'var(--info)' : 'var(--danger-text)', background: `color-mix(in srgb, ${scanning ? 'var(--info)' : 'var(--danger)'} 12%, transparent)` }}
    >
      {scanning ? 'Scanning…' : 'Last scan failed'}
    </span>
  );
}

// A plain left click is the peek; everything a browser means by "open this
// somewhere else" (a modifier key, or the middle button) is not ours to take.
function isPlainClick(e: React.MouseEvent): boolean {
  return e.button === 0 && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey;
}

/**
 * One row of the list.
 *
 * A click opens the asset DRAWER, the peek from a list (ADR-0006 D3), seeded
 * with the row so its header paints before the detail read returns. The full
 * page stays one click further: the drawer's "Open full page", and the name
 * here, which is a real link so a new tab, a copied address and a middle click
 * all do what a browser does with one. The link is also the keyboard target,
 * which is why the row itself is not a second tab stop.
 */
function AssetRow({ asset, cols, grid, onOpen, selected, onToggle }: {
  asset: Asset; cols: AssetColumn[]; grid: string; onOpen: OpenAsset; selected: boolean; onToggle: () => void;
}) {
  const ident = assetIdentity(asset);
  const risk = assetRisk(asset);
  const href = useHref(`/inventory/assets/${asset.id}`);
  // The rest of the row is a bigger target for the same link, so it answers a
  // modified click the way the link would. The link has already decided its
  // own clicks, hence the `closest('a')` guard.
  const outsideLink = (e: React.MouseEvent) => !(e.target as HTMLElement).closest('a');
  return (
    <div
      className="row-hover"
      onClick={(e) => {
        if (!outsideLink(e)) return;
        if (isPlainClick(e)) onOpen(asset.id, asset);
        else window.open(href, '_blank', 'noopener');
      }}
      onAuxClick={(e) => {
        if (e.button !== 1 || !outsideLink(e)) return;
        e.preventDefault();
        window.open(href, '_blank', 'noopener');
      }}
      aria-selected={selected}
      style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer', background: selected ? 'color-mix(in srgb, var(--accent) 6%, transparent)' : undefined }}
    >
      <SelectBox state={selected ? 'all' : 'none'} onChange={onToggle} label={`Select ${ident.primary}`} />
      <RiskChip level={risk.level} assessed={risk.assessed} size={22} title={risk.title} />
      <div style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name={classIcon(asset.class_key)} size={14} style={{ color: 'var(--app-t3)', flex: 'none' }} />
        <div style={{ minWidth: 0 }}>
          <Link
            to={`/inventory/assets/${asset.id}`}
            onClick={(e) => { if (isPlainClick(e)) { e.preventDefault(); onOpen(asset.id, asset); } }}
            // A link answers Enter by itself; the row answered Space too, and
            // keyboard users should not lose that.
            onKeyDown={(e) => { if (e.key === ' ') { e.preventDefault(); onOpen(asset.id, asset); } }}
            style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', textDecoration: 'none', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
          >
            {ident.primary}
          </Link>
          <IdentityStatus asset={asset} />
          <ScanBadge asset={asset} />
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

export function AssetsLens({ query, onQueryChange, page, onPageChange, pendingCount, onNewAsset, onImport, onOpenAsset }: {
  query: string;
  onQueryChange: (q: string) => void;
  page: number;
  onPageChange: (p: number) => void;
  pendingCount: number;
  onNewAsset: () => void;
  onImport?: () => void;
  // Stacks the asset drawer. The hosting page owns the drawer stack, and the
  // Edit modal the drawer opens, so the list only says which asset was asked for.
  onOpenAsset: OpenAsset;
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

  const assets = useMemo(() => assetsQ.data?.assets ?? [], [assetsQ.data]);
  const total = assetsQ.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / ASSETS_PAGE_SIZE));

  const cols = useMemo(() => columnsForClass(read.facets.class), [read.facets.class]);
  const grid = useMemo(() => gridTemplate(cols), [cols]);
  const rowGrid = `${SELECT_COL} ${grid}`;

  // The selection. It belongs to the query it was made under: a new
  // query is a different list, so ticked rows and "all N matching" both reset.
  // Kept with the query it was made under and read as empty under any other.
  const [made, setMade] = useState<{ query: string; selection: AssetSelection }>({ query, selection: NO_SELECTION });
  const selection = made.query === query ? made.selection : NO_SELECTION;
  const setSelection = (next: AssetSelection | ((s: AssetSelection) => AssetSelection)) =>
    setMade((m) => {
      const current = m.query === query ? m.selection : NO_SELECTION;
      return { query, selection: typeof next === 'function' ? next(current) : next };
    });
  const pageIds = useMemo(() => assets.map((a) => a.id), [assets]);
  // Every row this lens has shown, so ticked rows from earlier pages can be
  // exported and named in the "not scanned" list.
  // One Map for the lens's lifetime, filled as pages arrive; never replaced,
  // so its identity is stable for the bar and the feed.
  const [seen] = useState(() => new Map<string, Asset>());
  useEffect(() => { assets.forEach((a) => seen.set(a.id, a)); }, [assets, seen]);
  const feed = useScanFeed(useMemo(() => nameFrom(seen), [seen]));

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
        <SelectAllBanner selection={selection} pageIds={pageIds} total={total} query={query} queryable onChange={setSelection} />
        <Header cols={cols} grid={rowGrid} selectState={pageState(selection, pageIds)} onSelectPage={() => setSelection((s) => togglePage(s, pageIds))} />
        {assets.map((a) => (
          <AssetRow
            key={a.id}
            asset={a}
            cols={cols}
            grid={rowGrid}
            onOpen={onOpenAsset}
            selected={isSelected(selection, a.id)}
            onToggle={() => setSelection((s) => toggleRow(s, a.id, pageIds))}
          />
        ))}
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

      <BulkActionBar selection={selection} onChange={setSelection} seen={seen} onScanStarted={feed.record} />
      {(feed.scans.length > 0 || feed.skipped.length > 0) && (
        <div style={{ margin: '0 26px' }}>
          <ActiveScanJobsPanel
            scans={feed.scans}
            skipped={feed.skipped}
            onDismiss={feed.clear}
            // A scan this lens started has ended: re-read the list so its
            // rows (and the never-scanned view) show what the scan did.
            onScanSettled={() => { void assetsQ.refetch(); }}
          />
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
