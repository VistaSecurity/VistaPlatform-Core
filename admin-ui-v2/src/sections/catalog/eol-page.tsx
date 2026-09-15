// VISTA Operations — Catalog ▸ End-of-life.
//
// The `eol_catalogue` table: release cycles and the dates their support ends,
// mirrored from endoflife.date and importable from an offline bundle (ADR-0005
// D3, ADR-0006 D7). Platform data — no tenant_id, every tenant is evaluated
// against the same rows — which is why it sits beside Algorithms and Frameworks
// rather than in a tenant surface.
//
// Read-only in this slice. The `eol` PRODUCER — matching a tenant's OS and
// software facts against these rows and raising `os_end_of_life` /
// `software_end_of_life` findings — is part 2 and depends on the phase-1 asset
// rewrite. Nothing on this page claims otherwise.
import { useState } from 'react';
import { CalendarClock, Search } from 'lucide-react';
import { Tag, num } from '../../components/ui/primitives';
import {
  useEolCatalogue, daysUntil, shortDate, FEEDS_FOR, PAGE_SIZE,
  SOURCE_KIND_COLOR, SOURCE_KIND_LABEL,
  type EolEntry, type ProductKind,
} from './catalog-queries';
import { FeedStatusCard } from './feed-status-card';
import { CatalogGapsTab, EolProposalsTab } from './eol-proposals';

const KINDS: { value: ProductKind | ''; label: string }[] = [
  { value: '', label: 'All kinds' },
  { value: 'os', label: 'Operating systems' },
  { value: 'software', label: 'Software' },
  { value: 'hardware', label: 'Hardware' },
];

const KIND_COLOR: Record<string, string> = {
  os: 'var(--info)',
  software: 'var(--op-t2)',
  hardware: 'var(--chart-1)',
};

/**
 * Renders the support-end date and how far away it is.
 *
 * A missing date is "not published", NOT "0 days". endoflife.date says `true`
 * for "support has ended, date unknown" and `false` for "not announced", and the
 * mirror stores both as NULL rather than inventing a date — so this cell has to
 * say so instead of rendering a number derived from nothing.
 */
function EolCell({ entry }: { entry: EolEntry }) {
  const days = daysUntil(entry.eol_date);
  if (days === null) {
    return (
      <span className="t-muted" title="The source publishes no end-of-life date for this cycle.">
        not published
      </span>
    );
  }
  const past = days < 0;
  const soon = !past && days <= 180;
  const color = past ? 'var(--danger)' : soon ? 'var(--warn)' : 'var(--op-t2)';
  return (
    <span style={{ color }}>
      <span className="mono">{shortDate(entry.eol_date)}</span>
      <span style={{ fontSize: 11, marginLeft: 8 }}>
        {past ? `${num(Math.abs(days))}d ago` : `in ${num(days)}d`}
      </span>
    </span>
  );
}

/** The three views of the same catalogue, each its own left-rail sub-route. */
export type EolView = 'catalogue' | 'proposals' | 'gaps';

/**
 * End-of-life, in whichever of its three views the route selected.
 *
 * The views are LEFT-RAIL grandchildren (`/catalog/eol/{catalogue,proposals,gaps}`
 * — see nav.ts), not in-page tabs: sub-navigation in this console lives in the
 * rail, which is what makes each view linkable, bookmarkable and reachable from
 * the command palette. The feed card is above all three because all three are
 * views of what that feed fills.
 */
export function EolPage({ view = 'catalogue' }: { view?: EolView }) {
  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <FeedStatusCard feeds={FEEDS_FOR.eol} title="End-of-life feed" />

      {view === 'catalogue' && <CatalogueView />}
      {view === 'proposals' && <EolProposalsTab />}
      {view === 'gaps' && <CatalogGapsTab />}
    </div>
  );
}

function CatalogueView() {
  const [search, setSearch] = useState('');
  const [kind, setKind] = useState<ProductKind | ''>('');
  const [page, setPage] = useState(1);

  const { data, isLoading, isError, refetch } = useEolCatalogue({ search, kind, page });
  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / (data?.pageSize ?? PAGE_SIZE)));

  // Any filter change resets to page 1 — staying on page 7 of a two-page result
  // shows an empty table that looks like "no data" rather than "no such page".
  const onFilter = (fn: () => void) => { fn(); setPage(1); };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <CalendarClock size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
            End-of-life catalogue
          </span>
          {!isLoading && !isError && (
            <span className="t-muted" style={{ fontSize: 12 }} data-testid="eol-total">{num(total)} cycles</span>
          )}
          <div style={{ flex: 1 }} />
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Search size={14} style={{ color: 'var(--op-t3)' }} />
            <input
              value={search}
              onChange={(e) => onFilter(() => setSearch(e.target.value))}
              placeholder="Search product, vendor, cycle…"
              aria-label="Search the end-of-life catalogue"
              style={{ width: 230, height: 28, padding: '0 9px', fontSize: 12.5, borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
            />
          </label>
          <select
            value={kind}
            aria-label="Filter by product kind"
            onChange={(e) => onFilter(() => setKind(e.target.value as ProductKind | ''))}
            style={{ height: 28, padding: '0 8px', fontSize: 12.5, borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
          >
            {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </div>

        <table className="op-table">
          <thead>
            <tr><th>Product</th><th>Kind</th><th>Vendor</th><th>Cycle</th><th>Released</th><th>Support ends</th><th>Extended</th><th>Source</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>
                  {e.source_url
                    ? <a href={e.source_url} target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>{e.product}</a>
                    : e.product}
                </td>
                <td><Tag color={KIND_COLOR[e.product_kind] ?? 'var(--op-t2)'}>{e.product_kind}</Tag></td>
                <td className="t-muted">
                  {e.vendor ?? <span title="The source does not name a vendor for this product.">unknown</span>}
                </td>
                <td className="mono" style={{ fontSize: 12 }}>{e.cycle}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{shortDate(e.release_date)}</td>
                <td style={{ fontSize: 12 }}><EolCell entry={e} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{shortDate(e.extended_support_date)}</td>
                {/* Where the row came from. `AI-proposed` marks one a model
                    proposed and an admin accepted — it stays on the row forever,
                    and showing it is what stops an accepted proposal reading as
                    a mirrored fact. */}
                <td>
                  <Tag color={SOURCE_KIND_COLOR[e.source_kind] ?? 'var(--op-t2)'}>
                    {SOURCE_KIND_LABEL[e.source_kind] ?? e.source_kind}
                  </Tag>
                </td>
              </tr>
            ))}
            {isLoading && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading the end-of-life catalogue…</td></tr>
            )}
            {isError && !isLoading && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                Couldn't load the end-of-life catalogue.
                <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                {search || kind
                  ? 'No cycles match those filters.'
                  : 'The catalogue is empty. Run the endoflife.date feed above, or import an offline bundle.'}
              </td></tr>
            )}
          </tbody>
        </table>

        {!isLoading && !isError && total > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderTop: '1px solid var(--op-border)' }}>
            <span className="t-muted" style={{ fontSize: 12 }}>Page {data?.page ?? page} of {num(lastPage)}</span>
            <div style={{ flex: 1 }} />
            <button className="op-btn sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
            <button className="op-btn sm" disabled={page >= lastPage} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        )}
      </div>

      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6 }}>
        Source: <a href="https://endoflife.date" target="_blank" rel="noreferrer">endoflife.date</a>, a
        community-maintained dataset, mirrored daily. Rows are stored with
        <span className="mono"> source_kind = imported</span> and the upstream page as their source URL.
      </div>
    </div>
  );
}
