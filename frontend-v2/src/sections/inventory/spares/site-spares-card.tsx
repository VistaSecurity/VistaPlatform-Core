// The site page's Spares card (DCIM gap 8): what is in stock at the site's
// locations — each spare with its location, quantity and state, the unit
// count, and a link to Infrastructure → Spares & RMA. Mounted by site-page.tsx
// with one line. States: loading, error (never "no spares"), empty (none
// recorded here, which is not "this site has none"), the list. Reads need
// dcim.read (the site page's gate); the card has no write controls — stock is
// managed on the Spares & RMA page.
import { Link } from 'react-router';
import { SectionLabel } from '../../../components/ui';
import { PanelError, PanelLoading } from '../dcim/substrate-states';
import { useLocationPaths } from './spare-actions';
import { STOCK_STATE_LABELS, unitCount, useSpares } from './spares-queries';

export function SiteSparesCard({ siteId }: { siteId: string }) {
  const spares = useSpares({ siteId });
  const paths = useLocationPaths();
  const rows = spares.data ?? [];
  return (
    <div data-testid="site-spares-card" style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <SectionLabel icon="package">Spares</SectionLabel>
        <Link to="/inventory/manage/spares" data-testid="site-spares-link" style={{ marginLeft: 'auto', fontSize: 12, marginTop: 14 }}>Spares &amp; RMA</Link>
      </div>
      {spares.isLoading ? <PanelLoading label="Loading spares…" />
        : spares.isError ? <PanelError message={spares.error instanceof Error ? spares.error.message : "Couldn't load the site's spares."} onRetry={() => { void spares.refetch(); }} />
          : rows.length === 0
            ? <div data-testid="site-spares-empty" style={{ fontSize: 12, color: 'var(--app-t3)' }}>No spares are recorded at this site&rsquo;s locations, which says nothing about its shelves. Add them from Infrastructure → Spares &amp; RMA.</div>
            : (
              <>
                <div data-testid="site-spares-units" style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 4 }}>{unitCount(rows)} unit{unitCount(rows) === 1 ? '' : 's'} in {rows.length} row{rows.length === 1 ? '' : 's'}</div>
                {rows.map((i) => (
                  <div key={i.id} data-testid="site-spare" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, padding: '5px 0', borderBottom: '1px solid var(--app-border)' }}>
                    <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{i.name}</span>
                    {i.part_id && i.part_id !== i.name && <span className="mono" style={{ color: 'var(--app-t3)' }}>{i.part_id}</span>}
                    <span style={{ color: 'var(--app-t3)' }}>· {i.location_id ? paths.get(i.location_id) ?? 'a location' : 'no location'}</span>
                    <span className="mono" style={{ marginLeft: 'auto', color: 'var(--app-t2)' }}>×{i.quantity} · {STOCK_STATE_LABELS[i.stock_state]}</span>
                  </div>
                ))}
              </>
            )}
    </div>
  );
}
