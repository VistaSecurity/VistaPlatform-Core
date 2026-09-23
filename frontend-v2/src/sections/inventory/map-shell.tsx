// The Map lens's views (ADR-0006 D4, workstream 3.8).
//
//   - **Network** — every device by site and network, badged by the crypto it
// serves, with any device explodable into its services. The
//     default when nothing is focused.
//   - **Neighbourhood** — the interactive graph around one asset (2.9). Any
//     URL carrying `focus=` still opens here.
//   - **Topology** — the site → segment → class tree with counts (3.8).
//
// This shell owns only the switch between them and the `?view=` parameter that
// makes each one a link somebody can paste into a ticket. It holds no data and
// no layout of its own, so no view has to know the others exist.
//
// Every view is LAZY. The neighbourhood pulls in `@xyflow/react` and `dagre`,
// which is the reason the map lens was code-split in the first place; the
// others pull in nothing heavy, but there is no reason to ship them to someone
// who never opens them. A user who never opens the map downloads none of them.
import { Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router';
import { Icon } from '../../components/ui';
import { MAP_VIEWS, readMapView, type MapView } from './topology-model';

const AssetMapLens = lazy(() => import('./map-lens').then((m) => ({ default: m.AssetMapLens })));
const TopologyView = lazy(() => import('./topology-view').then((m) => ({ default: m.TopologyView })));
const NetworkMapView = lazy(() => import('./network-map-view').then((m) => ({ default: m.NetworkMapView })));

/** What each view is called, and what it answers. The sub-label is the whole
 *  point of having two: the names alone do not say which question is which. */
const VIEW_META: Readonly<Record<MapView, { label: string; icon: string; hint: string }>> = {
  network: {
    label: 'Network',
    icon: 'network',
    hint: 'Every device by site and network, and the crypto each one serves.',
  },
  neighbourhood: {
    label: 'Neighbourhood',
    icon: 'waypoints',
    hint: 'What one asset is attached to, out to three hops.',
  },
  topology: {
    label: 'Topology',
    icon: 'map',
    hint: 'Where everything is — by site, segment and class.',
  },
};

export function MapShell() {
  const [params, setParams] = useSearchParams();
  const view = readMapView(params.get('view'), params.has('focus'));

  const setView = (next: MapView) => {
    const p = new URLSearchParams(params);
    // The view the URL would imply anyway is left OUT of it rather than written
    // in, so `/inventory?lens=map` stays the estate and an old `focus=` link
    // stays a neighbourhood, and switching tabs does not churn shared links.
    if (next === readMapView(null, p.has('focus'))) p.delete('view'); else p.set('view', next);
    setParams(p, { replace: true });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }} data-testid="map-shell">
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '14px 26px 10px', flexWrap: 'wrap' }}>
        <div style={{ display: 'inline-flex', borderRadius: 9, border: '1px solid var(--app-border2)', overflow: 'hidden' }} role="tablist">
          {MAP_VIEWS.map((key) => {
            const meta = VIEW_META[key];
            const active = view === key;
            return (
              <button
                key={key}
                role="tab"
                aria-selected={active}
                data-testid={`map-view-${key}`}
                onClick={() => setView(key)}
                title={meta.hint}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '6px 13px', fontSize: 12.5, cursor: 'pointer', border: 'none',
                  background: active ? 'var(--accent-soft, var(--app-panel2))' : 'transparent',
                  color: active ? 'var(--app-t1)' : 'var(--app-t3)',
                  fontWeight: active ? 650 : 400,
                }}
              >
                <Icon name={meta.icon} size={13} />{meta.label}
              </button>
            );
          })}
        </div>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{VIEW_META[view].hint}</span>
      </div>

      <Suspense
        fallback={
          <div data-testid="map-chunk-loading" style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '40px 26px', fontSize: 12.5, color: 'var(--app-t3)' }}>
            <Icon name="loader" size={15} />Loading the map…
          </div>
        }
      >
        {view === 'topology' ? <TopologyView /> : view === 'network' ? <NetworkMapView /> : <AssetMapLens />}
      </Suspense>
    </div>
  );
}
