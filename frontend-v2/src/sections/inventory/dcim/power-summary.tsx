// The asset's power summary on the Ports tab (DCIM BUILD_PLAN row 6.1;
// ADR-0010 D9): what its power ports declare they draw, where each port's
// cable path ends (a PDU outlet, or the power feed beyond the PDU), what a
// PDU's outlets on each inlet feed, and the feeds the asset reaches with their
// available power. Reads GET /dcim/assets/{id}/power.
//
// States: loading, error (never shown as "no power"), empty (no power ports or
// outlets reported or declared), and the summary. A draw that was not declared
// is "not recorded", never 0 W: totals say how many ports declared one.
import { Link } from 'react-router';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import { useAssetPower, type AssetPowerSummary } from './component-queries';

type Endpoint = NonNullable<AssetPowerSummary['power_ports'][number]['endpoint']>;

/** "350 W", or "not recorded" for a draw nobody declared. */
export function drawText(w: number | null | undefined): string {
  return w == null ? 'not recorded' : `${w} W`;
}

/** "Panel 1:Feed A", "pdu-1:Outlet 3". */
export function endpointText(e: Endpoint): string {
  const owner = e.kind === 'power_feed' ? e.power_panel_name : e.asset_name;
  return owner ? `${owner}:${e.name ?? '?'}` : (e.name ?? '?');
}

function EndpointLink({ e }: { e: Endpoint }) {
  const text = endpointText(e);
  if (e.kind !== 'power_feed' && e.asset_id) {
    return <Link to={`/inventory/assets/${e.asset_id}/ports`} className="mono" style={{ color: 'var(--accent)' }}>{text}</Link>;
  }
  return <span className="mono">{text}</span>;
}

export function PowerSummary({ assetId }: { assetId: string }) {
  const q = useAssetPower(assetId);
  if (q.isLoading) return <div data-testid="power-summary"><PanelLoading label="Loading the asset's power…" /></div>;
  if (q.isError) {
    return (
      <div data-testid="power-summary">
        <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />
      </div>
    );
  }
  const s = q.data!;
  if (s.power_ports.length === 0 && s.power_outlets.length === 0) {
    return (
      <div data-testid="power-summary">
        <PanelEmpty icon="plug-zap" title="No power recorded" message="This asset has no power ports or outlets reported or declared, so nothing is known about what it draws or feeds." />
      </div>
    );
  }
  const t = s.totals;
  const ports = s.power_ports.length;
  return (
    <div data-testid="power-summary" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 13px', marginBottom: 12, fontSize: 12.5 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <Icon name="plug-zap" size={14} style={{ color: 'var(--accent)' }} />
        <strong style={{ color: 'var(--app-t1)' }}>Power</strong>
        <span data-testid="power-totals" style={{ color: 'var(--app-t2)' }}>
          {ports} power port{ports === 1 ? '' : 's'}
          {t.recorded_count > 0
            ? ` · maximum ${t.maximum_draw} W · allocated ${t.allocated_draw} W (declared on ${t.recorded_count} of ${ports})`
            : ports > 0 ? ' · no draw declared' : ''}
          {s.power_outlets.length > 0 ? ` · ${s.power_outlets.length} outlet${s.power_outlets.length === 1 ? '' : 's'}` : ''}
        </span>
      </div>
      {s.feeds.length > 0 && (
        <div data-testid="power-feeds" style={{ color: 'var(--app-t2)', marginBottom: 4 }}>
          <span style={{ color: 'var(--app-t3)' }}>Fed by </span>
          {s.feeds.map((f, i) => (
            <span key={f.id} data-testid="power-feed">
              {i > 0 ? ', ' : ''}<span className="mono">{f.power_panel_name}:{f.name}</span>
              {' '}({f.available_power} VA available, {f.voltage} V {f.phase}{f.operational_status !== 'active' ? `, ${f.operational_status}` : ''})
            </span>
          ))}
        </div>
      )}
      {s.power_ports.map((p) => (
        <div key={p.id} data-testid="power-port-line" style={{ color: 'var(--app-t2)', padding: '1px 0' }}>
          <span className="mono" style={{ display: 'inline-block', minWidth: 110, fontWeight: 600, color: 'var(--app-t1)' }}>{p.name}</span>
          {p.endpoint
            ? <>reaches <EndpointLink e={p.endpoint} /></>
            : p.cable_id ? <span style={{ color: 'var(--warn)' }}>cabled, but the path does not reach a feed or outlet</span>
              : p.mark_connected ? 'marked connected (cable not modelled)' : <span style={{ color: 'var(--app-t3)' }}>not cabled</span>}
          {p.downstream.outlet_count > 0 && (
            <span data-testid="power-downstream" style={{ color: 'var(--app-t3)' }}>
              {' '}· feeds {p.downstream.connected_count} of {p.downstream.outlet_count} outlet{p.downstream.outlet_count === 1 ? '' : 's'}
              {p.downstream.recorded_count > 0 ? `, drawing ${p.downstream.allocated_draw} W allocated / ${p.downstream.maximum_draw} W maximum` : ''}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
