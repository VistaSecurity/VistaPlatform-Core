// Dashboard · FACILITIES — capacity across the estate.
//
// The question this page answers is the facilities operator's: *where is there
// room, and what is about to run out?* Rack and prefix utilisation exist per
// object; this reads them as a roll-up — free U per site, switch interfaces
// with the least headroom, prefixes nearing full, and how long planned cables
// have been waiting, which racks draw more than their power feeds supply (row
// 6.2) — all from ONE read (`GET /dcim/capacity`), so every tile
// and panel is the same snapshot.
//
// Honesty: a failed request is an error state, never a row of zeros; "no
// addresses recorded" is stated beside the prefix figures instead of being
// folded into "0 % full". Every number links to the list that counted it.
import { useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import {
  BandHeading, DashboardHeader, DashboardShell, Grid, PageError, Panel, PanelLink, PanelNote, StatTile,
} from './dashboard-bits';
import { useCapacity } from './facilities-queries';
import {
  NETWORKS_HREF, RACKS_HREF, ageText, assetPortsHref, cableHref, cablingHref, fillColor, fmtPct, fmtSize, fmtUnits,
  isEmptyEstate, prefixHref, rackHref, racksHref, sortSites, type SiteSortKey, type SortDir,
} from './facilities-dashboard-metrics';

export function FacilitiesDashboardPage() {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={
        <DashboardShell testId="facilities-dashboard">
          <PageError title="Facilities capacity needs the data-centre read permission" message="Ask a tenant administrator for dcim.read to see rack, port and address capacity." />
        </DashboardShell>
      }
    >
      <FacilitiesBody />
    </PermissionGate>
  );
}

function FillBar({ pct }: { pct: number }) {
  return (
    <div style={{ flex: 1, minWidth: 60, height: 12, borderRadius: 4, background: 'var(--app-track)', overflow: 'hidden' }}>
      <div style={{ width: Math.min(100, Math.max(pct, 0)) + '%', height: '100%', background: fillColor(pct), minWidth: pct > 0 ? 3 : 0 }} />
    </div>
  );
}

const row: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none', padding: '4px 0' };
const label: React.CSSProperties = { fontSize: 12, color: 'var(--app-t2)', width: 150, flex: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };
const num: React.CSSProperties = { fontSize: 12, color: 'var(--app-t2)', textAlign: 'right' };

function FacilitiesBody() {
  const q = useCapacity();
  const [sortKey, setSortKey] = useState<SiteSortKey>('utilization');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  if (q.isError) {
    return (
      <DashboardShell testId="facilities-dashboard">
        <PageError title="Couldn't load the Facilities dashboard" message="The capacity roll-up failed. Check that inventory-service is reachable." />
      </DashboardShell>
    );
  }

  const r = q.data;
  const loading = q.isLoading || !r;
  const empty = !!r && isEmptyEstate(r);

  const header = (
    <DashboardHeader
      icon="building-2"
      title="Facilities"
      blurb="Rack space, port and address capacity, and the cabling backlog. Every figure links to the list it counted."
    />
  );

  if (r && empty) {
    return (
      <DashboardShell testId="facilities-dashboard">
        {header}
        <div className="panel fade-up" style={{ padding: '44px 24px', textAlign: 'center' }}>
          <Icon name="server" size={26} style={{ color: 'var(--accent)' }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>Nothing to roll up yet</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 4, marginBottom: 14 }}>
            No racks, switches, prefixes or cables are recorded. Add racks and place devices in them, or let discovery find the network.
          </div>
          <PanelLink to={RACKS_HREF}>Go to Racks</PanelLink>
        </div>
      </DashboardShell>
    );
  }

  const tile = (n: number | undefined) => (loading || n === undefined ? null : n);
  const sites = r ? sortSites(r.sites, sortKey, sortDir) : [];
  const toggle = (k: SiteSortKey) => {
    if (k === sortKey) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else { setSortKey(k); setSortDir(k === 'site_name' ? 'asc' : 'desc'); }
  };
  const th = (k: SiteSortKey, text: string, align: 'left' | 'right' = 'right') => (
    <th aria-sort={k === sortKey ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} style={{ textAlign: align, padding: '4px 8px', fontWeight: 600 }}>
      <button type="button" onClick={() => toggle(k)} style={{ all: 'unset', cursor: 'pointer', color: 'var(--app-t3)', fontSize: 11 }}>
        {text}{k === sortKey ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''}
      </button>
    </th>
  );

  return (
    <DashboardShell testId="facilities-dashboard">
      {header}

      {/* ---------- TILES ---------- */}
      <div className="fade-up" style={{ marginBottom: 18 }}>
        <Grid min={170} gap={11}>
          <StatTile value={tile(r?.rack_totals.free_units)} label="Free rack space" sub="U unused and unreserved" icon="server" tone="var(--accent)" href={RACKS_HREF} />
          <StatTile value={tile(r?.rack_totals.racks_over_95)} label="Racks over 95%" sub="nearly full" icon="alert-triangle" tone="var(--danger-text)" href={RACKS_HREF} />
          <StatTile value={tile(r?.rack_totals.racks_over_power_budget)} label="Racks over power budget"
            sub={r ? `of ${r.rack_totals.racks_with_power} with power feeds` : 'draw over feed capacity'} icon="zap" tone="var(--danger-text)" href={RACKS_HREF} />
          <StatTile value={tile(r?.prefixes.over_95)} label="Prefixes over 95%" sub="addresses nearly used up" icon="network" tone="var(--danger-text)" href={NETWORKS_HREF} />
          <StatTile value={tile(r?.cables.planned_over_90_days)} label="Planned cables over 90 days" sub="waiting to be connected" icon="clock" tone="var(--warn-strong)" href={cablingHref('planned')} />
          <StatTile value={tile(r?.ports.free)} label="Free switch interfaces" sub="enabled and uncabled" icon="ethernet-port" tone="var(--accent)" />
        </Grid>
      </div>

      {/* ---------- RACK SPACE ---------- */}
      <div className="fade-up" style={{ marginBottom: 18 }}>
        <BandHeading title="Rack space" note="free U per site, and the fullest racks" />
        <Grid min={420}>
          <Panel
            icon="building-2" title="Site capacity" testId="facilities-panel-sites" loading={loading}
            empty={sites.length === 0} emptyText="No site has racks yet."
            caption={r && r.sites_total > r.sites.length ? `Showing the ${r.sites.length} fullest of ${r.sites_total} sites.` : 'Used U over usable U; reserved space is not free.'}
            footer={<PanelLink to={RACKS_HREF}>Open Racks</PanelLink>}
          >
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr>{th('site_name', 'Site', 'left')}{th('racks', 'Racks')}{th('free_units', 'Free')}{th('utilization', 'Used')}{th('racks_over_95', 'Over 95%')}{th('racks_over_power_budget', 'Over power')}</tr>
                </thead>
                <tbody>
                  {sites.map((s) => (
                    <tr key={s.site_id} data-testid="facilities-site-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                      <td style={{ padding: '5px 8px' }}><Link to={racksHref(s.site_id)} style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>{s.site_name}</Link></td>
                      <td className="mono" style={{ ...num, padding: '5px 8px' }}>{s.racks}</td>
                      <td className="mono" style={{ ...num, padding: '5px 8px' }}>{fmtUnits(s.free_units)}{s.reserved_units > 0 ? <span style={{ color: 'var(--app-t3)' }}> ({fmtUnits(s.reserved_units)} reserved)</span> : null}</td>
                      <td className="mono" style={{ ...num, padding: '5px 8px', color: fillColor(s.utilization) }}>{fmtPct(s.utilization)}</td>
                      <td className="mono" style={{ ...num, padding: '5px 8px' }}>{s.racks_over_95}</td>
                      <td className="mono" data-testid="facilities-site-power" style={{ ...num, padding: '5px 8px', color: s.racks_over_power_budget > 0 ? 'var(--danger-text)' : undefined }}
                        title={s.racks_with_power ? `${s.racks_over_power_budget} of ${s.racks_with_power} racks with power feeds` : 'No rack here has a power feed declared'}>
                        {s.racks_with_power ? s.racks_over_power_budget : <span style={{ color: 'var(--app-t3)' }}>—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel
            icon="server" title="Fullest racks" testId="facilities-panel-racks" loading={loading}
            empty={!r || r.racks_top.length === 0} emptyText="No rack has any space used yet."
            caption="The ten most-used racks across every site."
          >
            {r?.racks_top.map((k) => (
              <Link key={k.rack_id} to={rackHref(k.rack_id)} style={row} data-testid="facilities-rack-row">
                <span style={label} title={`${k.rack_name} · ${k.site_name}`}>{k.rack_name} <span style={{ color: 'var(--app-t3)' }}>· {k.site_name}</span></span>
                <FillBar pct={k.utilization} />
                <span className="mono" style={{ ...num, width: 52, color: fillColor(k.utilization) }}>{fmtPct(k.utilization)}</span>
              </Link>
            ))}
          </Panel>
        </Grid>
      </div>

      {/* ---------- PORTS AND ADDRESSES ---------- */}
      <div className="fade-up" style={{ marginBottom: 18 }}>
        <BandHeading title="Ports and addresses" note="what is about to run out" />
        <Grid min={420}>
          <Panel
            icon="ethernet-port" title="Switches with the fewest free interfaces" testId="facilities-panel-ports" loading={loading}
            empty={!r || r.ports.fewest_free.length === 0} emptyText="No switch has interfaces recorded."
            caption={r ? `${r.ports.switches.toLocaleString()} switches · ${r.ports.cabled.toLocaleString()} cabled · ${r.ports.marked_connected.toLocaleString()} marked connected` : undefined}
          >
            {r?.ports.fewest_free.map((w) => (
              <Link key={w.asset_id} to={assetPortsHref(w.asset_id)} style={row} data-testid="facilities-switch-row">
                <span style={label} title={w.name}>{w.name}</span>
                <FillBar pct={w.total > 0 ? ((w.total - w.free) / w.total) * 100 : 0} />
                <span className="mono" style={{ ...num, width: 92 }}>{w.free} free of {w.total}</span>
              </Link>
            ))}
          </Panel>

          <Panel
            icon="network" title="Fullest prefixes" testId="facilities-panel-prefixes" loading={loading}
            empty={!r || r.prefixes.fullest.length === 0}
            emptyText={r && r.prefixes.total > 0 ? 'No prefix has addresses recorded yet.' : 'No prefixes recorded.'}
            caption={r ? `${r.prefixes.over_80} over 80% · ${r.prefixes.over_95} over 95% · ${r.prefixes.no_addresses_recorded} with no addresses recorded` : undefined}
            footer={<PanelLink to={NETWORKS_HREF}>Open Networks</PanelLink>}
          >
            {r?.prefixes.fullest.map((p) => (
              <Link key={p.prefix_id} to={prefixHref(p.prefix_id)} style={row} data-testid="facilities-prefix-row">
                <span style={label} title={`${p.prefix} · ${p.vrf_name ?? 'Global'}`}>{p.prefix} <span style={{ color: 'var(--app-t3)' }}>· {p.vrf_name ?? 'Global'}</span></span>
                <FillBar pct={p.utilization} />
                <span className="mono" style={{ ...num, width: 52, color: fillColor(p.utilization) }}>{fmtPct(p.utilization)}</span>
                <span className="mono" style={{ ...num, width: 70, color: 'var(--app-t3)' }}>{p.ip_count.toLocaleString()} / {fmtSize(p.size)}</span>
              </Link>
            ))}
          </Panel>
        </Grid>
      </div>

      {/* ---------- CABLING BACKLOG ---------- */}
      <div className="fade-up">
        <BandHeading title="Cabling backlog" note="planned work that is ageing, and cables nothing has confirmed" />
        <Grid min={420}>
          <Panel
            icon="cable" title="Cables by status" testId="facilities-panel-cables" loading={loading}
            empty={false}
            caption="Live cables. Proposals from LLDP / CDP wait for approval in Discovery."
          >
            {r && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {([
                  ['Connected', r.cables.by_status.connected, cablingHref('connected')],
                  ['Planned', r.cables.by_status.planned, cablingHref('planned')],
                  ['Decommissioning', r.cables.by_status.decommissioning, cablingHref('decommissioning')],
                  ['Proposed, awaiting approval', r.cables.proposed_pending, cablingHref('pending')],
                ] as const).map(([name, n, href]) => (
                  <Link key={name} to={href} style={row} data-testid="facilities-cable-status">
                    <span style={{ ...label, width: 190 }}>{name}</span>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{n.toLocaleString()}</span>
                  </Link>
                ))}
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', paddingTop: 6 }}>
                  {r.cables.declared_never_confirmed.toLocaleString()} declared {r.cables.declared_never_confirmed === 1 ? 'cable has' : 'cables have'} never been confirmed by LLDP / CDP.
                </div>
              </div>
            )}
          </Panel>

          <Panel
            icon="clock" title="Oldest planned cables" testId="facilities-panel-backlog" loading={loading}
            empty={!r || r.cables.oldest_planned.length === 0} emptyText="No planned cable is older than 30 days."
            caption={r ? `${r.cables.planned_over_30_days} planned over 30 days · ${r.cables.planned_over_90_days} over 90 days` : undefined}
            footer={<PanelLink to={cablingHref('planned')}>Open planned cables</PanelLink>}
          >
            {r?.cables.oldest_planned.map((c) => (
              <Link key={c.cable_id} to={cableHref(c.cable_id)} style={row} data-testid="facilities-backlog-row">
                <span style={{ ...label, width: 200 }}>{c.label ?? 'Unlabelled cable'}</span>
                <span className="mono" style={{ ...num, color: c.age_days > 90 ? 'var(--danger-text)' : 'var(--warn-strong)' }}>{ageText(c.age_days)}</span>
              </Link>
            ))}
          </Panel>
        </Grid>
      </div>
      {r && <PanelNote>Computed {new Date(r.generated_at).toLocaleString()}.</PanelNote>}
    </DashboardShell>
  );
}
