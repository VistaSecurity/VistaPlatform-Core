// Inventory → Racks (DCIM row 2.5): every rack with its site › location,
// role, status, height, utilisation, device count and business unit;
// filters by site, location, role and status (the site filter rides in the
// URL, `?site=`, so the site page's Racks card links straight in); a row
// opens the rack page; the list downloads as CSV. Racks are created and
// edited from its management page in the Infrastructure workspace.
import { useMemo } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { downloadCsv } from '../../findings/export-csv';
import { useBusinessUnits } from '../../settings/business-units-queries';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { flattenNodes, useLocations, useSites } from '../sites/sites-queries';
import { UtilisationBar } from './rack-page';
import { RACK_STATUSES, useRackRoles, useRacks, type Rack } from './racks-queries';

const COLS = 'minmax(0,1.1fr) minmax(0,1.5fr) minmax(0,0.8fr) 90px 60px minmax(170px,1.2fr) 64px minmax(0,0.9fr)';

const statusLabel = (s: string) => RACK_STATUSES.find((x) => x.value === s)?.label ?? s;

/** The CSV rows of the list as shown (page-local export, not evidence). */
export function racksCsvRows(rows: readonly Rack[], buName: (id: string | null) => string): (string | number | null)[][] {
  return rows.map((r) => [
    r.name, r.facility_id, r.site?.name ?? '', r.location?.name ?? '', r.role?.name ?? '', statusLabel(r.operational_status),
    r.u_height, r.utilization?.used_units ?? '', r.utilization?.utilization ?? '', r.device_count ?? 0, buName(r.business_unit_id), r.id,
  ]);
}
export const RACKS_CSV_HEADER = ['name', 'facility_id', 'site', 'location', 'role', 'status', 'u_height', 'used_units', 'utilization_pct', 'devices', 'business_unit', 'id'];

export function RacksLens() {
  const [params, setParams] = useSearchParams();
  const siteId = params.get('site') ?? '';
  const locationId = params.get('location') ?? '';
  const roleId = params.get('role') ?? '';
  const status = params.get('status') ?? '';
  const q = useRacks({ siteId: siteId || undefined, locationId: locationId || undefined, roleId: roleId || undefined, status: status || undefined });
  const sites = useSites();
  const locations = useLocations(siteId || undefined, !!siteId);
  const roles = useRackRoles();
  const bus = useBusinessUnits();
  const buName = useMemo(() => {
    const m = new Map((bus.data ?? []).map((b) => [b.id, b.name] as const));
    return (id: string | null) => (id ? m.get(id) ?? '' : '');
  }, [bus.data]);
  const rows = q.data ?? [];
  const filtered = !!(siteId || locationId || roleId || status);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key === 'site') next.delete('location');
    setParams(next, { replace: true });
  };
  const clear = () => {
    const next = new URLSearchParams(params);
    for (const k of ['site', 'location', 'role', 'status']) next.delete(k);
    setParams(next, { replace: true });
  };

  return (
    <div data-testid="racks-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '16px 26px 30px', overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="server" size={17} style={{ color: 'var(--accent)' }} />Racks
        </h1>
        <span data-testid="racks-count" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{q.data ? `${rows.length} ${rows.length === 1 ? 'rack' : 'racks'}` : ''}</span>
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 8 }}>
          <button type="button" className="ui-btn sm" data-testid="racks-export" disabled={rows.length === 0}
            title="Download these rows as CSV"
            onClick={() => downloadCsv(`vista-racks-${new Date().toISOString().slice(0, 10)}.csv`, RACKS_CSV_HEADER, racksCsvRows(rows, buName))}>
            <Icon name="download" size={13} />Export
          </button>
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            <Link to="/inventory/manage/racks" className="ui-btn sm"><Icon name="sliders-horizontal" size={14} />Manage racks</Link>
          </PermissionGate>
        </span>
      </div>

      <div data-testid="racks-filters" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <select aria-label="Site" className="ui-select" value={siteId} onChange={(e) => setFilter('site', e.target.value)}>
          <option value="">All sites</option>
          {(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <select aria-label="Location" className="ui-select" value={locationId} disabled={!siteId} onChange={(e) => setFilter('location', e.target.value)}>
          <option value="">{siteId ? 'All locations' : 'Location (pick a site)'}</option>
          {flattenNodes(locations.data ?? []).map(({ node, depth }) => <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}`}</option>)}
        </select>
        <select aria-label="Role" className="ui-select" value={roleId} onChange={(e) => setFilter('role', e.target.value)}>
          <option value="">All roles</option>
          {(roles.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
        <select aria-label="Status" className="ui-select" value={status} onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">All statuses</option>
          {RACK_STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        {filtered && <button type="button" className="ui-btn sm ghost" onClick={clear}>Clear filters</button>}
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Rack</span><span>Site › Location</span><span>Role</span><span>Status</span><span>Height</span><span>Utilisation</span><span style={{ textAlign: 'right' }}>Devices</span><span>Business unit</span>
        </div>
        {q.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading racks…" /></div>}
        {q.isError && <div style={{ padding: 14 }}><PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} /></div>}
        {q.data && rows.length === 0 && (filtered ? (
          <PanelEmpty icon="filter-x" title="No racks match" message="No rack matches these filters. Clear them to see every rack." />
        ) : (
          <PanelEmpty icon="server" title="No racks yet"
            message="Racks live in a site. Add them from Infrastructure → Racks, then place assets from their Placement card or from the rack page." />
        ))}
        {rows.map((r) => (
          <Link key={r.id} to={`/inventory/racks/${r.id}`} data-testid="rack-row"
            style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '8px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, color: 'var(--app-t1)', textDecoration: 'none' }}>
            <span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {r.name}{r.facility_id ? <span style={{ fontWeight: 400, color: 'var(--app-t3)' }}> · {r.facility_id}</span> : null}
            </span>
            <span style={{ color: 'var(--app-t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.site?.name ?? '—'}{r.location ? ` › ${r.location.name}` : ''}</span>
            <span style={{ color: 'var(--app-t2)' }}>{r.role?.name ?? '—'}</span>
            <span style={{ color: 'var(--app-t3)' }}>{statusLabel(r.operational_status)}</span>
            <span className="mono">{r.u_height}U</span>
            <UtilisationBar used={r.utilization?.used_units ?? 0} total={r.utilization?.total_units ?? r.u_height} pct={r.utilization?.utilization ?? null} />
            <span className="mono" style={{ textAlign: 'right' }}>{r.device_count ?? 0}</span>
            <span style={{ color: 'var(--app-t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{buName(r.business_unit_id) || '—'}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
