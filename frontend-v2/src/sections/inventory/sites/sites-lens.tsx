// Inventory → Sites (DCIM row 2.1): every site, with its region, group,
// facility and asset count; a row opens the site page. Sites are created and
// edited from its management page in the Infrastructure workspace.
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { SITE_STATUSES, useSites } from './sites-queries';

const COLS = 'minmax(0,1.4fr) minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 110px 70px';

export function SitesLens() {
  const q = useSites();
  const rows = q.data ?? [];
  return (
    <div data-testid="sites-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="building-2" size={17} style={{ color: 'var(--accent)' }} />Sites
        </h1>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{q.data ? `${rows.length} ${rows.length === 1 ? 'site' : 'sites'}` : ''}</span>
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <Link to="/inventory/manage/sites" className="ui-btn sm" style={{ marginLeft: 'auto' }}><Icon name="sliders-horizontal" size={14} />Manage sites</Link>
        </PermissionGate>
      </div>
      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Site</span><span>Region</span><span>Group</span><span>Facility</span><span>Status</span><span style={{ textAlign: 'right' }}>Assets</span>
        </div>
        {q.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading sites…" /></div>}
        {q.isError && <div style={{ padding: 14 }}><PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} /></div>}
        {q.data && rows.length === 0 && (
          <PanelEmpty icon="building-2" title="No sites yet"
            message="Sites are the places your assets live: data centres, offices, colocation suites. Create them from Infrastructure → Sites & locations; a connected cloud account gets one of its own." />
        )}
        {rows.map((s) => (
          <Link key={s.id} to={`/inventory/sites/${s.id}`} data-testid="site-row"
            style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '8px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, color: 'var(--app-t1)', textDecoration: 'none' }}>
            <span style={{ fontWeight: 600 }}>{s.name}</span>
            <span style={{ color: 'var(--app-t2)' }}>{s.region_name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{s.group_name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{s.facility ?? '—'}</span>
            <span style={{ color: 'var(--app-t3)' }}>{SITE_STATUSES.find((x) => x.value === s.operational_status)?.label}</span>
            <span className="mono" style={{ textAlign: 'right' }}>{s.asset_count}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
