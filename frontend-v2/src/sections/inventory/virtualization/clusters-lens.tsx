// Inventory → Clusters (DCIM BUILD_PLAN row 4.2; ADR-0010 D8): the tenant's
// clusters — vSphere, Proxmox, Hyper-V, Kubernetes, and each cloud account +
// region mirrored as one — with type, group, scope, host and VM counts and
// status. A row opens the cluster page. Writes are behind
// `virtualization.manage`.
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { Chip } from '../ipam/ipam-ui';
import { LIFECYCLE_LABEL } from '../ipam/ipam-queries';
import type { IpamField } from '../ipam/ipam-ui';
import { CLUSTER_STATUS_LABEL, clusterHref, useVirtList, type Cluster, type ClusterGroup, type ClusterType } from './virt-queries';
import { VirtFormModal } from './virt-ui';

const STATUS_OPTIONS = Object.entries(CLUSTER_STATUS_LABEL).map(([value, label]) => ({ value, label }));

export function clusterFields(types: ClusterType[], groups: ClusterGroup[]): IpamField[] {
  return [
    { name: 'name', label: 'Name', required: true },
    { name: 'type_id', label: 'Cluster type', kind: 'select', required: true, options: [{ value: '', label: 'Choose a type' }, ...types.map((t) => ({ value: t.id, label: t.name }))] },
    { name: 'group_id', label: 'Cluster group', kind: 'select', options: [{ value: '', label: 'No group' }, ...groups.map((g) => ({ value: g.id, label: g.name }))] },
    { name: 'operational_status', label: 'Status', kind: 'select', options: STATUS_OPTIONS },
    { name: 'description', label: 'Description' },
  ];
}

/** A cluster's scope as words: the kind, since the scoped object's own page
 *  arrives with sites (row 2.1). Unscoped is a dash. */
export function scopeText(c: Pick<Cluster, 'scope_kind' | 'scope_id'>): string {
  if (!c.scope_kind || !c.scope_id) return '—';
  return `${c.scope_kind.replace('_', ' ')} ${c.scope_id.slice(0, 8)}`;
}

const CONTROL = { height: 32, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5 } as const;

const GRID = 'minmax(0,1.5fr) minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 70px 70px 130px';

export function ClustersLens() {
  const [params, setParams] = useSearchParams();
  const typeFilter = params.get('type') ?? '';
  const [search, setSearch] = useState('');
  const query: Record<string, string | number> = { limit: 500 };
  if (typeFilter) query.type_id = typeFilter;
  if (search.trim()) query.q = search.trim();
  const clusters = useVirtList('clusters', query);
  const types = useVirtList('cluster-types', { limit: 500 });
  const groups = useVirtList('cluster-groups', { limit: 500 });
  const [adding, setAdding] = useState(false);
  const rows = clusters.data?.rows ?? [];
  const typeOptions = useMemo(() => types.data?.rows ?? [], [types.data]);
  const setType = (v: string) => {
    const n = new URLSearchParams(params);
    if (v) n.set('type', v); else n.delete('type');
    setParams(n, { replace: true });
  };

  return (
    <div data-testid="clusters-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="boxes" size={17} style={{ color: 'var(--accent)' }} />Clusters
        </h1>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{clusters.data ? `${clusters.data.total} ${clusters.data.total === 1 ? 'cluster' : 'clusters'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <select aria-label="Filter by cluster type" data-testid="cluster-type-filter" style={CONTROL} value={typeFilter} onChange={(e) => setType(e.target.value)}>
            <option value="">All types</option>
            {typeOptions.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <input aria-label="Search clusters" style={{ ...CONTROL, width: 200 }} placeholder="Search clusters" value={search} onChange={(e) => setSearch(e.target.value)} />
          <Link to="/inventory/manage/cluster-types" className="ui-btn sm"><Icon name="sliders-horizontal" size={14} />Types &amp; groups</Link>
          <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-cluster" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add cluster</button>
          </PermissionGate>
        </div>
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Name</span><span>Type</span><span>Group</span><span>Scope</span><span style={{ textAlign: 'right' }}>Hosts</span><span style={{ textAlign: 'right' }}>VMs</span><span>Status</span>
        </div>
        {clusters.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading clusters…" /></div>}
        {clusters.isError && <div style={{ padding: 14 }}><PanelError message={clusters.error instanceof Error ? clusters.error.message : 'Request failed'} onRetry={() => { void clusters.refetch(); }} /></div>}
        {clusters.data && rows.length === 0 && (
          <PanelEmpty icon="boxes" title={typeFilter || search ? 'No clusters match' : 'No clusters yet'}
            message="Add the vSphere, Proxmox, Hyper-V or Kubernetes clusters you run. A connected cloud account's regions appear here as clusters; collectors that see a hypervisor's cluster add it pending approval." />
        )}
        {rows.map((c) => (
          <div key={c.id} data-testid="cluster-row"
            style={{ display: 'grid', gridTemplateColumns: GRID, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
            <Link to={clusterHref(c.id)} style={{ fontWeight: 600, color: 'var(--accent)', textDecoration: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.name}</Link>
            <span style={{ color: 'var(--app-t2)' }}>{c.type?.name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{c.group?.name ?? '—'}</span>
            <span className="mono" style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{scopeText(c)}</span>
            <span className="mono" style={{ textAlign: 'right' }}>{(c.host_count ?? 0).toLocaleString()}</span>
            <span className="mono" style={{ textAlign: 'right' }}>{(c.vm_count ?? 0).toLocaleString()}</span>
            <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              <Chip>{CLUSTER_STATUS_LABEL[c.operational_status]}</Chip>
              {c.status !== 'active' && <Chip tone="var(--warn)">{LIFECYCLE_LABEL[c.status]}</Chip>}
            </span>
          </div>
        ))}
      </div>

      {adding && (
        <VirtFormModal route="clusters" title="Add cluster" fields={clusterFields(types.data?.rows ?? [], groups.data?.rows ?? [])}
          initial={{ operational_status: 'active', type_id: typeFilter }} onClose={() => setAdding(false)} />
      )}
    </div>
  );
}
