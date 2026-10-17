// The cluster page (DCIM BUILD_PLAN row 4.2) — `/inventory/clusters/:id`,
// reached from Inventory → Clusters and from an asset's VM / hypervisor card.
// The cluster, a resources summary over its VMs, its hosts (add / remove
// behind `virtualization.manage`), its VMs with vCPU / memory / disk, and its
// change log and journal.
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalSelect, SectionLabel } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectJournal } from '../dcim/object-journal';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { Chip } from '../ipam/ipam-ui';
import { LIFECYCLE_LABEL } from '../ipam/ipam-queries';
import { useAssetsQuery } from '../asset-queries';
import { clusterFields, scopeText } from './clusters-lens';
import {
  CLUSTER_STATUS_LABEL, cpuText, mbText, memberName, resourceTotals, useCluster, useClusterHosts, useClusterHostWrite, useClusterVms,
  useVirtList, useVirtWrite, type ClusterMember,
} from './virt-queries';
import { VirtDeleteModal, VirtFormModal } from './virt-ui';

const CLUSTERS_LENS = '/inventory?lens=clusters';
const assetName = (m: ClusterMember) => memberName(m);

function AddHostModal({ clusterId, existing, onClose }: { clusterId: string; existing: Set<string>; onClose: () => void }) {
  const candidates = useAssetsQuery('class:hypervisor', 1);
  const { add } = useClusterHostWrite(clusterId);
  const [pick, setPick] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const options = (candidates.data?.assets ?? []).filter((a) => !existing.has(a.id));
  return (
    <Modal
      open onClose={onClose} icon="server" title="Add host"
      description="A host is in one cluster: adding a hypervisor that is in another cluster moves it here."
      primary={(
        <button type="button" className="ui-btn accent" data-testid="add-host-save" disabled={!pick || add.isPending}
          onClick={() => { setErr(null); add.mutateAsync(pick).then(onClose, (e: unknown) => setErr(e instanceof Error ? e.message : 'The request failed')); }}>
          {add.isPending ? 'Adding…' : 'Add'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="virt-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 10 }}>{err}</div>}
      <ModalField label="Hypervisor" hint={candidates.isLoading ? 'Loading hypervisors…' : options.length === 0 ? 'No hypervisor assets to add.' : undefined}>
        <ModalSelect aria-label="Hypervisor" value={pick} onChange={(e) => setPick(e.target.value)}>
          <option value="">Choose a hypervisor</option>
          {options.map((a) => <option key={a.id} value={a.id}>{memberName({ display_name: a.display_name, hostname: a.hostname, asset_id: a.id })}</option>)}
        </ModalSelect>
      </ModalField>
    </Modal>
  );
}

const HOST_GRID = 'minmax(0,1.6fr) minmax(0,1fr) minmax(0,1fr) 90px 40px';
const VM_GRID = 'minmax(0,1.6fr) minmax(0,1fr) 70px 90px 90px 70px';

function HostsTable({ clusterId }: { clusterId: string }) {
  const hosts = useClusterHosts(clusterId);
  const { remove } = useClusterHostWrite(clusterId);
  const [adding, setAdding] = useState(false);
  const rows = hosts.data ?? [];
  return (
    <section data-testid="cluster-hosts">
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <SectionLabel icon="server">Hosts{hosts.data ? ` (${rows.length})` : ''}</SectionLabel>
        <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
          <button type="button" className="ui-btn sm" data-testid="add-host" style={{ marginLeft: 'auto' }} onClick={() => setAdding(true)}><Icon name="plus" size={13} />Add host</button>
        </PermissionGate>
      </div>
      {hosts.isLoading && <PanelLoading label="Loading hosts…" />}
      {hosts.isError && <PanelError message={hosts.error instanceof Error ? hosts.error.message : 'Request failed'} onRetry={() => { void hosts.refetch(); }} />}
      {hosts.data && rows.length === 0 && <PanelEmpty icon="server" title="No hosts recorded" message="Add the hypervisors that run this cluster's VMs, or let a collector that sees the cluster report them." />}
      {rows.length > 0 && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: HOST_GRID, gap: 10, padding: '0 0 5px' }}>
            <span className="eyebrow-app">Host</span><span className="eyebrow-app">Class</span><span className="eyebrow-app">Status</span><span className="eyebrow-app">Source</span><span />
          </div>
          {rows.map((h) => (
            <div key={h.asset_id} data-testid="host-row" style={{ display: 'grid', gridTemplateColumns: HOST_GRID, gap: 10, alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
              <Link to={`/inventory/assets/${h.asset_id}`} style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>{assetName(h)}</Link>
              <span style={{ color: 'var(--app-t2)' }}>{h.class_key}</span>
              <span style={{ color: 'var(--app-t2)' }}>{h.asset_status}</span>
              <span style={{ color: 'var(--app-t3)' }}>{h.source_kind ?? '—'}</span>
              <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
                <button type="button" className="ui-btn sm ghost" title="Remove from the cluster" data-testid="remove-host" style={{ color: 'var(--danger-text)' }}
                  onClick={() => { void remove.mutateAsync(h.asset_id).catch(() => undefined); }}><Icon name="x" size={13} /></button>
              </PermissionGate>
            </div>
          ))}
        </div>
      )}
      {adding && <AddHostModal clusterId={clusterId} existing={new Set(rows.map((r) => r.asset_id))} onClose={() => setAdding(false)} />}
    </section>
  );
}

function VmsSection({ clusterId }: { clusterId: string }) {
  const vms = useClusterVms(clusterId);
  const rows = vms.data ?? [];
  const totals = resourceTotals(rows);
  const known = (k: { total: number; known: number }, text: string) => (k.known === 0 ? '—' : `${text}${k.known < rows.length ? ` (${k.known} of ${rows.length} VMs report it)` : ''}`);
  return (
    <>
      <section data-testid="cluster-resources">
        <SectionLabel icon="gauge">Resources</SectionLabel>
        {vms.isLoading && <PanelLoading label="Loading resources…" />}
        {vms.isError && <PanelError message={vms.error instanceof Error ? vms.error.message : 'Request failed'} onRetry={() => { void vms.refetch(); }} />}
        {vms.data && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0,1fr))', gap: 10 }}>
            {[
              ['Virtual machines', rows.length.toLocaleString()],
              ['vCPUs', known(totals.vcpus, String(Math.round(totals.vcpus.total * 100) / 100))],
              ['Memory', known(totals.memory, mbText(totals.memory.total))],
              ['Disk', known(totals.disk, mbText(totals.disk.total))],
            ].map(([k, v]) => (
              <div key={k} data-testid="resource-tile" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 12px', background: 'var(--app-panel)' }}>
                <div className="eyebrow-app">{k}</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--app-t1)', marginTop: 4 }}>{v}</div>
              </div>
            ))}
          </div>
        )}
      </section>
      <section data-testid="cluster-vms">
        <SectionLabel icon="box">Virtual machines{vms.data ? ` (${rows.length})` : ''}</SectionLabel>
        {vms.data && rows.length === 0 && <PanelEmpty icon="box" title="No virtual machines recorded" message="A VM joins a cluster from its asset page, or when a collector reports where it runs." />}
        {rows.length > 0 && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: VM_GRID, gap: 10, padding: '0 0 5px' }}>
              <span className="eyebrow-app">VM</span><span className="eyebrow-app">Status</span><span className="eyebrow-app" style={{ textAlign: 'right' }}>vCPUs</span>
              <span className="eyebrow-app" style={{ textAlign: 'right' }}>Memory</span><span className="eyebrow-app" style={{ textAlign: 'right' }}>Disk</span><span className="eyebrow-app" style={{ textAlign: 'right' }}>Disks</span>
            </div>
            {rows.map((v) => (
              <div key={v.asset_id} data-testid="vm-row" style={{ display: 'grid', gridTemplateColumns: VM_GRID, gap: 10, alignItems: 'center', padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
                <Link to={`/inventory/assets/${v.asset_id}`} style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>{assetName(v)}</Link>
                <span style={{ color: 'var(--app-t2)' }}>{v.asset_status}</span>
                <span className="mono" style={{ textAlign: 'right' }}>{cpuText(v.vcpus)}</span>
                <span className="mono" style={{ textAlign: 'right' }}>{mbText(v.memory_mb)}</span>
                <span className="mono" style={{ textAlign: 'right' }}>{mbText(v.disk_mb)}</span>
                <span className="mono" style={{ textAlign: 'right' }}>{v.virtual_disk_count ?? 0}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

export function ClusterPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const cluster = useCluster(id);
  const types = useVirtList('cluster-types', { limit: 500 });
  const groups = useVirtList('cluster-groups', { limit: 500 });
  const { update } = useVirtWrite('clusters');
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');
  const c = cluster.data;
  const typeName = c ? (types.data?.rows ?? []).find((t) => t.id === c.type_id)?.name : undefined;
  const groupName = c?.group_id ? (groups.data?.rows ?? []).find((g) => g.id === c.group_id)?.name : undefined;

  return (
    <div data-testid="cluster-page" style={{ display: 'flex', flexDirection: 'column', gap: 18, padding: '4px 0' }}>
      <Link to={CLUSTERS_LENS} style={{ fontSize: 12, color: 'var(--app-t3)', textDecoration: 'none' }}><Icon name="arrow-left" size={12} /> Clusters</Link>
      {cluster.isLoading && <PanelLoading label="Loading the cluster…" />}
      {cluster.isError && <PanelError message={cluster.error instanceof Error ? cluster.error.message : 'Request failed'} onRetry={() => { void cluster.refetch(); }} />}
      {c && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <Icon name="boxes" size={20} style={{ color: 'var(--accent)' }} />
            <h1 data-testid="cluster-name" style={{ margin: 0, fontSize: 19, fontWeight: 700 }}>{c.name}</h1>
            <Chip>{typeName ?? 'Cluster'}</Chip>
            {groupName && <Chip>{groupName}</Chip>}
            <Chip>{CLUSTER_STATUS_LABEL[c.operational_status]}</Chip>
            {c.status !== 'active' && <Chip tone="var(--warn)">{LIFECYCLE_LABEL[c.status]}</Chip>}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
              <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
                {c.status === 'pending' && (
                  <button type="button" className="ui-btn sm accent" data-testid="approve-cluster" onClick={() => { void update.mutateAsync({ id: c.id, body: { status: 'active' } }); }}>
                    <Icon name="check" size={13} />Approve
                  </button>
                )}
                <button type="button" className="ui-btn sm" data-testid="edit-cluster" onClick={() => setEditing(true)}><Icon name="sliders-horizontal" size={13} />Edit</button>
                <button type="button" className="ui-btn sm" data-testid="delete-cluster" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(true)}><Icon name="trash-2" size={13} />Delete</button>
              </PermissionGate>
            </div>
          </div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <span>Scope: <span className="mono">{scopeText(c)}</span></span>
            <span>Source: {c.source_kind}</span>
            {typeof c.external_ids?.cloud === 'string' && <span data-testid="cloud-mirror">Mirror of cloud account + region <span className="mono">{c.external_ids.cloud}</span>, kept for NetBox sync</span>}
            {c.description && <span>{c.description}</span>}
          </div>
          <VmsSection clusterId={c.id} />
          <HostsTable clusterId={c.id} />
          <section>
            <div role="tablist" style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--app-border)' }}>
              {(['changes', 'journal'] as const).map((t) => (
                <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
                  style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
                  {t === 'changes' ? 'Changes' : 'Journal'}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 8 }}>{tab === 'changes' ? <ObjectChanges kind="cluster" id={c.id} /> : <ObjectJournal kind="cluster" id={c.id} />}</div>
          </section>
          {editing && (
            <VirtFormModal route="clusters" title={`Edit ${c.name}`} editId={c.id} fields={clusterFields(types.data?.rows ?? [], groups.data?.rows ?? [])}
              initial={{ name: c.name, type_id: c.type_id, group_id: c.group_id ?? '', operational_status: c.operational_status, description: c.description ?? '' }}
              onClose={() => setEditing(false)} />
          )}
          {deleting && <VirtDeleteModal route="clusters" id={c.id} what={c.name} onClose={() => setDeleting(false)} onDeleted={() => { void navigate(CLUSTERS_LENS); }} />}
        </>
      )}
    </div>
  );
}
