// The asset page's virtualisation cards (DCIM BUILD_PLAN row 4.2):
//
//   * VM card — a virtual machine's (or cloud instance's) cluster, linked to
//     the cluster page, its vCPUs / memory / disk and its virtual disks; the
//     cluster and resources are editable behind `virtualization.manage`.
//   * Hypervisor card — the cluster the host is in, and the VMs recorded as
//     running on it.
//
// Rendered only for an asset the card applies to. Reading needs
// `virtualization.read`; the page's other cards do not depend on it.
import { useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, MetaRow, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import { PanelError, PanelLoading } from '../dcim/substrate-states';
import {
  clusterHref, cpuText, mbText, memberName, useAssetVirtualization, useUpdateAssetVirtualization, useVirtList, type AssetVirtualization,
} from './virt-queries';

function num(v: string): number | null {
  const t = v.trim();
  if (t === '') return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

function EditVmModal({ assetId, card, onClose }: { assetId: string; card: AssetVirtualization; onClose: () => void }) {
  const clusters = useVirtList('clusters', { limit: 500 });
  const save = useUpdateAssetVirtualization(assetId);
  const [cluster, setCluster] = useState(card.cluster?.id ?? '');
  const [cpus, setCpus] = useState(card.vcpus == null ? '' : String(card.vcpus));
  const [mem, setMem] = useState(card.memory_mb == null ? '' : String(card.memory_mb));
  const [disk, setDisk] = useState(card.disk_mb == null ? '' : String(card.disk_mb));
  const [err, setErr] = useState<string | null>(null);
  const submit = () => {
    setErr(null);
    save.mutateAsync({ cluster_id: cluster || null, vcpus: num(cpus), memory_mb: num(mem), disk_mb: num(disk) })
      .then(onClose, (e: unknown) => setErr(e instanceof Error ? e.message : 'The request failed'));
  };
  return (
    <Modal
      open onClose={onClose} icon="box" title="Edit virtual machine"
      primary={<button type="button" className="ui-btn accent" data-testid="vm-save" disabled={save.isPending} onClick={submit}>{save.isPending ? 'Saving…' : 'Save'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="virt-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 10 }}>{err}</div>}
      <ModalField label="Cluster">
        <ModalSelect aria-label="Cluster" value={cluster} onChange={(e) => setCluster(e.target.value)}>
          <option value="">No cluster</option>
          {(clusters.data?.rows ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="vCPUs"><ModalInput aria-label="vCPUs" type="number" value={cpus} onChange={(e) => setCpus(e.target.value)} /></ModalField>
      <ModalField label="Memory (MB)"><ModalInput aria-label="Memory (MB)" type="number" value={mem} onChange={(e) => setMem(e.target.value)} /></ModalField>
      <ModalField label="Disk (MB)"><ModalInput aria-label="Disk (MB)" type="number" value={disk} onChange={(e) => setDisk(e.target.value)} /></ModalField>
    </Modal>
  );
}

function ClusterLink({ c }: { c: AssetVirtualization['cluster'] }) {
  if (!c) return <span style={{ color: 'var(--app-t3)' }}>Not in a cluster</span>;
  return (
    <Link to={clusterHref(c.id)} data-testid="card-cluster-link" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
      {c.name} <span style={{ color: 'var(--app-t3)' }}>· {c.type_name}</span>
    </Link>
  );
}

function CardBody({ assetId }: { assetId: string }) {
  const q = useAssetVirtualization(assetId);
  const [editing, setEditing] = useState(false);
  if (q.isLoading) return <div style={{ gridColumn: '1 / -1' }}><PanelLoading label="Loading virtualisation…" /></div>;
  if (q.isError) {
    return (
      <div style={{ gridColumn: '1 / -1' }}>
        <SectionLabel icon="boxes">Virtualisation</SectionLabel>
        <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />
      </div>
    );
  }
  const v = q.data;
  if (!v || (!v.is_vm && !v.is_host)) return null;
  return (
    <div style={{ gridColumn: '1 / -1', display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 26 }}>
      {v.is_vm && (
        <div data-testid="vm-card">
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <SectionLabel icon="box">Virtual machine</SectionLabel>
            <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
              <button type="button" className="ui-btn sm ghost" data-testid="edit-vm" style={{ marginLeft: 'auto' }} onClick={() => setEditing(true)}><Icon name="sliders-horizontal" size={13} />Edit</button>
            </PermissionGate>
          </div>
          <MetaRow k="Cluster" v={<ClusterLink c={v.cluster} />} />
          <MetaRow k="vCPUs" v={cpuText(v.vcpus)} mono />
          <MetaRow k="Memory" v={mbText(v.memory_mb)} mono />
          <MetaRow k="Disk" v={mbText(v.disk_mb)} mono />
          <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 6 }}>Virtual disks</div>
          {v.virtual_disks.length === 0
            ? <div data-testid="no-virtual-disks" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '4px 0' }}>None recorded</div>
            : v.virtual_disks.map((d) => <MetaRow key={d.id} k={d.name} v={mbText(d.size_mb)} mono />)}
          {editing && <EditVmModal assetId={assetId} card={v} onClose={() => setEditing(false)} />}
        </div>
      )}
      {v.is_host && (
        <div data-testid="hypervisor-card">
          <SectionLabel icon="server">Hypervisor</SectionLabel>
          <MetaRow k="Cluster" v={<ClusterLink c={v.host_cluster} />} />
          <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 6 }}>Hosted VMs ({v.hosted_vms.length})</div>
          {v.hosted_vms.length === 0
            ? <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '4px 0' }}>No VM is recorded as running on this host</div>
            : v.hosted_vms.map((m) => (
              <div key={m.asset_id} data-testid="hosted-vm" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, padding: '4px 0', borderBottom: '1px solid var(--app-border)' }}>
                <Link to={`/inventory/assets/${m.asset_id}`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>{memberName(m)}</Link>
                <span className="mono" style={{ color: 'var(--app-t3)' }}>{cpuText(m.vcpus)} vCPU · {mbText(m.memory_mb)}</span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

/** The cards, behind `virtualization.read`. */
export function VirtualizationCard({ assetId }: { assetId: string }) {
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.virtualization.read}>
      <CardBody assetId={assetId} />
    </PermissionGate>
  );
}
