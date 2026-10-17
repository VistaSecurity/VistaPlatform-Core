// Settings → Infrastructure → Cluster Types & Groups (DCIM BUILD_PLAN row
// 4.2): the catalogues Inventory → Clusters builds on. Cluster types the
// platform ships (VMware vSphere, Proxmox, Hyper-V, KVM, Nutanix, AWS, Azure,
// GCP, Kubernetes) are listed read-only; the tenant adds its own types and its
// groups. Reading needs `virtualization.read` (the nav entry); every write
// control sits behind `virtualization.manage`.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import type { IpamField } from '../inventory/ipam/ipam-ui';
import { useVirtList, type ClusterGroup, type ClusterType } from '../inventory/virtualization/virt-queries';
import { VirtDeleteModal, VirtFormModal } from '../inventory/virtualization/virt-ui';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const FIELDS: IpamField[] = [
  { name: 'name', label: 'Name', required: true },
  { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
  { name: 'description', label: 'Description' },
];
const COLS: STableCol[] = [{ label: 'Name', w: '1.2fr' }, { label: 'Slug', w: '1fr' }, { label: 'Description', w: '1.6fr' }, { label: '', w: '80px', align: 'right' }];

function Catalog({ route, title, noun, desc }: { route: 'cluster-types' | 'cluster-groups'; title: string; noun: string; desc: string }) {
  const q = useVirtList(route, { limit: 500 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<ClusterType | ClusterGroup | null>(null);
  const [deleting, setDeleting] = useState<ClusterType | ClusterGroup | null>(null);
  const rows: (ClusterType | ClusterGroup)[] = q.data?.rows ?? [];
  return (
    <SSection title={title} desc={desc} action={(
      <PermissionGate permission={TENANT_PERMISSIONS.virtualization.manage}>
        <button type="button" className="ui-btn sm accent" data-testid={`add-${route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {noun}</button>
      </PermissionGate>
    )}>
      <div data-testid={`virt-catalog-${route}`}>
        {q.isLoading && <PanelLoading label={`Loading ${title.toLowerCase()}…`} />}
        {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {q.data && rows.length === 0 && <PanelEmpty icon="boxes" title={`No ${title.toLowerCase()} yet`} message={desc} />}
        {rows.length > 0 && (
          <STable cols={COLS}>
            {rows.map((r, i) => (
              <STableRow key={r.id} first={i === 0} cols={COLS} cells={[
                r.name, <span key="s" className="mono">{r.slug}</span>, r.description ?? '—',
                r.tenant_id == null ? <STag key="p">Built in</STag> : (
                  <PermissionGate key="a" permission={TENANT_PERMISSIONS.virtualization.manage}>
                    <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(r)}><Icon name="sliders-horizontal" size={13} /></button>
                    <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(r)}><Icon name="x" size={13} /></button>
                  </PermissionGate>
                ),
              ]} />
            ))}
          </STable>
        )}
      </div>
      {adding && <VirtFormModal route={route} title={`Add ${noun}`} fields={FIELDS} onClose={() => setAdding(false)} />}
      {editing && (
        <VirtFormModal route={route} title={`Edit ${editing.name}`} editId={editing.id} fields={FIELDS}
          initial={{ name: editing.name, slug: editing.slug, description: editing.description ?? '' }} onClose={() => setEditing(null)} />
      )}
      {deleting && <VirtDeleteModal route={route} id={deleting.id} what={deleting.name} onClose={() => setDeleting(null)} />}
    </SSection>
  );
}

export function VirtualizationSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="virtualization-settings">
        <Catalog route="cluster-types" title="Cluster types" noun="cluster type"
          desc="The technology a cluster runs. The built-in types cover the common hypervisors, Kubernetes and the cloud providers (a cloud account's regions are mirrored as clusters of its provider's type)." />
        <Catalog route="cluster-groups" title="Cluster groups" noun="cluster group"
          desc="Your own grouping of clusters — by data centre, environment or team." />
      </div>
    </SPage>
  );
}
