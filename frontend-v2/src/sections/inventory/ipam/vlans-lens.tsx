// Inventory → VLANs (DCIM BUILD_PLAN row 1.3): VLAN groups, and the VLANs in
// them with the prefixes each one carries. Picking a VLAN shows its change log
// and journal. Writes are behind `ipam.manage`. A second view lists the VLAN
// translation policies (DCIM gap 10, vlan-translation-view.tsx).
import { useMemo, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectJournal } from '../dcim/object-journal';
import { ExportButton } from '../dcim/export-button';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { LIFECYCLE_LABEL, useIpamList, useIpamWrite, type Vlan, type VlanGroup } from './ipam-queries';
import { Chip, IpamDeleteModal, IpamFormModal, type IpamField } from './ipam-ui';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { fromState, vlanHref } from '../object-pages/object-links';
import { VlanTranslationView } from './vlan-translation-view';

const VLAN_STATUS = [
  { value: 'active', label: 'Active' }, { value: 'reserved', label: 'Reserved' }, { value: 'deprecated', label: 'Deprecated' },
];

function vlanFields(groups: VlanGroup[]): IpamField[] {
  return [
    { name: 'vid', label: 'VLAN ID', kind: 'number', required: true, hint: '1–4094, and inside the group’s VLAN ID ranges.' },
    { name: 'name', label: 'Name', required: true },
    { name: 'group_id', label: 'VLAN group', kind: 'select', options: [{ value: '', label: 'No group' }, ...groups.map((g) => ({ value: g.id, label: g.name }))] },
    { name: 'operational_status', label: 'Status', kind: 'select', options: VLAN_STATUS },
    { name: 'description', label: 'Description' },
  ];
}

const GROUP_FIELDS: IpamField[] = [
  { name: 'name', label: 'Name', required: true },
  { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
  { name: 'description', label: 'Description' },
];

function VlanDetail({ vlan, onClose }: { vlan: Vlan; onClose: () => void }) {
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');
  const { update } = useIpamWrite('vlans');
  const loc = useLocation();
  return (
    <aside data-testid="vlan-panel" style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Link to={vlanHref(vlan.id)} state={fromState(loc)} data-testid="vlan-open-page" title="Open the VLAN page" style={{ color: 'inherit', textDecoration: 'none', display: 'inline-flex', gap: 8 }}>
          <span className="mono" style={{ fontWeight: 700 }}>{vlan.vid}</span><span style={{ fontWeight: 600 }}>{vlan.name}</span>
        </Link>
        <button type="button" className="ui-btn sm ghost" aria-label="Close" style={{ marginLeft: 'auto' }} onClick={onClose}><Icon name="x" size={13} /></button>
      </div>
      <div style={{ fontSize: 12.5, marginTop: 8 }}>
        <span style={{ color: 'var(--app-t3)' }}>Prefixes: </span>
        {(vlan.prefixes ?? []).length === 0 ? 'none' : <span className="mono">{(vlan.prefixes ?? []).join(', ')}</span>}
      </div>
      {/* Custom fields (DCIM row 5.1): edited through the VLAN's PATCH. */}
      <div className="eyebrow-app" style={{ margin: '12px 0 4px' }}>Custom fields</div>
      <CustomFieldsPanel kind="vlan" id={vlan.id} values={vlan.custom_fields} permission={TENANT_PERMISSIONS.ipam.manage}
        onChange={(custom_fields) => update.mutateAsync({ id: vlan.id, body: { custom_fields } })} />
      <div role="tablist" style={{ display: 'flex', gap: 4, marginTop: 12, borderBottom: '1px solid var(--app-border)' }}>
        {(['changes', 'journal'] as const).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
            style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
            {t === 'changes' ? 'Changes' : 'Journal'}
          </button>
        ))}
      </div>
      <div style={{ marginTop: 8 }}>
        {tab === 'changes' ? <ObjectChanges kind="vlan" id={vlan.id} /> : <ObjectJournal kind="vlan" id={vlan.id} />}
      </div>
    </aside>
  );
}

/** The VLANs lens: VLANs by group, or (`view=translation`, DCIM gap 10) the
 *  VLAN translation policies interfaces apply. One lens with two views — the
 *  lens count is audited. */
export function VlansLens() {
  const [params, setParams] = useSearchParams();
  const translation = params.get('view') === 'translation';
  const show = (v: 'vlans' | 'translation') => {
    const n = new URLSearchParams(params);
    for (const k of ['view', 'vlan', 'group', 'policy']) n.delete(k);
    if (v === 'translation') n.set('view', 'translation');
    setParams(n, { replace: true });
  };
  const tabs = (
    <div role="tablist" aria-label="VLAN view" style={{ display: 'flex', gap: 6 }}>
      <button type="button" role="tab" aria-selected={!translation} data-testid="vlans-view-vlans" className={`ui-btn sm${!translation ? ' accent' : ''}`} onClick={() => show('vlans')}>VLANs</button>
      <button type="button" role="tab" aria-selected={translation} data-testid="vlans-view-translation" className={`ui-btn sm${translation ? ' accent' : ''}`} onClick={() => show('translation')}>Translation policies</button>
    </div>
  );
  if (translation) {
    return (
      <div data-testid="vlans-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="layers" size={17} style={{ color: 'var(--accent)' }} />VLANs
          </h1>
          {tabs}
        </div>
        <VlanTranslationView />
      </div>
    );
  }
  return <VlanList tabs={tabs} />;
}

function VlanList({ tabs }: { tabs: ReactNode }) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const loc = useLocation();
  const group = params.get('group') ?? '';
  const selected = params.get('vlan');
  const set = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    setParams(n, { replace: true });
  };
  const groups = useIpamList('vlan-groups', { limit: 1000 });
  const vlans = useIpamList('vlans', group ? { group_id: group, limit: 1000 } : { limit: 1000 });
  const groupNames = useMemo(() => new Map((groups.data?.rows ?? []).map((g) => [g.id, g.name])), [groups.data]);
  const [adding, setAdding] = useState(false);
  const [addingGroup, setAddingGroup] = useState(false);
  const [editing, setEditing] = useState<Vlan | null>(null);
  const [deleting, setDeleting] = useState<Vlan | null>(null);
  const rows = vlans.data?.rows ?? [];
  const sel = rows.find((v) => v.id === selected) ?? null;

  return (
    <div data-testid="vlans-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="layers" size={17} style={{ color: 'var(--accent)' }} />VLANs
        </h1>
        {tabs}
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{vlans.data ? `${vlans.data.total} ${vlans.data.total === 1 ? 'VLAN' : 'VLANs'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <ExportButton kind="vlan" filters={{ group_id: group }} />
          <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
            <button type="button" className="ui-btn sm" data-testid="add-vlan-group" onClick={() => setAddingGroup(true)}><Icon name="plus" size={14} />Add VLAN group</button>
            <button type="button" className="ui-btn sm accent" data-testid="add-vlan" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add VLAN</button>
          </PermissionGate>
        </div>
      </div>

      <div role="tablist" aria-label="VLAN groups" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <button type="button" role="tab" aria-selected={group === ''} className={`ui-btn sm${group === '' ? ' accent' : ''}`} onClick={() => set('group', null)}>All groups</button>
        {(groups.data?.rows ?? []).map((g) => (
          <button key={g.id} type="button" role="tab" aria-selected={group === g.id} data-testid="vlan-group" className={`ui-btn sm${group === g.id ? ' accent' : ''}`} onClick={() => set('group', g.id)}>{g.name}</button>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: sel ? 'minmax(0, 1.5fr) minmax(320px, 1fr)' : '1fr', gap: 14, alignItems: 'start' }}>
        <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '70px 1.2fr 1fr 100px 1.6fr 70px', gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
            <span>VID</span><span>Name</span><span>Group</span><span>Status</span><span>Prefixes</span><span />
          </div>
          {vlans.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading VLANs…" /></div>}
          {vlans.isError && <div style={{ padding: 14 }}><PanelError message={vlans.error instanceof Error ? vlans.error.message : 'Request failed'} onRetry={() => { void vlans.refetch(); }} /></div>}
          {vlans.data && rows.length === 0 && (
            <PanelEmpty icon="layers" title={group ? 'No VLANs in this group' : 'No VLANs yet'}
              message="Add the VLANs you run; a prefix carried on a VLAN shows here. Discovered VLANs arrive pending approval." />
          )}
          {rows.map((v) => (
            <div key={v.id} data-testid="vlan-row" onClick={() => navigate(vlanHref(v.id), { state: fromState(loc) })}
              style={{ display: 'grid', gridTemplateColumns: '70px 1.2fr 1fr 100px 1.6fr 70px', gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: selected === v.id ? 'var(--app-panel2)' : undefined }}>
              <span className="mono" style={{ fontWeight: 600 }}>{v.vid}</span>
              <span>{v.name}{v.status !== 'active' && <> <Chip tone="var(--warn)">{LIFECYCLE_LABEL[v.status]}</Chip></>}</span>
              <span style={{ color: 'var(--app-t2)' }}>{v.group_id ? groupNames.get(v.group_id) ?? '—' : '—'}</span>
              <span><Chip>{v.operational_status}</Chip></span>
              <span className="mono" style={{ color: 'var(--app-t2)', fontSize: 12 }}>{(v.prefixes ?? []).length ? (v.prefixes ?? []).join(', ') : '—'}</span>
              <span style={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
                <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(v)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(v)}><Icon name="trash-2" size={13} /></button>
                </PermissionGate>
              </span>
            </div>
          ))}
        </div>
        {sel && <VlanDetail vlan={sel} onClose={() => set('vlan', null)} />}
      </div>

      {adding && <IpamFormModal route="vlans" icon="layers" title="Add VLAN" fields={vlanFields(groups.data?.rows ?? [])} initial={{ group_id: group, operational_status: 'active' }} onClose={() => setAdding(false)} />}
      {addingGroup && <IpamFormModal route="vlan-groups" icon="layers" title="Add VLAN group" fields={GROUP_FIELDS} onClose={() => setAddingGroup(false)} onSaved={(g) => set('group', g.id)} />}
      {editing && (
        <IpamFormModal route="vlans" icon="layers" title={`Edit VLAN ${editing.vid}`} editId={editing.id} fields={vlanFields(groups.data?.rows ?? [])}
          initial={{ vid: editing.vid, name: editing.name, group_id: editing.group_id ?? '', operational_status: editing.operational_status, description: editing.description ?? '' }}
          onClose={() => setEditing(null)} />
      )}
      {deleting && <IpamDeleteModal route="vlans" id={deleting.id} what={`VLAN ${deleting.vid}`} onClose={() => setDeleting(null)} />}
    </div>
  );
}
