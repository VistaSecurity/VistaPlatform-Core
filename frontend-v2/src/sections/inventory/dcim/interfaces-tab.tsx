// The asset page's Interfaces tab (DCIM BUILD_PLAN row 1.2; asset-inventory
// ADR-0010 D3): every interface of the asset, physical and virtual, with an
// add/edit drawer, delete, and each interface's change record.
//
// Five states: loading, error, empty (nothing reported or declared yet — which
// is not the same as "this asset has no interfaces"), no search match, and the
// table. Reads need dcim.read; add, edit and delete need dcim.manage.
import { useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router';
import { fromState, interfaceHref } from '../object-pages/object-links';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import {
  INTERFACE_DUPLEXES, INTERFACE_DUPLEX_LABELS, INTERFACE_MODES, INTERFACE_MODE_LABELS,
  INTERFACE_TYPES, INTERFACE_TYPE_LABELS, INTERFACE_TYPE_GROUP,
  type InterfaceDuplex, type InterfaceMode, type InterfaceType,
} from '@vistasecurity/primitives/dcim';
import { CustomFieldsPanel } from './custom-fields-panel';
import { DrawerCloseBtn, DrawerShell, Icon, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import {
  InterfaceWriteError, useAssetInterfaces, useCreateInterface, useDeleteInterface, usePatchInterface,
  useVlanChoices, vlanLabel, type Interface, type InterfacePatch, type Vlan,
} from './interface-queries';
import { hierarchyChoices, isWireless, lagChoices, modeControls, parseVlanIds, speedText } from './interface-rules';
import { ObjectChanges } from './object-changes';
import { WirelessLansPanel } from './wireless-panel';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import { CableCell } from './cable-column';
import { useAssetCables } from './cable-queries';
import { useAssetVirtualDeviceContexts, type VirtualDeviceContext } from './vdc-queries';
import { useIpamList } from '../ipam/ipam-queries';

const OPER_TONE: Record<string, string> = { up: 'var(--ok)', down: 'var(--danger-text)', testing: 'var(--warn)', unknown: 'var(--app-t3)' };

function OperBadge({ i }: { i: Interface }) {
  if (!i.operational_status) return <span style={{ color: 'var(--app-t3)' }} title="No device has reported this interface's state">—</span>;
  return (
    <span data-testid="oper-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: OPER_TONE[i.operational_status] ?? 'var(--app-t3)' }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: 'currentColor' }} />
      {i.operational_status}
    </span>
  );
}

function modeText(i: Interface): string {
  if (!i.mode) return '';
  const label = INTERFACE_MODE_LABELS[i.mode];
  const tagged = i.tagged_vlan_ids.length;
  if (i.mode === 'tagged') return `${label} · ${tagged} VLAN${tagged === 1 ? '' : 's'}`;
  if (i.untagged_vlan_id) return `${label} · untagged set`;
  return label;
}

export function InterfacesTab({ asset }: { asset: Asset }) {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={<PanelEmpty icon="lock" title="You can't view interfaces" message="Interfaces need the DCIM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <InterfacesBody asset={asset} />
    </PermissionGate>
  );
}

function InterfacesBody({ asset }: { asset: Asset }) {
  const [search, setSearch] = useState('');
  const all = useAssetInterfaces(asset.id);
  const filtered = useAssetInterfaces(asset.id, search, search.trim() !== '');
  const q = search.trim() ? filtered : all;
  const [editing, setEditing] = useState<Interface | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Interface | null>(null);
  const del = useDeleteInterface(asset.id);
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.dcim.manage);
  const editable = !asset.deleted_at && asset.asset_status !== 'archived';
  const rows = q.data?.rows ?? [];
  const nameOf = useMemo(() => new Map((all.data?.rows ?? []).map((i) => [i.id, i.name])), [all.data]);
  const cables = useAssetCables(asset.id);

  const header = (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
      <div style={{ position: 'relative', flex: 1, maxWidth: 320 }}>
        <ModalInput aria-label="Search interfaces" placeholder="Search name, label or description" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <div style={{ flex: 1 }} />
      {/* The faceplate (row 3.4) draws these interfaces as ports, on the Ports tab. */}
      <Link to={`/inventory/assets/${asset.id}/ports#faceplate`} className="ui-btn sm ghost" data-testid="open-faceplate">
        <Icon name="ethernet-port" size={13} />Faceplate
      </Link>
      {canManage && editable && (
        <button type="button" className="ui-btn sm primary" onClick={() => setEditing('new')}>
          <Icon name="plus" size={13} />Add interface
        </button>
      )}
    </div>
  );

  let body: React.ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading interfaces…" />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if (rows.length === 0 && search.trim()) {
    body = <PanelEmpty icon="search-x" title="No interfaces match" message={`Nothing on this asset matches “${search.trim()}”.`} />;
  } else if (rows.length === 0) {
    body = (
      <PanelEmpty
        icon="ethernet-port"
        title="No interfaces reported yet"
        message="Nothing has reported this asset's interfaces and none has been declared, so this says nothing about whether it has any. Add them here, or they will appear when discovery interrogates the device."
      />
    );
  } else {
    body = (
      <div style={{ overflowX: 'auto', border: '1px solid var(--app-border)', borderRadius: 10 }}>
        <table data-testid="interfaces-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Name', 'Type', 'Enabled', 'MAC address', 'Speed', 'MTU', '802.1Q', 'Context', 'State', 'Cable', 'Description', ''].map((h) => (
                <th key={h} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.id} data-testid="interface-row" style={{ borderTop: '1px solid var(--app-border)', opacity: i.status === 'stale' ? 0.6 : 1 }}>
                <td style={{ padding: '8px 11px', whiteSpace: 'nowrap' }}>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{i.name}</span>
                  {i.lag_id && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}> · in {nameOf.get(i.lag_id) ?? 'LAG'}</span>}
                  {i.mgmt_only && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}> · mgmt</span>}
                  {i.status === 'pending' && (
                    <span data-testid="pending-badge" title="Discovered while its asset is waiting for approval; approved with the asset" style={{ marginLeft: 6, fontSize: 10.5, padding: '1px 6px', borderRadius: 6, background: 'color-mix(in srgb, var(--warn) 14%, transparent)', color: 'var(--warn)' }}>Pending</span>
                  )}
                  {i.status === 'stale' && <span style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--app-t3)' }}>Stale</span>}
                </td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{i.type_label !== '' ? i.type_label : i.type}</td>
                <td style={{ padding: '8px 11px' }}>{i.enabled ? 'Yes' : <span style={{ color: 'var(--app-t3)' }}>No</span>}</td>
                <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>
                  {i.mac_address ?? '—'}
                  {i.mac_addresses.length > 1 && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}> +{i.mac_addresses.length - 1}</span>}
                </td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{speedText(i.speed_kbps) || '—'}</td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{i.mtu ?? '—'}</td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{modeText(i) || '—'}</td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }} data-testid="interface-contexts">
                  {(i.virtual_device_contexts ?? []).length > 0 ? i.virtual_device_contexts.map((c) => c.name).join(', ') : '—'}
                </td>
                <td style={{ padding: '8px 11px' }}><OperBadge i={i} /></td>
                <td style={{ padding: '8px 11px' }} data-testid="interface-cable">
                  {/* A virtual or wireless interface never takes a cable (NetBox). */}
                  {INTERFACE_TYPE_GROUP[i.type] === 'virtual' || isWireless(i.type)
                    ? <span style={{ color: 'var(--app-t3)' }}>—</span>
                    : <CableCell port={{ kind: 'interface', id: i.id, name: i.name, cableId: i.cable_id, markConnected: i.mark_connected }} cables={cables} canManage={canManage && editable} />}
                </td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.description ?? ''}</td>
                <td style={{ padding: '8px 11px', whiteSpace: 'nowrap', textAlign: 'right' }}>
                  <button type="button" className="ui-btn sm" aria-label={`Open ${i.name}`} onClick={() => setEditing(i)}>
                    <Icon name={canManage && editable ? 'sliders-horizontal' : 'eye'} size={12} />
                  </button>
                  {canManage && editable && (
                    <button type="button" className="ui-btn sm" aria-label={`Delete ${i.name}`} style={{ marginLeft: 4 }} onClick={() => setDeleting(i)}>
                      <Icon name="trash-2" size={12} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {(q.data?.total ?? 0) > rows.length && (
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', padding: 8 }}>Showing {rows.length} of {q.data?.total} interfaces.</div>
        )}
      </div>
    );
  }

  return (
    <div data-testid="interfaces-tab">
      {header}
      {body}
      {/* An access point's SSIDs (row 4.4): only where a radio exists. */}
      {(all.data?.rows ?? []).some((i) => isWireless(i.type)) && <WirelessLansPanel assetId={asset.id} />}
      {editing && (
        <InterfaceDrawer
          asset={asset}
          iface={editing === 'new' ? null : editing}
          siblings={all.data?.rows ?? []}
          readOnly={!canManage || !editable}
          onClose={() => setEditing(null)}
        />
      )}
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title={`Delete ${deleting?.name ?? 'interface'}?`}
        description="Its LAG members and child interfaces are detached, not deleted. The change log keeps what it was."
        secondary={<button type="button" className="ui-btn" onClick={() => setDeleting(null)}>Cancel</button>}
        primary={(
          <button
            type="button"
            className="ui-btn danger"
            disabled={del.isPending}
            onClick={() => { if (deleting) del.mutate(deleting, { onSettled: () => setDeleting(null) }); }}
          >
            Delete
          </button>
        )}
      />
    </div>
  );
}

// ------------------------------------------------------------------ drawer --

export interface Draft {
  name: string;
  label: string;
  type: InterfaceType | '';
  enabled: boolean;
  mgmt_only: boolean;
  mtu: string;
  mac_address: string;
  speed_kbps: string;
  duplex: InterfaceDuplex | '';
  mode: InterfaceMode | '';
  untagged_vlan_id: string;
  tagged_vlan_ids: string;
  lag_id: string;
  parent_id: string;
  bridge_id: string;
  /** The virtual device contexts (of this asset) the interface belongs to. */
  virtual_device_context_ids: string[];
  /** The interface's VLAN translation policy (DCIM gap 10); '' is none. */
  vlan_translation_policy_id: string;
  description: string;
}

function draftOf(i: Interface | null): Draft {
  return {
    name: i?.name ?? '',
    label: i?.label ?? '',
    type: i?.type ?? '',
    enabled: i?.enabled ?? true,
    mgmt_only: i?.mgmt_only ?? false,
    mtu: i?.mtu != null ? String(i.mtu) : '',
    mac_address: i?.mac_address ?? '',
    speed_kbps: i?.speed_kbps != null ? String(i.speed_kbps) : '',
    duplex: i?.duplex ?? '',
    mode: i?.mode ?? '',
    untagged_vlan_id: i?.untagged_vlan_id ?? '',
    tagged_vlan_ids: (i?.tagged_vlan_ids ?? []).join('\n'),
    lag_id: i?.lag_id ?? '',
    parent_id: i?.parent_id ?? '',
    bridge_id: i?.bridge_id ?? '',
    virtual_device_context_ids: [...(i?.virtual_device_context_ids ?? [])],
    vlan_translation_policy_id: i?.vlan_translation_policy_id ?? '',
    description: i?.description ?? '',
  };
}

const nullIfEmpty = (s: string) => (s.trim() === '' ? null : s.trim());
const numOrNull = (s: string) => (s.trim() === '' ? null : Number(s));

/** The body a draft saves as. Fields a mode does not allow are cleared, so a
 *  mode change never leaves a value the server would refuse. */
export function bodyOf(d: Draft): InterfacePatch & { name: string; type: InterfaceType } {
  const mc = modeControls(d.mode);
  return {
    name: d.name.trim(),
    label: nullIfEmpty(d.label),
    type: d.type as InterfaceType,
    enabled: d.enabled,
    mgmt_only: d.mgmt_only,
    mtu: numOrNull(d.mtu),
    mac_address: nullIfEmpty(d.mac_address),
    speed_kbps: numOrNull(d.speed_kbps),
    duplex: d.duplex === '' ? null : d.duplex,
    mode: d.mode === '' ? null : d.mode,
    untagged_vlan_id: mc.untagged ? nullIfEmpty(d.untagged_vlan_id) : null,
    tagged_vlan_ids: mc.tagged ? parseVlanIds(d.tagged_vlan_ids).ids : [],
    lag_id: nullIfEmpty(d.lag_id),
    parent_id: nullIfEmpty(d.parent_id),
    bridge_id: nullIfEmpty(d.bridge_id),
    virtual_device_context_ids: d.virtual_device_context_ids,
    vlan_translation_policy_id: nullIfEmpty(d.vlan_translation_policy_id),
    description: nullIfEmpty(d.description),
  };
}

/** What stops a draft saving, before the server is asked. */
export function draftProblem(d: Draft): string | null {
  if (!d.name.trim()) return 'A name is required.';
  if (!d.type) return 'Choose a type.';
  const mc = modeControls(d.mode);
  const { ids, bad } = parseVlanIds(d.tagged_vlan_ids);
  if (mc.tagged && bad.length > 0) return `Not a VLAN id: ${bad[0]}`;
  if (mc.taggedRequired && ids.length === 0) return 'Tagged mode needs at least one tagged VLAN.';
  if (d.mtu.trim() && !(Number(d.mtu) >= 1 && Number(d.mtu) <= 65536)) return 'MTU must be between 1 and 65536.';
  return null;
}

function InterfaceDrawer({ asset, iface, siblings, readOnly, onClose }: {
  asset: Asset; iface: Interface | null; siblings: readonly Interface[]; readOnly: boolean; onClose: () => void;
}) {
  const loc = useLocation();
  const [d, setD] = useState<Draft>(() => draftOf(iface));
  const [serverError, setServerError] = useState<{ message: string; field?: string } | null>(null);
  const create = useCreateInterface(asset.id);
  const patch = usePatchInterface(asset.id);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((cur) => ({ ...cur, [k]: v }));
  const mc = modeControls(d.mode);
  const lags = lagChoices(siblings, iface?.id, d.type);
  const parents = hierarchyChoices(siblings, iface?.id, 'parent_id');
  const bridges = hierarchyChoices(siblings, iface?.id, 'bridge_id');
  const problem = draftProblem(d);
  const busy = create.isPending || patch.isPending;
  // VLAN picker (row 1.3's VLANs). Typed ids remain the fallback when the
  // person cannot read IPAM or the list fails, so the drawer never dead-ends.
  const perms = usePermissions();
  const canReadIpam = perms.hasPermission(TENANT_PERMISSIONS.ipam.read);
  const vlans = useVlanChoices(canReadIpam && !readOnly);
  const picker = canReadIpam && vlans.isSuccess ? vlans.data : null;
  const contexts = useAssetVirtualDeviceContexts(asset.id);
  const policies = useIpamList('vlan-translation-policies', { limit: 1000 }, { enabled: canReadIpam && !readOnly });
  const policyPicker = canReadIpam && policies.isSuccess ? policies.data.rows : null;

  const save = () => {
    if (problem) return;
    setServerError(null);
    const body = bodyOf(d);
    const done = { onSuccess: onClose, onError: (e: Error) => setServerError({ message: e.message, field: e instanceof InterfaceWriteError ? e.field : undefined }) };
    if (iface) patch.mutate({ id: iface.id, patch: body }, done);
    else create.mutate({ ...body, asset_id: asset.id }, done);
  };

  const field = (k: string) => (serverError?.field === k ? { outline: '1px solid var(--danger)' } : undefined);

  return (
    <DrawerShell onClose={onClose} width={520}>
      <div data-testid="interface-drawer" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <Icon name="ethernet-port" size={16} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, fontSize: 15, fontWeight: 700, color: 'var(--app-t1)' }}>
            {iface
              ? <Link to={interfaceHref(iface.id)} state={fromState(loc)} data-testid="interface-open-page" title="Open the interface page" style={{ color: 'inherit', textDecoration: 'none' }}>{iface.name}</Link>
              : 'Add interface'}
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <fieldset disabled={readOnly || busy} style={{ border: 0, padding: 0, margin: 0 }}>
          <ModalField label="Name" hint="The device's own long form, e.g. GigabitEthernet1/0/24.">
            <ModalInput aria-label="Name" value={d.name} style={field('name')} onChange={(e) => set('name', e.target.value)} />
          </ModalField>
          <ModalField label="Type">
            <ModalSelect aria-label="Type" value={d.type} style={field('type')} onChange={(e) => set('type', e.target.value as InterfaceType)}>
              <option value="">Choose a type…</option>
              {INTERFACE_TYPES.map((t) => <option key={t} value={t}>{INTERFACE_TYPE_LABELS[t]}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Label">
            <ModalInput aria-label="Label" value={d.label} onChange={(e) => set('label', e.target.value)} />
          </ModalField>
          <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
            <label style={{ fontSize: 12.5, display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" aria-label="Enabled" checked={d.enabled} onChange={(e) => set('enabled', e.target.checked)} />Enabled
            </label>
            <label style={{ fontSize: 12.5, display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" aria-label="Management only" checked={d.mgmt_only} onChange={(e) => set('mgmt_only', e.target.checked)} />Management only
            </label>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <ModalField label="MAC address">
              <ModalInput aria-label="MAC address" value={d.mac_address} style={field('mac_address')} onChange={(e) => set('mac_address', e.target.value)} />
            </ModalField>
            <ModalField label="MTU">
              <ModalInput aria-label="MTU" inputMode="numeric" value={d.mtu} style={field('mtu')} onChange={(e) => set('mtu', e.target.value)} />
            </ModalField>
            <ModalField label="Speed (kbps)">
              <ModalInput aria-label="Speed" inputMode="numeric" value={d.speed_kbps} onChange={(e) => set('speed_kbps', e.target.value)} />
            </ModalField>
            <ModalField label="Duplex">
              <ModalSelect aria-label="Duplex" value={d.duplex} onChange={(e) => set('duplex', e.target.value as InterfaceDuplex | '')}>
                <option value="">—</option>
                {INTERFACE_DUPLEXES.map((x) => <option key={x} value={x}>{INTERFACE_DUPLEX_LABELS[x]}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
          <SectionLabel icon="layers">LAG, parent and bridge</SectionLabel>
          <ModalField label="LAG" hint={lags.length === 0 ? (d.type === 'lag' || d.type === 'virtual' || d.type === 'bridge' ? 'This type cannot be a LAG member.' : 'This asset has no LAG interface yet.') : undefined}>
            <ModalSelect aria-label="LAG" value={d.lag_id} disabled={lags.length === 0} style={field('lag_id')} onChange={(e) => set('lag_id', e.target.value)}>
              <option value="">None</option>
              {lags.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
            </ModalSelect>
          </ModalField>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <ModalField label="Parent">
              <ModalSelect aria-label="Parent" value={d.parent_id} style={field('parent_id')} onChange={(e) => set('parent_id', e.target.value)}>
                <option value="">None</option>
                {parents.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Bridge">
              <ModalSelect aria-label="Bridge" value={d.bridge_id} style={field('bridge_id')} onChange={(e) => set('bridge_id', e.target.value)}>
                <option value="">None</option>
                {bridges.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
          <SectionLabel icon="tags">802.1Q</SectionLabel>
          <ModalField label="Mode">
            <ModalSelect aria-label="Mode" value={d.mode} style={field('mode')} onChange={(e) => set('mode', e.target.value as InterfaceMode | '')}>
              <option value="">None</option>
              {INTERFACE_MODES.map((m) => <option key={m} value={m}>{INTERFACE_MODE_LABELS[m]}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Untagged VLAN" hint={picker ? undefined : "The VLAN's id."}>
            {picker ? (
              <ModalSelect aria-label="Untagged VLAN" value={d.untagged_vlan_id} disabled={!mc.untagged} style={field('untagged_vlan_id')} onChange={(e) => set('untagged_vlan_id', e.target.value)}>
                <option value="">None</option>
                {vlanOptions(picker, d.untagged_vlan_id).map((v) => <option key={v.id} value={v.id}>{vlanLabel(v)}</option>)}
              </ModalSelect>
            ) : (
              <ModalInput aria-label="Untagged VLAN" value={d.untagged_vlan_id} disabled={!mc.untagged} style={field('untagged_vlan_id')} onChange={(e) => set('untagged_vlan_id', e.target.value)} />
            )}
          </ModalField>
          <ModalField label="Tagged VLANs" hint={d.mode === 'tagged-all' ? 'Tagged (All) carries every VLAN; no list.' : !mc.tagged ? 'Only in Tagged mode.' : picker ? 'At least one.' : 'One VLAN id per line; at least one.'}>
            {picker ? (
              <TaggedVlanPicker vlans={picker} value={d.tagged_vlan_ids} disabled={!mc.tagged} onChange={(v) => set('tagged_vlan_ids', v)} />
            ) : (
            <textarea
              aria-label="Tagged VLANs"
              value={d.tagged_vlan_ids}
              disabled={!mc.tagged}
              rows={3}
              onChange={(e) => set('tagged_vlan_ids', e.target.value)}
              style={{ width: '100%', padding: '8px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, ...field('tagged_vlan_ids') }}
            />
            )}
          </ModalField>
          <ModalField label="VLAN translation policy" hint={policyPicker ? 'Kept in Infrastructure → VLANs → Translation policies.' : "The policy's id."}>
            {policyPicker ? (
              <ModalSelect aria-label="VLAN translation policy" value={d.vlan_translation_policy_id} style={field('vlan_translation_policy_id')} onChange={(e) => set('vlan_translation_policy_id', e.target.value)}>
                <option value="">None</option>
                {d.vlan_translation_policy_id && !policyPicker.some((p) => p.id === d.vlan_translation_policy_id) && (
                  <option value={d.vlan_translation_policy_id}>A policy not in the list</option>
                )}
                {policyPicker.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </ModalSelect>
            ) : (
              <ModalInput aria-label="VLAN translation policy" value={d.vlan_translation_policy_id} style={field('vlan_translation_policy_id')} onChange={(e) => set('vlan_translation_policy_id', e.target.value)} />
            )}
          </ModalField>
          {isWireless(d.type) && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 10 }}>Radio settings for wireless interfaces arrive with the wireless pages.</div>
          )}
          <SectionLabel icon="split">Virtual device contexts</SectionLabel>
          <ContextPicker
            contexts={contexts.isSuccess ? contexts.data : null}
            loading={contexts.isLoading}
            failed={contexts.isError}
            value={d.virtual_device_context_ids}
            onChange={(v) => set('virtual_device_context_ids', v)}
          />
          <ModalField label="Description">
            <ModalInput aria-label="Description" value={d.description} onChange={(e) => set('description', e.target.value)} />
          </ModalField>
        </fieldset>
        {!readOnly && (problem !== null || serverError !== null) && (
          <div data-testid="interface-form-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginBottom: 8 }}>
            {serverError?.message ?? problem}
          </div>
        )}
        {!readOnly && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="ui-btn" onClick={onClose}>Cancel</button>
            <button type="button" className="ui-btn primary" disabled={!!problem || busy} onClick={save}>
              {iface ? 'Save' : 'Add interface'}
            </button>
          </div>
        )}
        {iface && (
          <>
            {/* Custom fields (DCIM row 5.1): edited through the interface's PATCH. */}
            <SectionLabel icon="list-checks">Custom fields</SectionLabel>
            <CustomFieldsPanel kind="interface" id={iface.id} values={iface.custom_fields} permission={TENANT_PERMISSIONS.dcim.manage}
              onChange={(custom_fields) => patch.mutateAsync({ id: iface.id, patch: { custom_fields } })} />
            <SectionLabel icon="git-compare">Changes</SectionLabel>
            <ObjectChanges kind="interface" id={iface.id} />
          </>
        )}
      </div>
    </DrawerShell>
  );
}

/** The asset's virtual device contexts as a checkbox list (DCIM gap 1). A
 *  membership the list does not hold (it failed to load, or the context is
 *  gone) is kept, so an edit never silently drops it. */
function ContextPicker({ contexts, loading, failed, value, onChange }: {
  contexts: readonly VirtualDeviceContext[] | null; loading: boolean; failed: boolean;
  value: readonly string[]; onChange: (v: string[]) => void;
}) {
  if (loading) return <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 10 }}>Loading the asset's contexts…</div>;
  if (failed || !contexts) {
    return <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 10 }}>The asset's contexts could not be loaded; this interface's memberships are kept as they are.</div>;
  }
  if (contexts.length === 0) {
    return <div data-testid="context-picker-empty" style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 10 }}>This asset has no virtual device contexts. Add them on the Hardware tab.</div>;
  }
  const chosen = new Set(value);
  const toggle = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange([...next]);
  };
  return (
    <div data-testid="context-picker" role="group" aria-label="Virtual device contexts" style={{ border: '1px solid var(--app-border2)', borderRadius: 9, padding: '6px 10px', marginBottom: 10 }}>
      {contexts.map((c) => (
        <label key={c.id} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5, padding: '2px 0' }}>
          <input type="checkbox" aria-label={`Context ${c.name}`} checked={chosen.has(c.id)} onChange={() => toggle(c.id)} />
          <span className="mono">{c.name}</span>
          {c.identifier != null && <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>#{c.identifier}</span>}
        </label>
      ))}
    </div>
  );
}

/** The tenant's VLANs, plus a placeholder for an id the interface already
 *  carries that is not in the list (so an edit never silently drops it). */
function vlanOptions(vlans: readonly Vlan[], current: string): Pick<Vlan, 'id' | 'vid' | 'name'>[] {
  const out: Pick<Vlan, 'id' | 'vid' | 'name'>[] = [...vlans].sort((a, b) => a.vid - b.vid || a.name.localeCompare(b.name));
  if (current && !vlans.some((v) => v.id === current)) out.unshift({ id: current, vid: 0, name: 'unknown VLAN' });
  return out;
}

/** Tagged VLANs as a checkbox list; the draft keeps them as newline-separated
 *  ids, the same shape the typed fallback edits. */
function TaggedVlanPicker({ vlans, value, disabled, onChange }: {
  vlans: readonly Vlan[]; value: string; disabled: boolean; onChange: (v: string) => void;
}) {
  const chosen = new Set(parseVlanIds(value).ids);
  const toggle = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange([...next].join('\n'));
  };
  if (vlans.length === 0) {
    return <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No VLANs yet. Add them under Inventory → VLANs.</div>;
  }
  return (
    <div data-testid="tagged-vlan-picker" role="group" aria-label="Tagged VLANs" style={{ maxHeight: 160, overflowY: 'auto', border: '1px solid var(--app-border2)', borderRadius: 9, padding: '6px 10px', opacity: disabled ? 0.55 : 1 }}>
      {vlanOptions(vlans, '').map((v) => (
        <label key={v.id} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5, padding: '2px 0' }}>
          <input type="checkbox" aria-label={`Tagged ${vlanLabel(v)}`} disabled={disabled} checked={chosen.has(v.id)} onChange={() => toggle(v.id)} />
          {vlanLabel(v)}
        </label>
      ))}
    </div>
  );
}
