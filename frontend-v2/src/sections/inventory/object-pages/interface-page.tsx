// The interface page (DCIM gap 7) — `/inventory/interfaces/:id`: the asset it
// belongs to, type, speed, mode, VLANs and VLAN translation policy, its virtual
// circuit (DCIM gap 10), addresses, the cable and its far end, and the trace,
// then the substrate panels. Read-only here; editing an
// interface stays in the asset's Interfaces tab (`dcim.manage`).
import { useState } from 'react';
import { Link, useLocation, useParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { INTERFACE_DUPLEX_LABELS, INTERFACE_MODE_LABELS, INTERFACE_TYPE_LABELS } from '@vistasecurity/primitives/dcim';
import { Icon, MetaRow, SectionLabel } from '../../../components/ui';
import { useAsset } from '../asset-queries';
import { assetIdentity } from '../asset-shape';
import { TraceBody } from '../cabling/trace-view';
import { endText, lengthText, statusText, typeText } from '../cabling/cabling-model';
import { useCable } from '../cabling/cabling-queries';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { speedText } from '../dcim/interface-rules';
import { usePatchInterface, useVlanChoices, vlanLabel } from '../dcim/interface-queries';
import { PanelError, PanelLoading } from '../dcim/substrate-states';
import { Chip, ObjectFormModal, type IpamField } from '../ipam/ipam-ui';
import { useIpamList } from '../ipam/ipam-queries';
import { VC_ROLE_LABEL, VC_ROLE_OPTIONS, useCircuitList, useCircuitWrite } from '../circuits/circuits-queries';
import { virtualCircuitHref } from '../circuits/virtual-circuits-view';
import { ObjectPageShell } from './object-page-shell';
import { cableHref, fromState, vlanHref } from './object-links';
import { isNotFound, useInterfaceAddresses, useInterfaceById } from './object-queries';

/** The interface's place in a virtual circuit (DCIM gap 10; NetBox
 *  VirtualCircuitTermination, one per interface): shown, removed, or added
 *  here — the interface is the one end the Circuits lens cannot pick. */
function VirtualCircuitSection({ interfaceId }: { interfaceId: string }) {
  const loc = useLocation();
  const perms = usePermissions();
  const canRead = perms.hasPermission(TENANT_PERMISSIONS.circuits.read);
  const terms = useCircuitList('virtual-circuit-terminations', { interface_id: interfaceId }, { enabled: canRead });
  const write = useCircuitWrite('virtual-circuit-terminations');
  const [adding, setAdding] = useState(false);
  const vcs = useCircuitList('virtual-circuits', { limit: 1000 }, { enabled: adding });
  const fields: IpamField[] = [
    { name: 'virtual_circuit_id', label: 'Virtual circuit', kind: 'select', required: true,
      options: [{ value: '', label: vcs.isLoading ? 'Loading…' : 'Choose a virtual circuit' }, ...(vcs.data?.rows ?? []).map((v) => ({ value: v.id, label: v.cid }))] },
    { name: 'role', label: 'Role', kind: 'select', options: VC_ROLE_OPTIONS },
  ];
  const t = (terms.data?.rows ?? [])[0] as ({ id: string; role: keyof typeof VC_ROLE_LABEL; virtual_circuit_id: string; virtual_circuit_cid?: string | null } | undefined);
  return (
    <div data-testid="interface-virtual-circuit" style={{ fontSize: 12.5 }}>
      {!canRead ? <span style={{ color: 'var(--app-t3)' }}>Virtual circuits need the circuits read permission.</span>
        : terms.isLoading ? <PanelLoading label="Loading the virtual circuit…" />
          : terms.isError ? <PanelError message={terms.error instanceof Error ? terms.error.message : 'Request failed'} onRetry={() => { void terms.refetch(); }} />
            : t ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Chip>{VC_ROLE_LABEL[t.role]}</Chip>
                <span>of</span>
                <Link to={virtualCircuitHref(t.virtual_circuit_id)} state={fromState(loc)} className="mono" data-testid="interface-virtual-circuit-link">{t.virtual_circuit_cid ?? 'a virtual circuit'}</Link>
                <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
                  <button type="button" className="ui-btn sm ghost" data-testid="interface-virtual-circuit-remove" title="Take the interface out of the virtual circuit" style={{ color: 'var(--danger-text)', marginLeft: 'auto' }}
                    onClick={() => { void write.remove.mutateAsync(t.id); }}><Icon name="x" size={13} /></button>
                </PermissionGate>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--app-t3)' }}>This interface terminates no virtual circuit.</span>
                <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
                  <button type="button" className="ui-btn sm" data-testid="interface-virtual-circuit-add" style={{ marginLeft: 'auto' }} onClick={() => setAdding(true)}><Icon name="plus" size={13} />Add to a virtual circuit</button>
                </PermissionGate>
              </div>
            )}
      {adding && (
        <ObjectFormModal write={write} icon="cable" title="Add to a virtual circuit" fields={fields} initial={{ role: 'peer' }} fixed={{ interface_id: interfaceId }} onClose={() => setAdding(false)} />
      )}
    </div>
  );
}

/** The VLANs lens's link to one translation policy. */
const translationPolicyHref = (id: string) => `/inventory?lens=vlans&view=translation&policy=${encodeURIComponent(id)}`;

const OPER_TONE: Record<string, string> = { up: 'var(--ok)', down: 'var(--danger-text)', testing: 'var(--warn)', unknown: 'var(--app-t3)' };

export function InterfacePage() {
  const { id } = useParams();
  const loc = useLocation();
  const perms = usePermissions();
  const canReadIpam = perms.hasPermission(TENANT_PERMISSIONS.ipam.read);
  const q = useInterfaceById(id);
  const i = q.data;
  const asset = useAsset(i?.asset_id);
  const vlans = useVlanChoices(canReadIpam && !!i);
  const ips = useInterfaceAddresses(id, canReadIpam && !!i);
  const cable = useCable(i?.cable_id ?? null);
  const patch = usePatchInterface(i?.asset_id ?? '');
  const assetName = asset.data ? assetIdentity(asset.data).primary : undefined;
  const policies = useIpamList('vlan-translation-policies', { limit: 1000 }, { enabled: canReadIpam && !!i?.vlan_translation_policy_id });
  const policyText = (pid: string | null | undefined) => {
    if (!pid) return '';
    if (!canReadIpam) return 'Set (its name needs the IPAM read permission)';
    const p = (policies.data?.rows ?? []).find((x) => x.id === pid);
    return p ? <Link to={translationPolicyHref(pid)} state={fromState(loc)} data-testid="interface-translation-policy">{p.name}</Link> : policies.isLoading ? 'Loading…' : 'A policy not in the list';
  };
  const vlanText = (vid: string) => {
    const v = (vlans.data ?? []).find((x) => x.id === vid);
    return v ? <Link key={vid} to={vlanHref(vid)} state={fromState(loc)}>{vlanLabel(v)}</Link> : <span key={vid}>VLAN (not readable)</span>;
  };

  return (
    <ObjectPageShell
      kind="interface" id={id} icon="ethernet-port"
      status={q.isLoading ? 'loading' : q.isError ? (isNotFound(q.error) ? 'not-found' : 'error') : i ? 'ready' : 'loading'}
      errorMessage={q.error instanceof Error ? q.error.message : undefined} onRetry={() => { void q.refetch(); }}
      lens={i ? { label: assetName ?? 'Asset', href: `/inventory/assets/${i.asset_id}/interfaces` } : undefined}
      breadcrumbName={i?.name} title={<span className="mono">{i?.name}</span>}
      subtitle={i && (
        <>
          <Link to={`/inventory/assets/${i.asset_id}`} data-testid="interface-asset">{assetName ?? 'Asset'}</Link>
          {i.label ? ` · ${i.label}` : ''}
        </>
      )}
      badges={i && (
        <>
          {i.operational_status
            ? <Chip tone={OPER_TONE[i.operational_status] ?? 'var(--app-t3)'}>{i.operational_status}</Chip>
            : <Chip title="No device has reported this interface's state">State not reported</Chip>}
          {!i.enabled && <Chip tone="var(--warn)">Disabled</Chip>}
        </>
      )}
      actions={i && (
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <Link to={`/inventory/assets/${i.asset_id}/interfaces`} className="ui-btn sm" data-testid="interface-edit-in-asset"><Icon name="sliders-horizontal" size={13} />Edit on the asset</Link>
        </PermissionGate>
      )}
      customFields={i && (
        <CustomFieldsPanel kind="interface" id={i.id} values={i.custom_fields} permission={TENANT_PERMISSIONS.dcim.manage}
          onChange={(custom_fields) => patch.mutateAsync({ id: i.id, patch: { custom_fields } })} />
      )}
    >
      {i && (
        <>
          <MetaRow k="Type" v={INTERFACE_TYPE_LABELS[i.type] ?? i.type_label} />
          <MetaRow k="Speed" v={speedText(i.speed_kbps)} />
          <MetaRow k="Duplex" v={i.duplex ? INTERFACE_DUPLEX_LABELS[i.duplex] : ''} />
          <MetaRow k="MTU" v={i.mtu == null ? '' : String(i.mtu)} />
          <MetaRow k="MAC address" v={i.mac_address} mono />
          <MetaRow k="Mode" v={i.mode ? INTERFACE_MODE_LABELS[i.mode] : ''} />

          <SectionLabel icon="layers">VLANs</SectionLabel>
          <div data-testid="interface-vlans" style={{ fontSize: 12.5 }}>
            {!canReadIpam ? <span style={{ color: 'var(--app-t3)' }}>VLAN names need the IPAM read permission.</span>
              : vlans.isLoading ? <PanelLoading label="Loading VLANs…" />
                : !i.untagged_vlan_id && i.tagged_vlan_ids.length === 0 ? <span style={{ color: 'var(--app-t3)' }}>No VLAN is set on this interface.</span>
                  : (
                    <>
                      {i.untagged_vlan_id && <div>Untagged: {vlanText(i.untagged_vlan_id)}</div>}
                      {i.tagged_vlan_ids.length > 0 && <div>Tagged: {i.tagged_vlan_ids.map((v, n) => <span key={v}>{n > 0 && ', '}{vlanText(v)}</span>)}</div>}
                    </>
                  )}
          </div>

          <MetaRow k="VLAN translation" v={policyText(i.vlan_translation_policy_id)} />

          <SectionLabel icon="cable">Virtual circuit</SectionLabel>
          <VirtualCircuitSection interfaceId={i.id} />

          <SectionLabel icon="network">Addresses</SectionLabel>
          <div data-testid="interface-addresses" style={{ fontSize: 12.5 }}>
            {!canReadIpam ? <span style={{ color: 'var(--app-t3)' }}>Addresses need the IPAM read permission.</span>
              : ips.isLoading ? <PanelLoading label="Loading addresses…" />
                : ips.isError ? <PanelError message={ips.error instanceof Error ? ips.error.message : 'Request failed'} onRetry={() => { void ips.refetch(); }} />
                  : (ips.data ?? []).length === 0 ? <span style={{ color: 'var(--app-t3)' }}>No address is recorded on this interface.</span>
                    : (ips.data ?? []).map((a) => <div key={a.id} className="mono">{a.address}</div>)}
          </div>

          <SectionLabel icon="cable">Cable</SectionLabel>
          <div data-testid="interface-cable" style={{ fontSize: 12.5 }}>
            {!i.cable_id ? <span style={{ color: 'var(--app-t3)' }}>{i.mark_connected ? 'Marked connected, with no cable recorded.' : 'Not cabled.'}</span>
              : cable.isLoading ? <PanelLoading label="Loading the cable…" />
                : cable.isError || !cable.data ? <PanelError message="Couldn't load the cable." onRetry={() => { void cable.refetch(); }} />
                  : (
                    <>
                      <Link to={cableHref(cable.data.id)} state={fromState(loc)} data-testid="interface-cable-link">{cable.data.label?.trim() ? cable.data.label.trim() : 'Cable'}</Link>
                      {` · ${typeText(cable.data.type)} · ${statusText(cable.data)}`}
                      {lengthText(cable.data) !== '—' ? ` · ${lengthText(cable.data)}` : ''}
                      <div style={{ color: 'var(--app-t2)', marginTop: 3 }}>{endText(cable.data.a_terminations)} ↔ {endText(cable.data.b_terminations)}</div>
                    </>
                  )}
          </div>

          <SectionLabel icon="route">Trace</SectionLabel>
          <TraceBody kind="interface" id={i.id} />
        </>
      )}
    </ObjectPageShell>
  );
}
