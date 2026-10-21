// The Hardware tab's Virtual device contexts card (DCIM gap 1; NetBox
// dcim/virtual-device-context): the logical partitions of this device — a
// Cisco Nexus VDC, a Palo Alto vsys, a Fortinet VDOM, an F5 route domain —
// each with its identifier, status, business unit, primary addresses and how
// many of the asset's interfaces belong to it. Interfaces join a context from
// the Interfaces tab (the interface's Contexts field).
//
// Five states: loading, error, empty ("not recorded" — which is not "this
// device has none"), the table, and a write's result (a toast and the
// refreshed list). Reads need dcim.read (the tab's gate); add, edit and delete
// need dcim.manage.
import { useMemo, useState } from 'react';
import type { Asset } from '@vistasecurity/api-contract';
import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { useBusinessUnits } from '../../settings/business-units-queries';
import { useIpamList, type IpAddress } from '../ipam/ipam-queries';
import { useAssetInterfaces } from './interface-queries';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import {
  VDC_STATUSES, VDC_STATUS_LABEL, useAssetVirtualDeviceContexts, useCreateVirtualDeviceContext,
  useDeleteVirtualDeviceContext, useUpdateVirtualDeviceContext,
  type VdcStatus, type VirtualDeviceContext, type VirtualDeviceContextInput,
} from './vdc-queries';

const box: React.CSSProperties = { border: '1px solid var(--app-border)', borderRadius: 10 };
const cell: React.CSSProperties = { padding: '8px 11px', color: 'var(--app-t2)' };
const errMsg = (e: unknown) => (e instanceof Error ? e.message : 'Request failed');
const isV6 = (ip: Pick<IpAddress, 'address'>) => String(ip.address).includes(':');
const hostOf = (ip: Pick<IpAddress, 'address'>) => String(ip.address);

export function VirtualDeviceContextsSection({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const contexts = useAssetVirtualDeviceContexts(asset.id);
  const ifaces = useAssetInterfaces(asset.id);
  const perms = usePermissions();
  const canReadIpam = perms.hasPermission(TENANT_PERMISSIONS.ipam.read);
  const ips = useIpamList('ip-addresses', { asset_id: asset.id, limit: 500 }, { enabled: canReadIpam });
  const units = useBusinessUnits();
  const del = useDeleteVirtualDeviceContext(asset.id);
  const [editing, setEditing] = useState<VirtualDeviceContext | 'new' | null>(null);
  const [deleting, setDeleting] = useState<VirtualDeviceContext | null>(null);

  const memberCount = useMemo(() => {
    const out = new Map<string, number>();
    for (const i of ifaces.data?.rows ?? []) {
      for (const c of i.virtual_device_contexts ?? []) out.set(c.id, (out.get(c.id) ?? 0) + 1);
    }
    return out;
  }, [ifaces.data]);
  const ipById = useMemo(() => new Map((ips.data?.rows ?? []).map((ip) => [ip.id, ip])), [ips.data]);
  const unitName = useMemo(() => new Map((units.data ?? []).map((u) => [u.id, u.name])), [units.data]);

  // An address is set but this person cannot read it (no ipam.read, or not in
  // the list): say so, never show it as empty.
  const address = (id: string | null) => {
    if (!id) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
    const ip = ipById.get(id);
    return ip ? <span className="mono">{hostOf(ip)}</span> : <span style={{ color: 'var(--app-t3)' }} title="An address is set; you cannot read IPAM">set</span>;
  };

  let body: React.ReactNode;
  if (contexts.isLoading) body = <PanelLoading label="Loading virtual device contexts…" />;
  else if (contexts.isError) body = <PanelError message={errMsg(contexts.error)} onRetry={() => { void contexts.refetch(); }} />;
  else if ((contexts.data ?? []).length === 0) {
    body = (
      <PanelEmpty
        icon="split"
        title="No virtual device contexts recorded"
        message="None has been declared, imported or discovered for this device, so this says nothing about whether it is partitioned. A context is a VDOM, vsys, VDC or route domain that owns some of its interfaces; interrogating a FortiGate, Palo Alto, F5 or Nexus device records them."
      />
    );
  } else {
    body = (
      <div style={{ ...box, overflowX: 'auto' }}>
        <table data-testid="vdc-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Name', 'Identifier', 'Status', 'Business unit', 'Primary IPv4', 'Primary IPv6', 'Interfaces', ''].map((h) => (
                <th key={h} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(contexts.data ?? []).map((c) => (
              <tr key={c.id} data-testid="vdc-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={cell}>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{c.name}</span>
                  {c.status === 'pending' && <span style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--warn)' }}>Pending</span>}
                  {c.status === 'stale' && (
                    <span title="The device has stopped reporting this context" style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--app-t3)' }}>Stale</span>
                  )}
                  {c.source_kind === 'measured' && (
                    <span title="Reported by the device when it was interrogated" style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--app-t3)' }}>Discovered</span>
                  )}
                  {c.description && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{c.description}</div>}
                </td>
                <td style={cell} className="mono">{c.identifier ?? '—'}</td>
                <td style={cell}>{VDC_STATUS_LABEL[c.operational_status]}</td>
                <td style={cell}>{c.business_unit_id ? unitName.get(c.business_unit_id) ?? 'set' : '—'}</td>
                <td style={cell}>{address(c.primary_ip4_id)}</td>
                <td style={cell}>{address(c.primary_ip6_id)}</td>
                <td style={cell} data-testid="vdc-interface-count">{ifaces.isSuccess ? memberCount.get(c.id) ?? 0 : '—'}</td>
                <td style={{ ...cell, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  {canManage && (
                    <>
                      <button type="button" className="ui-btn sm" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)}>
                        <Icon name="pencil" size={12} />
                      </button>
                      <button type="button" className="ui-btn sm" aria-label={`Delete ${c.name}`} style={{ marginLeft: 4 }} onClick={() => setDeleting(c)}>
                        <Icon name="trash-2" size={12} />
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <section data-testid="hardware-virtual-device-contexts">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <Icon name="split" size={14} style={{ color: 'var(--accent)' }} />
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>Virtual device contexts</div>
        <div style={{ flex: 1 }} />
        {canManage && !contexts.isLoading && !contexts.isError && (
          <button type="button" className="ui-btn sm" onClick={() => setEditing('new')}>
            <Icon name="plus" size={12} />Add context
          </button>
        )}
      </div>
      {body}
      {editing && (
        <VdcModal
          asset={asset}
          ctx={editing === 'new' ? null : editing}
          ips={canReadIpam && ips.isSuccess ? ips.data.rows : null}
          units={units.data ?? []}
          onClose={() => setEditing(null)}
        />
      )}
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title={`Delete ${deleting?.name ?? 'the context'}?`}
        description="Its interfaces leave it; they and their addresses stay on the asset. The change log keeps what it was."
        secondary={<button type="button" className="ui-btn" onClick={() => setDeleting(null)}>Cancel</button>}
        primary={(
          <button type="button" className="ui-btn danger" disabled={del.isPending}
            onClick={() => { if (deleting) del.mutate(deleting, { onSettled: () => setDeleting(null) }); }}>
            Delete
          </button>
        )}
      />
    </section>
  );
}

export interface VdcDraft {
  name: string;
  identifier: string;
  operational_status: VdcStatus;
  business_unit_id: string;
  primary_ip4_id: string;
  primary_ip6_id: string;
  description: string;
}

export function vdcDraftOf(c: VirtualDeviceContext | null): VdcDraft {
  return {
    name: c?.name ?? '',
    identifier: c?.identifier != null ? String(c.identifier) : '',
    operational_status: c?.operational_status ?? 'active',
    business_unit_id: c?.business_unit_id ?? '',
    primary_ip4_id: c?.primary_ip4_id ?? '',
    primary_ip6_id: c?.primary_ip6_id ?? '',
    description: c?.description ?? '',
  };
}

/** What stops a draft saving, before the server is asked. */
export function vdcDraftProblem(d: VdcDraft): string | null {
  const name = d.name.trim();
  if (!name) return 'A name is required.';
  if (name.length > 64) return 'A name is at most 64 characters.';
  if (d.identifier.trim() !== '') {
    const n = Number(d.identifier);
    if (!Number.isInteger(n) || n < 0 || n > 32767) return 'The identifier is a whole number from 0 to 32767.';
  }
  return null;
}

const nullIfEmpty = (s: string) => (s.trim() === '' ? null : s.trim());

export function vdcBodyOf(d: VdcDraft): VirtualDeviceContextInput {
  return {
    name: d.name.trim(),
    identifier: d.identifier.trim() === '' ? null : Number(d.identifier),
    operational_status: d.operational_status,
    business_unit_id: nullIfEmpty(d.business_unit_id),
    primary_ip4_id: nullIfEmpty(d.primary_ip4_id),
    primary_ip6_id: nullIfEmpty(d.primary_ip6_id),
    description: nullIfEmpty(d.description),
  };
}

function VdcModal({ asset, ctx, ips, units, onClose }: {
  asset: Asset; ctx: VirtualDeviceContext | null; ips: readonly IpAddress[] | null;
  units: readonly { id: string; name: string }[]; onClose: () => void;
}) {
  const [d, setD] = useState<VdcDraft>(() => vdcDraftOf(ctx));
  const [error, setError] = useState<string | null>(null);
  const create = useCreateVirtualDeviceContext(asset.id);
  const update = useUpdateVirtualDeviceContext(asset.id);
  const set = <K extends keyof VdcDraft>(k: K, v: VdcDraft[K]) => setD((cur) => ({ ...cur, [k]: v }));
  const problem = vdcDraftProblem(d);
  const busy = create.isPending || update.isPending;
  // Addresses the asset holds, by family; the server checks they are on one
  // of its interfaces. Without ipam.read the current value is kept as is.
  const v4 = (ips ?? []).filter((ip) => !isV6(ip));
  const v6 = (ips ?? []).filter(isV6);
  const save = () => {
    if (problem) return;
    setError(null);
    const body = vdcBodyOf(d);
    if (!ips) {
      delete body.primary_ip4_id;
      delete body.primary_ip6_id;
    }
    const done = { onSuccess: onClose, onError: (e: Error) => setError(e.message) };
    if (ctx) update.mutate({ id: ctx.id, patch: body }, done);
    else create.mutate(body, done);
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon="split"
      title={ctx ? `Edit ${ctx.name}` : 'Add a virtual device context'}
      description="A logical partition of this device that owns some of its interfaces: a Fortinet VDOM, a Palo Alto vsys, a Cisco Nexus VDC or an F5 route domain."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={<button type="button" className="ui-btn primary" disabled={!!problem || busy} onClick={save}>{ctx ? 'Save' : 'Add context'}</button>}
    >
      <div data-testid="vdc-modal">
        <ModalField label="Name">
          <ModalInput aria-label="Context name" value={d.name} onChange={(e) => set('name', e.target.value)} />
        </ModalField>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <ModalField label="Identifier" hint="The device's number for it, if it has one.">
            <ModalInput aria-label="Context identifier" inputMode="numeric" value={d.identifier} onChange={(e) => set('identifier', e.target.value)} />
          </ModalField>
          <ModalField label="Status">
            <ModalSelect aria-label="Context status" value={d.operational_status} onChange={(e) => set('operational_status', e.target.value as VdcStatus)}>
              {VDC_STATUSES.map((s) => <option key={s} value={s}>{VDC_STATUS_LABEL[s]}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <ModalField label="Business unit">
          <ModalSelect aria-label="Context business unit" value={d.business_unit_id} onChange={(e) => set('business_unit_id', e.target.value)}>
            <option value="">None</option>
            {units.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}
          </ModalSelect>
        </ModalField>
        {ips ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <ModalField label="Primary IPv4" hint={v4.length === 0 ? 'The asset holds no IPv4 address.' : undefined}>
              <ModalSelect aria-label="Primary IPv4" value={d.primary_ip4_id} onChange={(e) => set('primary_ip4_id', e.target.value)}>
                <option value="">None</option>
                {v4.map((ip) => <option key={ip.id} value={ip.id}>{hostOf(ip)}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Primary IPv6" hint={v6.length === 0 ? 'The asset holds no IPv6 address.' : undefined}>
              <ModalSelect aria-label="Primary IPv6" value={d.primary_ip6_id} onChange={(e) => set('primary_ip6_id', e.target.value)}>
                <option value="">None</option>
                {v6.map((ip) => <option key={ip.id} value={ip.id}>{hostOf(ip)}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
        ) : (
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 10 }}>Primary addresses need the IPAM read permission; they are left as they are.</div>
        )}
        <ModalField label="Description">
          <ModalInput aria-label="Context description" value={d.description} onChange={(e) => set('description', e.target.value)} />
        </ModalField>
        {(problem !== null || error !== null) && <div data-testid="vdc-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{error ?? problem}</div>}
      </div>
    </Modal>
  );
}
