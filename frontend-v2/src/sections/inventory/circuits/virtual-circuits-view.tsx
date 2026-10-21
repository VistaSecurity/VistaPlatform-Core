// Inventory → Circuits → Virtual circuits (DCIM gap 10; NetBox 4.2
// circuits/virtual-circuit): circuits delivered over a provider network — an
// SD-WAN overlay, an MPLS L3VPN, a Metro Ethernet EVC — whose ends are
// interfaces. A sub-view of the Circuits lens (not a lens of its own). Picking
// one opens its drawer with its terminations; an interface joins a virtual
// circuit from its own page. Writes are behind `circuits.manage`; virtual
// circuit types are kept in Circuit Providers beside the circuit types.
import { useMemo, useState } from 'react';
import { Link, useLocation, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { DrawerCloseBtn, DrawerShell, Icon, MetaRow, SectionLabel } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { fromState, interfaceHref } from '../object-pages/object-links';
import { Chip, ObjectDeleteModal, ObjectFormModal, type IpamField } from '../ipam/ipam-ui';
import {
  CIRCUIT_STATUS_LABEL, CIRCUIT_STATUS_OPTIONS, VC_ROLE_LABEL, useCircuitList, useCircuitWrite,
  type ProviderAccount, type ProviderNetwork, type Provider, type VirtualCircuit, type VirtualCircuitTerminationSummary, type VirtualCircuitType,
} from './circuits-queries';

/** A virtual circuit list row: the table's columns plus the list-only extras. */
export type VirtualCircuitRow = VirtualCircuit & {
  provider_network_name?: string | null; provider_id?: string | null; provider_name?: string | null; type_name?: string | null;
  terminations?: VirtualCircuitTerminationSummary[];
};

/** The Circuits lens's link to one virtual circuit. */
export const virtualCircuitHref = (id: string) => `/inventory?lens=circuits&view=virtual&vc=${encodeURIComponent(id)}`;

const STATUS_TONE: Record<VirtualCircuit['operational_status'], string> = {
  planned: 'var(--app-t3)', provisioning: 'var(--warn)', active: 'var(--ok, var(--accent))', offline: 'var(--danger-text)',
  deprovisioning: 'var(--warn)', decommissioned: 'var(--app-t3)',
};

export function virtualCircuitFields(providers: Provider[], networks: ProviderNetwork[], accounts: ProviderAccount[], types: VirtualCircuitType[]): IpamField[] {
  const provName = new Map(providers.map((p) => [p.id, p.name]));
  return [
    { name: 'cid', label: 'Circuit ID', required: true, mono: true, hint: 'The provider’s reference for the virtual circuit; unique per provider network.' },
    { name: 'provider_network_id', label: 'Provider Network', kind: 'select', required: true, options: [{ value: '', label: 'Choose a provider network' }, ...networks.map((n) => ({ value: n.id, label: `${provName.get(n.provider_id) ?? '—'} · ${n.name}` }))] },
    { name: 'provider_account_id', label: 'Provider Account', kind: 'select', hint: 'An account of the network’s provider.', options: [{ value: '', label: 'None' }, ...accounts.map((a) => ({ value: a.id, label: `${provName.get(a.provider_id) ?? '—'} · ${a.name ?? a.account}` }))] },
    { name: 'type_id', label: 'Virtual Circuit Type', kind: 'select', required: true, options: [{ value: '', label: 'Choose a type' }, ...types.map((t) => ({ value: t.id, label: t.name }))] },
    { name: 'operational_status', label: 'Status', kind: 'select', options: CIRCUIT_STATUS_OPTIONS },
    { name: 'description', label: 'Description' },
  ];
}

const vcInitial = (c: VirtualCircuitRow) => ({
  cid: c.cid, provider_network_id: c.provider_network_id, provider_account_id: c.provider_account_id ?? '', type_id: c.type_id,
  operational_status: c.operational_status, description: c.description ?? '',
});

/** "hub on pe-1 xe-0/0/1": one end as the list says it. */
export function vcTerminationText(t: VirtualCircuitTerminationSummary): string {
  return `${VC_ROLE_LABEL[t.role]} on ${t.asset_name ?? 'an asset'} ${t.interface_name ?? ''}`.trim();
}

function VirtualCircuitDrawer({ vc, onClose, onEdit, onDelete }: { vc: VirtualCircuitRow; onClose: () => void; onEdit: () => void; onDelete: () => void }) {
  const loc = useLocation();
  const terms = useCircuitList('virtual-circuit-terminations', { virtual_circuit_id: vc.id });
  const write = useCircuitWrite('virtual-circuit-terminations');
  const rows = terms.data?.rows ?? [];
  return (
    <DrawerShell onClose={onClose} width={520}>
      <div data-testid="virtual-circuit-drawer" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="cable" size={18} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="mono" style={{ fontWeight: 700, fontSize: 15 }}>{vc.cid}</div>
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>{vc.provider_name ?? '—'} · {vc.provider_network_name ?? '—'} · {vc.type_name ?? '—'}</div>
          </div>
          <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
            <button type="button" className="ui-btn sm ghost" title="Edit" data-testid="virtual-circuit-edit" onClick={onEdit}><Icon name="sliders-horizontal" size={13} /></button>
            <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={onDelete}><Icon name="trash-2" size={13} /></button>
          </PermissionGate>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <SectionLabel icon="file-text">Details</SectionLabel>
        <MetaRow k="Status" v={<Chip tone={STATUS_TONE[vc.operational_status]}>{CIRCUIT_STATUS_LABEL[vc.operational_status]}</Chip>} />
        <MetaRow k="Description" v={vc.description} />

        <SectionLabel icon="ethernet-port">Terminations</SectionLabel>
        <div data-testid="virtual-circuit-terminations">
          {terms.isLoading && <PanelLoading label="Loading terminations…" />}
          {terms.isError && <PanelError message={terms.error instanceof Error ? terms.error.message : 'Request failed'} onRetry={() => { void terms.refetch(); }} />}
          {terms.data && rows.length === 0 && (
            <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '6px 0' }}>No interface terminates this virtual circuit yet. Add one from the interface’s page.</div>
          )}
          {rows.map((t) => (
            <div key={t.id} data-testid="virtual-circuit-termination" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
              <Chip>{VC_ROLE_LABEL[t.role]}</Chip>
              <Link to={interfaceHref(t.interface_id)} state={fromState(loc)} style={{ flex: 1 }}>
                {t.asset_name ?? 'Asset'} <span className="mono">{t.interface_name ?? ''}</span>
              </Link>
              <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
                <button type="button" className="ui-btn sm ghost" title="Remove the termination" data-testid="virtual-circuit-termination-remove" style={{ color: 'var(--danger-text)' }}
                  onClick={() => { void write.remove.mutateAsync(t.id); }}><Icon name="x" size={13} /></button>
              </PermissionGate>
            </div>
          ))}
        </div>
        <SectionLabel icon="git-compare">Changes</SectionLabel>
        <ObjectChanges kind="virtual_circuit" id={vc.id} />
      </div>
    </DrawerShell>
  );
}

const COLS = '1.1fr 1fr 1.1fr 0.9fr 110px 1.6fr';

export function VirtualCircuitsView() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('vc');
  const status = params.get('status') ?? '';
  const [q, setQ] = useState('');
  const set = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    setParams(n, { replace: true });
  };
  const query = useMemo(() => ({ limit: 500, ...(status ? { operational_status: status } : {}), ...(q.trim() ? { q: q.trim() } : {}) }), [status, q]);
  const vcs = useCircuitList('virtual-circuits', query);
  const providers = useCircuitList('providers', { limit: 1000 });
  const networks = useCircuitList('provider-networks', { limit: 1000 });
  const accounts = useCircuitList('provider-accounts', { limit: 1000 });
  const types = useCircuitList('virtual-circuit-types', { limit: 1000 });
  const write = useCircuitWrite('virtual-circuits');
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VirtualCircuitRow | null>(null);
  const [deleting, setDeleting] = useState<VirtualCircuitRow | null>(null);
  const rows = (vcs.data?.rows ?? []) as VirtualCircuitRow[];
  const sel = rows.find((c) => c.id === selected) ?? null;
  const fields = virtualCircuitFields(providers.data?.rows ?? [], networks.data?.rows ?? [], accounts.data?.rows ?? [], types.data?.rows ?? []);
  const filtered = status !== '' || q.trim() !== '';

  return (
    <div data-testid="virtual-circuits-view" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{vcs.data ? `${vcs.data.total} ${vcs.data.total === 1 ? 'virtual circuit' : 'virtual circuits'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <input aria-label="Search virtual circuits" placeholder="Search circuit ID…" value={q} onChange={(e) => setQ(e.target.value)} className="ui-input" style={{ width: 180 }} />
          <select aria-label="Status" value={status} onChange={(e) => set('status', e.target.value || null)} className="ui-input">
            <option value="">Any status</option>
            {CIRCUIT_STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-virtual-circuit" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add virtual circuit</button>
          </PermissionGate>
        </div>
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Circuit ID</span><span>Circuit Provider</span><span>Provider Network</span><span>Type</span><span>Status</span><span>Terminations</span>
        </div>
        {vcs.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading virtual circuits…" /></div>}
        {vcs.isError && <div style={{ padding: 14 }}><PanelError message={vcs.error instanceof Error ? vcs.error.message : 'Request failed'} onRetry={() => { void vcs.refetch(); }} /></div>}
        {vcs.data && rows.length === 0 && (
          <PanelEmpty icon="cable" title={filtered ? 'No virtual circuits match' : 'No virtual circuits yet'}
            message={filtered ? 'Nothing matches this search or status.' : 'Add the overlays a provider runs for you — SD-WAN, MPLS L3VPN, Metro Ethernet — on one of its provider networks; interfaces join them from their own page. Virtual circuit types are kept in Circuit Providers.'} />
        )}
        {rows.map((c) => (
          <div key={c.id} data-testid="virtual-circuit-row" role="button" tabIndex={0} onClick={() => set('vc', c.id)}
            onKeyDown={(e) => { if (e.key === 'Enter') set('vc', c.id); }}
            style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: selected === c.id ? 'var(--app-panel2)' : undefined }}>
            <span className="mono" style={{ fontWeight: 600 }}>{c.cid}</span>
            <span>{c.provider_name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{c.provider_network_name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{c.type_name ?? '—'}</span>
            <span><Chip tone={STATUS_TONE[c.operational_status]}>{CIRCUIT_STATUS_LABEL[c.operational_status]}</Chip></span>
            <span style={{ color: 'var(--app-t2)' }}>{(c.terminations ?? []).length === 0 ? 'None yet' : (c.terminations ?? []).map(vcTerminationText).join(', ')}</span>
          </div>
        ))}
      </div>

      {sel && <VirtualCircuitDrawer vc={sel} onClose={() => set('vc', null)} onEdit={() => setEditing(sel)} onDelete={() => setDeleting(sel)} />}
      {adding && (
        <ObjectFormModal write={write} icon="cable" title="Add virtual circuit" fields={fields} initial={{ operational_status: 'active' }}
          onClose={() => setAdding(false)} onSaved={(row) => set('vc', row.id)} />
      )}
      {editing && (
        <ObjectFormModal write={write} icon="cable" title={`Edit ${editing.cid}`} editId={editing.id} fields={fields} initial={vcInitial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && (
        <ObjectDeleteModal write={write} id={deleting.id} what={`virtual circuit ${deleting.cid}`} onClose={() => setDeleting(null)} onDeleted={() => set('vc', null)} />
      )}
    </div>
  );
}
