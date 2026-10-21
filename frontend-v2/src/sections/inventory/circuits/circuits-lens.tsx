// Inventory → Circuits (DCIM BUILD_PLAN row 4.1; ADR-0010 D8): the tenant's
// circuits with their provider, type, status, both ends and commit rate.
// Picking a circuit opens its drawer: the details, the A and Z terminations
// (editable), and the change log and journal. A second view lists the virtual
// circuits (DCIM gap 10, virtual-circuits-view.tsx). Writes are behind
// `circuits.manage`; providers, accounts, networks and types are kept in
// Settings → Circuit Providers.
import { useMemo, useState } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { DrawerCloseBtn, DrawerShell, Icon, MetaRow, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectJournal } from '../dcim/object-journal';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { circuitHref, fromState } from '../object-pages/object-links';
import { Chip, ObjectDeleteModal, ObjectFormModal, type IpamField } from '../ipam/ipam-ui';
import {
  CIRCUIT_STATUS_LABEL, CIRCUIT_STATUS_OPTIONS, rateText, terminationText, useCircuitList, useCircuitWrite,
  type Circuit, type CircuitTermination, type CircuitTerminationSummary, type CircuitType, type Provider, type ProviderAccount, type ProviderNetwork,
} from './circuits-queries';
import { VirtualCircuitsView } from './virtual-circuits-view';

/** Settings → Circuit Providers, where the circuit catalogues are kept. */
export const CIRCUIT_PROVIDERS_HREF = '/inventory/manage/circuit-providers';

/** A circuit list row: the table's columns plus the list-only extras. */
export type CircuitRow = Circuit & { provider_name?: string; type_name?: string; terminations?: CircuitTerminationSummary[] };

const STATUS_TONE: Record<Circuit['operational_status'], string> = {
  planned: 'var(--app-t3)', provisioning: 'var(--warn)', active: 'var(--ok, var(--accent))', offline: 'var(--danger-text)',
  deprovisioning: 'var(--warn)', decommissioned: 'var(--app-t3)',
};

const end = (c: CircuitRow, side: 'A' | 'Z') => (c.terminations ?? []).find((t) => t.term_side === side);

export function circuitFields(providers: Provider[], accounts: ProviderAccount[], types: CircuitType[]): IpamField[] {
  const provName = new Map(providers.map((p) => [p.id, p.name]));
  return [
    { name: 'cid', label: 'Circuit ID', required: true, mono: true, hint: 'The provider’s reference for the circuit; unique per provider.' },
    { name: 'provider_id', label: 'Circuit Provider', kind: 'select', required: true, options: [{ value: '', label: 'Choose a provider' }, ...providers.map((p) => ({ value: p.id, label: p.name }))] },
    { name: 'provider_account_id', label: 'Provider Account', kind: 'select', options: [{ value: '', label: 'None' }, ...accounts.map((a) => ({ value: a.id, label: `${provName.get(a.provider_id) ?? '—'} · ${a.name ?? a.account}` }))] },
    { name: 'type_id', label: 'Circuit Type', kind: 'select', required: true, options: [{ value: '', label: 'Choose a type' }, ...types.map((t) => ({ value: t.id, label: t.name }))] },
    { name: 'operational_status', label: 'Status', kind: 'select', options: CIRCUIT_STATUS_OPTIONS },
    { name: 'commit_rate_kbps', label: 'Commit rate (kbps)', kind: 'number', placeholder: '100000' },
    { name: 'install_date', label: 'Installed', placeholder: 'YYYY-MM-DD' },
    { name: 'termination_date', label: 'Contract ends', placeholder: 'YYYY-MM-DD' },
    { name: 'description', label: 'Description' },
  ];
}

export const circuitInitial = (c: Circuit) => ({
  cid: c.cid, provider_id: c.provider_id, provider_account_id: c.provider_account_id ?? '', type_id: c.type_id,
  operational_status: c.operational_status, commit_rate_kbps: c.commit_rate_kbps ?? '', install_date: c.install_date ?? '',
  termination_date: c.termination_date ?? '', description: c.description ?? '',
});

/** Set or change one end of a circuit: where it lands and its port details.
 *  Creates the termination when the side has none yet. */
function TerminationEditor({ circuit, side, current, networks, onClose }: {
  circuit: CircuitRow; side: 'A' | 'Z'; current: CircuitTermination | undefined; networks: ProviderNetwork[]; onClose: () => void;
}) {
  const write = useCircuitWrite('circuit-terminations');
  const [target, setTarget] = useState(current?.termination_kind === 'provider_network' ? current.termination_id ?? '' : '');
  const [port, setPort] = useState(current?.port_speed_kbps != null ? String(current.port_speed_kbps) : '');
  const [xconnect, setXconnect] = useState(current?.xconnect_id ?? '');
  const [pp, setPp] = useState(current?.pp_info ?? '');
  const [err, setErr] = useState<string | null>(null);
  const busy = write.create.isPending || write.update.isPending;
  // A termination on a kind this editor does not offer yet (a site, set by an
  // import) is kept as it is unless the person picks a provider network.
  const otherKind = current?.termination_kind && current.termination_kind !== 'provider_network';
  const submit = async () => {
    setErr(null);
    const body: Record<string, unknown> = {
      port_speed_kbps: port.trim() === '' ? null : Number(port),
      xconnect_id: xconnect.trim() || null,
      pp_info: pp.trim() || null,
    };
    if (target) Object.assign(body, { termination_kind: 'provider_network', termination_id: target });
    else if (!otherKind) Object.assign(body, { termination_kind: null, termination_id: null });
    try {
      if (current) await write.update.mutateAsync({ id: current.id, body });
      else await write.create.mutateAsync({ ...body, circuit_id: circuit.id, term_side: side });
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="cable" title={`${side} end of ${circuit.cid}`}
      primary={<button type="button" className="ui-btn accent" data-testid="termination-save" disabled={busy} onClick={() => { void submit(); }}>{busy ? 'Saving…' : 'Save'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      {err && <div role="alert" data-testid="termination-error" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 12 }}>{err}</div>}
      <ModalField label="Lands on" hint={otherKind ? `Currently ${terminationText(current as CircuitTerminationSummary)}; pick a provider network to change it.` : 'A provider network of the circuit’s provider. Sites become available with the Sites view.'}>
        <ModalSelect aria-label="Lands on" value={target} onChange={(e) => setTarget(e.target.value)}>
          <option value="">{otherKind ? 'Keep the current target' : 'Not connected'}</option>
          {networks.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Port speed (kbps)">
        <ModalInput aria-label="Port speed (kbps)" type="number" value={port} onChange={(e) => setPort(e.target.value)} />
      </ModalField>
      <ModalField label="Cross-connect ID">
        <ModalInput aria-label="Cross-connect ID" className="mono" value={xconnect} onChange={(e) => setXconnect(e.target.value)} />
      </ModalField>
      <ModalField label="Patch panel / port">
        <ModalInput aria-label="Patch panel / port" value={pp} onChange={(e) => setPp(e.target.value)} />
      </ModalField>
    </Modal>
  );
}

const PRIORITY_OPTIONS = [
  { value: '', label: 'No priority' }, { value: 'primary', label: 'Primary' }, { value: 'secondary', label: 'Secondary' },
  { value: 'tertiary', label: 'Tertiary' }, { value: 'inactive', label: 'Inactive' },
];

/** The circuit's circuit groups (NetBox circuit-group assignments): listed,
 *  added with a priority, removed. */
function CircuitGroupsSection({ circuit }: { circuit: CircuitRow }) {
  const assignments = useCircuitList('circuit-group-assignments', { circuit_id: circuit.id });
  const groups = useCircuitList('circuit-groups', { limit: 1000 });
  const write = useCircuitWrite('circuit-group-assignments');
  const [adding, setAdding] = useState(false);
  const groupName = new Map((groups.data?.rows ?? []).map((g) => [g.id, g.name]));
  const rows = assignments.data?.rows ?? [];
  const fields: IpamField[] = [
    { name: 'group_id', label: 'Circuit Group', kind: 'select', required: true, options: [{ value: '', label: 'Choose a group' }, ...(groups.data?.rows ?? []).map((g) => ({ value: g.id, label: g.name }))] },
    { name: 'priority', label: 'Priority', kind: 'select', options: PRIORITY_OPTIONS },
  ];
  return (
    <div data-testid="circuit-groups">
      {assignments.isLoading && <PanelLoading label="Loading circuit groups…" />}
      {assignments.isError && <PanelError message={assignments.error instanceof Error ? assignments.error.message : 'Request failed'} onRetry={() => { void assignments.refetch(); }} />}
      {assignments.data && rows.length === 0 && <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '6px 0' }}>In no circuit group.</div>}
      {rows.map((a) => (
        <div key={a.id} data-testid="circuit-group-row" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
          <span style={{ flex: 1 }}>{groupName.get(a.group_id) ?? '—'}</span>
          {a.priority && <Chip>{a.priority}</Chip>}
          <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
            <button type="button" className="ui-btn sm ghost" title="Remove from group" style={{ color: 'var(--danger-text)' }}
              onClick={() => { void write.remove.mutateAsync(a.id); }}><Icon name="x" size={13} /></button>
          </PermissionGate>
        </div>
      ))}
      <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
        <button type="button" className="ui-btn sm" data-testid="add-circuit-group" style={{ marginTop: 8 }} onClick={() => setAdding(true)}><Icon name="plus" size={13} />Add to group</button>
      </PermissionGate>
      {adding && (
        <ObjectFormModal write={write} icon="cable" title={`Add ${circuit.cid} to a group`} fields={fields} fixed={{ circuit_id: circuit.id }} onClose={() => setAdding(false)} />
      )}
    </div>
  );
}

/** The circuit's body — details, A/Z terminations (editable), groups — shared
 *  by the drawer and the circuit page. `substrate` adds the custom fields,
 *  changes and journal the page supplies itself. */
export function CircuitDetails({ circuit, substrate = true }: { circuit: CircuitRow; substrate?: boolean }) {
  const terms = useCircuitList('circuit-terminations', { circuit_id: circuit.id });
  const networks = useCircuitList('provider-networks', { provider_id: circuit.provider_id, limit: 1000 });
  const [editing, setEditing] = useState<'A' | 'Z' | null>(null);
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');
  const { update: updateCircuit } = useCircuitWrite('circuits');
  const bySide = (s: 'A' | 'Z') => (terms.data?.rows ?? []).find((t) => t.term_side === s);
  const nameOf = (t: CircuitTermination | undefined) =>
    (t ? terminationText({ ...t, termination_name: t.termination_name ?? null }) : 'Not set');
  return (
    <>
        <SectionLabel icon="file-text">Details</SectionLabel>
        <MetaRow k="Status" v={<Chip tone={STATUS_TONE[circuit.operational_status]}>{CIRCUIT_STATUS_LABEL[circuit.operational_status]}</Chip>} />
        <MetaRow k="Commit rate" v={rateText(circuit.commit_rate_kbps)} />
        <MetaRow k="Installed" v={circuit.install_date} />
        <MetaRow k="Contract ends" v={circuit.termination_date} />
        <MetaRow k="Description" v={circuit.description} />

        <SectionLabel icon="cable">Terminations</SectionLabel>
        <div data-testid="circuit-terminations">
          {terms.isLoading && <PanelLoading label="Loading terminations…" />}
          {terms.isError && <PanelError message={terms.error instanceof Error ? terms.error.message : 'Request failed'} onRetry={() => { void terms.refetch(); }} />}
          {terms.data && (['A', 'Z'] as const).map((side) => {
            const t = bySide(side);
            return (
              <div key={side} data-testid={`termination-${side}`} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
                <span className="mono" style={{ fontWeight: 700, width: 18 }}>{side}</span>
                <span style={{ flex: 1 }}>
                  {nameOf(t)}
                  {t && <span style={{ color: 'var(--app-t3)' }}> · port {rateText(t.port_speed_kbps)}{t.xconnect_id ? ` · xconnect ${t.xconnect_id}` : ''}</span>}
                </span>
                <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
                  <button type="button" className="ui-btn sm" data-testid={`termination-edit-${side}`} onClick={() => setEditing(side)}>{t ? 'Edit' : 'Set'}</button>
                </PermissionGate>
              </div>
            );
          })}
        </div>

        <SectionLabel icon="layers">Circuit Groups</SectionLabel>
        <CircuitGroupsSection circuit={circuit} />

        {substrate && (
          <>
            {/* Custom fields (DCIM row 5.1): edited through the circuit's PATCH. */}
            <SectionLabel icon="list-checks">Custom fields</SectionLabel>
            <CustomFieldsPanel kind="circuit" id={circuit.id} values={circuit.custom_fields} permission={TENANT_PERMISSIONS.circuits.manage}
              onChange={(custom_fields) => updateCircuit.mutateAsync({ id: circuit.id, body: { custom_fields } })} />

            <div role="tablist" style={{ display: 'flex', gap: 4, marginTop: 18, borderBottom: '1px solid var(--app-border)' }}>
              {(['changes', 'journal'] as const).map((tb) => (
                <button key={tb} type="button" role="tab" aria-selected={tab === tb} className="ui-btn ghost sm"
                  style={{ borderBottom: tab === tb ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(tb)}>
                  {tb === 'changes' ? 'Changes' : 'Journal'}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 8 }}>
              {tab === 'changes' ? <ObjectChanges kind="circuit" id={circuit.id} /> : <ObjectJournal kind="circuit" id={circuit.id} />}
            </div>
          </>
        )}
      {editing && (
        <TerminationEditor circuit={circuit} side={editing} current={bySide(editing)} networks={networks.data?.rows ?? []} onClose={() => setEditing(null)} />
      )}
    </>
  );
}

function CircuitDrawer({ circuit, onClose, onEdit, onDelete }: {
  circuit: CircuitRow; onClose: () => void; onEdit: () => void; onDelete: () => void;
}) {
  const loc = useLocation();
  return (
    <DrawerShell onClose={onClose} width={520}>
      <div data-testid="circuit-drawer" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="cable" size={18} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <Link to={circuitHref(circuit.id)} state={fromState(loc)} data-testid="circuit-open-page" title="Open the circuit page" className="mono" style={{ fontWeight: 700, fontSize: 15, color: 'inherit' }}>{circuit.cid}</Link>
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>{circuit.provider_name ?? '—'} · {circuit.type_name ?? '—'}</div>
          </div>
          <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
            <button type="button" className="ui-btn sm ghost" title="Edit" data-testid="circuit-edit" onClick={onEdit}><Icon name="sliders-horizontal" size={13} /></button>
            <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={onDelete}><Icon name="trash-2" size={13} /></button>
          </PermissionGate>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <CircuitDetails circuit={circuit} />
      </div>
    </DrawerShell>
  );
}

const COLS = '1.1fr 1fr 0.9fr 110px 1.2fr 1.2fr 110px';

/** The Circuits lens: physical circuits, or (`view=virtual`, DCIM gap 10)
 *  the virtual circuits that run over provider networks. One lens with two
 *  views — the lens count is audited. */
export function CircuitsLens() {
  const [params, setParams] = useSearchParams();
  const virtual = params.get('view') === 'virtual';
  const show = (v: 'physical' | 'virtual') => {
    const n = new URLSearchParams(params);
    for (const k of ['view', 'circuit', 'vc', 'status']) n.delete(k);
    if (v === 'virtual') n.set('view', 'virtual');
    setParams(n, { replace: true });
  };
  return (
    <div data-testid="circuits-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="cable" size={17} style={{ color: 'var(--accent)' }} />Circuits
        </h1>
        <div role="tablist" aria-label="Circuit view" style={{ display: 'flex', gap: 6 }}>
          <button type="button" role="tab" aria-selected={!virtual} data-testid="circuits-view-physical" className={`ui-btn sm${!virtual ? ' accent' : ''}`} onClick={() => show('physical')}>Circuits</button>
          <button type="button" role="tab" aria-selected={virtual} data-testid="circuits-view-virtual" className={`ui-btn sm${virtual ? ' accent' : ''}`} onClick={() => show('virtual')}>Virtual circuits</button>
        </div>
        <Link to={CIRCUIT_PROVIDERS_HREF} className="ui-btn sm ghost" style={{ marginLeft: 'auto' }}><Icon name="globe" size={14} />Circuit Providers</Link>
      </div>
      {virtual ? <VirtualCircuitsView /> : <PhysicalCircuits />}
    </div>
  );
}

function PhysicalCircuits() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const loc = useLocation();
  const selected = params.get('circuit');
  const status = params.get('status') ?? '';
  const [q, setQ] = useState('');
  const set = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    setParams(n, { replace: true });
  };
  const query = useMemo(() => ({ limit: 500, ...(status ? { operational_status: status } : {}), ...(q.trim() ? { q: q.trim() } : {}) }), [status, q]);
  const circuits = useCircuitList('circuits', query);
  const providers = useCircuitList('providers', { limit: 1000 });
  const accounts = useCircuitList('provider-accounts', { limit: 1000 });
  const types = useCircuitList('circuit-types', { limit: 1000 });
  const write = useCircuitWrite('circuits');
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CircuitRow | null>(null);
  const [deleting, setDeleting] = useState<CircuitRow | null>(null);
  const rows = (circuits.data?.rows ?? []) as CircuitRow[];
  const sel = rows.find((c) => c.id === selected) ?? null;
  const fields = circuitFields(providers.data?.rows ?? [], accounts.data?.rows ?? [], types.data?.rows ?? []);
  const filtered = status !== '' || q.trim() !== '';

  return (
    <div data-testid="physical-circuits-view" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{circuits.data ? `${circuits.data.total} ${circuits.data.total === 1 ? 'circuit' : 'circuits'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <input aria-label="Search circuits" placeholder="Search circuit ID…" value={q} onChange={(e) => setQ(e.target.value)} className="ui-input" style={{ width: 180 }} />
          <select aria-label="Status" value={status} onChange={(e) => set('status', e.target.value || null)} className="ui-input">
            <option value="">Any status</option>
            {CIRCUIT_STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-circuit" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add circuit</button>
          </PermissionGate>
        </div>
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Circuit ID</span><span>Circuit Provider</span><span>Type</span><span>Status</span><span>A end</span><span>Z end</span><span>Commit rate</span>
        </div>
        {circuits.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading circuits…" /></div>}
        {circuits.isError && <div style={{ padding: 14 }}><PanelError message={circuits.error instanceof Error ? circuits.error.message : 'Request failed'} onRetry={() => { void circuits.refetch(); }} /></div>}
        {circuits.data && rows.length === 0 && (
          <PanelEmpty icon="cable" title={filtered ? 'No circuits match' : 'No circuits yet'}
            message={filtered ? 'Nothing matches this search or status.' : 'Add the circuits your sites run on — internet, MPLS, dark fibre — with their provider and both ends. Providers and circuit types are managed from Infrastructure → Circuits.'} />
        )}
        {rows.map((c) => (
          <div key={c.id} data-testid="circuit-row" role="button" tabIndex={0} onClick={() => navigate(circuitHref(c.id), { state: fromState(loc) })}
            onKeyDown={(e) => { if (e.key === 'Enter') navigate(circuitHref(c.id), { state: fromState(loc) }); }}
            style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: selected === c.id ? 'var(--app-panel2)' : undefined }}>
            <span className="mono" style={{ fontWeight: 600 }}>{c.cid}</span>
            <span>{c.provider_name ?? '—'}</span>
            <span style={{ color: 'var(--app-t2)' }}>{c.type_name ?? '—'}</span>
            <span><Chip tone={STATUS_TONE[c.operational_status]}>{CIRCUIT_STATUS_LABEL[c.operational_status]}</Chip></span>
            <span style={{ color: 'var(--app-t2)' }}>{terminationText(end(c, 'A'))}</span>
            <span style={{ color: 'var(--app-t2)' }}>{terminationText(end(c, 'Z'))}</span>
            <span className="mono" style={{ fontSize: 12 }}>{rateText(c.commit_rate_kbps)}</span>
          </div>
        ))}
      </div>

      {sel && <CircuitDrawer circuit={sel} onClose={() => set('circuit', null)} onEdit={() => setEditing(sel)} onDelete={() => setDeleting(sel)} />}
      {adding && (
        <ObjectFormModal write={write} icon="cable" title="Add circuit" fields={fields} initial={{ operational_status: 'active' }}
          onClose={() => setAdding(false)} onSaved={(row) => set('circuit', row.id)} />
      )}
      {editing && (
        <ObjectFormModal write={write} icon="cable" title={`Edit ${editing.cid}`} editId={editing.id} fields={fields} initial={circuitInitial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && (
        <ObjectDeleteModal write={write} id={deleting.id} what={`circuit ${deleting.cid}`} onClose={() => setDeleting(null)} onDeleted={() => set('circuit', null)} />
      )}
    </div>
  );
}
