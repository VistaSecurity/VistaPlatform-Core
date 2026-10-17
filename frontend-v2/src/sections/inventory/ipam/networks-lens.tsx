// Inventory → Networks (DCIM BUILD_PLAN row 1.3): one VRF's prefixes as a
// tree, with utilisation, and a Find box that says where an address lives.
//
// The tree is containment computed from the addresses on the server
// (`/ipam/prefixes/tree`); nothing here works out parents. Picking a prefix
// opens its panel: children, ranges, addresses, free space, its changes and
// journal. Writes are behind `ipam.manage`; reading needs `ipam.read`.
import { useMemo, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { ExportButton } from '../dcim/export-button';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import {
  GLOBAL_VRF, LIFECYCLE_LABEL, PREFIX_STATUS_LABEL, useIpamFind, useIpamList, usePrefixTree,
  type Prefix, type PrefixTreeNode,
} from './ipam-queries';
import { Chip, IpamFormModal, UtilizationBar } from './ipam-ui';
import { PrefixPanel, prefixFields } from './prefix-panel';
import { useBusinessUnits } from '../../settings/business-units-queries';

const STATUS_TONE: Record<Prefix['operational_status'], string> = {
  container: 'var(--app-t2)', active: 'var(--ok)', reserved: 'var(--warn)', deprecated: 'var(--app-t3)',
};

/** The VRF picker: the global table first, then the tenant's VRFs. */
export function VrfSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const vrfs = useIpamList('vrfs', { limit: 1000 });
  return (
    <select aria-label="VRF" data-testid="vrf-select" value={value} onChange={(e) => onChange(e.target.value)}
      style={{ height: 32, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5 }}>
      <option value={GLOBAL_VRF}>Global (no VRF)</option>
      {(vrfs.data?.rows ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}{v.rd ? ` (${v.rd})` : ''}</option>)}
    </select>
  );
}

function TreeRow({ node, open, toggle, selected, onSelect, roles, vlans, units }: {
  node: PrefixTreeNode; open: Set<string>; toggle: (id: string) => void; selected: string | null;
  onSelect: (id: string) => void; roles: Map<string, string>; vlans: Map<string, string>; units: Map<string, string>;
}) {
  const p = node.prefix;
  const isOpen = open.has(p.id);
  const kids = node.children ?? [];
  return (
    <>
      <div role="treeitem" aria-expanded={kids.length ? isOpen : undefined} aria-selected={selected === p.id} data-testid="prefix-row"
        onClick={() => onSelect(p.id)}
        style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 2fr) 110px 1fr 1fr 150px 130px', alignItems: 'center', gap: 10, padding: '7px 12px',
          borderBottom: '1px solid var(--app-border)', cursor: 'pointer', background: selected === p.id ? 'var(--app-panel2)' : undefined }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: node.depth * 18 }}>
          {kids.length > 0 ? (
            <button type="button" className="ui-btn ghost" aria-label={isOpen ? `Collapse ${p.prefix}` : `Expand ${p.prefix}`} data-testid="prefix-toggle"
              style={{ padding: 0, height: 20, width: 20 }} onClick={(e) => { e.stopPropagation(); toggle(p.id); }}>
              <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={14} />
            </button>
          ) : <span style={{ width: 20 }} />}
          <span className="mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{p.prefix}</span>
          {p.status !== 'active' && <Chip tone="var(--warn)">{LIFECYCLE_LABEL[p.status]}</Chip>}
        </span>
        <span><Chip tone={STATUS_TONE[p.operational_status]}>{PREFIX_STATUS_LABEL[p.operational_status]}</Chip></span>
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{p.role_id ? roles.get(p.role_id) ?? '—' : '—'}</span>
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>
          {p.vlan_id ? vlans.get(p.vlan_id) ?? 'VLAN' : '—'}
          {p.business_unit_id && <span data-testid="prefix-business-unit" style={{ marginLeft: 6, color: 'var(--app-t3)' }}>· {units.get(p.business_unit_id) ?? 'business unit'}</span>}
        </span>
        <UtilizationBar pct={p.utilization} />
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
          {p.child_count ?? 0} {p.child_count === 1 ? 'prefix' : 'prefixes'} · {p.ip_count ?? 0} {p.ip_count === 1 ? 'address' : 'addresses'}
        </span>
      </div>
      {isOpen && kids.map((c) => (
        <TreeRow key={c.prefix.id} node={c} open={open} toggle={toggle} selected={selected} onSelect={onSelect} roles={roles} vlans={vlans} units={units} />
      ))}
    </>
  );
}

/** The Find box: where does this address live, in every VRF that has it. */
export function FindBox() {
  const [draft, setDraft] = useState('');
  const [address, setAddress] = useState('');
  const q = useIpamFind(address, '');
  const submit = (e: FormEvent) => { e.preventDefault(); setAddress(draft.trim()); };
  return (
    <div style={{ position: 'relative' }}>
      <form onSubmit={submit} style={{ display: 'flex', gap: 6 }}>
        <input aria-label="Find an address" data-testid="find-input" placeholder="Find an address, e.g. 10.10.0.5" value={draft} onChange={(e) => setDraft(e.target.value)}
          className="mono" style={{ height: 32, width: 240, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5 }} />
        <button type="submit" className="ui-btn sm" data-testid="find-submit"><Icon name="search" size={13} />Find</button>
      </form>
      {address && (
        <div data-testid="find-results" style={{ position: 'absolute', right: 0, top: 38, zIndex: 5, width: 420, padding: 12, borderRadius: 12, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: 'var(--shadow-md, 0 8px 24px rgba(0,0,0,.12))' }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 6 }}>
            <span className="mono" style={{ fontWeight: 600, fontSize: 13 }}>{address}</span>
            <button type="button" className="ui-btn ghost sm" aria-label="Close" style={{ marginLeft: 'auto' }} onClick={() => setAddress('')}><Icon name="x" size={13} /></button>
          </div>
          {q.isLoading && <PanelLoading label="Looking it up…" />}
          {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} />}
          {q.data && q.data.length === 0 && (
            <PanelEmpty icon="search-x" title="Not in IPAM" message="No prefix contains this address and no IP address record has it, in any VRF." />
          )}
          {q.data?.map((r) => (
            <div key={r.vrf_id ?? 'global'} data-testid="find-result" style={{ padding: '8px 0', borderTop: '1px solid var(--app-border)', fontSize: 12.5 }}>
              <div style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{r.vrf_name ?? 'Global (no VRF)'}</div>
              <div>Prefix: <span className="mono">{r.prefix ? r.prefix.prefix : 'none'}</span></div>
              <div>IP address: <span className="mono">{r.ip_address ? r.ip_address.address : 'not recorded'}</span>
                {r.ip_address?.dns_name && <span style={{ color: 'var(--app-t3)' }}> · {r.ip_address.dns_name}</span>}</div>
              <div>
                Held by:{' '}
                {r.asset ? <Link to={`/inventory/assets/${r.asset.id}`}>{r.asset.name}</Link>
                  : r.ip_address ? <span style={{ color: 'var(--app-t3)' }}>no asset says it holds this address</span>
                    : <span style={{ color: 'var(--app-t3)' }}>—</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function NetworksLens() {
  const [params, setParams] = useSearchParams();
  const vrf = params.get('vrf') ?? GLOBAL_VRF;
  const selected = params.get('prefix');
  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };
  const tree = usePrefixTree(vrf);
  const roles = useIpamList('prefix-roles', { limit: 1000 });
  const vlans = useIpamList('vlans', { limit: 1000 });
  const roleNames = useMemo(() => new Map((roles.data?.rows ?? []).map((r) => [r.id, r.name])), [roles.data]);
  const vlanNames = useMemo(() => new Map((vlans.data?.rows ?? []).map((v) => [v.id, `${v.vid} ${v.name}`])), [vlans.data]);
  // Business units are a DCIM catalogue (row 1.1, dcim.read); without it the
  // row still says a unit is assigned, just not which.
  const units = useBusinessUnits();
  const unitNames = useMemo(() => new Map((units.data ?? []).map((u) => [u.id, u.name])), [units.data]);
  // null until the person first toggles: roots start open, because a tree that
  // opens fully collapsed shows one line per /8.
  const [open, setOpen] = useState<Set<string> | null>(null);
  const [adding, setAdding] = useState(false);
  const roots = useMemo(() => tree.data?.nodes ?? [], [tree.data]);
  const effectiveOpen = useMemo(() => open ?? new Set(roots.map((r) => r.prefix.id)), [open, roots]);
  const toggle = (id: string) => {
    const s = new Set(effectiveOpen);
    if (s.has(id)) s.delete(id); else s.add(id);
    setOpen(s);
  };

  return (
    <div data-testid="networks-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="network" size={17} style={{ color: 'var(--accent)' }} />Networks
        </h1>
        <VrfSelect value={vrf} onChange={(v) => { const n = new URLSearchParams(params); n.set('vrf', v); n.delete('prefix'); setParams(n, { replace: true }); setOpen(null); }} />
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{tree.data ? `${tree.data.total} ${tree.data.total === 1 ? 'prefix' : 'prefixes'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <FindBox />
          <ExportButton kind="prefix" filters={{ vrf_id: vrf }} />
          <Link to="/inventory/manage/ipam" className="ui-btn sm"><Icon name="sliders-horizontal" size={14} />IPAM catalogs</Link>
          <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-prefix" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add prefix</button>
          </PermissionGate>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? 'minmax(0, 1.5fr) minmax(360px, 1fr)' : '1fr', gap: 14, alignItems: 'start' }}>
        <div role="tree" aria-label="Prefixes" style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
          {tree.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading prefixes…" /></div>}
          {tree.isError && (
            <div style={{ padding: 14 }}>
              <PanelError message={tree.error instanceof Error ? tree.error.message : 'Request failed'} onRetry={() => { void tree.refetch(); }} />
            </div>
          )}
          {tree.data && roots.length === 0 && (
            <PanelEmpty icon="network" title="No prefixes in this VRF yet"
              message="Add the networks you run — a /16 container and the /24s inside it — and their utilisation, free space and addresses appear here. Discovered networks arrive pending approval." />
          )}
          {roots.map((n) => (
            <TreeRow key={n.prefix.id} node={n} open={effectiveOpen} toggle={toggle} selected={selected}
              onSelect={(id) => setParam('prefix', id)} roles={roleNames} vlans={vlanNames} units={unitNames} />
          ))}
        </div>
        {selected && <PrefixPanel id={selected} onClose={() => setParam('prefix', null)} onSelect={(id) => setParam('prefix', id)} />}
      </div>

      {adding && (
        <IpamFormModal route="prefixes" title="Add prefix" fields={prefixFields(roles.data?.rows ?? [], vlans.data?.rows ?? [], units.data ?? [])}
          initial={{ operational_status: 'active' }} fixed={{ vrf_id: vrf === GLOBAL_VRF ? null : vrf }}
          onClose={() => setAdding(false)} onSaved={(row) => setParam('prefix', row.id)} />
      )}
    </div>
  );
}
