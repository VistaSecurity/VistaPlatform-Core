// Inventory → Tunnels (DCIM BUILD_PLAN row 4.3; ADR-0010 D8): every VPN
// tunnel with its posture — encapsulation, status, the devices and peers it
// joins, its IKE version, the weakest catalogue component across both phases
// (banded with the one risk ladder) and its PQC class. Picking a tunnel opens
// its IKE and IPsec proposals with each algorithm's catalogue assessment, and
// its change log. Writes are behind `vpn.manage`.
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { riskColor } from '../../../components/ui/risk';
import { ObjectChanges } from '../dcim/object-changes';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { LIFECYCLE_LABEL } from '../ipam/ipam-queries';
import { Chip, ObjectDeleteModal, ObjectFormModal, type IpamField } from '../ipam/ipam-ui';
import {
  ENCAPSULATION_LABEL, PQC_LABEL, riskBand, useVpnList, useVpnWrite,
  type IkeProposal, type IpsecProposal, type Tunnel, type VpnAlgorithmAssessment,
} from './vpn-queries';

const ENCAPSULATIONS = Object.entries(ENCAPSULATION_LABEL).map(([value, label]) => ({ value, label }));
const STATUSES = [{ value: 'active', label: 'Active' }, { value: 'planned', label: 'Planned' }, { value: 'disabled', label: 'Disabled' }];

function tunnelFields(profiles: { id: string; name: string }[]): IpamField[] {
  return [
    { name: 'name', label: 'Name', required: true },
    { name: 'encapsulation', label: 'Encapsulation', kind: 'select', options: ENCAPSULATIONS, required: true },
    { name: 'operational_status', label: 'Status', kind: 'select', options: STATUSES },
    { name: 'ipsec_profile_id', label: 'IPsec profile', kind: 'select', options: [{ value: '', label: 'None' }, ...profiles.map((p) => ({ value: p.id, label: p.name }))] },
    { name: 'description', label: 'Description' },
  ];
}

/** The weakest component, banded; "not assessed" when nothing scored it. */
export function WeakestComponent({ tunnel }: { tunnel: Tunnel }) {
  const w = tunnel.weakest_component;
  const band = riskBand(w?.risk_score);
  if (!w || !band) return <span style={{ color: 'var(--app-t3)' }} title="No catalogued algorithm scored this tunnel">Not assessed</span>;
  return (
    <span data-testid="weakest-component" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <Chip tone={riskColor(band)} title={`${w.phase.toUpperCase()} ${w.role.replace('_', ' ')} — catalogue risk ${w.risk_score}`}>{band}</Chip>
      <span className="mono" style={{ fontSize: 11.5 }}>{w.code}</span>
    </span>
  );
}

function PqcChip({ tunnel }: { tunnel: Tunnel }) {
  const s = tunnel.pqc_status ?? 'unclassified';
  const tone = s === 'needs_migration' ? 'var(--warn-strong)' : s === 'unclassified' ? 'var(--app-t3)' : 'var(--ok)';
  return <span data-testid="pqc-status"><Chip tone={tone}>{PQC_LABEL[s]}</Chip></span>;
}

function peersOf(t: Tunnel): string {
  const ends = (t.terminations ?? []).map((e) => `${e.asset_name ?? 'device'} ${e.interface}`);
  const peers = (t.observed_peer_addresses ?? []).map((p) => p.replace(/\/(32|128)$/, ''));
  const all = [...ends, ...peers];
  return all.length ? all.join(' ↔ ') : '—';
}

function Assessment({ a, text }: { a: VpnAlgorithmAssessment | null | undefined; text: string | null | undefined }) {
  if (!text) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
  const band = riskBand(a?.risk_score);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span className="mono">{text}</span>
      {a && band ? <Chip tone={riskColor(band)} title={`${a.code}: ${a.strength}${a.deprecation_status ? `, ${a.deprecation_status}` : ''} (catalogue risk ${a.risk_score})`}>{a.strength}</Chip>
        : <Chip title="Not in the algorithm catalogue">unassessed</Chip>}
    </span>
  );
}

/** A tunnel's proposals, through its profile and policies. */
function TunnelProposals({ tunnel }: { tunnel: Tunnel }) {
  const profiles = useVpnList('ipsec-profiles', { limit: 1000 });
  const ikePolicies = useVpnList('ike-policies', { limit: 1000 });
  const ipsecPolicies = useVpnList('ipsec-policies', { limit: 1000 });
  const ikeProposals = useVpnList('ike-proposals', { limit: 1000 });
  const ipsecProposals = useVpnList('ipsec-proposals', { limit: 1000 });
  const loading = [profiles, ikePolicies, ipsecPolicies, ikeProposals, ipsecProposals].some((q) => q.isLoading);
  const failed = [profiles, ikePolicies, ipsecPolicies, ikeProposals, ipsecProposals].find((q) => q.isError);
  if (!tunnel.ipsec_profile_id) return <PanelEmpty icon="shield" title="No IPsec profile" message="This tunnel names no IKE or IPsec proposals." />;
  if (loading) return <PanelLoading label="Loading proposals…" />;
  if (failed) return <PanelError message={failed.error instanceof Error ? failed.error.message : 'Request failed'} onRetry={() => { void failed.refetch(); }} />;
  const profile = profiles.data?.rows.find((p) => p.id === tunnel.ipsec_profile_id);
  const ikePol = ikePolicies.data?.rows.find((p) => p.id === profile?.ike_policy_id);
  const ipsecPol = ipsecPolicies.data?.rows.find((p) => p.id === profile?.ipsec_policy_id);
  const ike = (ikePol?.proposals ?? []).map((id) => ikeProposals.data?.rows.find((p) => p.id === id)).filter((p): p is IkeProposal => !!p);
  const esp = (ipsecPol?.proposals ?? []).map((id) => ipsecProposals.data?.rows.find((p) => p.id === id)).filter((p): p is IpsecProposal => !!p);
  return (
    <div data-testid="tunnel-proposals" style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12.5 }}>
      <div>
        <div style={{ fontWeight: 600, marginBottom: 4 }}>
          IKE (phase 1){ikePol?.version ? ` · IKEv${ikePol.version}` : ''}{ikePol?.mode ? ` · ${ikePol.mode} mode` : ''}
          {ikePol?.preshared_key_present && <span style={{ color: 'var(--app-t3)', fontWeight: 400 }}> · pre-shared key configured (never collected)</span>}
        </div>
        {ike.length === 0 ? <span style={{ color: 'var(--app-t3)' }}>No IKE proposals.</span> : ike.map((p) => (
          <div key={p.id} data-testid="ike-proposal" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '4px 0', borderBottom: '1px solid var(--app-border)' }}>
            <Assessment a={p.encryption_assessment} text={p.encryption_algorithm} />
            <Assessment a={p.authentication_assessment} text={p.authentication_algorithm} />
            <Assessment a={p.group_assessment} text={p.group ? `group ${p.group}` : null} />
          </div>
        ))}
      </div>
      <div>
        <div style={{ fontWeight: 600, marginBottom: 4 }}>
          IPsec (phase 2){profile?.mode ? ` · ${profile.mode.toUpperCase()}` : ''}{ipsecPol?.pfs_group ? ' · PFS ' : ' · no PFS'}
          {ipsecPol?.pfs_group ? <Assessment a={ipsecPol.pfs_group_assessment} text={`group ${ipsecPol.pfs_group}`} /> : null}
        </div>
        {esp.length === 0 ? <span style={{ color: 'var(--app-t3)' }}>No IPsec proposals.</span> : esp.map((p) => (
          <div key={p.id} data-testid="ipsec-proposal" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '4px 0', borderBottom: '1px solid var(--app-border)' }}>
            <Assessment a={p.encryption_assessment} text={p.encryption_algorithm} />
            <Assessment a={p.authentication_assessment} text={p.authentication_algorithm} />
          </div>
        ))}
      </div>
    </div>
  );
}

function TunnelDetail({ tunnel, onClose }: { tunnel: Tunnel; onClose: () => void }) {
  const [tab, setTab] = useState<'proposals' | 'changes'>('proposals');
  return (
    <aside data-testid="tunnel-panel" style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name="shield" size={15} style={{ color: 'var(--accent)' }} />
        <span style={{ fontWeight: 700 }}>{tunnel.name}</span>
        <Chip>{ENCAPSULATION_LABEL[tunnel.encapsulation]}</Chip>
        <button type="button" className="ui-btn sm ghost" aria-label="Close" style={{ marginLeft: 'auto' }} onClick={onClose}><Icon name="x" size={13} /></button>
      </div>
      <div style={{ fontSize: 12.5, marginTop: 8, display: 'grid', gap: 4 }}>
        <div><span style={{ color: 'var(--app-t3)' }}>Ends: </span>{peersOf(tunnel)}</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><span style={{ color: 'var(--app-t3)' }}>Weakest component:</span><WeakestComponent tunnel={tunnel} /><PqcChip tunnel={tunnel} /></div>
      </div>
      <div role="tablist" style={{ display: 'flex', gap: 4, marginTop: 12, borderBottom: '1px solid var(--app-border)' }}>
        {(['proposals', 'changes'] as const).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
            style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
            {t === 'proposals' ? 'Proposals' : 'Changes'}
          </button>
        ))}
      </div>
      <div style={{ marginTop: 8 }}>
        {tab === 'proposals' ? <TunnelProposals tunnel={tunnel} /> : <ObjectChanges kind="tunnel" id={tunnel.id} />}
      </div>
    </aside>
  );
}

const COLS = '1.3fr 120px 90px 1.6fr 70px 1.4fr 150px 70px';

export function TunnelsLens() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('tunnel');
  const encapsulation = params.get('encapsulation') ?? '';
  const set = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    setParams(n, { replace: true });
  };
  const tunnels = useVpnList('tunnels', encapsulation ? { encapsulation, limit: 500 } : { limit: 500 });
  const write = useVpnWrite('tunnels');
  const profiles = useVpnList('ipsec-profiles', { limit: 1000 });
  const profileOptions = useMemo(() => (profiles.data?.rows ?? []).map((p) => ({ id: p.id, name: p.name })), [profiles.data]);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Tunnel | null>(null);
  const [deleting, setDeleting] = useState<Tunnel | null>(null);
  const rows = tunnels.data?.rows ?? [];
  const sel = rows.find((t) => t.id === selected) ?? null;

  return (
    <div data-testid="tunnels-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="shield" size={17} style={{ color: 'var(--accent)' }} />Tunnels
        </h1>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{tunnels.data ? `${tunnels.data.total} ${tunnels.data.total === 1 ? 'tunnel' : 'tunnels'}` : ''}</span>
        <select aria-label="Encapsulation" className="ui-input sm" value={encapsulation} onChange={(e) => set('encapsulation', e.target.value || null)} style={{ marginLeft: 8 }}>
          <option value="">All encapsulations</option>
          {ENCAPSULATIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <Link to="/inventory/manage/vpn-policies" className="ui-btn sm"><Icon name="sliders-horizontal" size={14} />VPN policies</Link>
          <PermissionGate permission={TENANT_PERMISSIONS.vpn.manage}>
            <button type="button" className="ui-btn sm accent" data-testid="add-tunnel" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add tunnel</button>
          </PermissionGate>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: sel ? 'minmax(0, 1.6fr) minmax(340px, 1fr)' : '1fr', gap: 14, alignItems: 'start' }}>
        <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
            <span>Name</span><span>Encapsulation</span><span>Status</span><span>Ends</span><span>IKE</span><span>Weakest component</span><span>PQC</span><span />
          </div>
          {tunnels.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading tunnels…" /></div>}
          {tunnels.isError && <div style={{ padding: 14 }}><PanelError message={tunnels.error instanceof Error ? tunnels.error.message : 'Request failed'} onRetry={() => { void tunnels.refetch(); }} /></div>}
          {tunnels.data && rows.length === 0 && (
            <PanelEmpty icon="shield" title={encapsulation ? 'No tunnels with this encapsulation' : 'No tunnels yet'}
              message="Interrogating a firewall or VPN gateway (Fortinet, Palo Alto, Cisco, UniFi) records its tunnels here, with every IKE and IPsec proposal scored against the algorithm catalogue." />
          )}
          {rows.map((t) => (
            <div key={t.id} data-testid="tunnel-row" onClick={() => set('tunnel', t.id)}
              style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: selected === t.id ? 'var(--app-panel2)' : undefined }}>
              <span style={{ fontWeight: 600 }}>{t.name}{t.status !== 'active' && <> <Chip tone="var(--warn)">{LIFECYCLE_LABEL[t.status]}</Chip></>}</span>
              <span>{ENCAPSULATION_LABEL[t.encapsulation]}</span>
              <span><Chip>{t.operational_status}</Chip></span>
              <span style={{ color: 'var(--app-t2)', fontSize: 12 }}>{peersOf(t)}</span>
              <span className="mono">{t.ike_version ? `v${t.ike_version}` : '—'}</span>
              <span><WeakestComponent tunnel={t} /></span>
              <span><PqcChip tunnel={t} /></span>
              <span style={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }} onClick={(e) => e.stopPropagation()}>
                <PermissionGate permission={TENANT_PERMISSIONS.vpn.manage}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(t)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(t)}><Icon name="trash-2" size={13} /></button>
                </PermissionGate>
              </span>
            </div>
          ))}
        </div>
        {sel && <TunnelDetail tunnel={sel} onClose={() => set('tunnel', null)} />}
      </div>

      {adding && <ObjectFormModal write={write} icon="shield" title="Add tunnel" fields={tunnelFields(profileOptions)} initial={{ encapsulation: 'ipsec-tunnel', operational_status: 'active' }} onClose={() => setAdding(false)} onSaved={(r) => set('tunnel', r.id)} />}
      {editing && (
        <ObjectFormModal write={write} icon="shield" title={`Edit ${editing.name}`} editId={editing.id} fields={tunnelFields(profileOptions)}
          initial={{ name: editing.name, encapsulation: editing.encapsulation, operational_status: editing.operational_status, ipsec_profile_id: editing.ipsec_profile_id ?? '', description: editing.description ?? '' }}
          onClose={() => setEditing(null)} />
      )}
      {deleting && <ObjectDeleteModal write={write} id={deleting.id} what={`tunnel ${deleting.name}`} onClose={() => setDeleting(null)} />}
    </div>
  );
}
