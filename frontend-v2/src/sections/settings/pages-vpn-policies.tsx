// Settings → Infrastructure → VPN Policies (DCIM BUILD_PLAN row 4.3): the IKE
// and IPsec proposals, policies and profiles tunnels are built from. Each
// proposal shows the catalogue assessment of its algorithms — the same rows
// that score the tunnel. Discovered rows arrive from interrogated firewalls;
// a tenant may add its own. Reading needs `vpn.read` (the nav entry); every
// write control sits behind `vpn.manage`.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { riskColor } from '../../components/ui/risk';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import { Chip, ObjectDeleteModal, ObjectFormModal, type IpamField } from '../inventory/ipam/ipam-ui';
import { riskBand, useVpnList, useVpnWrite, type VpnAlgorithmAssessment, type VpnRoute, type VpnRows } from '../inventory/vpn/vpn-queries';
import { SPage, SSection, STable, STableRow, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

type Options = { value: string; label: string }[];
interface Lookups { ikeProposals: Options; ipsecProposals: Options; ikePolicies: Options; ipsecPolicies: Options }

interface Catalog<R extends VpnRoute> {
  route: R;
  title: string;
  desc: string;
  noun: string;
  cols: STableCol[];
  cells: (row: VpnRows[R], names: (id: string) => string) => ReactNode[];
  fields: (l: Lookups) => IpamField[];
  initial: (row: VpnRows[R]) => Record<string, unknown>;
  name: (row: VpnRows[R]) => string;
}

const ACTIONS_COL: STableCol = { label: '', w: '80px', align: 'right' };

function Assessed({ a, text }: { a: VpnAlgorithmAssessment | null | undefined; text: string | null | undefined }) {
  if (!text) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
  const band = riskBand(a?.risk_score);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span className="mono">{text}</span>
      {a && band ? <Chip tone={riskColor(band)} title={`${a.code} (catalogue risk ${a.risk_score})`}>{a.strength}</Chip> : <Chip title="Not in the algorithm catalogue">unassessed</Chip>}
    </span>
  );
}

const ENCRYPTION: Options = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', '3des-cbc', 'des-cbc']
  .map((v) => ({ value: v, label: v }));
const INTEGRITY: Options = [{ value: '', label: 'None (AEAD)' }, ...['hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-md5'].map((v) => ({ value: v, label: v }))];
const AUTH_METHODS: Options = ['preshared-keys', 'certificates', 'rsa-signatures', 'dsa-signatures'].map((v) => ({ value: v, label: v }));

function CatalogSection<R extends VpnRoute>({ c, lookups, names }: { c: Catalog<R>; lookups: Lookups; names: (id: string) => string }) {
  const q = useVpnList(c.route, { limit: 1000 });
  const write = useVpnWrite(c.route);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VpnRows[R] | null>(null);
  const [deleting, setDeleting] = useState<VpnRows[R] | null>(null);
  const cols = [...c.cols, ACTIONS_COL];
  const rows = q.data?.rows ?? [];
  return (
    <SSection title={c.title} desc={c.desc} action={(
      <PermissionGate permission={TENANT_PERMISSIONS.vpn.manage}>
        <button type="button" className="ui-btn sm accent" data-testid={`add-${c.route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {c.noun}</button>
      </PermissionGate>
    )}>
      <div data-testid={`vpn-catalog-${c.route}`}>
        {q.isLoading && <PanelLoading label={`Loading ${c.title.toLowerCase()}…`} />}
        {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {q.data && rows.length === 0 && <PanelEmpty icon="list" title={`No ${c.title.toLowerCase()} yet`} message={c.desc} />}
        {rows.length > 0 && (
          <STable cols={cols}>
            {rows.map((row, i) => (
              <STableRow key={(row as { id: string }).id} first={i === 0} cols={cols} cells={[
                ...c.cells(row, names),
                <PermissionGate key="a" permission={TENANT_PERMISSIONS.vpn.manage}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(row)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(row)}><Icon name="x" size={13} /></button>
                </PermissionGate>,
              ]} />
            ))}
          </STable>
        )}
      </div>
      {adding && <ObjectFormModal write={write} icon="shield" title={`Add ${c.noun}`} fields={c.fields(lookups)} onClose={() => setAdding(false)} />}
      {editing && (
        <ObjectFormModal write={write} icon="shield" title={`Edit ${c.name(editing)}`} editId={(editing as { id: string }).id}
          fields={c.fields(lookups)} initial={c.initial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && <ObjectDeleteModal write={write} id={(deleting as { id: string }).id} what={c.name(deleting)} onClose={() => setDeleting(null)} />}
    </SSection>
  );
}

export const IKE_PROPOSALS: Catalog<'ike-proposals'> = {
  route: 'ike-proposals', title: 'IKE proposals', noun: 'IKE proposal',
  desc: 'Phase-1 transforms: encryption, integrity and Diffie-Hellman group. Each algorithm is scored by the algorithm catalogue.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Encryption', w: '1.2fr' }, { label: 'Integrity', w: '1.2fr' }, { label: 'DH group', w: '1fr' }],
  cells: (p) => [p.name, <Assessed key="e" a={p.encryption_assessment} text={p.encryption_algorithm} />,
    <Assessed key="i" a={p.authentication_assessment} text={p.authentication_algorithm} />,
    <Assessed key="g" a={p.group_assessment} text={p.group ? `group ${p.group}` : null} />],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'authentication_method', label: 'Authentication', kind: 'select', options: AUTH_METHODS },
    { name: 'encryption_algorithm', label: 'Encryption', kind: 'select', options: ENCRYPTION },
    { name: 'authentication_algorithm', label: 'Integrity', kind: 'select', options: INTEGRITY },
    { name: 'group', label: 'DH group', kind: 'number', hint: 'IANA group number: 14, 19, 20, 21, 31…' },
    { name: 'sa_lifetime_seconds', label: 'SA lifetime (seconds)', kind: 'number' },
  ],
  initial: (p) => ({ name: p.name, authentication_method: p.authentication_method, encryption_algorithm: p.encryption_algorithm ?? '',
    authentication_algorithm: p.authentication_algorithm ?? '', group: p.group ?? '', sa_lifetime_seconds: p.sa_lifetime_seconds ?? '' }),
  name: (p) => p.name,
};

export const IKE_POLICIES: Catalog<'ike-policies'> = {
  route: 'ike-policies', title: 'IKE policies', noun: 'IKE policy',
  desc: 'An IKE version and mode with the proposals it offers. Only THAT a pre-shared key is configured is recorded — never the key.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Version', w: '0.6fr' }, { label: 'Mode', w: '0.7fr' }, { label: 'Pre-shared key', w: '0.9fr' }, { label: 'Proposals', w: '2fr' }],
  cells: (p, names) => [p.name, p.version ? `IKEv${p.version}` : '—', p.mode ?? '—', p.preshared_key_present ? 'Configured' : '—',
    (p.proposals ?? []).map(names).join(', ') || '—'],
  fields: (l) => [
    { name: 'name', label: 'Name', required: true },
    { name: 'version', label: 'IKE version', kind: 'select', options: [{ value: '2', label: 'IKEv2' }, { value: '1', label: 'IKEv1' }], decode: (v) => (v ? Number(v) : null) },
    { name: 'mode', label: 'Mode (IKEv1)', kind: 'select', options: [{ value: '', label: '—' }, { value: 'main', label: 'Main' }, { value: 'aggressive', label: 'Aggressive' }] },
    { name: 'proposals', label: 'Proposals', kind: 'multi', options: l.ikeProposals },
  ],
  initial: (p) => ({ name: p.name, version: p.version ? String(p.version) : '', mode: p.mode ?? '', proposals: p.proposals ?? [] }),
  name: (p) => p.name,
};

export const IPSEC_PROPOSALS: Catalog<'ipsec-proposals'> = {
  route: 'ipsec-proposals', title: 'IPsec proposals', noun: 'IPsec proposal',
  desc: 'Phase-2 (ESP / AH) transforms: encryption and integrity, scored by the algorithm catalogue.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Encryption', w: '1.2fr' }, { label: 'Integrity', w: '1.2fr' }, { label: 'Lifetime', w: '0.8fr' }],
  cells: (p) => [p.name, <Assessed key="e" a={p.encryption_assessment} text={p.encryption_algorithm} />,
    <Assessed key="i" a={p.authentication_assessment} text={p.authentication_algorithm} />, p.sa_lifetime_seconds ? `${p.sa_lifetime_seconds}s` : '—'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'encryption_algorithm', label: 'Encryption', kind: 'select', options: ENCRYPTION },
    { name: 'authentication_algorithm', label: 'Integrity', kind: 'select', options: INTEGRITY },
    { name: 'sa_lifetime_seconds', label: 'SA lifetime (seconds)', kind: 'number' },
    { name: 'sa_lifetime_data_kb', label: 'SA lifetime (KB)', kind: 'number' },
  ],
  initial: (p) => ({ name: p.name, encryption_algorithm: p.encryption_algorithm ?? '', authentication_algorithm: p.authentication_algorithm ?? '',
    sa_lifetime_seconds: p.sa_lifetime_seconds ?? '', sa_lifetime_data_kb: p.sa_lifetime_data_kb ?? '' }),
  name: (p) => p.name,
};

export const IPSEC_POLICIES: Catalog<'ipsec-policies'> = {
  route: 'ipsec-policies', title: 'IPsec policies', noun: 'IPsec policy',
  desc: 'The phase-2 proposals offered and the perfect-forward-secrecy group.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'PFS group', w: '1fr' }, { label: 'Proposals', w: '2fr' }],
  cells: (p, names) => [p.name, <Assessed key="g" a={p.pfs_group_assessment} text={p.pfs_group ? `group ${p.pfs_group}` : null} />,
    (p.proposals ?? []).map(names).join(', ') || '—'],
  fields: (l) => [
    { name: 'name', label: 'Name', required: true },
    { name: 'pfs_group', label: 'PFS group', kind: 'number', hint: 'Empty for no PFS.' },
    { name: 'proposals', label: 'Proposals', kind: 'multi', options: l.ipsecProposals },
  ],
  initial: (p) => ({ name: p.name, pfs_group: p.pfs_group ?? '', proposals: p.proposals ?? [] }),
  name: (p) => p.name,
};

export const IPSEC_PROFILES: Catalog<'ipsec-profiles'> = {
  route: 'ipsec-profiles', title: 'IPsec profiles', noun: 'IPsec profile',
  desc: 'An IKE policy and an IPsec policy together — what a tunnel names.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Mode', w: '0.6fr' }, { label: 'IKE policy', w: '1.2fr' }, { label: 'IPsec policy', w: '1.2fr' }],
  cells: (p, names) => [p.name, p.mode.toUpperCase(), names(p.ike_policy_id), names(p.ipsec_policy_id)],
  fields: (l) => [
    { name: 'name', label: 'Name', required: true },
    { name: 'mode', label: 'Mode', kind: 'select', options: [{ value: 'esp', label: 'ESP' }, { value: 'ah', label: 'AH' }] },
    { name: 'ike_policy_id', label: 'IKE policy', kind: 'select', required: true, options: [{ value: '', label: 'Choose' }, ...l.ikePolicies] },
    { name: 'ipsec_policy_id', label: 'IPsec policy', kind: 'select', required: true, options: [{ value: '', label: 'Choose' }, ...l.ipsecPolicies] },
  ],
  initial: (p) => ({ name: p.name, mode: p.mode, ike_policy_id: p.ike_policy_id, ipsec_policy_id: p.ipsec_policy_id }),
  name: (p) => p.name,
};

export function VpnPoliciesSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const ikeP = useVpnList('ike-proposals', { limit: 1000 });
  const espP = useVpnList('ipsec-proposals', { limit: 1000 });
  const ikePol = useVpnList('ike-policies', { limit: 1000 });
  const espPol = useVpnList('ipsec-policies', { limit: 1000 });
  const opts = (rows: { id: string; name: string }[] | undefined): Options => (rows ?? []).map((r) => ({ value: r.id, label: r.name }));
  const lookups: Lookups = {
    ikeProposals: opts(ikeP.data?.rows), ipsecProposals: opts(espP.data?.rows),
    ikePolicies: opts(ikePol.data?.rows), ipsecPolicies: opts(espPol.data?.rows),
  };
  const byId = new Map([...lookups.ikeProposals, ...lookups.ipsecProposals, ...lookups.ikePolicies, ...lookups.ipsecPolicies].map((o) => [o.value, o.label]));
  const names = (id: string) => byId.get(id) ?? '—';
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="vpn-policies-settings">
        <CatalogSection c={IPSEC_PROFILES} lookups={lookups} names={names} />
        <CatalogSection c={IKE_POLICIES} lookups={lookups} names={names} />
        <CatalogSection c={IKE_PROPOSALS} lookups={lookups} names={names} />
        <CatalogSection c={IPSEC_POLICIES} lookups={lookups} names={names} />
        <CatalogSection c={IPSEC_PROPOSALS} lookups={lookups} names={names} />
      </div>
    </SPage>
  );
}
