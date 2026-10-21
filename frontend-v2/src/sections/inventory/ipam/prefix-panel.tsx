// The prefix panel on Inventory → Networks: one prefix and everything computed
// from it — parent, direct children, IP ranges, addresses (and the asset that
// holds each, where something says so), free addresses and free child
// prefixes — plus its change log and journal (the DCIM substrate panels).
//
// Since DCIM row 1.6 a prefix is also the tenant's network for discovery: its
// scan posture (declared or learned, excluded, auto-approve), its DHCP posture,
// its gateway, the sensor that reaches it and the FHRP groups whose virtual
// address is in it are shown and edited here — what Settings → Network
// Segments did before the table was retired.
import { useState } from 'react';
import { Link, useLocation } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectJournal } from '../dcim/object-journal';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import {
  GLOBAL_VRF, IP_STATUS_LABEL, LIFECYCLE_LABEL, PREFIX_STATUS_LABEL, useIpamList, useIpamWrite, usePrefixDetail,
  type IpAddress, type Prefix, type PrefixRole, type Vlan,
} from './ipam-queries';
import { Chip, IpamDeleteModal, IpamFormModal, UtilizationBar, type IpamField } from './ipam-ui';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { useBusinessUnits } from '../../settings/business-units-queries';
import { GATEWAY_NOT_RECORDED, GATEWAY_NOT_RECORDED_TITLE, dhcpText, fhrpText } from '../prefix-gateway';
import { CoverageText, GatewayLink } from '../prefix-gateway-view';
import { fromState, prefixHref } from '../object-pages/object-links';

/** The add/edit prefix form. */
export function prefixFields(roles: PrefixRole[], vlans: Vlan[], units: { id: string; name: string }[] = []): IpamField[] {
  return [
    { name: 'prefix', label: 'Prefix', required: true, mono: true, placeholder: '10.10.0.0/24', hint: 'Host bits are cleared: 10.10.0.7/24 is stored as 10.10.0.0/24.' },
    { name: 'operational_status', label: 'Status', kind: 'select', options: Object.entries(PREFIX_STATUS_LABEL).map(([value, label]) => ({ value, label })), hint: 'A container holds other prefixes; its utilisation counts their space.' },
    { name: 'role_id', label: 'Role', kind: 'select', options: [{ value: '', label: 'None' }, ...roles.map((r) => ({ value: r.id, label: r.name }))] },
    { name: 'vlan_id', label: 'VLAN', kind: 'select', options: [{ value: '', label: 'None' }, ...vlans.map((v) => ({ value: v.id, label: `${v.vid} ${v.name}` }))] },
    ...(units.length ? [{ name: 'business_unit_id', label: 'Business unit', kind: 'select' as const, options: [{ value: '', label: 'None' }, ...units.map((u) => ({ value: u.id, label: u.name }))] }] : []),
    { name: 'is_pool', label: 'Pool (every address usable, including network and broadcast)', kind: 'bool' },
    { name: 'mark_utilized', label: 'Treat as fully used', kind: 'bool' },
    { name: 'description', label: 'Description' },
    // Discovery posture (DCIM row 1.6: what a network segment carried).
    { name: 'network_type', label: 'Network type', kind: 'select', options: [{ value: '', label: 'From the address' }, ...['private', 'public', 'vpn', 'cloud'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))],
      hint: 'Left unset, the address decides: private space reads private, everything else public.' },
    { name: 'environment', label: 'Environment', kind: 'select', options: [{ value: '', label: 'None' }, ...['production', 'staging', 'development', 'test'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))],
      hint: 'Assets placed in this prefix take this environment.' },
    { name: 'dhcp_managed', label: 'Addresses handed out by DHCP', kind: 'select', decode: decodeTriState,
      options: [{ value: '', label: 'Unknown' }, { value: 'true', label: 'Yes' }, { value: 'false', label: 'No — addresses do not move' }],
      hint: 'On a DHCP network an address does not identify a device. “No” lets an address decide identity here.' },
    { name: 'auto_approve_discoveries', label: 'Auto-approve what sensors discover in this prefix', kind: 'bool' },
    { name: 'active_probes_disabled', label: 'Never actively scan this prefix', kind: 'bool' },
    { name: 'sensitive', label: 'Sensitive — never scan, and review before acting', kind: 'bool' },
  ];
}

/** A tri-state select's text as the value sent: '' is "nobody has said". */
export function decodeTriState(v: string): boolean | null {
  return v === 'true' ? true : v === 'false' ? false : null;
}

function triStateText(v: boolean | null | undefined): string {
  return v === true ? 'true' : v === false ? 'false' : '';
}

/** A prefix's scan posture, as one line. Learned = a collector reported it;
 *  it scopes identities but is never treated as the tenant's until claimed. */
export function scanPostureText(p: Pick<Prefix, 'source_kind' | 'sensitive' | 'active_probes_disabled'>): string {
  if (p.sensitive) return 'Sensitive — never scanned';
  if (p.active_probes_disabled) return 'Excluded from active scanning';
  if (p.source_kind === 'measured' || p.source_kind === 'inferred') return 'Learned from a device — not treated as yours';
  if (p.source_kind === 'imported') return 'Imported from a system of record';
  return 'Declared by your organization';
}

/** True for a learned prefix a person can claim as the organization's. */
export function isClaimablePrefix(p: Pick<Prefix, 'source_kind' | 'status'>): boolean {
  return (p.source_kind === 'measured' || p.source_kind === 'inferred') && p.status !== 'rejected';
}

export const IP_FIELDS: IpamField[] = [
  { name: 'address', label: 'Address', required: true, mono: true, placeholder: '10.10.0.5/24', hint: 'With its prefix length; a zone (%eth0) is dropped.' },
  { name: 'operational_status', label: 'Status', kind: 'select', options: Object.entries(IP_STATUS_LABEL).map(([value, label]) => ({ value, label })) },
  { name: 'role', label: 'Role', kind: 'select', options: [{ value: '', label: 'None' }, ...['loopback', 'secondary', 'anycast', 'vip', 'vrrp', 'hsrp', 'glbp', 'carp'].map((r) => ({ value: r, label: r.toUpperCase() === r ? r : r.length <= 4 ? r.toUpperCase() : r[0].toUpperCase() + r.slice(1) }))] },
  { name: 'dns_name', label: 'DNS name', mono: true },
  { name: 'description', label: 'Description' },
];

function Section({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 6 }}>
        <h3 className="eyebrow-app" style={{ margin: 0 }}>{title}</h3>
        <span style={{ marginLeft: 'auto' }}>{action}</span>
      </div>
      {children}
    </section>
  );
}

/** Approve a pending (discovered) object: its lifecycle status becomes
 *  approved, and the server records who approved it and when. */
export function ApproveButton({ route, id }: { route: 'prefixes' | 'ip-addresses'; id: string }) {
  const { update } = useIpamWrite(route);
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
      <button type="button" className="ui-btn sm" data-testid={`approve-${route}`} disabled={update.isPending}
        onClick={() => { update.mutate({ id, body: { status: 'active' } }); }}>
        <Icon name="check" size={12} />Approve
      </button>
    </PermissionGate>
  );
}

function IpRow({ ip }: { ip: IpAddress }) {
  return (
    <div data-testid="ip-row" style={{ display: 'grid', gridTemplateColumns: '1.3fr 90px 1.2fr 1.2fr', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
      <span className="mono">{ip.address}{ip.status === 'pending' && <> <ApproveButton route="ip-addresses" id={ip.id} /></>}</span>
      <span><Chip>{IP_STATUS_LABEL[ip.operational_status]}</Chip></span>
      <span className="mono" style={{ color: 'var(--app-t2)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ip.dns_name ?? '—'}</span>
      <span style={{ color: 'var(--app-t2)' }}>
        {ip.asset ? <Link to={`/inventory/assets/${ip.asset.id}`}>{ip.asset.name}</Link>
          : ip.assigned_kind ? `Assigned (${ip.assigned_kind.replace('_', ' ')})`
            : <span style={{ color: 'var(--app-t3)' }}>Not assigned</span>}
      </span>
    </div>
  );
}

/** `embedded` is the prefix PAGE's body (`/inventory/prefixes/:id`): the page
 *  supplies the close affordance and the substrate panels (custom fields,
 *  changes, journal), so the panel leaves those out. */
export function PrefixPanel({ id, onClose, onSelect, embedded = false }: { id: string; onClose: () => void; onSelect: (id: string) => void; embedded?: boolean }) {
  const loc = useLocation();
  const [length, setLength] = useState(0);
  const q = usePrefixDetail(id, length);
  const roles = useIpamList('prefix-roles', { limit: 1000 });
  const vlans = useIpamList('vlans', { limit: 1000 });
  const units = useBusinessUnits();
  const p = q.data?.prefix;
  const { update: updatePrefix } = useIpamWrite('prefixes');
  const vrfParam = p?.vrf_id ?? GLOBAL_VRF;
  const ips = useIpamList('ip-addresses', p ? { parent: p.prefix, vrf_id: vrfParam, limit: 200 } : {}, { enabled: !!p });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [addChild, setAddChild] = useState<string | null>(null);
  const [addIP, setAddIP] = useState<string | null>(null);
  const [tab, setTab] = useState<'addresses' | 'changes' | 'journal'>('addresses');
  const [claiming, setClaiming] = useState(false);

  return (
    <aside data-testid="prefix-panel" style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {p && !embedded
          ? <Link to={prefixHref(p.id)} state={fromState(loc)} data-testid="prefix-open-page" title="Open the prefix page" className="mono" style={{ fontSize: 16, fontWeight: 700, color: 'inherit' }}>{p.prefix}</Link>
          : <span className="mono" style={{ fontSize: 16, fontWeight: 700 }}>{p?.prefix ?? '…'}</span>}
        {p && <Chip>{PREFIX_STATUS_LABEL[p.operational_status]}</Chip>}
        {p && p.status !== 'active' && <Chip tone="var(--warn)">{LIFECYCLE_LABEL[p.status]}</Chip>}
        {p && p.status === 'pending' && <ApproveButton route="prefixes" id={p.id} />}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          {p && (
            <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
              <button type="button" className="ui-btn sm ghost" title="Edit" data-testid="edit-prefix" onClick={() => setEditing(true)}><Icon name="sliders-horizontal" size={13} /></button>
              <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(true)}><Icon name="trash-2" size={13} /></button>
            </PermissionGate>
          )}
          {!embedded && <button type="button" className="ui-btn sm ghost" aria-label="Close" onClick={onClose}><Icon name="x" size={13} /></button>}
        </span>
      </div>

      {q.isLoading && <PanelLoading label="Loading the prefix…" />}
      {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
      {q.data && p && (
        <>
          <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 14px', fontSize: 12.5 }}>
            <span style={{ color: 'var(--app-t3)' }}>Utilisation</span>
            <span><UtilizationBar pct={q.data.utilization.percent} /> <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{q.data.utilization.used} of {q.data.utilization.size}</span></span>
            <span style={{ color: 'var(--app-t3)' }}>Parent</span>
            <span className="mono">{q.data.parent ? <button type="button" className="ui-btn ghost sm" style={{ padding: 0 }} onClick={() => onSelect(q.data.parent!.id)}>{q.data.parent.prefix}</button> : 'none (top level)'}</span>
            <span style={{ color: 'var(--app-t3)' }}>Contains</span>
            <span>{q.data.child_count} {q.data.child_count === 1 ? 'prefix' : 'prefixes'}, {q.data.ip_count} {q.data.ip_count === 1 ? 'address' : 'addresses'}</span>
            {p.description && <><span style={{ color: 'var(--app-t3)' }}>Description</span><span>{p.description}</span></>}
          </div>

          <Section title="Discovery" action={isClaimablePrefix(p) ? (
            <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
              <button type="button" className="ui-btn sm" data-testid="claim-prefix" onClick={() => setClaiming(true)}>
                <Icon name="shield-check" size={12} />Claim as ours
              </button>
            </PermissionGate>
          ) : undefined}>
            <div data-testid="prefix-discovery" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 14px', fontSize: 12.5 }}>
              <span style={{ color: 'var(--app-t3)' }}>Scanning</span>
              <span data-testid="prefix-scan-posture">{scanPostureText(p)}</span>
              <span style={{ color: 'var(--app-t3)' }}>Network type</span>
              <span>{p.network_type || 'From the address'}</span>
              <span style={{ color: 'var(--app-t3)' }}>Environment</span>
              <span style={{ textTransform: 'capitalize' }}>{p.environment || '—'}</span>
              <span style={{ color: 'var(--app-t3)' }}>DHCP</span>
              <span data-testid="prefix-dhcp">{dhcpText(p.dhcp_managed)}</span>
              <span style={{ color: 'var(--app-t3)' }}>Auto-approve</span>
              <span>{p.auto_approve_discoveries ? 'Sensor discoveries' : 'Off'}</span>
              <span style={{ color: 'var(--app-t3)' }}>Gateway</span>
              <span data-testid="prefix-gateway" style={{ minWidth: 0 }}>
                {q.data.gateway
                  ? <GatewayLink gateway={q.data.gateway} />
                  : <span title={GATEWAY_NOT_RECORDED_TITLE} style={{ color: 'var(--app-t3)' }}>{GATEWAY_NOT_RECORDED}</span>}
              </span>
              <span style={{ color: 'var(--app-t3)' }}>Sensor coverage</span>
              <span style={{ minWidth: 0 }}><CoverageText coverage={q.data.coverage} /></span>
              {(q.data.fhrp_groups ?? []).length > 0 && (
                <>
                  <span style={{ color: 'var(--app-t3)' }}>FHRP</span>
                  <span data-testid="prefix-fhrp" className="mono">{(q.data.fhrp_groups ?? []).map((g) => fhrpText(g)).join(', ')}</span>
                </>
              )}
            </div>
          </Section>

          <Section title="Child prefixes">
            {q.data.children.length === 0
              ? <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>None.</div>
              : q.data.children.map((c) => (
                <button key={c.id} type="button" className="ui-btn ghost sm" data-testid="child-prefix" style={{ marginRight: 6, marginBottom: 4 }} onClick={() => onSelect(c.id)}>
                  <span className="mono">{c.prefix}</span>
                </button>
              ))}
          </Section>

          <Section title="Free space" action={(
            <select aria-label="Free prefix length" value={length} onChange={(e) => setLength(Number(e.target.value))} style={{ fontSize: 11.5 }}>
              <option value={0}>Largest blocks</option>
              {Array.from({ length: Math.max(0, (p.prefix.includes(':') ? 128 : 32) - Number(p.prefix.split('/')[1])) }, (_, i) => Number(p.prefix.split('/')[1]) + i + 1)
                .filter((n) => n <= (p.prefix.includes(':') ? 64 : 30)).map((n) => <option key={n} value={n}>/{n}</option>)}
            </select>
          )}>
            {q.data.available_prefixes.length === 0
              ? <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>No free prefixes.</div>
              : (
                <div data-testid="available-prefixes" style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {q.data.available_prefixes.slice(0, 12).map((a) => (
                    <span key={a} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <span className="mono" style={{ fontSize: 12 }}>{a}</span>
                      <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
                        <button type="button" className="ui-btn ghost sm" title={`Add ${a}`} style={{ padding: '0 4px' }} onClick={() => setAddChild(a)}><Icon name="plus" size={12} /></button>
                      </PermissionGate>
                    </span>
                  ))}
                </div>
              )}
            <div style={{ marginTop: 8, fontSize: 12.5 }}>
              <span style={{ color: 'var(--app-t3)' }}>Free addresses: </span>
              <span data-testid="available-ips-count">{q.data.available_ips.available}</span>
              {q.data.available_ips.addresses.length > 0 && (
                <span className="mono" style={{ color: 'var(--app-t2)' }}> — first: {q.data.available_ips.addresses.slice(0, 4).join(', ')}</span>
              )}
              {q.data.available_ips.subnet_router_anycast && (
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>
                  {q.data.available_ips.subnet_router_anycast} is the subnet-router anycast address: free, but every router on the link answers it.
                </div>
              )}
            </div>
          </Section>

          {q.data.ip_ranges.length > 0 && (
            <Section title="IP ranges">
              {q.data.ip_ranges.map((r) => (
                <div key={r.id} style={{ fontSize: 12.5, padding: '3px 0' }}>
                  <span className="mono">{r.start_address} – {r.end_address}</span>
                  <span style={{ color: 'var(--app-t3)' }}> · {r.size} addresses{r.mark_utilized ? ' · reserved' : ''}</span>
                </div>
              ))}
            </Section>
          )}

          {/* Custom fields (DCIM row 5.1): edited through the prefix's PATCH. */}
          {!embedded && (
            <Section title="Custom fields">
              <CustomFieldsPanel kind="prefix" id={p.id} values={p.custom_fields} permission={TENANT_PERMISSIONS.ipam.manage}
                onChange={(custom_fields) => updatePrefix.mutateAsync({ id: p.id, body: { custom_fields } })} />
            </Section>
          )}

          <div role="tablist" style={{ display: 'flex', gap: 4, marginTop: 16, borderBottom: '1px solid var(--app-border)' }}>
            {(embedded ? (['addresses'] as const) : (['addresses', 'changes', 'journal'] as const)).map((t) => (
              <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
                style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
                {t === 'addresses' ? 'IP addresses' : t === 'changes' ? 'Changes' : 'Journal'}
              </button>
            ))}
            <span style={{ marginLeft: 'auto' }}>
              {tab === 'addresses' && (
                <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
                  <button type="button" className="ui-btn sm" data-testid="add-ip" onClick={() => setAddIP(q.data.available_ips.addresses[0] ? `${q.data.available_ips.addresses[0]}/${p.prefix.split('/')[1]}` : '')}>
                    <Icon name="plus" size={13} />Add address
                  </button>
                </PermissionGate>
              )}
            </span>
          </div>
          <div style={{ marginTop: 8 }}>
            {tab === 'addresses' && (
              <>
                {ips.isLoading && <PanelLoading label="Loading addresses…" />}
                {ips.isError && <PanelError message={ips.error instanceof Error ? ips.error.message : 'Request failed'} onRetry={() => { void ips.refetch(); }} />}
                {ips.data && ips.data.rows.length === 0 && (
                  <PanelEmpty icon="list" title="No addresses recorded"
                    message="Nothing in this prefix has an IP address record yet. Add one, or they arrive as discovery sees them (pending approval)." />
                )}
                {ips.data?.rows.map((ip) => <IpRow key={ip.id} ip={ip} />)}
                {ips.data && ips.data.total > ips.data.rows.length && (
                  <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 6 }}>Showing {ips.data.rows.length} of {ips.data.total}.</div>
                )}
              </>
            )}
            {tab === 'changes' && <ObjectChanges kind="prefix" id={p.id} />}
            {tab === 'journal' && <ObjectJournal kind="prefix" id={p.id} />}
          </div>
        </>
      )}

      {editing && p && (
        <IpamFormModal route="prefixes" title={`Edit ${p.prefix}`} editId={p.id}
          fields={prefixFields(roles.data?.rows ?? [], vlans.data?.rows ?? [], units.data ?? [])}
          initial={{
            prefix: p.prefix, operational_status: p.operational_status, role_id: p.role_id ?? '', vlan_id: p.vlan_id ?? '', business_unit_id: p.business_unit_id ?? '',
            is_pool: p.is_pool, mark_utilized: p.mark_utilized, description: p.description ?? '',
            network_type: p.network_type ?? '', environment: p.environment ?? '', dhcp_managed: triStateText(p.dhcp_managed),
            auto_approve_discoveries: p.auto_approve_discoveries, active_probes_disabled: p.active_probes_disabled, sensitive: p.sensitive,
          }}
          onClose={() => setEditing(false)} />
      )}
      {claiming && p && <ClaimPrefixModal prefix={p} onClose={() => setClaiming(false)} />}
      {deleting && p && <IpamDeleteModal route="prefixes" id={p.id} what={p.prefix} onClose={() => setDeleting(false)} onDeleted={onClose} />}
      {addChild !== null && p && (
        <IpamFormModal route="prefixes" title="Add child prefix" fields={prefixFields(roles.data?.rows ?? [], vlans.data?.rows ?? [], units.data ?? [])}
          initial={{ prefix: addChild, operational_status: 'active' }} fixed={{ vrf_id: p.vrf_id ?? null }} onClose={() => setAddChild(null)} onSaved={(row) => onSelect(row.id)} />
      )}
      {addIP !== null && p && (
        <IpamFormModal route="ip-addresses" title={`Add an address in ${p.prefix}`} fields={IP_FIELDS}
          initial={{ address: addIP, operational_status: 'reserved' }} fixed={{ vrf_id: p.vrf_id ?? null }} onClose={() => setAddIP(null)} />
      )}
    </aside>
  );
}

/**
 * Claim a learned prefix as the organization's (DCIM row 1.6 D8: a claim
 * sets the prefix's source to declared). One click with a confirmation that
 * says, in plain words, what the person is stating and what it lets the
 * platform do. There is no proof-of-control step behind it — the claim is the
 * person's own word, recorded in the change log — so the dialog carries the
 * warning about ranges they do not control.
 */
export function ClaimPrefixModal({ prefix, onClose }: { prefix: Prefix; onClose: () => void }) {
  const { update } = useIpamWrite('prefixes');
  const [err, setErr] = useState<string | null>(null);
  return (
    <Modal
      open onClose={update.isPending ? undefined : onClose} dismissible={!update.isPending}
      size="md" tone="accent" icon="shield-check" eyebrow="Networks"
      title={`Claim ${prefix.prefix} as yours?`}
      description="Vista Platform learned this prefix from a device. A device's settings cannot show whether a range is yours or your internet provider's, so it is not treated as yours until someone says so."
      primary={(
        <button type="button" className="ui-btn accent" data-testid="claim-prefix-confirm" disabled={update.isPending}
          onClick={() => { setErr(null); update.mutateAsync({ id: prefix.id, body: { source_kind: 'declared' } }).then(onClose, (e: unknown) => setErr(e instanceof Error ? e.message : 'The claim could not be saved.')); }}>
          {update.isPending ? 'Claiming…' : 'Claim as ours'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose} disabled={update.isPending}>Cancel</button>}
      footerNote={err ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{err}</span> : undefined}
    >
      <ul data-testid="claim-consequences" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6, fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.5 }}>
        <li>You are stating that this range belongs to your organization.</li>
        <li>Vista Platform will then be able to scan it when someone in your organization asks. A public range is never scanned automatically.</li>
        <li>Sensors will treat it as yours, and may check the services they see your systems use on it.</li>
        <li><strong>Do not claim a range you don&apos;t control</strong> — your internet provider&apos;s link, for example. Scanning it would be scanning someone else&apos;s network.</li>
        <li>Vista Platform does not verify the claim. It is recorded in the prefix&apos;s change log under your name.</li>
      </ul>
    </Modal>
  );
}
