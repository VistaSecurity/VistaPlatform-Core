// Settings → Infrastructure → Wireless (DCIM BUILD_PLAN row 4.4; asset-inventory
// ADR-0010 D8): wireless LAN groups, wireless LANs with their authentication and
// the catalogue's verdict on the cipher, and wireless links. Inventory only - no
// RF planning, no controller management. Reading needs `wireless.read` (the nav
// entry); every write control sits behind `wireless.manage`.
//
// A pre-shared key is never entered, shown or stored: the form has a checkbox
// saying one exists. Links are created by discovery or the API (they join two
// interfaces by id); here they can be edited and deleted.
//
// A discovered LAN or link that no approved access point reports stays
// pending (an approved AP's LANs follow it to active on their own); its row
// carries the Pending tag and, for wireless.manage, an Approve button.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { AUTH_CIPHER_LABEL, AUTH_TYPE_LABEL, AuthRisk, authText, keyText } from '../inventory/dcim/wireless-auth';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import {
  useIpamList, type IpamRoute, type IpamRows, type WirelessLan, type WirelessLanGroup, type WirelessLink,
} from '../inventory/ipam/ipam-queries';
import { IpamDeleteModal, IpamFormModal, type IpamField } from '../inventory/ipam/ipam-ui';
import { ApproveButton } from '../inventory/ipam/prefix-panel';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

type WirelessRoute = Extract<IpamRoute, `wireless-${string}`>;

const ACTIONS_COL: STableCol = { label: '', w: '80px', align: 'right' };
// Wide enough for the Pending tag and Approve beside the edit controls.
const ACTIONS_COL_PENDING: STableCol = { ...ACTIONS_COL, w: '200px' };

const select = (labels: Record<string, string>, none: string) => [
  { value: '', label: none },
  ...Object.entries(labels).map(([value, label]) => ({ value, label })),
];

interface Section<R extends WirelessRoute> {
  route: R;
  title: string;
  desc: string;
  noun: string;
  cols: STableCol[];
  cells: (row: IpamRows[R], ctx: Ctx) => ReactNode[];
  fields: (ctx: Ctx) => IpamField[];
  initial: (row: IpamRows[R]) => Record<string, unknown>;
  name: (row: IpamRows[R]) => string;
  /** False where rows are not created here (links). */
  addable?: boolean;
}

interface Ctx {
  groups: WirelessLanGroup[];
  groupName: (id: string | null | undefined) => string;
}

function WirelessSection<R extends WirelessRoute>({ s }: { s: Section<R> }) {
  const q = useIpamList(s.route, { limit: 1000 });
  const groups = useIpamList('wireless-lan-groups', { limit: 1000 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<IpamRows[R] | null>(null);
  const [deleting, setDeleting] = useState<IpamRows[R] | null>(null);
  const rows = q.data?.rows ?? [];
  const anyPending = rows.some((row) => (row as { status?: string }).status === 'pending');
  const cols = [...s.cols, anyPending ? ACTIONS_COL_PENDING : ACTIONS_COL];
  const groupRows = groups.data?.rows ?? [];
  const ctx: Ctx = {
    groups: groupRows,
    groupName: (id) => (id ? groupRows.find((g) => g.id === id)?.name ?? '—' : '—'),
  };
  return (
    <SSection title={s.title} desc={s.desc} action={s.addable === false ? undefined : (
      <PermissionGate permission={TENANT_PERMISSIONS.wireless.manage}>
        <button type="button" className="ui-btn sm accent" data-testid={`add-${s.route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {s.noun}</button>
      </PermissionGate>
    )}>
      <div data-testid={`wireless-section-${s.route}`}>
        {q.isLoading && <PanelLoading label={`Loading ${s.title.toLowerCase()}…`} />}
        {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {q.data && rows.length === 0 && <PanelEmpty icon="wifi" title={`No ${s.title.toLowerCase()} yet`} message={s.desc} />}
        {rows.length > 0 && (
          <STable cols={cols}>
            {rows.map((row, i) => {
              const r = row as { id: string; status?: string };
              return (
                <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                  ...s.cells(row, ctx),
                  <span key="a" style={{ display: 'inline-flex', gap: 2, alignItems: 'center' }}>
                    {r.status === 'pending' && <STag>Pending</STag>}
                    {r.status === 'pending' && (s.route === 'wireless-lans' || s.route === 'wireless-links') && (
                      <ApproveButton route={s.route} id={r.id} permission={TENANT_PERMISSIONS.wireless.manage} label={s.name(row)} />
                    )}
                    <PermissionGate permission={TENANT_PERMISSIONS.wireless.manage}>
                      <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${s.name(row)}`} onClick={() => setEditing(row)}><Icon name="sliders-horizontal" size={13} /></button>
                      <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${s.name(row)}`} style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(row)}><Icon name="x" size={13} /></button>
                    </PermissionGate>
                  </span>,
                ]} />
              );
            })}
          </STable>
        )}
      </div>
      {adding && <IpamFormModal route={s.route} icon="wifi" title={`Add ${s.noun}`} fields={s.fields(ctx)} onClose={() => setAdding(false)} />}
      {editing && (
        <IpamFormModal route={s.route} icon="wifi" title={`Edit ${s.name(editing)}`} editId={(editing as { id: string }).id}
          fields={s.fields(ctx)} initial={s.initial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && <IpamDeleteModal route={s.route} id={(deleting as { id: string }).id} what={s.name(deleting)} onClose={() => setDeleting(null)} />}
    </SSection>
  );
}

const GROUPS: Section<'wireless-lan-groups'> = {
  route: 'wireless-lan-groups', title: 'Wireless LAN groups', noun: 'group',
  desc: 'Families of wireless LANs - a campus, a controller site, a brand - so the same SSID on two sites can be told apart.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Parent', w: '1fr' }],
  cells: (g, ctx) => [g.name, <span key="s" className="mono">{g.slug}</span>, ctx.groupName(g.parent_id)],
  fields: (ctx) => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'parent_id', label: 'Parent group', kind: 'select', options: [{ value: '', label: 'None' }, ...ctx.groups.map((g) => ({ value: g.id, label: g.name }))] },
    { name: 'description', label: 'Description' },
  ],
  initial: (g) => ({ name: g.name, slug: g.slug, parent_id: g.parent_id ?? '', description: g.description ?? '' }),
  name: (g) => g.name,
};

const LANS: Section<'wireless-lans'> = {
  route: 'wireless-lans', title: 'Wireless LANs', noun: 'wireless LAN',
  desc: 'The SSIDs your access points broadcast, with how each authenticates. The cipher is rated by the algorithms catalogue; a pre-shared key is never stored, only whether one is set.',
  cols: [{ label: 'SSID', w: '1.1fr' }, { label: 'Group', w: '0.9fr' }, { label: 'Authentication', w: '1.7fr' }, { label: 'Key', w: '0.6fr' }, { label: 'Cipher risk', w: '1fr' }],
  cells: (l: WirelessLan, ctx) => [
    <span key="s" className="mono" style={{ fontWeight: 600 }}>{l.ssid}</span>,
    ctx.groupName(l.group_id),
    authText(l),
    keyText(l),
    <AuthRisk key="r" lan={l} />,
  ],
  fields: (ctx) => [
    { name: 'ssid', label: 'SSID', required: true, mono: true, hint: 'Case-sensitive, up to 32 bytes.' },
    { name: 'group_id', label: 'Group', kind: 'select', options: [{ value: '', label: 'None' }, ...ctx.groups.map((g) => ({ value: g.id, label: g.name }))] },
    { name: 'auth_type', label: 'Authentication', kind: 'select', options: select(AUTH_TYPE_LABEL, 'Not reported') },
    { name: 'auth_cipher', label: 'Cipher', kind: 'select', options: select(AUTH_CIPHER_LABEL, 'Not reported'), hint: 'Not used by an open or WEP network.' },
    { name: 'auth_psk_present', label: 'A pre-shared key is configured', kind: 'bool', hint: 'Record that one exists. The key itself is never entered or stored.' },
    { name: 'operational_status', label: 'Status', kind: 'select', options: select({ active: 'Active', reserved: 'Reserved', disabled: 'Disabled', deprecated: 'Deprecated' }, 'Active') },
    { name: 'description', label: 'Description' },
  ],
  initial: (l) => ({
    ssid: l.ssid, group_id: l.group_id ?? '', auth_type: l.auth_type ?? '', auth_cipher: l.auth_cipher ?? '',
    auth_psk_present: l.auth_psk_present, operational_status: l.operational_status, description: l.description ?? '',
  }),
  name: (l) => l.ssid,
};

const LINKS: Section<'wireless-links'> = {
  route: 'wireless-links', title: 'Wireless links', noun: 'wireless link', addable: false,
  desc: 'Point-to-point wireless links between two interfaces - a mesh uplink, a bridge pair. Discovery and the API create them; they can be edited and removed here.',
  cols: [{ label: 'From', w: '1.2fr' }, { label: 'To', w: '1.2fr' }, { label: 'SSID', w: '0.9fr' }, { label: 'Authentication', w: '1.4fr' }, { label: 'Cipher risk', w: '1fr' }],
  cells: (k: WirelessLink) => [
    <span key="a" className="mono">{k.interface_a_name ?? k.interface_a_id.slice(0, 8)}</span>,
    <span key="b" className="mono">{k.interface_b_name ?? k.interface_b_id.slice(0, 8)}</span>,
    k.ssid ?? '—',
    authText(k),
    <AuthRisk key="r" lan={k} />,
  ],
  fields: () => [
    { name: 'operational_status', label: 'Status', kind: 'select', options: select({ connected: 'Connected', planned: 'Planned', decommissioning: 'Decommissioning' }, 'Connected') },
    { name: 'distance', label: 'Distance', kind: 'number' },
    { name: 'distance_unit', label: 'Distance unit', kind: 'select', options: select({ km: 'km', m: 'm', mi: 'mi', ft: 'ft' }, 'None') },
    { name: 'description', label: 'Description' },
  ],
  initial: (k) => ({ operational_status: k.operational_status, distance: k.distance ?? '', distance_unit: k.distance_unit ?? '', description: k.description ?? '' }),
  name: (k) => `${k.interface_a_name ?? 'link'} ↔ ${k.interface_b_name ?? ''}`.trim(),
};

export function WirelessSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="wireless-settings">
        <WirelessSection s={LANS} />
        <WirelessSection s={GROUPS} />
        <WirelessSection s={LINKS} />
      </div>
    </SPage>
  );
}
