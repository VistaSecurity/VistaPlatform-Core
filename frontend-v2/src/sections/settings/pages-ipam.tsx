// Settings → Infrastructure → IPAM (DCIM BUILD_PLAN row 1.3): the catalogues
// the Networks lens builds on — VRFs, RIRs, aggregates, prefix roles, ASNs and
// ASN ranges (DCIM gap 10).
// Simple tables with add / edit / delete; RIRs and prefix roles the platform
// ships are listed read-only. Reading needs `ipam.read` (the nav entry);
// every write control sits behind `ipam.manage`.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import { useAvailableAsns, useIpamList, type AsnRange, type IpamRoute, type IpamRows, type Rir } from '../inventory/ipam/ipam-queries';
import { IpamDeleteModal, IpamFormModal, type IpamField } from '../inventory/ipam/ipam-ui';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

interface Catalog<R extends IpamRoute> {
  route: R;
  title: string;
  desc: string;
  noun: string;
  cols: STableCol[];
  cells: (row: IpamRows[R], rirName: (id: string | null | undefined) => string) => ReactNode[];
  fields: (rirs: Rir[]) => IpamField[];
  initial: (row: IpamRows[R]) => Record<string, unknown>;
  name: (row: IpamRows[R]) => string;
}

const ACTIONS_COL: STableCol = { label: '', w: '80px', align: 'right' };
const platformRow = (row: { tenant_id?: string | null }) => row.tenant_id == null;

function CatalogSection<R extends IpamRoute>({ c }: { c: Catalog<R> }) {
  const q = useIpamList(c.route, { limit: 1000 });
  const rirs = useIpamList('rirs', { limit: 1000 });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<IpamRows[R] | null>(null);
  const [deleting, setDeleting] = useState<IpamRows[R] | null>(null);
  const cols = [...c.cols, ACTIONS_COL];
  const rirName = (id: string | null | undefined) => (id ? (rirs.data?.rows ?? []).find((r) => r.id === id)?.name ?? '—' : '—');
  const rows = q.data?.rows ?? [];
  return (
    <SSection title={c.title} desc={c.desc} action={(
      <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
        <button type="button" className="ui-btn sm accent" data-testid={`add-${c.route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {c.noun}</button>
      </PermissionGate>
    )}>
      <div data-testid={`ipam-catalog-${c.route}`}>
        {q.isLoading && <PanelLoading label={`Loading ${c.title.toLowerCase()}…`} />}
        {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {q.data && rows.length === 0 && <PanelEmpty icon="list" title={`No ${c.title.toLowerCase()} yet`} message={c.desc} />}
        {rows.length > 0 && (
          <STable cols={cols}>
            {rows.map((row, i) => {
              const r = row as IpamRows[R] & { id: string; tenant_id?: string | null };
              return (
                <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                  ...c.cells(row, rirName),
                  platformRow(r) ? <STag key="p">Built in</STag> : (
                    <PermissionGate key="a" permission={TENANT_PERMISSIONS.ipam.manage}>
                      <button type="button" className="ui-btn sm ghost" title="Edit" onClick={() => setEditing(row)}><Icon name="sliders-horizontal" size={13} /></button>
                      <button type="button" className="ui-btn sm ghost" title="Delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(row)}><Icon name="x" size={13} /></button>
                    </PermissionGate>
                  ),
                ]} />
              );
            })}
          </STable>
        )}
      </div>
      {adding && <IpamFormModal route={c.route} title={`Add ${c.noun}`} fields={c.fields(rirs.data?.rows ?? [])} onClose={() => setAdding(false)} />}
      {editing && (
        <IpamFormModal route={c.route} title={`Edit ${c.name(editing)}`} editId={(editing as { id: string }).id}
          fields={c.fields(rirs.data?.rows ?? [])} initial={c.initial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && <IpamDeleteModal route={c.route} id={(deleting as { id: string }).id} what={c.name(deleting)} onClose={() => setDeleting(null)} />}
    </SSection>
  );
}

const rirOptions = (rirs: Rir[], none?: string) => [
  ...(none ? [{ value: '', label: none }] : [{ value: '', label: 'Choose a registry' }]),
  ...rirs.map((r) => ({ value: r.id, label: r.name })),
];

const VRFS: Catalog<'vrfs'> = {
  route: 'vrfs', title: 'VRFs', noun: 'VRF',
  desc: 'Separate routing tables. A prefix or address outside every VRF is in the global table; the same prefix in two VRFs is two networks.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Route distinguisher', w: '1fr' }, { label: 'Unique addresses', w: '1fr' }],
  cells: (v) => [v.name, <span key="rd" className="mono">{v.rd ?? '—'}</span>, v.enforce_unique ? 'Enforced' : 'Not enforced'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'rd', label: 'Route distinguisher', mono: true, placeholder: '65000:100' },
    { name: 'enforce_unique', label: 'Refuse duplicate addresses in this VRF', kind: 'bool' },
    { name: 'description', label: 'Description' },
  ],
  initial: (v) => ({ name: v.name, rd: v.rd ?? '', enforce_unique: v.enforce_unique, description: v.description ?? '' }),
  name: (v) => v.name,
};

const RIRS: Catalog<'rirs'> = {
  route: 'rirs', title: 'RIRs', noun: 'RIR',
  desc: 'Regional internet registries and private address authorities your aggregates are allocated from.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Private', w: '0.8fr' }],
  cells: (r) => [r.name, <span key="s" className="mono">{r.slug}</span>, r.is_private ? 'Yes' : 'No'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'is_private', label: 'Private address space', kind: 'bool' },
    { name: 'description', label: 'Description' },
  ],
  initial: (r) => ({ name: r.name, slug: r.slug, is_private: r.is_private, description: r.description ?? '' }),
  name: (r) => r.name,
};

const AGGREGATES: Catalog<'aggregates'> = {
  route: 'aggregates', title: 'Aggregates', noun: 'aggregate',
  desc: 'The top of your address space: the blocks you hold, and the registry each came from.',
  cols: [{ label: 'Prefix', w: '1.2fr' }, { label: 'RIR', w: '1fr' }, { label: 'Added', w: '0.8fr' }],
  cells: (a, rirName) => [<span key="p" className="mono">{a.prefix}</span>, rirName(a.rir_id), a.date_added ?? '—'],
  fields: (rirs) => [
    { name: 'prefix', label: 'Prefix', required: true, mono: true, placeholder: '10.0.0.0/8' },
    { name: 'rir_id', label: 'RIR', kind: 'select', required: true, options: rirOptions(rirs) },
    { name: 'date_added', label: 'Date added', placeholder: 'YYYY-MM-DD' },
    { name: 'description', label: 'Description' },
  ],
  initial: (a) => ({ prefix: a.prefix, rir_id: a.rir_id, date_added: a.date_added ?? '', description: a.description ?? '' }),
  name: (a) => a.prefix,
};

const ROLES: Catalog<'prefix-roles'> = {
  route: 'prefix-roles', title: 'Prefix roles', noun: 'prefix role',
  desc: 'What a prefix, IP range or VLAN is for — production, management, guest. Lower weights sort first.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Weight', w: '0.6fr' }],
  cells: (r) => [r.name, <span key="s" className="mono">{r.slug}</span>, r.weight],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'weight', label: 'Weight', kind: 'number' },
    { name: 'description', label: 'Description' },
  ],
  initial: (r) => ({ name: r.name, slug: r.slug, weight: r.weight, description: r.description ?? '' }),
  name: (r) => r.name,
};

const ASNS: Catalog<'asns'> = {
  route: 'asns', title: 'ASNs', noun: 'ASN',
  desc: 'The autonomous system numbers your organisation uses (32-bit).',
  cols: [{ label: 'ASN', w: '1fr' }, { label: 'RIR', w: '1fr' }, { label: 'Description', w: '1.4fr' }],
  cells: (a, rirName) => [<span key="n" className="mono">{a.asn}</span>, rirName(a.rir_id), a.description ?? '—'],
  fields: (rirs) => [
    { name: 'asn', label: 'ASN', kind: 'number', required: true },
    { name: 'rir_id', label: 'RIR', kind: 'select', options: rirOptions(rirs, 'None') },
    { name: 'description', label: 'Description' },
  ],
  initial: (a) => ({ asn: a.asn, rir_id: a.rir_id ?? '', description: a.description ?? '' }),
  name: (a) => `AS${a.asn}`,
};

/** An ASN range's free numbers: how many, and — on request — the first few
 *  (the server walks the gaps between the ASNs in it; DCIM gap 10). */
function FreeAsns({ range }: { range: AsnRange & { asn_count?: number; available_count?: number } }) {
  const [open, setOpen] = useState(false);
  const free = useAvailableAsns(open ? range.id : null, 10);
  return (
    <span data-testid="asn-range-free" style={{ display: 'inline-flex', flexDirection: 'column', gap: 2 }}>
      <span>
        {range.asn_count ?? 0} in use · {(range.available_count ?? 0).toLocaleString()} free
        {(range.available_count ?? 0) > 0 && (
          <button type="button" className="ui-btn sm ghost" data-testid="asn-range-show-free" style={{ marginLeft: 6 }} onClick={() => setOpen((o) => !o)}>
            {open ? 'Hide' : 'Show free'}
          </button>
        )}
      </span>
      {open && (
        free.isLoading ? <PanelLoading label="Finding free AS numbers…" />
          : free.isError ? <PanelError message={free.error instanceof Error ? free.error.message : 'Request failed'} onRetry={() => { void free.refetch(); }} />
            : <span className="mono" data-testid="asn-range-free-list" style={{ fontSize: 12 }}>{(free.data?.asns ?? []).map((a) => `AS${a}`).join(', ')}{(free.data?.available ?? 0) > (free.data?.asns ?? []).length ? ', …' : ''}</span>
      )}
    </span>
  );
}

const ASN_RANGES: Catalog<'asn-ranges'> = {
  route: 'asn-ranges', title: 'ASN ranges', noun: 'ASN range',
  desc: 'Blocks of AS numbers a registry delegated to you, and which numbers in each are still free.',
  cols: [{ label: 'Name', w: '1.1fr' }, { label: 'Range', w: '1fr' }, { label: 'RIR', w: '0.8fr' }, { label: 'ASNs', w: '1.5fr' }],
  cells: (r, rirName) => [r.name, <span key="r" className="mono">AS{r.start}–AS{r.end}</span>, rirName(r.rir_id), <FreeAsns key="f" range={r} />],
  fields: (rirs) => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'rir_id', label: 'RIR', kind: 'select', required: true, options: rirOptions(rirs) },
    { name: 'start', label: 'First ASN', kind: 'number', required: true, placeholder: '64512' },
    { name: 'end', label: 'Last ASN', kind: 'number', required: true, placeholder: '65534' },
    { name: 'description', label: 'Description' },
  ],
  initial: (r) => ({ name: r.name, slug: r.slug, rir_id: r.rir_id, start: r.start, end: r.end, description: r.description ?? '' }),
  name: (r) => r.name,
};

export function IpamSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="ipam-settings">
        <CatalogSection c={VRFS} />
        <CatalogSection c={AGGREGATES} />
        <CatalogSection c={RIRS} />
        <CatalogSection c={ROLES} />
        <CatalogSection c={ASNS} />
        <CatalogSection c={ASN_RANGES} />
      </div>
    </SPage>
  );
}
