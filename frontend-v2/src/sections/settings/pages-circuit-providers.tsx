// Settings → Infrastructure → Circuit Providers (DCIM BUILD_PLAN row 4.1;
// ADR-0010 D8): the catalogues the Inventory → Circuits lens builds on —
// circuit providers, their accounts and networks, circuit types, virtual
// circuit types (DCIM gap 10) and circuit groups. Simple tables with add / edit / delete; the circuit types the
// platform ships are listed read-only. Reading needs `circuits.read` (the nav
// entry); every write control sits behind `circuits.manage`.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import { ObjectDeleteModal, ObjectFormModal, type IpamField } from '../inventory/ipam/ipam-ui';
import { useCircuitList, useCircuitWrite, type CircuitRoute, type CircuitRows, type Provider } from '../inventory/circuits/circuits-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

interface Catalog<R extends CircuitRoute> {
  route: R;
  title: string;
  desc: string;
  noun: string;
  cols: STableCol[];
  cells: (row: CircuitRows[R], providerName: (id: string | null | undefined) => string) => ReactNode[];
  fields: (providers: Provider[]) => IpamField[];
  initial: (row: CircuitRows[R]) => Record<string, unknown>;
  name: (row: CircuitRows[R]) => string;
}

const ACTIONS_COL: STableCol = { label: '', w: '80px', align: 'right' };
const platformRow = (row: { tenant_id?: string | null }) => row.tenant_id == null;

function CatalogSection<R extends CircuitRoute>({ c }: { c: Catalog<R> }) {
  const q = useCircuitList(c.route, { limit: 1000 });
  const providers = useCircuitList('providers', { limit: 1000 });
  const write = useCircuitWrite(c.route);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CircuitRows[R] | null>(null);
  const [deleting, setDeleting] = useState<CircuitRows[R] | null>(null);
  const cols = [...c.cols, ACTIONS_COL];
  const providerName = (id: string | null | undefined) => (id ? (providers.data?.rows ?? []).find((p) => p.id === id)?.name ?? '—' : '—');
  const rows = q.data?.rows ?? [];
  const provs = providers.data?.rows ?? [];
  return (
    <SSection title={c.title} desc={c.desc} action={(
      <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
        <button type="button" className="ui-btn sm accent" data-testid={`add-${c.route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {c.noun}</button>
      </PermissionGate>
    )}>
      <div data-testid={`circuit-catalog-${c.route}`}>
        {q.isLoading && <PanelLoading label={`Loading ${c.title.toLowerCase()}…`} />}
        {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {q.data && rows.length === 0 && <PanelEmpty icon="list" title={`No ${c.title.toLowerCase()} yet`} message={c.desc} />}
        {rows.length > 0 && (
          <STable cols={cols}>
            {rows.map((row, i) => {
              const r = row as CircuitRows[R] & { id: string; tenant_id?: string | null };
              return (
                <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                  ...c.cells(row, providerName),
                  platformRow(r) ? <STag key="p">Built in</STag> : (
                    <PermissionGate key="a" permission={TENANT_PERMISSIONS.circuits.manage}>
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
      {adding && <ObjectFormModal write={write} icon="globe" title={`Add ${c.noun}`} fields={c.fields(provs)} onClose={() => setAdding(false)} />}
      {editing && (
        <ObjectFormModal write={write} icon="globe" title={`Edit ${c.name(editing)}`} editId={(editing as { id: string }).id}
          fields={c.fields(provs)} initial={c.initial(editing)} onClose={() => setEditing(null)} />
      )}
      {deleting && <ObjectDeleteModal write={write} id={(deleting as { id: string }).id} what={c.name(deleting)} onClose={() => setDeleting(null)} />}
    </SSection>
  );
}

const providerOptions = (providers: Provider[]) => [
  { value: '', label: 'Choose a provider' },
  ...providers.map((p) => ({ value: p.id, label: p.name })),
];

/** "3356, 174" ⇄ [3356, 174]. A blank list is an empty one, never null. */
export function parseAsns(text: string): number[] {
  return text.split(/[\s,]+/).map((s) => s.trim().replace(/^as/i, '')).filter((s) => s !== '').map(Number);
}

const PROVIDERS: Catalog<'providers'> = {
  route: 'providers', title: 'Circuit Providers', noun: 'circuit provider',
  desc: 'The companies your circuits come from — internet, MPLS, dark fibre and wavelength suppliers — and their AS numbers.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'ASNs', w: '1fr' }],
  cells: (p) => [p.name, <span key="s" className="mono">{p.slug}</span>, <span key="a" className="mono">{p.asns.length ? p.asns.map((a) => `AS${a}`).join(', ') : '—'}</span>],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'asns', label: 'AS numbers', mono: true, placeholder: '3356, 174', hint: 'Separated by commas.', decode: parseAsns },
    { name: 'description', label: 'Description' },
  ],
  initial: (p) => ({ name: p.name, slug: p.slug, asns: p.asns.join(', '), description: p.description ?? '' }),
  name: (p) => p.name,
};

const ACCOUNTS: Catalog<'provider-accounts'> = {
  route: 'provider-accounts', title: 'Provider Accounts', noun: 'provider account',
  desc: 'Your accounts with each circuit provider, so a circuit can say which contract it is billed under.',
  cols: [{ label: 'Account', w: '1fr' }, { label: 'Name', w: '1.2fr' }, { label: 'Circuit Provider', w: '1.2fr' }],
  cells: (a, providerName) => [<span key="a" className="mono">{a.account}</span>, a.name ?? '—', providerName(a.provider_id)],
  fields: (providers) => [
    { name: 'provider_id', label: 'Circuit Provider', kind: 'select', required: true, options: providerOptions(providers) },
    { name: 'account', label: 'Account number', required: true, mono: true },
    { name: 'name', label: 'Name' },
    { name: 'description', label: 'Description' },
  ],
  initial: (a) => ({ provider_id: a.provider_id, account: a.account, name: a.name ?? '', description: a.description ?? '' }),
  name: (a) => a.name ?? a.account,
};

const NETWORKS: Catalog<'provider-networks'> = {
  route: 'provider-networks', title: 'Provider Networks', noun: 'provider network',
  desc: 'A provider’s own network a circuit can end on instead of a site — an MPLS cloud, an internet exchange fabric.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Circuit Provider', w: '1.2fr' }, { label: 'Service ID', w: '1fr' }],
  cells: (n, providerName) => [n.name, providerName(n.provider_id), <span key="s" className="mono">{n.service_id ?? '—'}</span>],
  fields: (providers) => [
    { name: 'provider_id', label: 'Circuit Provider', kind: 'select', required: true, options: providerOptions(providers) },
    { name: 'name', label: 'Name', required: true },
    { name: 'service_id', label: 'Service ID', mono: true },
    { name: 'description', label: 'Description' },
  ],
  initial: (n) => ({ provider_id: n.provider_id, name: n.name, service_id: n.service_id ?? '', description: n.description ?? '' }),
  name: (n) => n.name,
};

const TYPES: Catalog<'circuit-types'> = {
  route: 'circuit-types', title: 'Circuit Types', noun: 'circuit type',
  desc: 'What kind of service a circuit is. The common ones are built in; add your own beside them.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Colour', w: '0.8fr' }],
  cells: (t) => [t.name, <span key="s" className="mono">{t.slug}</span>, t.color ? <span key="c" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><span style={{ width: 10, height: 10, borderRadius: 3, background: `#${t.color}` }} /><span className="mono">#{t.color}</span></span> : '—'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'color', label: 'Colour', mono: true, placeholder: '2196f3' },
    { name: 'description', label: 'Description' },
  ],
  initial: (t) => ({ name: t.name, slug: t.slug, color: t.color ?? '', description: t.description ?? '' }),
  name: (t) => t.name,
};

// DCIM gap 10: the kinds of virtual circuit (NetBox 4.2
// circuits/virtual-circuit-type) the Circuits lens's Virtual circuits view
// picks from. A tenant's own; none are built in.
const VC_TYPES: Catalog<'virtual-circuit-types'> = {
  route: 'virtual-circuit-types', title: 'Virtual Circuit Types', noun: 'virtual circuit type',
  desc: 'What kind of overlay a virtual circuit is — SD-WAN, MPLS L3VPN, Metro Ethernet.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Colour', w: '0.8fr' }],
  cells: (t) => [t.name, <span key="s" className="mono">{t.slug}</span>, t.color ? <span key="c" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><span style={{ width: 10, height: 10, borderRadius: 3, background: `#${t.color}` }} /><span className="mono">#{t.color}</span></span> : '—'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'color', label: 'Colour', mono: true, placeholder: '2196f3' },
    { name: 'description', label: 'Description' },
  ],
  initial: (t) => ({ name: t.name, slug: t.slug, color: t.color ?? '', description: t.description ?? '' }),
  name: (t) => t.name,
};

const GROUPS: Catalog<'circuit-groups'> = {
  route: 'circuit-groups', title: 'Circuit Groups', noun: 'circuit group',
  desc: 'Name a set of circuits that belong together, such as the primary and backup links to one office.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Description', w: '1.4fr' }],
  cells: (g) => [g.name, <span key="s" className="mono">{g.slug}</span>, g.description ?? '—'],
  fields: () => [
    { name: 'name', label: 'Name', required: true },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' },
    { name: 'description', label: 'Description' },
  ],
  initial: (g) => ({ name: g.name, slug: g.slug, description: g.description ?? '' }),
  name: (g) => g.name,
};

export function CircuitProvidersPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="circuit-providers-settings">
        <CatalogSection c={PROVIDERS} />
        <CatalogSection c={ACCOUNTS} />
        <CatalogSection c={NETWORKS} />
        <CatalogSection c={TYPES} />
        <CatalogSection c={VC_TYPES} />
        <CatalogSection c={GROUPS} />
      </div>
    </SPage>
  );
}
