// Settings → Infrastructure → Manufacturers / Device Roles / Platforms (OS)
// (DCIM BUILD_PLAN row 2.2): simple tables over the device catalogue. The rows
// the product ships (the library's and the OUI registry's manufacturers, one
// device role per hardware/virtual asset class) are listed as "Built in" and
// cannot be edited; a tenant adds its own. Reading needs `dcim.read` (the nav
// entry); every write control sits behind `dcim.manage`.
import { useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import { CatalogueDeleteModal, CatalogueFormModal, eosFields, eosInitial, type CatalogueField } from '../inventory/dcim/catalogue-form';
import {
  isPlatformRow, useCatalogueList, useCatalogueWrite, useEOLCatalogue,
  type CatalogueRoute, type CatalogueRows, type EOLCatalogueRef, type Manufacturer,
} from '../inventory/dcim/catalogue-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

interface TableConfig<R extends CatalogueRoute> {
  route: R;
  title: string;
  noun: string;
  desc: string;
  cols: STableCol[];
  cells: (row: CatalogueRows[R], manufacturerName: (id: string | null | undefined) => string) => ReactNode[];
  /** `eol` is the end-of-life catalogue picker's state, for the kinds that link to it (platforms). */
  fields: (manufacturers: Manufacturer[], eol: { entries: EOLCatalogueRef[]; loading: boolean; current?: string | null; source?: string | null }) => CatalogueField[];
  initial: (row: CatalogueRows[R]) => Record<string, unknown>;
}

const ACTIONS_COL: STableCol = { label: '', w: '84px', align: 'right' };

function CatalogueTable<R extends CatalogueRoute>({ c }: { c: TableConfig<R> }) {
  const [q, setQ] = useState('');
  const list = useCatalogueList(c.route, { limit: 1000, ...(q.trim() ? { q: q.trim() } : {}) });
  const needsManufacturers = c.route === 'platforms';
  const mfrs = useCatalogueList('manufacturers', { limit: 1000 }, { enabled: needsManufacturers });
  const write = useCatalogueWrite(c.route);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CatalogueRows[R] | null>(null);
  const [deleting, setDeleting] = useState<CatalogueRows[R] | null>(null);
  const eolQ = useEOLCatalogue('os', needsManufacturers && (adding || editing !== null));
  const eol = (current?: string | null, source?: string | null) => ({ entries: eolQ.data ?? [], loading: eolQ.isLoading, current, source });
  const cols = [...c.cols, ACTIONS_COL];
  const mfrName = (id: string | null | undefined) => (id ? (mfrs.data?.rows ?? []).find((m) => m.id === id)?.name ?? '—' : '—');
  const rows = list.data?.rows ?? [];
  const name = (row: CatalogueRows[R]) => (row as { name: string }).name;

  return (
    <SSection title={c.title} desc={c.desc} action={(
      <span style={{ display: 'inline-flex', gap: 8 }}>
        <input aria-label={`Search ${c.title.toLowerCase()}`} placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)}
          style={{ width: 180, padding: '5px 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5 }} />
        <PermissionGate permission={MANAGE}>
          <button type="button" className="ui-btn sm accent" data-testid={`add-${c.route}`} onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add {c.noun}</button>
        </PermissionGate>
      </span>
    )}>
      <div data-testid={`catalogue-${c.route}`}>
        {list.isLoading && <PanelLoading label={`Loading ${c.title.toLowerCase()}…`} />}
        {list.isError && <PanelError message={list.error instanceof Error ? list.error.message : 'Request failed'} onRetry={() => { void list.refetch(); }} />}
        {list.data && rows.length === 0 && (
          <PanelEmpty icon="list" title={q.trim() ? `No ${c.title.toLowerCase()} match “${q.trim()}”` : `No ${c.title.toLowerCase()} yet`} message={c.desc} />
        )}
        {rows.length > 0 && (
          <STable cols={cols}>
            {rows.map((row, i) => {
              const r = row as CatalogueRows[R] & { id: string };
              return (
                <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                  ...c.cells(row, mfrName),
                  isPlatformRow(r) ? <STag key="p">Built in</STag> : (
                    <PermissionGate key="a" permission={MANAGE} fallback={<span />}>
                      <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${name(row)}`} onClick={() => setEditing(row)}><Icon name="sliders-horizontal" size={13} /></button>
                      <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${name(row)}`} style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(row)}><Icon name="x" size={13} /></button>
                    </PermissionGate>
                  ),
                ]} />
              );
            })}
          </STable>
        )}
      </div>
      {adding && (
        <CatalogueFormModal title={`Add ${c.noun}`} editing={false} fields={c.fields(mfrs.data?.rows ?? [], eol())}
          onSubmit={(body) => write.create.mutateAsync(body)} onClose={() => setAdding(false)} />
      )}
      {editing && (
        <CatalogueFormModal title={`Edit ${name(editing)}`} editing fields={c.fields(mfrs.data?.rows ?? [], eol((editing as { eol_catalogue_id?: string | null }).eol_catalogue_id, (editing as { eol_link_source?: string | null }).eol_link_source))} initial={c.initial(editing)}
          onSubmit={(body) => write.update.mutateAsync({ id: (editing as { id: string }).id, body })} onClose={() => setEditing(null)} />
      )}
      {deleting && (
        <CatalogueDeleteModal what={name(deleting)} onConfirm={() => write.remove.mutateAsync((deleting as { id: string }).id)} onClose={() => setDeleting(null)} />
      )}
    </SSection>
  );
}

const slugField: CatalogueField = { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the name.' };

export const MANUFACTURERS: TableConfig<'manufacturers'> = {
  route: 'manufacturers', title: 'Manufacturers', noun: 'manufacturer',
  desc: 'Who makes the hardware your device types describe. The product ships the device-type library’s manufacturers and the vendors the MAC registry knows.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }],
  cells: (m) => [m.name, <span key="s" className="mono">{m.slug}</span>],
  fields: () => [{ name: 'name', label: 'Name', required: true }, slugField, { name: 'description', label: 'Description' }],
  initial: (m) => ({ name: m.name, slug: m.slug, description: m.description ?? '' }),
};

export const DEVICE_ROLES: TableConfig<'device-roles'> = {
  route: 'device-roles', title: 'Device Roles', noun: 'device role',
  desc: 'What a device does in your estate. One role ships per hardware and virtual asset class, so a NetBox role maps onto a class and back.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Colour', w: '0.7fr' }, { label: 'VM role', w: '0.6fr' }],
  cells: (r) => [
    r.name, <span key="s" className="mono">{r.slug}</span>,
    <span key="c" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span aria-hidden style={{ width: 10, height: 10, borderRadius: 3, background: `#${r.color}` }} /><span className="mono">{r.color}</span>
    </span>,
    r.vm_role ? 'Yes' : 'No',
  ],
  fields: () => [
    { name: 'name', label: 'Name', required: true }, slugField,
    { name: 'color', label: 'Colour', mono: true, placeholder: '2196f3', hint: 'Six hex digits.' },
    { name: 'vm_role', label: 'Can be a virtual machine’s role', kind: 'bool' },
    { name: 'description', label: 'Description' },
  ],
  initial: (r) => ({ name: r.name, slug: r.slug, color: r.color, vm_role: r.vm_role, description: r.description ?? '' }),
};

export const PLATFORMS: TableConfig<'platforms'> = {
  route: 'platforms', title: 'Platforms (OS)', noun: 'platform (OS)',
  desc: 'The operating system or firmware family a device runs — IOS-XE, Junos, FortiOS, Ubuntu.',
  cols: [{ label: 'Name', w: '1.4fr' }, { label: 'Slug', w: '1fr' }, { label: 'Manufacturer', w: '1fr' }],
  cells: (p, mfrName) => [p.name, <span key="s" className="mono">{p.slug}</span>, mfrName(p.manufacturer_id)],
  fields: (mfrs, eol) => [
    { name: 'name', label: 'Name', required: true }, slugField,
    { name: 'manufacturer_id', label: 'Manufacturer', kind: 'select', options: [{ value: '', label: 'None' }, ...mfrs.map((m) => ({ value: m.id, label: m.name }))] },
    { name: 'description', label: 'Description' },
    ...eosFields(eol.entries, eol.current, eol.loading, eol.source),
  ],
  initial: (p) => ({ name: p.name, slug: p.slug, manufacturer_id: p.manufacturer_id ?? '', description: p.description ?? '', ...eosInitial(p) }),
};

export function ManufacturersPage({ meta }: { meta: SettingsNavItem }) {
  return <SPage eyebrow="Infrastructure" title="Manufacturers" job={meta.job}><CatalogueTable c={MANUFACTURERS} /></SPage>;
}

export function DeviceRolesPage({ meta }: { meta: SettingsNavItem }) {
  return <SPage eyebrow="Infrastructure" title="Device Roles" job={meta.job}><CatalogueTable c={DEVICE_ROLES} /></SPage>;
}

export function PlatformsPage({ meta }: { meta: SettingsNavItem }) {
  return <SPage eyebrow="Infrastructure" title="Platforms (OS)" job={meta.job}><CatalogueTable c={PLATFORMS} /></SPage>;
}
