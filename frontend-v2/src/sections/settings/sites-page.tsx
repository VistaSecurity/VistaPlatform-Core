// Settings → Sites (DCIM row 2.1): the tenant's Region › Site group › Site ›
// Location tree, with a create/edit dialog per level (each edit dialog carries
// the object's Changes and Journal), delete for every level and
// delete-with-reassign for a site that still holds assets. Reads need
// dcim.read; every write control is behind dcim.manage.
import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { unwrap } from '../../lib/api-result';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, StateNote } from './kit';
import { ObjectChanges } from '../inventory/dcim/object-changes';
import { ObjectJournal } from '../inventory/dcim/object-journal';
import type { SettingsNavItem } from './nav';
import {
  ALL_SITE_KEYS, SITE_STATUSES, buildSiteTree, flattenNodes, subtreeIds, useLocations, useRegions, useSiteGroups, useSites,
  type Location, type Region, type Site, type SiteGroup, type SiteTreeRow,
} from '../inventory/sites/sites-queries';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

type Editing =
  | { kind: 'region' | 'site_group'; node: Region | SiteGroup | null }
  | { kind: 'site'; site: Site | null }
  | { kind: 'location'; location: Location | null; siteId?: string; parentId?: string };
type Deleting =
  | { kind: 'region' | 'site_group'; id: string; name: string }
  | { kind: 'site'; site: Site }
  | { kind: 'location'; id: string; name: string };

function useInvalidateSites() {
  const qc = useQueryClient();
  return () => { for (const k of ALL_SITE_KEYS) void qc.invalidateQueries({ queryKey: k }); };
}

export function SitesPage({ meta }: { meta: SettingsNavItem }) {
  const regions = useRegions();
  const groups = useSiteGroups();
  const sites = useSites();
  const locations = useLocations();
  const [editing, setEditing] = useState<Editing | null>(null);
  const [deleting, setDeleting] = useState<Deleting | null>(null);

  const queries = [regions, groups, sites, locations];
  const isError = queries.some((q) => q.isError);
  const isLoading = queries.some((q) => q.isLoading);
  const rows = buildSiteTree(regions.data ?? [], groups.data ?? [], sites.data ?? [], locations.data ?? []);
  const empty = !isLoading && !isError && rows.length === 0 && (groups.data ?? []).length === 0;
  const cols = [
    { label: 'Name' }, { label: 'Kind', w: '110px' }, { label: 'Detail', w: '200px' },
    { label: 'Assets', w: '70px', align: 'right' as const }, { label: '', w: '120px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="Infrastructure" title="Sites" job={meta.job} maxWidth={1060}
      actions={
        <PermissionGate permission={MANAGE}>
          <button className="ui-btn sm" onClick={() => setEditing({ kind: 'region', node: null })}><Icon name="plus" size={14} />Region</button>
          <button className="ui-btn sm" onClick={() => setEditing({ kind: 'site_group', node: null })}><Icon name="plus" size={14} />Site group</button>
          <button className="ui-btn sm" disabled={(sites.data ?? []).length === 0} onClick={() => setEditing({ kind: 'location', location: null })}><Icon name="plus" size={14} />Location</button>
          <button className="ui-btn sm accent" onClick={() => setEditing({ kind: 'site', site: null })}><Icon name="plus" size={14} />New site</button>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load sites" message="The site tree failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading sites…" message="Fetching regions, site groups, sites and locations." /></SCard>
      ) : empty ? (
        <SCard><StateNote icon="map-pin" tone="var(--app-t3)" title="No sites" message="No sites are defined yet. Create a site, add the halls, cages or rows inside it as locations, and place assets there from the asset form." /></SCard>
      ) : (
        <>
          <SSection title="Regions, sites and locations">
            <STable cols={cols}>
              {rows.map((r, i) => (
                <STableRow key={`${r.kind}:${r.id}`} first={i === 0} cols={cols} cells={treeCells(r, setEditing, setDeleting)} />
              ))}
            </STable>
          </SSection>
          <SiteGroupsSection groups={groups.data ?? []} onEdit={(g) => setEditing({ kind: 'site_group', node: g })}
            onDelete={(g) => setDeleting({ kind: 'site_group', id: g.id, name: g.name })} />
        </>
      )}

      {editing && (editing.kind === 'region' || editing.kind === 'site_group') && (
        <TreeNodeModal key={editing.node?.id ?? `new-${editing.kind}`} kind={editing.kind} node={editing.node}
          nodes={editing.kind === 'region' ? regions.data ?? [] : groups.data ?? []} onClose={() => setEditing(null)} />
      )}
      {editing?.kind === 'site' && (
        <SiteModal key={editing.site?.id ?? 'new-site'} site={editing.site} regions={regions.data ?? []} groups={groups.data ?? []} onClose={() => setEditing(null)} />
      )}
      {editing?.kind === 'location' && (
        <LocationModal key={editing.location?.id ?? `new-location-${editing.siteId ?? ''}-${editing.parentId ?? ''}`} location={editing.location}
          siteId={editing.siteId} parentId={editing.parentId} sites={sites.data ?? []} locations={locations.data ?? []} onClose={() => setEditing(null)} />
      )}
      {deleting?.kind === 'site' && <DeleteSiteModal site={deleting.site} sites={sites.data ?? []} onClose={() => setDeleting(null)} />}
      {deleting && deleting.kind !== 'site' && <DeleteNodeModal kind={deleting.kind} id={deleting.id} name={deleting.name} onClose={() => setDeleting(null)} />}
    </SPage>
  );
}

const KIND_LABEL: Record<SiteTreeRow['kind'], string> = { region: 'Region', site_group: 'Site group', site: 'Site', location: 'Location' };
const KIND_ICON: Record<SiteTreeRow['kind'], string> = {
  region: 'globe',
  site_group: 'folder-tree',
  site: 'building-2',
  location: 'map-pin',
};

function RowButtons({ label, onAdd, addLabel, onEdit, onDelete }: { label: string; onAdd?: () => void; addLabel?: string; onEdit?: () => void; onDelete?: () => void }) {
  return (
    <PermissionGate permission={MANAGE} fallback={<span />}>
      <span style={{ display: 'inline-flex', justifyContent: 'flex-end', gap: 6 }}>
        {onAdd && <button className="ui-btn sm ghost" title={addLabel} aria-label={`${addLabel} in ${label}`} onClick={onAdd}><Icon name="plus" size={13} /></button>}
        {onEdit && <button className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${label}`} onClick={onEdit}><Icon name="sliders-horizontal" size={13} /></button>}
        {onDelete && <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Delete" aria-label={`Delete ${label}`} onClick={onDelete}><Icon name="x" size={13} /></button>}
      </span>
    </PermissionGate>
  );
}

function treeCells(r: SiteTreeRow, edit: (e: Editing) => void, del: (d: Deleting) => void) {
  const name = r.kind === 'region' ? r.region.name : r.kind === 'site_group' ? r.group.name : r.kind === 'site' ? r.site.name : r.location.name;
  const label = (
    <span data-testid={`sites-row-${r.kind}`} style={{ fontSize: 12.5, color: 'var(--app-t1)', paddingLeft: r.depth * 18, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <Icon name={KIND_ICON[r.kind]} size={13} style={{ color: 'var(--app-t3)' }} />
      {r.kind === 'site'
        ? <Link to={`/inventory/sites/${r.site.id}`} style={{ fontWeight: 700, color: 'var(--app-t1)' }}>{name}</Link>
        : <span style={{ fontWeight: r.kind === 'location' ? 500 : 600 }}>{name}</span>}
    </span>
  );
  const kind = <STag>{KIND_LABEL[r.kind]}</STag>;
  switch (r.kind) {
    case 'region':
      return [label, kind, <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{r.region.slug}</span>, <span />,
        <RowButtons label={name} onEdit={() => edit({ kind: 'region', node: r.region })} onDelete={() => del({ kind: 'region', id: r.region.id, name })} />];
    case 'site_group':
      return [label, kind, <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{r.group.slug}</span>, <span />,
        <RowButtons label={name} onEdit={() => edit({ kind: 'site_group', node: r.group })} />];
    case 'site':
      return [label, kind,
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{[r.site.facility, r.site.time_zone].filter(Boolean).join(' · ') || '—'}{r.site.operational_status !== 'active' && <> <STag>{r.site.operational_status}</STag></>}</span>,
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{r.site.asset_count}</span>,
        <RowButtons label={name} addLabel="Add a location" onAdd={() => edit({ kind: 'location', location: null, siteId: r.site.id })}
          onEdit={() => edit({ kind: 'site', site: r.site })} onDelete={() => del({ kind: 'site', site: r.site })} />];
    case 'location':
      return [label, kind,
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{r.location.facility ?? r.location.slug}</span>,
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{r.location.asset_count}</span>,
        <RowButtons label={name} addLabel="Add a location" onAdd={() => edit({ kind: 'location', location: null, siteId: r.location.site_id, parentId: r.location.id })}
          onEdit={() => edit({ kind: 'location', location: r.location })} onDelete={() => del({ kind: 'location', id: r.location.id, name })} />];
  }
}

function SiteGroupsSection({ groups, onEdit, onDelete }: { groups: readonly SiteGroup[]; onEdit: (g: SiteGroup) => void; onDelete: (g: SiteGroup) => void }) {
  if (groups.length === 0) return null;
  const cols = [{ label: 'Site group' }, { label: 'Sites', w: '70px', align: 'right' as const }, { label: '', w: '88px', align: 'right' as const }];
  return (
    <SSection title="Site groups" desc="Functional groupings (Branches, Colo) a site can belong to, independent of its region.">
      <STable cols={cols}>
        {flattenNodes(groups).map(({ node, depth }, i) => (
          <STableRow key={node.id} first={i === 0} cols={cols} cells={[
            <span data-testid="sites-group" style={{ fontSize: 12.5, paddingLeft: depth * 18, fontWeight: 600 }}>{node.name}</span>,
            <span className="mono" style={{ fontSize: 12 }}>{node.site_count}</span>,
            <RowButtons label={node.name} onEdit={() => onEdit(node)} onDelete={() => onDelete(node)} />,
          ]} />
        ))}
      </STable>
    </SSection>
  );
}

function History({ kind, id }: { kind: 'region' | 'site_group' | 'site' | 'location'; id: string }) {
  return (
    <div data-testid="sites-history" style={{ marginTop: 6 }}>
      <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Changes</div>
      <ObjectChanges kind={kind} id={id} />
      <div className="eyebrow-app" style={{ margin: '14px 0 8px' }}>Journal</div>
      <ObjectJournal kind={kind} id={id} />
    </div>
  );
}

function SaveButtons({ pending, valid, isEdit, noun, onSave, onClose }: { pending: boolean; valid: boolean; isEdit: boolean; noun: string; onSave: () => void; onClose: () => void }) {
  return {
    primary: <button className="ui-btn accent" disabled={!valid || pending} onClick={onSave}>{pending ? 'Saving…' : isEdit ? 'Save changes' : `Create ${noun}`}</button>,
    secondary: <button className="ui-btn" onClick={onClose} disabled={pending}>Cancel</button>,
  };
}

const orNull = (s: string) => (s.trim() ? s.trim() : null);

export function TreeNodeModal({ kind, node, nodes, onClose }: {
  kind: 'region' | 'site_group'; node: Region | SiteGroup | null; nodes: readonly (Region | SiteGroup)[]; onClose: () => void;
}) {
  const invalidate = useInvalidateSites();
  const isEdit = !!node;
  const noun = kind === 'region' ? 'region' : 'site group';
  const [name, setName] = useState(node?.name ?? '');
  const [slug, setSlug] = useState(node?.slug ?? '');
  const [parentId, setParentId] = useState(node?.parent_id ?? '');
  const [description, setDescription] = useState(node?.description ?? '');
  const blocked = node ? subtreeIds(nodes, node.id) : new Set<string>();
  const options = flattenNodes(nodes).filter(({ node: n }) => !blocked.has(n.id));
  const save = useMutation({
    mutationFn: async () => {
      const body = { name: name.trim(), ...(slug.trim() ? { slug: slug.trim() } : {}), parent_id: parentId || null, description: orNull(description) };
      if (kind === 'region') {
        unwrap(isEdit
          ? await clients.inventory.PUT('/dcim/regions/{id}', { params: { path: { id: node.id } }, body })
          : await clients.inventory.POST('/dcim/regions', { body }), `Failed to save the ${noun}`);
      } else {
        unwrap(isEdit
          ? await clients.inventory.PUT('/dcim/site-groups/{id}', { params: { path: { id: node.id } }, body })
          : await clients.inventory.POST('/dcim/site-groups', { body }), `Failed to save the ${noun}`);
      }
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  const buttons = SaveButtons({ pending: save.isPending, valid: name.trim().length > 0, isEdit, noun, onSave: () => save.mutate(), onClose });
  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="md" tone="accent"
      icon={kind === 'region' ? 'globe' : 'folder-tree'} eyebrow="Infrastructure · Sites"
      title={isEdit ? `Edit ${node.name}` : `New ${noun}`}
      description={kind === 'region' ? 'A region is geography — a continent, a country, a metro. Regions nest.' : 'A site group is a functional grouping — Branches, Colo — independent of geography.'}
      primary={buttons.primary} secondary={buttons.secondary}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === 'region' ? 'e.g. Europe' : 'e.g. Branches'} /></ModalField>
      <ModalField label="Slug" hint="Optional — derived from the name when left empty."><ModalInput aria-label="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} /></ModalField>
      <ModalField label={`Parent ${noun}`} hint="Optional.">
        <ModalSelect aria-label={`Parent ${noun}`} value={parentId} onChange={(e) => setParentId(e.target.value)}>
          <option value="">None (top level)</option>
          {options.map(({ node: n, depth }) => <option key={n.id} value={n.id}>{`${'  '.repeat(depth)}${n.name}`}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
      {isEdit && <History kind={kind} id={node.id} />}
    </Modal>
  );
}

export function SiteModal({ site, regions, groups, onClose }: {
  site: Site | null; regions: readonly Region[]; groups: readonly SiteGroup[]; onClose: () => void;
}) {
  const invalidate = useInvalidateSites();
  const isEdit = !!site;
  const [name, setName] = useState(site?.name ?? '');
  const [slug, setSlug] = useState(site?.slug ?? '');
  const [status, setStatus] = useState<Site['operational_status']>(site?.operational_status ?? 'active');
  const [regionId, setRegionId] = useState(site?.region_id ?? '');
  const [groupId, setGroupId] = useState(site?.group_id ?? '');
  const [facility, setFacility] = useState(site?.facility ?? '');
  const [timeZone, setTimeZone] = useState(site?.time_zone ?? '');
  const [physical, setPhysical] = useState(site?.physical_address ?? '');
  const [shipping, setShipping] = useState(site?.shipping_address ?? '');
  const [lat, setLat] = useState(site?.latitude != null ? String(site.latitude) : '');
  const [lon, setLon] = useState(site?.longitude != null ? String(site.longitude) : '');
  const [description, setDescription] = useState(site?.description ?? '');
  const num = (s: string) => (s.trim() === '' ? null : Number(s));
  const coordsOk = [lat, lon].every((s) => s.trim() === '' || Number.isFinite(Number(s)));
  const save = useMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(), ...(slug.trim() ? { slug: slug.trim() } : {}), operational_status: status,
        region_id: regionId || null, group_id: groupId || null, facility: orNull(facility), time_zone: orNull(timeZone),
        physical_address: orNull(physical), shipping_address: orNull(shipping), latitude: num(lat), longitude: num(lon),
        description: orNull(description),
      };
      unwrap(isEdit
        ? await clients.inventory.PUT('/dcim/sites/{id}', { params: { path: { id: site.id } }, body })
        : await clients.inventory.POST('/dcim/sites', { body }), 'Failed to save the site');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  const buttons = SaveButtons({ pending: save.isPending, valid: name.trim().length > 0 && coordsOk, isEdit, noun: 'site', onSave: () => save.mutate(), onClose });
  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="lg" tone="accent" icon="building-2" eyebrow="Infrastructure · Sites"
      title={isEdit ? `Edit ${site.name}` : 'New site'}
      description="A site is one place — a data centre, an office, a colocation suite, a cloud account."
      primary={buttons.primary} secondary={buttons.secondary}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. AMS-1" /></ModalField>
        <ModalField label="Slug" hint="Optional — derived from the name."><ModalInput aria-label="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} /></ModalField>
        <ModalField label="Status">
          <ModalSelect aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as Site['operational_status'])}>
            {SITE_STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Facility" hint="The facility's own name or code."><ModalInput aria-label="Facility" value={facility} onChange={(e) => setFacility(e.target.value)} placeholder="Optional" /></ModalField>
        <ModalField label="Region">
          <ModalSelect aria-label="Region" value={regionId} onChange={(e) => setRegionId(e.target.value)}>
            <option value="">None</option>
            {flattenNodes(regions).map(({ node: r, depth }) => <option key={r.id} value={r.id}>{`${'  '.repeat(depth)}${r.name}`}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Site group">
          <ModalSelect aria-label="Site group" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">None</option>
            {flattenNodes(groups).map(({ node: g, depth }) => <option key={g.id} value={g.id}>{`${'  '.repeat(depth)}${g.name}`}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Time zone" hint="IANA name, e.g. Europe/Amsterdam."><ModalInput aria-label="Time zone" value={timeZone} onChange={(e) => setTimeZone(e.target.value)} placeholder="Optional" /></ModalField>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 10px' }}>
          <ModalField label="Latitude"><ModalInput aria-label="Latitude" value={lat} onChange={(e) => setLat(e.target.value)} placeholder="52.3" /></ModalField>
          <ModalField label="Longitude"><ModalInput aria-label="Longitude" value={lon} onChange={(e) => setLon(e.target.value)} placeholder="4.9" /></ModalField>
        </div>
      </div>
      <ModalField label="Physical address"><ModalInput aria-label="Physical address" value={physical} onChange={(e) => setPhysical(e.target.value)} placeholder="Optional" /></ModalField>
      <ModalField label="Shipping address"><ModalInput aria-label="Shipping address" value={shipping} onChange={(e) => setShipping(e.target.value)} placeholder="Optional" /></ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
      {isEdit && <History kind="site" id={site.id} />}
    </Modal>
  );
}

export function LocationModal({ location, siteId, parentId, sites, locations, onClose }: {
  location: Location | null; siteId?: string; parentId?: string; sites: readonly Site[]; locations: readonly Location[]; onClose: () => void;
}) {
  const invalidate = useInvalidateSites();
  const isEdit = !!location;
  const [site, setSite] = useState(location?.site_id ?? siteId ?? '');
  const [parent, setParent] = useState(location?.parent_id ?? parentId ?? '');
  const [name, setName] = useState(location?.name ?? '');
  const [status, setStatus] = useState<Location['operational_status']>(location?.operational_status ?? 'active');
  const [facility, setFacility] = useState(location?.facility ?? '');
  const [description, setDescription] = useState(location?.description ?? '');
  // A parent is a location of the SAME site, never this one or one beneath it.
  const blocked = location ? subtreeIds(locations, location.id) : new Set<string>();
  const parents = flattenNodes(locations.filter((l) => l.site_id === site)).filter(({ node }) => !blocked.has(node.id));
  const save = useMutation({
    mutationFn: async () => {
      const common = { name: name.trim(), parent_id: parent || null, operational_status: status, facility: orNull(facility), description: orNull(description) };
      unwrap(isEdit
        ? await clients.inventory.PUT('/dcim/locations/{id}', { params: { path: { id: location.id } }, body: common })
        : await clients.inventory.POST('/dcim/locations', { body: { ...common, site_id: site } }), 'Failed to save the location');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  const buttons = SaveButtons({ pending: save.isPending, valid: name.trim().length > 0 && site !== '', isEdit, noun: 'location', onSave: () => save.mutate(), onClose });
  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="md" tone="accent" icon="map-pin" eyebrow="Infrastructure · Sites"
      title={isEdit ? `Edit ${location.name}` : 'New location'}
      description="A location is a place inside one site — a hall, a cage, a row. Locations nest."
      primary={buttons.primary} secondary={buttons.secondary}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <ModalField label="Site" hint={isEdit ? 'A location cannot move to another site.' : undefined}>
        <ModalSelect aria-label="Site" value={site} disabled={isEdit} onChange={(e) => { setSite(e.target.value); setParent(''); }}>
          <option value="">Choose a site…</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Parent location" hint="Optional — nest inside another location of the same site.">
        <ModalSelect aria-label="Parent location" value={parent} onChange={(e) => setParent(e.target.value)} disabled={!site}>
          <option value="">None (top level of the site)</option>
          {parents.map(({ node, depth }) => <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}`}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Hall 2" /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Status">
          <ModalSelect aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as Location['operational_status'])}>
            {SITE_STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Facility"><ModalInput aria-label="Facility" value={facility} onChange={(e) => setFacility(e.target.value)} placeholder="Optional" /></ModalField>
      </div>
      <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
      {isEdit && <History kind="location" id={location.id} />}
    </Modal>
  );
}

export function DeleteNodeModal({ kind, id, name, onClose }: { kind: 'region' | 'site_group' | 'location'; id: string; name: string; onClose: () => void }) {
  const invalidate = useInvalidateSites();
  const del = useMutation({
    mutationFn: async () => {
      const opts = { params: { path: { id } } };
      unwrap(kind === 'region' ? await clients.inventory.DELETE('/dcim/regions/{id}', opts)
        : kind === 'site_group' ? await clients.inventory.DELETE('/dcim/site-groups/{id}', opts)
          : await clients.inventory.DELETE('/dcim/locations/{id}', opts), 'Delete failed');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  const what = kind === 'region' ? 'region' : kind === 'site_group' ? 'site group' : 'location';
  const effect = kind === 'location'
    ? 'Locations inside it are deleted with it; the assets in them stay in the site.'
    : `What is in it moves up to its parent ${what}.`;
  return (
    <Modal open onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending} size="sm" tone="danger" icon="octagon-alert" eyebrow="Infrastructure · Sites"
      title={`Delete ${what}?`} description={`“${name}” will be removed. ${effect}`}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error.message}</span> : undefined}
    />
  );
}

export function DeleteSiteModal({ site, sites, onClose }: { site: Site; sites: readonly Site[]; onClose: () => void }) {
  const invalidate = useInvalidateSites();
  const [target, setTarget] = useState('');
  const inUse = site.asset_count > 0;
  const del = useMutation({
    mutationFn: async () => {
      unwrap(await clients.inventory.DELETE('/dcim/sites/{id}', {
        params: { path: { id: site.id }, query: target ? { reassign_to: target } : {} },
      }), 'Delete failed');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  return (
    <Modal open onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending} size="sm" tone="danger" icon="octagon-alert" eyebrow="Infrastructure · Sites"
      title="Delete site?" description={`“${site.name}” and every location inside it will be removed.`}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending || (inUse && !target)} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error.message}</span> : undefined}
    >
      {inUse && (
        <ModalField label="Move its assets to" hint={`${site.asset_count} asset${site.asset_count === 1 ? ' is' : 's are'} in this site; choose where they go. They lose their location, which is deleted with the site.`}>
          <ModalSelect aria-label="Move its assets to" value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">Choose a site…</option>
            {sites.filter((s) => s.id !== site.id).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </ModalSelect>
        </ModalField>
      )}
    </Modal>
  );
}
