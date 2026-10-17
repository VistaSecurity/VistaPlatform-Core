// Settings → Racks (DCIM row 2.3): the tenant's racks with their site,
// location, role, status and utilisation; a create/edit dialog (rack type
// picker, dimensions) whose Reservations tab lists, adds and removes the
// rack's reserved units; delete. Reads need dcim.read; every write control is
// behind dcim.manage. Row 2.5 adds the Inventory → Racks lens and the drawn
// elevation; this page is where racks are maintained until then.
import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, StateNote } from './kit';
import { ObjectChanges } from '../inventory/dcim/object-changes';
import { ObjectJournal } from '../inventory/dcim/object-journal';
import { flattenNodes, useLocations, useSites } from '../inventory/sites/sites-queries';
import { ConflictNote } from '../inventory/racks/placement-card';
import {
  ALL_RACK_KEYS, PlacementConflict, RACK_STATUSES, RACK_WIDTHS, parseUnits, placementError, unitsLabel,
  useRackReservations, useRackRoles, useRackTypes, useRacks, type Rack, type RackStatus,
} from '../inventory/racks/racks-queries';
import type { SettingsNavItem } from './nav';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

function useInvalidateRacks() {
  const qc = useQueryClient();
  return () => { for (const k of ALL_RACK_KEYS) void qc.invalidateQueries({ queryKey: k }); };
}

/** "12 / 42U · 28.6%" — a real 0 % for an empty rack, "—" before the first refresh. */
export function utilisationLabel(r: Pick<Rack, 'u_height'> & { utilization?: { used_units?: number; total_units?: number; utilization?: number } | null }): string {
  const u = r.utilization;
  if (!u || u.utilization == null) return '—';
  return `${u.used_units ?? 0} / ${u.total_units ?? r.u_height}U · ${u.utilization}%`;
}

export function RacksPage({ meta }: { meta: SettingsNavItem }) {
  const racks = useRacks();
  const sites = useSites();
  const [editing, setEditing] = useState<{ rack: Rack | null } | null>(null);
  const [deleting, setDeleting] = useState<Rack | null>(null);
  const cols = [
    { label: 'Rack' }, { label: 'Site · Location', w: '210px' }, { label: 'Role', w: '110px' }, { label: 'Status', w: '96px' },
    { label: 'Utilisation', w: '150px' }, { label: 'Devices', w: '70px', align: 'right' as const }, { label: '', w: '88px', align: 'right' as const },
  ];
  const noSites = sites.isSuccess && (sites.data ?? []).length === 0;

  return (
    <SPage
      eyebrow="Infrastructure" title="Racks" job={meta.job} maxWidth={1100}
      actions={
        <PermissionGate permission={MANAGE}>
          <button className="ui-btn sm accent" disabled={noSites} title={noSites ? 'Create a site first (Infrastructure → Sites).' : undefined}
            onClick={() => setEditing({ rack: null })}><Icon name="plus" size={14} />New rack</button>
        </PermissionGate>
      }
    >
      {racks.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load racks" message="The rack list failed to load." /></SCard>
      ) : racks.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading racks…" message="Fetching racks, their sites and utilisation." /></SCard>
      ) : (racks.data ?? []).length === 0 ? (
        <SCard><StateNote icon="server" tone="var(--app-t3)" title="No racks" message={noSites
          ? 'Racks live in a site. Create a site in Infrastructure → Sites, then add its racks here.'
          : 'No racks are defined yet. Add a rack to a site (and a row or hall inside it), then place assets in it from their Placement card.'} /></SCard>
      ) : (
        <SSection title="Racks">
          <STable cols={cols}>
            {(racks.data ?? []).map((r, i) => (
              <STableRow key={r.id} first={i === 0} cols={cols} cells={[
                <span data-testid="racks-row" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>
                  {r.name}{r.facility_id ? <span style={{ fontWeight: 400, color: 'var(--app-t3)' }}> · {r.facility_id}</span> : null}
                </span>,
                <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>
                  {r.site ? <Link to={`/inventory/sites/${r.site.id}`}>{r.site.name}</Link> : '—'}{r.location ? ` › ${r.location.name}` : ''}
                </span>,
                r.role ? <STag>{r.role.name}</STag> : <span style={{ color: 'var(--app-t3)' }}>—</span>,
                <STag>{r.operational_status}</STag>,
                <span data-testid="racks-utilisation" className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{utilisationLabel(r)}</span>,
                <span className="mono" style={{ fontSize: 12 }}>{r.device_count ?? 0}</span>,
                <PermissionGate permission={MANAGE} fallback={<span />}>
                  <span style={{ display: 'inline-flex', justifyContent: 'flex-end', gap: 6 }}>
                    <button className="ui-btn sm ghost" aria-label={`Edit ${r.name}`} title="Edit" onClick={() => setEditing({ rack: r })}><Icon name="sliders-horizontal" size={13} /></button>
                    <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} aria-label={`Delete ${r.name}`} title="Delete" onClick={() => setDeleting(r)}><Icon name="x" size={13} /></button>
                  </span>
                </PermissionGate>,
              ]} />
            ))}
          </STable>
        </SSection>
      )}
      {editing && <RackModal key={editing.rack?.id ?? 'new-rack'} rack={editing.rack} onClose={() => setEditing(null)} />}
      {deleting && <DeleteRackModal rack={deleting} onClose={() => setDeleting(null)} />}
    </SPage>
  );
}

const orNull = (s: string) => (s.trim() ? s.trim() : null);

export function RackModal({ rack, onClose }: { rack: Rack | null; onClose: () => void }) {
  const invalidate = useInvalidateRacks();
  const isEdit = !!rack;
  const [tab, setTab] = useState<'details' | 'reservations' | 'history'>('details');
  const [name, setName] = useState(rack?.name ?? '');
  const [siteId, setSiteId] = useState(rack?.site_id ?? '');
  const [locationId, setLocationId] = useState(rack?.location_id ?? '');
  const [roleId, setRoleId] = useState(rack?.role_id ?? '');
  const [typeId, setTypeId] = useState(rack?.rack_type_id ?? '');
  const [status, setStatus] = useState<RackStatus>(rack?.operational_status ?? 'active');
  const [uHeight, setUHeight] = useState(String(rack?.u_height ?? 42));
  const [startingUnit, setStartingUnit] = useState(String(rack?.starting_unit ?? 1));
  const [width, setWidth] = useState(String(rack?.width ?? 19));
  const [descUnits, setDescUnits] = useState(rack?.desc_units ?? false);
  const [facilityId, setFacilityId] = useState(rack?.facility_id ?? '');
  const [serial, setSerial] = useState(rack?.serial ?? '');
  const [assetTag, setAssetTag] = useState(rack?.asset_tag ?? '');
  const [description, setDescription] = useState(rack?.description ?? '');
  const sites = useSites();
  const locations = useLocations(siteId || undefined, !!siteId);
  const roles = useRackRoles();
  const types = useRackTypes();
  const h = Number(uHeight); const s = Number(startingUnit);
  const dimsOk = Number.isInteger(h) && h >= 1 && h <= 100 && Number.isInteger(s) && s >= 1;
  const typeChanged = !!typeId && typeId !== (rack?.rack_type_id ?? '');

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(), site_id: siteId, location_id: locationId || null, role_id: roleId || null,
        rack_type_id: typeId || null, operational_status: status,
        // A newly chosen rack type supplies the dimensions (the server copies them).
        ...(typeChanged ? {} : { u_height: h, starting_unit: s, width: Number(width) as Rack['width'], desc_units: descUnits }),
        facility_id: orNull(facilityId), serial: orNull(serial), asset_tag: orNull(assetTag), description: orNull(description),
      };
      const res = isEdit
        ? await clients.inventory.PATCH('/dcim/racks/{id}', { params: { path: { id: rack.id } }, body })
        : await clients.inventory.POST('/dcim/racks', { body });
      if (res.error) throw placementError(res.error, 'Failed to save the rack');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });

  const valid = name.trim().length > 0 && siteId !== '' && dimsOk;
  const tabs = isEdit ? (['details', 'reservations', 'history'] as const) : (['details'] as const);
  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="lg" tone="accent" icon="server" eyebrow="Infrastructure · Racks"
      title={isEdit ? `Edit ${rack.name}` : 'New rack'}
      description="A rack is a frame of numbered units in a site — optionally in a row, hall or cage inside it."
      primary={tab === 'details'
        ? <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create rack'}</button>
        : undefined}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>{tab === 'details' ? 'Cancel' : 'Close'}</button>}
      footerNote={save.isError && tab === 'details' ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      {tabs.length > 1 && (
        <div role="tablist" style={{ display: 'flex', gap: 4, marginBottom: 12 }}>
          {tabs.map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} className={`ui-btn sm${tab === t ? ' accent' : ' ghost'}`} onClick={() => setTab(t)}>
              {t === 'details' ? 'Details' : t === 'reservations' ? 'Reservations' : 'Changes'}
            </button>
          ))}
        </div>
      )}
      {tab === 'details' && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
            <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. R12" /></ModalField>
            <ModalField label="Facility ID" hint="The facility's own label for it."><ModalInput aria-label="Facility ID" value={facilityId} onChange={(e) => setFacilityId(e.target.value)} placeholder="Optional" /></ModalField>
            <ModalField label="Site">
              <ModalSelect aria-label="Site" value={siteId} onChange={(e) => { setSiteId(e.target.value); setLocationId(''); }}>
                <option value="">Choose a site…</option>
                {(sites.data ?? []).map((st) => <option key={st.id} value={st.id}>{st.name}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Location" hint="Optional — the row, hall or cage.">
              <ModalSelect aria-label="Location" value={locationId} disabled={!siteId} onChange={(e) => setLocationId(e.target.value)}>
                <option value="">None (directly in the site)</option>
                {flattenNodes(locations.data ?? []).map(({ node, depth }) => <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}`}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Role">
              <ModalSelect aria-label="Role" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
                <option value="">None</option>
                {(roles.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Status">
              <ModalSelect aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as RackStatus)}>
                {RACK_STATUSES.map((st) => <option key={st.value} value={st.value}>{st.label}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Rack type" hint={typeChanged ? 'Its height, numbering and width replace the ones below when you save.' : 'Optional — a model whose dimensions the rack copies.'}>
              <ModalSelect aria-label="Rack type" value={typeId} onChange={(e) => setTypeId(e.target.value)}>
                <option value="">None</option>
                {(types.data ?? []).map((t) => <option key={t.id} value={t.id}>{`${t.manufacturer?.name ? `${t.manufacturer.name} ` : ''}${t.model} (${t.u_height}U)`}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Width">
              <ModalSelect aria-label="Width" value={width} disabled={typeChanged} onChange={(e) => setWidth(e.target.value)}>
                {RACK_WIDTHS.map((w) => <option key={w} value={String(w)}>{`${w} in`}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Height (U)"><ModalInput aria-label="Height (U)" inputMode="numeric" value={uHeight} disabled={typeChanged} onChange={(e) => setUHeight(e.target.value)} /></ModalField>
            <ModalField label="Starting unit"><ModalInput aria-label="Starting unit" inputMode="numeric" value={startingUnit} disabled={typeChanged} onChange={(e) => setStartingUnit(e.target.value)} /></ModalField>
            <ModalField label="Serial"><ModalInput aria-label="Serial" value={serial} onChange={(e) => setSerial(e.target.value)} placeholder="Optional" /></ModalField>
            <ModalField label="Asset tag"><ModalInput aria-label="Asset tag" value={assetTag} onChange={(e) => setAssetTag(e.target.value)} placeholder="Optional" /></ModalField>
          </div>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, margin: '2px 0 10px' }}>
            <input type="checkbox" aria-label="Number units top-down" checked={descUnits} disabled={typeChanged} onChange={(e) => setDescUnits(e.target.checked)} />
            Number units top-down
          </label>
          <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
          {!dimsOk && <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Height is 1–100 whole units and the starting unit at least 1.</div>}
        </>
      )}
      {tab === 'reservations' && isEdit && <ReservationsTab rack={rack} />}
      {tab === 'history' && isEdit && (
        <div data-testid="racks-history">
          <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Changes</div>
          <ObjectChanges kind="rack" id={rack.id} />
          <div className="eyebrow-app" style={{ margin: '14px 0 8px' }}>Journal</div>
          <ObjectJournal kind="rack" id={rack.id} />
        </div>
      )}
    </Modal>
  );
}

/** The rack's reservations: list, add (units as "1-2, 7"), remove. */
export function ReservationsTab({ rack }: { rack: Rack }) {
  const q = useRackReservations(rack.id);
  const invalidate = useInvalidateRacks();
  const [units, setUnits] = useState('');
  const [description, setDescription] = useState('');
  const parsed = parseUnits(units);
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.POST('/dcim/rack-reservations', {
        body: { rack_id: rack.id, units: parsed ?? [], description: description.trim() },
      });
      if (error) throw placementError(error, 'Could not reserve those units');
    },
    onSuccess: () => { invalidate(); setUnits(''); setDescription(''); },
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.inventory.DELETE('/dcim/rack-reservations/{id}', { params: { path: { id } } });
      if (error) throw new Error('Could not remove the reservation');
    },
    onSuccess: () => invalidate(),
  });
  const conflict = add.error instanceof PlacementConflict ? add.error : null;

  let list;
  if (q.isLoading) list = <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Loading reservations…</div>;
  else if (q.isError) list = <div style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>Couldn't load the reservations.</div>;
  else if ((q.data ?? []).length === 0) list = <div data-testid="reservations-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>No units of {rack.name} are reserved.</div>;
  else list = (
    <div>
      {(q.data ?? []).map((r) => (
        <div key={r.id} data-testid="reservation-row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--app-line)' }}>
          <span className="mono" style={{ fontSize: 12, minWidth: 110 }}>{unitsLabel(r.units)}</span>
          <span style={{ fontSize: 12.5, flex: 1 }}>{r.description}</span>
          <PermissionGate permission={MANAGE} fallback={null}>
            <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} aria-label={`Remove reservation ${unitsLabel(r.units)}`} disabled={remove.isPending} onClick={() => remove.mutate(r.id)}>
              <Icon name="x" size={13} />
            </button>
          </PermissionGate>
        </div>
      ))}
    </div>
  );
  return (
    <div data-testid="reservations-tab">
      {list}
      <PermissionGate permission={MANAGE} fallback={null}>
        <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr auto', gap: 10, alignItems: 'end', marginTop: 12 }}>
          <ModalField label="Units" hint="e.g. 1-2, 7"><ModalInput aria-label="Units" value={units} onChange={(e) => setUnits(e.target.value)} /></ModalField>
          <ModalField label="For"><ModalInput aria-label="Reservation description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. Future PDU" /></ModalField>
          <button className="ui-btn accent" style={{ marginBottom: 12 }} disabled={!parsed || !description.trim() || add.isPending} onClick={() => add.mutate()}>Reserve</button>
        </div>
        {units.trim() !== '' && !parsed && <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Write units as numbers and ranges: 1-2, 7.</div>}
        {conflict ? <ConflictNote conflict={conflict} /> : add.isError && <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>{add.error.message}</div>}
      </PermissionGate>
    </div>
  );
}

export function DeleteRackModal({ rack, onClose }: { rack: Rack; onClose: () => void }) {
  const invalidate = useInvalidateRacks();
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.DELETE('/dcim/racks/{id}', { params: { path: { id: rack.id } } });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: () => { invalidate(); onClose(); },
  });
  const n = rack.device_count ?? 0;
  return (
    <Modal open onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending} size="sm" tone="danger" icon="octagon-alert" eyebrow="Infrastructure · Racks"
      title="Delete rack?"
      description={`“${rack.name}” and its reservations will be removed.${n > 0 ? ` Its ${n} device${n === 1 ? '' : 's'} leave the rack and stay in the site.` : ''}`}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error.message}</span> : undefined}
    />
  );
}
