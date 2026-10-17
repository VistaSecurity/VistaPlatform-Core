// The asset page's Placement card (DCIM row 2.3): Site › Location › Rack ›
// U · Face, from GET /dcim/assets/{id}/placement. A manager edits it in a
// modal with cascading Site → Location → Rack selects, a half-U position
// stepper and a Front/Rear toggle; a refusal because the units are taken names
// the asset (or reservation) in the way, linking to that asset. Reads need
// dcim.read, writes dcim.manage. Row 2.5 draws the elevation itself.
import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../../lib/clients';
import { Icon, MetaRow, Modal, ModalField, ModalSelect, SectionLabel } from '../../../components/ui';
import { useLocations, useSites, flattenNodes } from '../sites/sites-queries';
import {
  ALL_RACK_KEYS, PlacementConflict, placementError, placementKey, placementLabel, unitLabel, unitsLabel, useAssetPlacement, useRacks,
  type AssetPlacement, type RackFace,
} from './racks-queries';

const READ = TENANT_PERMISSIONS.dcim.read;
const MANAGE = TENANT_PERMISSIONS.dcim.manage;

export function PlacementCard({ assetId }: { assetId: string }) {
  return (
    <div data-testid="placement-card">
      <SectionLabel icon="server">Placement</SectionLabel>
      <PermissionGate permission={READ} fallback={
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '6px 0' }}>Rack placement needs the data-centre read permission.</div>
      }>
        <PlacementBody assetId={assetId} />
      </PermissionGate>
    </div>
  );
}

function PlacementBody({ assetId }: { assetId: string }) {
  const q = useAssetPlacement(assetId);
  const [editing, setEditing] = useState(false);
  const qc = useQueryClient();
  const unplace = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.DELETE('/dcim/assets/{id}/placement', { params: { path: { id: assetId } } });
      if (error) throw placementError(error, 'Could not take the asset out of its rack');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: placementKey(assetId) });
      for (const k of ALL_RACK_KEYS) void qc.invalidateQueries({ queryKey: k });
    },
  });

  if (q.isLoading) {
    return <div data-testid="placement-loading" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '6px 0' }}>Loading placement…</div>;
  }
  if (q.isError || !q.data) {
    return (
      <div data-testid="placement-error" style={{ fontSize: 12.5, color: 'var(--danger-text)', padding: '6px 0' }}>
        Couldn't load the placement. <button className="ui-btn sm ghost" onClick={() => { void q.refetch(); }}>Retry</button>
      </div>
    );
  }
  const p = q.data;
  const racked = !!p.rack && p.position != null;
  return (
    <>
      {p.is_child ? (
        <div data-testid="placement-child" style={{ fontSize: 12.5, color: 'var(--app-t2)', padding: '6px 0' }}>
          In a parent device's bay — it takes no rack units of its own.
        </div>
      ) : racked ? (
        <div data-testid="placement-placed">
          <div style={{ fontSize: 13, color: 'var(--app-t1)', fontWeight: 600, padding: '4px 0 6px' }}>{placementLabel(p)}</div>
          <MetaRow k="Height" v={`${p.u_height}U${p.has_device_type ? '' : ' (no device type: 1U assumed)'}`} />
          <MetaRow k="Depth" v={p.is_full_depth ? 'Full depth (both faces)' : 'Half depth'} />
          <Link to={`/inventory/racks/${p.rack!.id}?asset=${assetId}`} data-testid="placement-open-rack" className="ui-btn sm" style={{ marginTop: 8 }}>
            <Icon name="server" size={13} />Open rack
          </Link>
        </div>
      ) : (
        <div data-testid="placement-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '6px 0', lineHeight: 1.55 }}>
          Not in a rack{p.site ? ` (site: ${placementLabel(p)})` : ''}. Place it to record which units it takes.
        </div>
      )}
      {!p.is_child && (
        <PermissionGate permission={MANAGE} fallback={null}>
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            <button className="ui-btn sm" onClick={() => setEditing(true)}>
              <Icon name="sliders-horizontal" size={13} />{racked ? 'Edit placement' : 'Place in a rack'}
            </button>
            {racked && (
              <button className="ui-btn sm ghost" disabled={unplace.isPending} onClick={() => unplace.mutate()}>Remove from rack</button>
            )}
          </div>
          {unplace.isError && <div style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 4 }}>{unplace.error.message}</div>}
        </PermissionGate>
      )}
      {editing && <PlacementModal assetId={assetId} placement={p} onClose={() => setEditing(false)} />}
    </>
  );
}

const HALF = 0.5;

export function PlacementModal({ assetId, placement, onClose }: { assetId: string; placement: AssetPlacement; onClose: () => void }) {
  const qc = useQueryClient();
  const [siteId, setSiteId] = useState(placement.site?.id ?? '');
  const [locationId, setLocationId] = useState(placement.location?.id ?? '');
  const [rackId, setRackId] = useState(placement.rack?.id ?? '');
  const [position, setPosition] = useState<number>(placement.position ?? 1);
  const [face, setFace] = useState<RackFace>(placement.face ?? 'front');
  const sites = useSites();
  const locations = useLocations(siteId || undefined, !!siteId);
  const racks = useRacks({ siteId: siteId || undefined }, !!siteId);
  // A rack in the chosen location, or any rack of the site when no location
  // is chosen (the asset then takes the rack's location).
  const rackChoices = (racks.data ?? []).filter((r) => !locationId || r.location_id === locationId);
  const rack = rackChoices.find((r) => r.id === rackId);
  const top = rack ? rack.starting_unit + rack.u_height - Math.max(placement.u_height, HALF) : position;
  const bottom = rack ? rack.starting_unit : 1;
  const inRange = !!rack && position >= bottom && position <= top;

  const save = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.PUT('/dcim/assets/{id}/placement', {
        params: { path: { id: assetId } }, body: { rack_id: rackId, position, face },
      });
      if (error) throw placementError(error, 'Could not place the asset');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: placementKey(assetId) });
      void qc.invalidateQueries({ queryKey: ['asset-detail', assetId] });
      for (const k of ALL_RACK_KEYS) void qc.invalidateQueries({ queryKey: k });
      onClose();
    },
  });
  const step = (d: number) => setPosition((p) => Math.min(Math.max(p + d, bottom), Math.max(top, bottom)));
  const conflict = save.error instanceof PlacementConflict ? save.error : null;

  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="md" tone="accent" icon="server"
      eyebrow="Asset · Placement" title={placement.rack ? 'Edit placement' : 'Place in a rack'}
      description={`The asset takes ${placement.u_height}U from the position you choose upward${placement.is_full_depth ? ', on both faces (full depth)' : ''}. It moves to the rack's site and location.`}
      primary={<button className="ui-btn accent" disabled={!inRange || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save placement'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError && !conflict ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <ModalField label="Site">
        <ModalSelect aria-label="Site" value={siteId} onChange={(e) => { setSiteId(e.target.value); setLocationId(''); setRackId(''); }}>
          <option value="">Choose a site…</option>
          {(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Location" hint="Optional — narrows the racks.">
        <ModalSelect aria-label="Location" value={locationId} disabled={!siteId} onChange={(e) => { setLocationId(e.target.value); setRackId(''); }}>
          <option value="">Any location</option>
          {flattenNodes(locations.data ?? []).map(({ node, depth }) => <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}`}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Rack" hint={siteId && racks.isSuccess && rackChoices.length === 0 ? 'No racks here yet — add one from Infrastructure → Racks.' : undefined}>
        <ModalSelect aria-label="Rack" value={rackId} disabled={!siteId} onChange={(e) => setRackId(e.target.value)}>
          <option value="">Choose a rack…</option>
          {rackChoices.map((r) => <option key={r.id} value={r.id}>{`${r.name} (${r.u_height}U)`}</option>)}
        </ModalSelect>
      </ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Position" hint={rack ? `Lowest unit, U${bottom}–${unitLabel(top)}, in half units.` : 'Choose a rack first.'}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <button type="button" className="ui-btn sm" aria-label="Lower position" disabled={!rack || position <= bottom} onClick={() => step(-HALF)}><Icon name="minus" size={13} /></button>
            <span data-testid="placement-position" className="mono" style={{ minWidth: 52, textAlign: 'center', fontSize: 13 }}>{unitLabel(position)}</span>
            <button type="button" className="ui-btn sm" aria-label="Raise position" disabled={!rack || position >= top} onClick={() => step(HALF)}><Icon name="plus" size={13} /></button>
          </span>
        </ModalField>
        <ModalField label="Face">
          <span role="group" aria-label="Face" style={{ display: 'inline-flex', gap: 4 }}>
            {(['front', 'rear'] as const).map((f) => (
              <button key={f} type="button" className={`ui-btn sm${face === f ? ' accent' : ''}`} aria-pressed={face === f} onClick={() => setFace(f)}>
                {f === 'front' ? 'Front' : 'Rear'}
              </button>
            ))}
          </span>
        </ModalField>
      </div>
      {conflict && <ConflictNote conflict={conflict} />}
    </Modal>
  );
}

/** The refusal, naming what holds the units. */
export function ConflictNote({ conflict }: { conflict: PlacementConflict }) {
  const a = conflict.blockingAsset;
  const r = conflict.blockingReservation;
  return (
    <div data-testid="placement-conflict" role="alert" style={{ marginTop: 8, padding: '9px 12px', borderRadius: 10, border: '1px solid var(--danger)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)', fontSize: 12.5, color: 'var(--app-t1)', lineHeight: 1.55 }}>
      <Icon name="alert-triangle" size={13} style={{ color: 'var(--danger-text)', marginRight: 6, verticalAlign: -2 }} />
      {a ? (
        <>Those units are taken by <Link to={`/inventory/assets/${a.id}`} data-testid="placement-conflict-asset">{a.name}</Link> ({unitLabel(a.position)}, {a.face}, {a.u_height}U).</>
      ) : r ? (
        <>Those units are reserved: {r.description} ({unitsLabel(r.units)}).</>
      ) : conflict.message}
    </div>
  );
}
