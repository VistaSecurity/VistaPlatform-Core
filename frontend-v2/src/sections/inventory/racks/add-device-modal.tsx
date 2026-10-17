// The rack page's "Add device" picker (DCIM row 2.5): search the site's
// unracked assets, choose the lowest unit and the face, and place it. A
// refusal because the units are taken names what holds them.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Icon, Modal, ModalField, ModalInput } from '../../../components/ui';
import { useAssetsQuery } from '../asset-queries';
import { assetIdentity, classLabel } from '../asset-shape';
import { ConflictNote } from './placement-card';
import { positionRange, snapPosition, type RackGeom } from './rack-geometry';
import {
  ALL_RACK_KEYS, PlacementConflict, placementKey, putPlacement, unitLabel, type RackFace,
} from './racks-queries';

/** The site's assets with no rack, optionally narrowed by free text. */
export function unrackedQuery(siteId: string, search: string): string {
  const term = search.trim().replace(/["\\]/g, '');
  return `site.id = "${siteId}" and not exists(rack.id)${term ? ` and "${term}"` : ''}`;
}

export function AddDeviceModal({ rack, siteId, initial, onClose }: {
  rack: RackGeom & { id: string; name: string };
  siteId: string;
  initial?: { position?: number; face?: RackFace };
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [assetId, setAssetId] = useState('');
  const [position, setPosition] = useState(initial?.position ?? rack.starting_unit);
  const [face, setFace] = useState<RackFace>(initial?.face ?? 'front');
  const assets = useAssetsQuery(unrackedQuery(siteId, search), 1);
  // The server's answer is the filter; this only drops a row whose rack the
  // list already carries, should a stale page still hold it.
  const rows = (assets.data?.assets ?? []).filter((a) => !a.rack);
  const { min, max } = positionRange(rack, 0.5);

  const save = useMutation({
    mutationFn: () => putPlacement(assetId, { rack_id: rack.id, position, face }),
    onSuccess: () => {
      for (const k of ALL_RACK_KEYS) void qc.invalidateQueries({ queryKey: k });
      void qc.invalidateQueries({ queryKey: placementKey(assetId) });
      void qc.invalidateQueries({ queryKey: ['inventory', 'assets'] });
      onClose();
    },
  });
  const conflict = save.error instanceof PlacementConflict ? save.error : null;
  const step = (d: number) => setPosition((p) => snapPosition(rack, p + d, 0.5));

  return (
    <Modal open onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending} size="md" tone="accent" icon="server"
      eyebrow={`Rack · ${rack.name}`} title="Add a device"
      description="Assets of this site that are not in a rack yet. The device takes its type's height from the unit you choose upward."
      primary={<button className="ui-btn accent" data-testid="add-device-save" disabled={!assetId || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Placing…' : 'Place device'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError && !conflict ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <ModalField label="Asset">
        <ModalInput aria-label="Search assets" placeholder="Search this site's unracked assets…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </ModalField>
      <div data-testid="add-device-list" role="listbox" aria-label="Unracked assets" style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--app-border)', borderRadius: 10, marginBottom: 12 }}>
        {assets.isLoading ? <div style={{ padding: 12, fontSize: 12.5, color: 'var(--app-t3)' }}>Loading assets…</div>
          : assets.isError ? <div role="alert" style={{ padding: 12, fontSize: 12.5, color: 'var(--danger-text)' }}>Couldn't load the site's assets.</div>
            : rows.length === 0 ? <div data-testid="add-device-empty" style={{ padding: 12, fontSize: 12.5, color: 'var(--app-t3)' }}>{search ? 'No unracked asset of this site matches.' : 'Every asset of this site is already in a rack.'}</div>
              : rows.map((a) => (
                <button key={a.id} type="button" role="option" aria-selected={assetId === a.id} data-testid="add-device-option"
                  onClick={() => setAssetId(a.id)}
                  style={{ display: 'flex', width: '100%', alignItems: 'center', gap: 8, padding: '7px 12px', border: 0, borderBottom: '1px solid var(--app-border)', textAlign: 'left', cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)', background: assetId === a.id ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent' }}>
                  <Icon name={assetId === a.id ? 'check' : 'server'} size={13} style={{ color: assetId === a.id ? 'var(--accent)' : 'var(--app-t3)' }} />
                  <span style={{ fontWeight: 600 }}>{assetIdentity(a).primary}</span>
                  <span style={{ marginLeft: 'auto', color: 'var(--app-t3)', fontSize: 11.5 }}>{classLabel(a.class_key)}</span>
                </button>
              ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Position" hint={`Lowest unit, U${min}–${unitLabel(max)}, in half units.`}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <button type="button" className="ui-btn sm" aria-label="Lower position" disabled={position <= min} onClick={() => step(-0.5)}><Icon name="minus" size={13} /></button>
            <span data-testid="add-device-position" className="mono" style={{ minWidth: 52, textAlign: 'center', fontSize: 13 }}>{unitLabel(position)}</span>
            <button type="button" className="ui-btn sm" aria-label="Raise position" disabled={position >= max} onClick={() => step(0.5)}><Icon name="plus" size={13} /></button>
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
