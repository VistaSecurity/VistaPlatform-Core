// The spares action dialogs (DCIM gap 8), shared by the Spares & RMA page and
// the asset's Hardware tab: add a spare, install a spare on an asset, remove an
// item from its asset to stock, and open an RMA case. Each is a hand-rolled
// useState form; the server holds the rules (a spare in stock installs, an
// item on an asset removes, a closed case is final) and its message is shown.
// The callers render them only behind dcim.manage.
import { useMemo, useState } from 'react';
import { useDebouncedValue } from '@vistasecurity/primitives/shared';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { useAssetsQuery } from '../asset-queries';
import type { InventoryItem } from '../dcim/hardware-queries';
import { useLocations } from '../sites/sites-queries';
import { useCreateSpare, useInstallSpare, useOpenRma, useRemoveToStock } from './spares-queries';

/** An asset's name for the picker: its display name, else hostname, else a short id. */
function assetLabel(a: { id: string; display_name?: string | null; hostname?: string | null }): string {
  if (a.display_name?.trim()) return a.display_name;
  if (a.hostname?.trim()) return a.hostname;
  return a.id.slice(0, 8);
}

const errStyle = { fontSize: 12, color: 'var(--danger-text)' } as const;

/** A stock location picker over every location of the tenant ("Site / Location"). */
export function LocationSelect({ value, onChange, label = 'Stock location', allowNone }: {
  value: string; onChange: (v: string) => void; label?: string; allowNone?: string;
}) {
  const locations = useLocations();
  const rows = [...(locations.data ?? [])].sort((a, b) => a.path.localeCompare(b.path));
  const hint = locations.isError ? 'Could not load the locations.'
    : locations.isLoading ? 'Loading…'
      : rows.length === 0 ? 'No locations yet. Add one to a site in Infrastructure → Sites & locations.' : undefined;
  return (
    <ModalField label={label} hint={hint}>
      <ModalSelect aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{allowNone ?? 'Choose a location…'}</option>
        {rows.map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}
      </ModalSelect>
    </ModalField>
  );
}

/** Location id → "Site / Location" for the tables. */
export function useLocationPaths() {
  const locations = useLocations();
  return useMemo(() => new Map((locations.data ?? []).map((l) => [l.id, l.path])), [locations.data]);
}

export function AddSpareModal({ onClose, defaultLocation = '' }: { onClose: () => void; defaultLocation?: string }) {
  const [name, setName] = useState('');
  const [part, setPart] = useState('');
  const [serial, setSerial] = useState('');
  const [qty, setQty] = useState('1');
  const [loc, setLoc] = useState(defaultLocation);
  const [reserved, setReserved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const create = useCreateSpare();
  const n = Number(qty);
  const badQty = !(Number.isInteger(n) && n >= 1) || (serial.trim() !== '' && n !== 1);
  const ok = name.trim() !== '' && loc !== '' && !badQty;
  return (
    <Modal
      open onClose={onClose} icon="package" title="Add a spare"
      description="A spare sits at a stock location until it is installed. A box of identical, unserialised parts is one row with a quantity; a serialised unit is a row of its own."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={(
        <button type="button" className="ui-btn primary" disabled={!ok || create.isPending}
          onClick={() => {
            setError(null);
            create.mutate({
              name: name.trim(), location_id: loc, quantity: n, part_id: part.trim() || null, serial: serial.trim() || null,
              stock_state: reserved ? 'reserved' : 'in_stock',
            }, { onSuccess: onClose, onError: (e) => setError(e.message) });
          }}>
          Add spare
        </button>
      )}
    >
      <div data-testid="add-spare-modal">
        <ModalField label="Name"><ModalInput aria-label="Spare name" value={name} placeholder="SFP-10G-SR" onChange={(e) => setName(e.target.value)} /></ModalField>
        <ModalField label="Part number"><ModalInput aria-label="Part number" value={part} onChange={(e) => setPart(e.target.value)} /></ModalField>
        <ModalField label="Serial" hint="Leave empty for a box of identical parts."><ModalInput aria-label="Serial" value={serial} onChange={(e) => setSerial(e.target.value)} /></ModalField>
        <ModalField label="Quantity" hint={badQty ? 'A whole number of at least 1; a serialised unit counts 1.' : undefined}>
          <ModalInput aria-label="Quantity" inputMode="numeric" value={qty} onChange={(e) => setQty(e.target.value)} />
        </ModalField>
        <LocationSelect value={loc} onChange={setLoc} />
        <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
          <input type="checkbox" aria-label="Reserved" checked={reserved} onChange={(e) => setReserved(e.target.checked)} />Reserved (set aside, not free to use)
        </label>
        {error && <div role="alert" data-testid="spare-error" style={errStyle}>{error}</div>}
      </div>
    </Modal>
  );
}

export function InstallSpareModal({ item, onClose }: { item: InventoryItem; onClose: () => void }) {
  const [search, setSearch] = useState('');
  const [picked, setPicked] = useState<{ id: string; name: string } | null>(null);
  const [name, setName] = useState(item.name);
  const [qty, setQty] = useState('1');
  const [error, setError] = useState<string | null>(null);
  const term = useDebouncedValue(search).trim();
  const results = useAssetsQuery(term ? JSON.stringify(term) : '', 1, term.length >= 2 && !picked);
  const install = useInstallSpare();
  const n = Number(qty);
  const badQty = !(Number.isInteger(n) && n >= 1 && n <= item.quantity);
  return (
    <Modal
      open onClose={onClose} icon="package" title={`Install ${item.name}`}
      description={item.quantity > 1
        ? `This row counts ${item.quantity}. The units you install become an item on the asset; the rest stay on the shelf.`
        : 'The spare becomes an item on the asset, and leaves the stock.'}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={(
        <button type="button" className="ui-btn primary" disabled={!picked || badQty || !name.trim() || install.isPending}
          onClick={() => {
            if (!picked) return;
            setError(null);
            install.mutate({ id: item.id, body: { asset_id: picked.id, name: name.trim(), quantity: n } },
              { onSuccess: onClose, onError: (e) => setError(e.message) });
          }}>
          Install
        </button>
      )}
    >
      <div data-testid="install-spare-modal">
        <ModalField label="Asset">
          <ModalInput aria-label="Search for an asset" placeholder="Search by name or hostname…" value={picked ? picked.name : search}
            onChange={(e) => { setPicked(null); setSearch(e.target.value); }} />
        </ModalField>
        {!picked && term.length >= 2 && (
          <div data-testid="spare-asset-results" style={{ marginBottom: 10, border: '1px solid var(--app-border)', borderRadius: 10, overflow: 'hidden' }}>
            {results.isLoading && <div style={{ padding: '7px 11px', fontSize: 12, color: 'var(--app-t3)' }}>Searching…</div>}
            {results.isError && <div style={{ ...errStyle, padding: '7px 11px' }}>Couldn&rsquo;t search — this is not &ldquo;no matches&rdquo;.</div>}
            {!results.isLoading && !results.isError && (results.data?.assets ?? []).length === 0 && (
              <div style={{ padding: '7px 11px', fontSize: 12, color: 'var(--app-t3)' }}>No assets match that.</div>
            )}
            {(results.data?.assets ?? []).slice(0, 8).map((a) => (
              <button key={a.id} type="button" className="ui-btn ghost sm" style={{ display: 'block', width: '100%', textAlign: 'left', borderRadius: 0 }}
                onClick={() => setPicked({ id: a.id, name: assetLabel(a) })}>
                {assetLabel(a)}
              </button>
            ))}
          </div>
        )}
        <ModalField label="Name on the asset"><ModalInput aria-label="Name on the asset" value={name} onChange={(e) => setName(e.target.value)} /></ModalField>
        {item.quantity > 1 && (
          <ModalField label="Units" hint={badQty ? `1 to ${item.quantity}.` : undefined}>
            <ModalInput aria-label="Units" inputMode="numeric" value={qty} onChange={(e) => setQty(e.target.value)} />
          </ModalField>
        )}
        {error && <div role="alert" data-testid="spare-error" style={errStyle}>{error}</div>}
      </div>
    </Modal>
  );
}

export function RemoveToStockModal({ item, assetId, onClose }: { item: InventoryItem; assetId: string; onClose: () => void }) {
  const [loc, setLoc] = useState('');
  const [reserved, setReserved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const remove = useRemoveToStock(assetId);
  return (
    <Modal
      open onClose={onClose} icon="archive" title={`Remove ${item.name} to stock`}
      description={item.serial
        ? 'The item leaves the asset and sits at the stock location as a spare.'
        : 'The item leaves the asset. A spare of the same name and part at that location takes it into its count.'}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={(
        <button type="button" className="ui-btn primary" disabled={!loc || remove.isPending}
          onClick={() => {
            setError(null);
            remove.mutate({ id: item.id, body: { location_id: loc, ...(item.stock_state === 'installed' && reserved ? { stock_state: 'reserved' as const } : {}) } },
              { onSuccess: onClose, onError: (e) => setError(e.message) });
          }}>
          Remove to stock
        </button>
      )}
    >
      <div data-testid="remove-to-stock-modal">
        <LocationSelect value={loc} onChange={setLoc} />
        {item.stock_state === 'installed' && (
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
            <input type="checkbox" aria-label="Reserved" checked={reserved} onChange={(e) => setReserved(e.target.checked)} />Reserved
          </label>
        )}
        {error && <div role="alert" data-testid="spare-error" style={errStyle}>{error}</div>}
      </div>
    </Modal>
  );
}

export function OpenRmaModal({ item, assetId, onClose }: { item: InventoryItem; assetId?: string; onClose: () => void }) {
  const [vendor, setVendor] = useState('');
  const [caseNo, setCaseNo] = useState('');
  const [notes, setNotes] = useState('');
  const [loc, setLoc] = useState('');
  const [error, setError] = useState<string | null>(null);
  const open = useOpenRma(assetId);
  const onAsset = !!item.asset_id;
  const needsLoc = onAsset && item.quantity > 1;
  return (
    <Modal
      open onClose={onClose} icon="recycle" title={`Open an RMA for ${item.name}`}
      description={onAsset
        ? 'The part is marked out for RMA. It stays in the asset until it ships unless you name a stock location it comes off to now.'
        : item.quantity > 1
          ? `One unit of the ${item.quantity} goes out for RMA; the rest stay in stock.`
          : 'The spare is marked out for RMA.'}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={(
        <button type="button" className="ui-btn primary" disabled={(needsLoc && !loc) || open.isPending}
          onClick={() => {
            setError(null);
            open.mutate({
              id: item.id,
              body: {
                ...(vendor.trim() ? { vendor: vendor.trim() } : {}), ...(caseNo.trim() ? { case_number: caseNo.trim() } : {}),
                ...(notes.trim() ? { notes: notes.trim() } : {}), ...(onAsset && loc ? { location_id: loc } : {}),
              },
            }, { onSuccess: onClose, onError: (e) => setError(e.message) });
          }}>
          Open RMA
        </button>
      )}
    >
      <div data-testid="open-rma-modal">
        <ModalField label="Vendor"><ModalInput aria-label="Vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} /></ModalField>
        <ModalField label="Case number"><ModalInput aria-label="Case number" value={caseNo} onChange={(e) => setCaseNo(e.target.value)} /></ModalField>
        <ModalField label="Notes"><ModalInput aria-label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} /></ModalField>
        {onAsset && (
          <LocationSelect value={loc} onChange={setLoc} label="Take it off the asset to"
            allowNone={needsLoc ? 'Choose a location…' : 'Leave it in the asset for now'} />
        )}
        {error && <div role="alert" data-testid="spare-error" style={errStyle}>{error}</div>}
      </div>
    </Modal>
  );
}
