// The multi-select surface of Inventory → All assets and Stale: the
// checkbox column's boxes, the "Select all N matching" banner, the bulk action
// bar and its dialogs, and the feed of scans started from it.
//
// Every action goes to the server as a SELECTION (asset-selection.ts): ticked
// rows, or a query plus the count the person confirmed. A control the person
// lacks the permission for is not rendered — the server checks again.
import { useCallback, useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { Asset, inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { downloadCsv } from '../findings/export-csv';
import { ASSET_CSV_HEADER, assetCsvRow } from './asset-csv';
import { ActiveScanJobsPanel, type SkippedAsset, type StartedScan } from '../discovery/active-scan-jobs-panel';
import type { ActiveScanResponse } from '../discovery/active-scan-run-from';
import { assetIdentity } from './asset-shape';
import {
  MAX_BULK, assetsLabel, offerSelectAll, overCapReason, pageState, selectAllMatching, selectedCount,
  selectionBody, selectionRefusal, type AssetSelection,
} from './asset-selection';
import { ScanDialog } from './scan-dialog';

type BulkResult = inventoryComponents['schemas']['BulkAssetActionResult'];
type BulkChanges = inventoryComponents['schemas']['BulkAssetChanges'];
type LifecycleAction = 'archive' | 'restore' | 'delete';

// ---- checkboxes ------------------------------------------------------------

/** A checkbox that can show "some". Clicks never reach the row underneath,
 *  whose own click opens the asset drawer. */
export function SelectBox({ state, onChange, label }: {
  state: 'none' | 'some' | 'all';
  onChange: () => void;
  label: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (ref.current) ref.current.indeterminate = state === 'some'; }, [state]);
  return (
    <input
      ref={ref}
      type="checkbox"
      aria-label={label}
      checked={state === 'all'}
      onChange={onChange}
      onClick={(e) => e.stopPropagation()}
      style={{ width: 15, height: 15, margin: 0, cursor: 'pointer', accentColor: 'var(--accent)' }}
    />
  );
}

/** Gmail's banner: the page is ticked, offer the rest; everything is
 *  selected, say so and offer to clear. */
export function SelectAllBanner({ selection, pageIds, total, query, queryable, onChange }: {
  selection: AssetSelection;
  pageIds: readonly string[];
  total: number;
  query: string;
  /** False where the rows on screen are not exactly what a query names. */
  queryable: boolean;
  onChange: (s: AssetSelection) => void;
}) {
  const style = { display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, padding: '7px 16px', fontSize: 12.5, color: 'var(--app-t2)', background: 'color-mix(in srgb, var(--accent) 7%, transparent)', borderBottom: '1px solid var(--app-border)' } as const;
  if (selection.kind === 'query') {
    return (
      <div role="status" style={style}>
        All <strong>{assetsLabel(selection.count)}</strong> matching this query are selected.
        <button className="ui-btn sm ghost" onClick={() => onChange({ kind: 'none' })} style={{ height: 24 }}>Clear selection</button>
      </div>
    );
  }
  if (!offerSelectAll(selection, pageIds, total, queryable)) return null;
  return (
    <div role="status" style={style}>
      All {assetsLabel(pageIds.length)} on this page are selected.
      <button className="ui-btn sm ghost" onClick={() => onChange(selectAllMatching(query, total))} style={{ height: 24, color: 'var(--accent)', fontWeight: 600 }}>
        Select all {assetsLabel(total)} matching
      </button>
    </div>
  );
}

export { pageState };

// ---- the scan feed ---------------------------------------------------------

/** The scans started from a lens, and the assets they did not reach. */
export function useScanFeed(nameOf?: (id: string) => string | undefined) {
  const [scans, setScans] = useState<StartedScan[]>([]);
  const [skipped, setSkipped] = useState<SkippedAsset[]>([]);
  const record = useCallback((r: ActiveScanResponse) => {
    const at = new Date().toISOString();
    setScans((prev) => [
      ...(r.jobs ?? []).map((j) => ({ jobId: j.job_id, executor: j.executor, sensorName: j.sensor_name, count: j.count, startedAt: at })),
      ...prev,
    ].slice(0, 20));
    setSkipped((r.skipped ?? []).map((s) => ({ assetId: s.asset_id, reason: s.reason, assetName: nameOf?.(s.asset_id) })));
  }, [nameOf]);
  const clear = useCallback(() => { setScans([]); setSkipped([]); }, []);
  return { scans, skipped, record, clear };
}

// ---- export ----------------------------------------------------------------

const EXPORT_PAGE = 100; // the API's page-size ceiling

/** Every asset in the selection, for the CSV. A query selection is read page
 *  by page through the same list endpoint the lens shows. */
export async function selectionRows(sel: AssetSelection, seen: ReadonlyMap<string, Asset>): Promise<Asset[]> {
  if (sel.kind === 'ids') return Array.from(sel.ids).map((id) => seen.get(id)).filter((a): a is Asset => !!a);
  if (sel.kind !== 'query') return [];
  const out: Asset[] = [];
  for (let page = 1; out.length < Math.min(sel.count, MAX_BULK); page++) {
    const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
      params: { query: { ...(sel.query ? { query: sel.query } : {}), page, page_size: EXPORT_PAGE } },
    });
    if (error || !data) throw new Error('Failed to read the selected assets');
    out.push(...data.assets);
    if (data.assets.length < EXPORT_PAGE) break;
  }
  return out;
}

// ---- the bar ---------------------------------------------------------------

const LIFECYCLE: Record<LifecycleAction, { verb: string; done: string; icon: string; tone: 'accent' | 'danger'; text: string }> = {
  archive: {
    verb: 'Archive', done: 'archived', icon: 'archive', tone: 'danger',
    text: 'Archived assets drop out of active inventory and reporting. Discovery can resurface them, and you can restore them.',
  },
  restore: {
    verb: 'Restore', done: 'restored', icon: 'recycle', tone: 'accent',
    text: 'Archived assets in the selection return to active inventory. One that stays unseen past your lifecycle policy is archived again. Assets that are not archived are left as they are.',
  },
  delete: {
    verb: 'Delete', done: 'deleted', icon: 'x-circle', tone: 'danger',
    text: 'The assets are soft-deleted and leave inventory. Each can be restored later from its own page.',
  },
};

function outcome(r: BulkResult, done: string): string {
  const unchanged = r.unchanged > 0 ? `; ${r.unchanged.toLocaleString()} already ${done} or not changed` : '';
  return `${assetsLabel(r.changed)} ${done}${unchanged}`;
}

function useBulkAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ action, sel, changes }: { action: LifecycleAction | 'update'; sel: AssetSelection; changes?: BulkChanges }) => {
      const body = { ...selectionBody(sel), ...(changes ? { changes } : {}) };
      const path = `/infrastructure-assets/bulk-actions/${action}` as const;
      const { data, error, response } = await clients.inventory.POST(path, { body: body as never });
      if (error || !data) {
        const refusal = selectionRefusal(response.status, error);
        if (refusal) throw new Error(refusal);
        const e = error as { error?: string; details?: string } | undefined;
        throw new Error(e?.details ?? e?.error ?? `Failed (${response.status})`);
      }
      return data;
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['inventory'] });
      void qc.invalidateQueries({ queryKey: ['asset-detail'] });
    },
  });
}

export function BulkActionBar({ selection, onChange, seen, onScanStarted }: {
  selection: AssetSelection;
  onChange: (s: AssetSelection) => void;
  /** Rows the lens has shown, for exporting ticked rows. */
  seen: ReadonlyMap<string, Asset>;
  onScanStarted: (r: ActiveScanResponse) => void;
}) {
  const n = selectedCount(selection);
  const [scanOpen, setScanOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [lifecycle, setLifecycle] = useState<LifecycleAction | null>(null);
  const [exporting, setExporting] = useState(false);
  const bulk = useBulkAction();
  const overCap = overCapReason(selection, 'update');
  if (n === 0) return null;
  const busy = bulk.isPending || exporting;

  const runLifecycle = (action: LifecycleAction) => {
    bulk.mutate({ action, sel: selection }, {
      onSuccess: (r) => { toast.success(outcome(r, LIFECYCLE[action].done)); setLifecycle(null); onChange({ kind: 'none' }); },
    });
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const rows = await selectionRows(selection, seen);
      downloadCsv(`vista-inventory-selection-${new Date().toISOString().slice(0, 10)}.csv`, ASSET_CSV_HEADER, rows.map(assetCsvRow));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const btn = { height: 28, padding: '0 10px', fontSize: 12 } as const;
  return (
    <>
      <div role="toolbar" aria-label="Bulk actions" style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', margin: '0 26px 10px', padding: '7px 12px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--accent) 35%, transparent)', background: 'color-mix(in srgb, var(--accent) 7%, transparent)' }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{assetsLabel(n)} selected</span>
        <div style={{ flex: 1 }} />
        <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
          <button className="ui-btn sm accent" disabled={busy} onClick={() => setScanOpen(true)} style={btn}><Icon name="radar" size={13} />Scan</button>
          <button className="ui-btn sm" disabled={busy || overCap !== null} title={overCap ?? 'Set owner, environment, business unit, support group or tags'} onClick={() => setEditOpen(true)} style={btn}><Icon name="sliders-horizontal" size={13} />Edit</button>
          <button className="ui-btn sm" disabled={busy || overCap !== null} title={overCap ?? 'Archive the selected assets'} onClick={() => setLifecycle('archive')} style={btn}><Icon name="archive" size={13} />Archive</button>
          <button className="ui-btn sm" disabled={busy || overCap !== null} title={overCap ?? 'Return archived assets in the selection to active inventory'} onClick={() => setLifecycle('restore')} style={btn}><Icon name="recycle" size={13} />Restore</button>
        </PermissionGate>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.delete}>
          <button className="ui-btn sm" disabled={busy || overCap !== null} title={overCap ?? 'Delete the selected assets'} onClick={() => setLifecycle('delete')} style={{ ...btn, color: 'var(--danger-text)' }}><Icon name="x-circle" size={13} />Delete</button>
        </PermissionGate>
        <button className="ui-btn sm" disabled={busy || overCap !== null} title={overCap ?? 'Download the selected assets as CSV'} onClick={() => { void exportCsv(); }} style={btn}>
          <Icon name="download" size={13} />{exporting ? 'Exporting…' : 'Export'}
        </button>
        <button className="ui-btn sm ghost" disabled={busy} onClick={() => onChange({ kind: 'none' })} style={btn}>Clear</button>
      </div>

      {scanOpen && (
        <ScanDialog
          open={scanOpen}
          selection={selection}
          onClose={() => setScanOpen(false)}
          onStarted={(r) => { onScanStarted(r); onChange({ kind: 'none' }); }}
        />
      )}
      {editOpen && (
        <EditFieldsDialog
          count={n}
          busy={bulk.isPending}
          error={bulk.isError ? (bulk.error).message : null}
          onClose={() => { setEditOpen(false); bulk.reset(); }}
          onApply={(changes) => bulk.mutate({ action: 'update', sel: selection, changes }, {
            onSuccess: (r) => { toast.success(`${assetsLabel(r.changed)} updated${r.unchanged ? `; ${r.unchanged.toLocaleString()} already had these values` : ''}`); setEditOpen(false); onChange({ kind: 'none' }); },
          })}
        />
      )}
      {lifecycle && (
        <Modal
          open
          onClose={bulk.isPending ? undefined : () => { setLifecycle(null); bulk.reset(); }}
          dismissible={!bulk.isPending}
          size="sm"
          tone={LIFECYCLE[lifecycle].tone}
          icon={LIFECYCLE[lifecycle].icon}
          eyebrow="Inventory"
          title={`${LIFECYCLE[lifecycle].verb} ${assetsLabel(n)}?`}
          description={LIFECYCLE[lifecycle].text}
          primary={
            <button
              className="ui-btn"
              style={LIFECYCLE[lifecycle].tone === 'danger' ? { background: 'var(--danger)', color: '#1a0707', fontWeight: 600 } : undefined}
              disabled={bulk.isPending}
              onClick={() => runLifecycle(lifecycle)}
            >
              {bulk.isPending ? 'Working…' : `${LIFECYCLE[lifecycle].verb} ${assetsLabel(n)}`}
            </button>
          }
          secondary={<button className="ui-btn" disabled={bulk.isPending} onClick={() => { setLifecycle(null); bulk.reset(); }}>Cancel</button>}
          footerNote={bulk.isError ? <span style={{ color: 'var(--danger-text)' }}>{(bulk.error).message}</span> : undefined}
        />
      )}
    </>
  );
}

// ---- edit fields -----------------------------------------------------------

type FieldMode = 'keep' | 'set' | 'clear';
const TEXT_FIELDS = [
  { key: 'owner_email', label: 'Owner email', placeholder: 'owner@example.com' },
  { key: 'business_unit', label: 'Business unit', placeholder: 'Payments' },
  { key: 'support_group', label: 'Support group', placeholder: 'Network Ops' },
] as const;
const ENVIRONMENTS = ['production', 'staging', 'development', 'test'] as const;

/** "zone=dmz, team=payments" → { zone: 'dmz', team: 'payments' }; a bare
 *  name is a tag with an empty value. */
export function parseTagPairs(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of text.split(',')) {
    const [k, ...v] = part.split('=');
    const key = k.trim();
    if (key) out[key] = v.join('=').trim();
  }
  return out;
}

/** The edit form's state → the API's changes, or null when it changes nothing. */
export function buildChanges(modes: Record<string, FieldMode>, values: Record<string, string>, addTags: string, removeTags: string): BulkChanges | null {
  const ch: Record<string, unknown> = {};
  for (const key of ['owner_email', 'business_unit', 'support_group', 'environment']) {
    if (modes[key] === 'clear') ch[key] = '';
    else if (modes[key] === 'set' && (values[key] ?? '').trim()) ch[key] = values[key].trim();
  }
  const add = parseTagPairs(addTags);
  if (Object.keys(add).length) ch.add_tags = add;
  const remove = removeTags.split(',').map((s) => s.trim()).filter(Boolean);
  if (remove.length) ch.remove_tags = remove;
  return Object.keys(ch).length ? (ch) : null;
}

function EditFieldsDialog({ count, busy, error, onClose, onApply }: {
  count: number;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onApply: (c: BulkChanges) => void;
}) {
  const [modes, setModes] = useState<Record<string, FieldMode>>({});
  const [values, setValues] = useState<Record<string, string>>({});
  const [addTags, setAddTags] = useState('');
  const [removeTags, setRemoveTags] = useState('');
  const changes = buildChanges(modes, values, addTags, removeTags);
  const mode = (k: string) => modes[k] ?? 'keep';
  const modeSelect = (k: string, label: string) => (
    <ModalSelect aria-label={`${label}: change`} value={mode(k)} onChange={(e) => setModes((m) => ({ ...m, [k]: e.target.value as FieldMode }))} style={{ width: 130, flex: 'none' }}>
      <option value="keep">Leave as is</option>
      <option value="set">Set to</option>
      <option value="clear">Clear</option>
    </ModalSelect>
  );
  return (
    <Modal
      open
      onClose={busy ? undefined : onClose}
      dismissible={!busy}
      size="md"
      icon="sliders-horizontal"
      eyebrow="Inventory"
      title={`Edit ${assetsLabel(count)}`}
      description="Each change applies to every selected asset and is recorded in its history under your name. Fields left as they are stay untouched."
      primary={<button className="ui-btn accent" disabled={busy || changes === null} onClick={() => changes && onApply(changes)}>{busy ? 'Applying…' : `Apply to ${assetsLabel(count)}`}</button>}
      secondary={<button className="ui-btn" disabled={busy} onClick={onClose}>Cancel</button>}
      footerNote={error ? <span style={{ color: 'var(--danger-text)' }}>{error}</span> : undefined}
    >
      {TEXT_FIELDS.map((f) => (
        <ModalField key={f.key} label={f.label}>
          <div style={{ display: 'flex', gap: 8 }}>
            {modeSelect(f.key, f.label)}
            <ModalInput
              aria-label={f.label}
              placeholder={f.placeholder}
              disabled={mode(f.key) !== 'set'}
              value={values[f.key] ?? ''}
              onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
            />
          </div>
        </ModalField>
      ))}
      <ModalField label="Environment">
        <div style={{ display: 'flex', gap: 8 }}>
          {modeSelect('environment', 'Environment')}
          <ModalSelect aria-label="Environment" disabled={mode('environment') !== 'set'} value={values.environment ?? ''} onChange={(e) => setValues((v) => ({ ...v, environment: e.target.value }))}>
            <option value="">Choose…</option>
            {ENVIRONMENTS.map((env) => <option key={env} value={env}>{env}</option>)}
          </ModalSelect>
        </div>
      </ModalField>
      <ModalField label="Add tags" hint="name=value, separated by commas. An existing tag of the same name is overwritten; other tags are kept.">
        <ModalInput aria-label="Add tags" placeholder="zone=dmz, team=payments" value={addTags} onChange={(e) => setAddTags(e.target.value)} />
      </ModalField>
      <ModalField label="Remove tags" hint="Tag names, separated by commas.">
        <ModalInput aria-label="Remove tags" placeholder="legacy, temp" value={removeTags} onChange={(e) => setRemoveTags(e.target.value)} />
      </ModalField>
    </Modal>
  );
}

/** The display name a lens knows for an asset id, for the "not scanned" list. */
export function nameFrom(seen: ReadonlyMap<string, Asset>) {
  return (id: string) => {
    const a = seen.get(id);
    return a ? assetIdentity(a).primary : undefined;
  };
}

export { ActiveScanJobsPanel };
