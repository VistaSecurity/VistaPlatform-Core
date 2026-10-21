// The bulk cable editor (DCIM BUILD_PLAN row 3.4), opened from the faceplate's
// "Edit cables as table": a grid of local port → far asset / far port / cable
// type / label. Paste a block from a spreadsheet (tab-separated) into any cell
// or the paste box and it fills the grid from that row. "Check rows" resolves
// the far asset names and their ports and validates every row (unknown port,
// already cabled, compatibility matrix, unknown cable type, duplicates);
// "Apply" creates the valid rows' cables one after another and reports each
// row's result. Nothing is written until Apply; a failed row does not stop
// the others.
import { useMemo, useState } from 'react';
import { CABLE_TYPES, CABLE_TYPE_LABELS } from '@vistasecurity/primitives/dcim';
import type { Asset } from '@vistasecurity/api-contract';
import { Icon, Modal } from '../../../components/ui';
import { clients } from '../../../lib/clients';
import type { CableIndex } from '../dcim/cable-queries';
import {
  BULK_COLUMNS, checkRows, emptyRow, isBlank, parseCablePaste, pasteInto, rowReady,
  type BulkRow, type CheckedRow, type FarAssetMatch, type FarPortChoice,
} from './bulk-cable-model';
import { createCable, useRefreshCabling } from './cabling-queries';
import type { FacePort } from './faceplate-model';

interface Reply { data?: unknown; error?: unknown }
const loose = () => clients.inventory as unknown as { GET: (p: string, i?: object) => Promise<Reply> };

function errorText(e: unknown, fallback: string): string {
  const m = (e as { error?: { message?: unknown } } | undefined)?.error?.message;
  return typeof m === 'string' ? m : e instanceof Error ? e.message : fallback;
}

/** An asset by exact display name or hostname (case-insensitive). */
export async function lookupAsset(name: string): Promise<FarAssetMatch> {
  try {
    const { data, error } = await loose().GET('/infrastructure-assets', { params: { query: { query: JSON.stringify(name), page: 1, page_size: 50 } } });
    if (error || !data) return { status: 'error', message: errorText(error, 'search failed') };
    const assets = (data as { assets?: { id: string; display_name?: string | null; hostname?: string | null }[] }).assets ?? [];
    const want = name.toLowerCase();
    const exact = assets.filter((a) => [a.display_name, a.hostname].some((x) => x?.toLowerCase() === want));
    if (exact.length === 1) return { status: 'found', id: exact[0].id, name: firstText(exact[0].display_name, exact[0].hostname) ?? name };
    if (exact.length > 1) return { status: 'ambiguous', count: exact.length };
    return { status: 'missing' };
  } catch (e) {
    return { status: 'error', message: errorText(e, 'search failed') };
  }
}

const PORT_ROUTES = [
  ['front_port', 'front-ports'], ['rear_port', 'rear-ports'], ['console_port', 'console-ports'], ['console_server_port', 'console-server-ports'],
  // Row 6.1: a server's power supply to a PDU outlet.
  ['power_port', 'power-ports'], ['power_outlet', 'power-outlets'],
] as const;

/** Every cable-able port of an asset: interfaces, the four port kinds and the
 *  power ports and outlets (a power feed is not on an asset: connect one from
 *  the port's Connect). */
export async function loadFarPorts(assetId: string): Promise<FarPortChoice[] | null> {
  const opts = { params: { path: { id: assetId }, query: { limit: 1000 } } };
  const replies = await Promise.all([
    loose().GET('/dcim/assets/{id}/interfaces', opts),
    ...PORT_ROUTES.map(([, r]) => loose().GET(`/dcim/assets/{id}/${r}`, opts)),
  ]);
  if (replies.some((r) => !!r.error || !r.data)) return null;
  const rows = (r: Reply) => ((r.data as { data?: { id: string; name: string; cable_id: string | null; mark_connected: boolean; type?: string }[] }).data ?? []);
  const out: FarPortChoice[] = rows(replies[0]).map((i) => ({ kind: 'interface', id: i.id, name: i.name, cabled: !!i.cable_id || i.mark_connected }));
  PORT_ROUTES.forEach(([kind], idx) => {
    for (const p of rows(replies[idx + 1])) out.push({ kind, id: p.id, name: p.name, cabled: !!p.cable_id || p.mark_connected });
  });
  return out;
}

/** The first non-empty string (empty strings are not names). */
const firstText = (...xs: (string | null | undefined)[]): string | undefined => xs.find((x): x is string => !!x);

type RowResult = { ok: true } | { ok: false; message: string };

export function BulkCableEditor({ asset, ports, cables, onClose }: { asset: Asset; ports: readonly FacePort[]; cables: CableIndex | undefined; onClose: () => void }) {
  const [grid, setGrid] = useState<BulkRow[]>(() => [emptyRow(), emptyRow(), emptyRow()]);
  const [farAssets, setFarAssets] = useState<Map<string, FarAssetMatch>>(new Map());
  const [farPorts, setFarPorts] = useState<Map<string, FarPortChoice[]>>(new Map());
  const [checked, setChecked] = useState<CheckedRow[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [results, setResults] = useState<Map<number, RowResult>>(new Map());
  const refresh = useRefreshCabling();
  const free = useMemo(() => ports.filter((p) => !cables?.get(p.id) && !p.cableId && !p.markConnected), [ports, cables]);

  const edit = (i: number, k: keyof BulkRow, v: string) => {
    setGrid((g) => g.map((r, j) => (j === i ? { ...r, [k]: v } : r)));
    setChecked(null);
    setResults(new Map());
  };
  const paste = (i: number, e: React.ClipboardEvent) => {
    const t = e.clipboardData.getData('text');
    if (!/[\t\n]/.test(t)) return;
    e.preventDefault();
    setGrid((g) => pasteInto(g, i, parseCablePaste(t)));
    setChecked(null);
    setResults(new Map());
  };

  const check = async () => {
    setChecking(true);
    try {
      const names = [...new Set(grid.filter((r) => !isBlank(r)).map((r) => r.farAsset.trim()).filter(Boolean))];
      const assets = new Map(farAssets);
      await Promise.all(names.filter((n) => !assets.has(n.toLowerCase())).map(async (n) => { assets.set(n.toLowerCase(), await lookupAsset(n)); }));
      const portsBy = new Map(farPorts);
      const ids = [...new Set([...assets.values()].flatMap((m) => (m.status === 'found' ? [m.id] : [])))];
      await Promise.all(ids.filter((id) => !portsBy.has(id)).map(async (id) => {
        const p = await loadFarPorts(id);
        if (p) portsBy.set(id, p);
      }));
      setFarAssets(assets);
      setFarPorts(portsBy);
      setChecked(checkRows(grid, { localPorts: ports, cables, farAssets: assets, farPorts: portsBy }));
    } finally {
      setChecking(false);
    }
  };

  const ready = (checked ?? []).filter(rowReady);
  const apply = async () => {
    if (!checked) return;
    setApplying(true);
    const out = new Map<number, RowResult>();
    // One after another: each is its own transaction server-side, and a
    // refused row (409, compatibility) must not stop the others.
    for (let i = 0; i < checked.length; i++) {
      const c = checked[i];
      if (!rowReady(c)) continue;
      try {
        await createCable({
          a_terminations: [{ termination_kind: c.local!.kind, termination_id: c.local!.id }],
          b_terminations: [{ termination_kind: c.far!.kind, termination_id: c.far!.id }],
          operational_status: 'connected',
          ...(c.type ? { type: c.type } : {}),
          ...(c.row.label.trim() ? { label: c.row.label.trim() } : {}),
        });
        out.set(i, { ok: true });
      } catch (e) {
        out.set(i, { ok: false, message: e instanceof Error ? e.message : 'Failed' });
      }
      setResults(new Map(out));
    }
    setApplying(false);
    refresh();
  };

  const done = results.size > 0 && !applying;
  const okCount = [...results.values()].filter((r) => r.ok).length;
  // checkRows drops blank rows; map grid rows to their checked entry by order.
  const checkedByGrid = useMemo(() => {
    const m = new Map<number, { c: CheckedRow; idx: number }>();
    if (!checked) return m;
    let k = 0;
    grid.forEach((r, i) => { if (!isBlank(r)) { m.set(i, { c: checked[k], idx: k }); k++; } });
    return m;
  }, [checked, grid]);

  return (
    <Modal open onClose={onClose} size="lg" icon="cable" title={`Edit cables of ${firstText(asset.display_name, asset.hostname) ?? 'this asset'} as a table`}
      description="One row per cable. Paste a block from a spreadsheet (local port, far asset, far port, cable type, label) into any cell. Check the rows, then apply."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>{done ? 'Close' : 'Cancel'}</button>}
      primary={done
        ? <span data-testid="bulk-summary" style={{ fontSize: 12.5 }}>{okCount} of {results.size} connected</span>
        : checked
          ? <button type="button" className="ui-btn primary" data-testid="bulk-apply" disabled={applying || ready.length === 0} onClick={() => { void apply(); }}>{applying ? 'Applying…' : `Apply ${ready.length} cable${ready.length === 1 ? '' : 's'}`}</button>
          : <button type="button" className="ui-btn primary" data-testid="bulk-check" disabled={checking || grid.every(isBlank)} onClick={() => { void check(); }}>{checking ? 'Checking…' : 'Check rows'}</button>}>
      <div data-testid="bulk-cable-editor">
        <datalist id="bulk-local-ports">{free.map((p) => <option key={p.id} value={p.name} />)}</datalist>
        <datalist id="bulk-cable-types">{CABLE_TYPES.map((t) => <option key={t} value={t}>{CABLE_TYPE_LABELS[t]}</option>)}</datalist>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <thead>
              <tr>
                <th style={th}>#</th>
                {BULK_COLUMNS.map((c) => <th key={c.key} style={th}>{c.label}</th>)}
                <th style={th}>Result</th>
              </tr>
            </thead>
            <tbody>
              {grid.map((r, i) => {
                const chk = checkedByGrid.get(i);
                const res = chk ? results.get(chk.idx) : undefined;
                return (
                  <tr key={i} data-testid="bulk-row">
                    <td style={{ ...td, color: 'var(--app-t3)' }}>{i + 1}</td>
                    {BULK_COLUMNS.map((c) => (
                      <td key={c.key} style={td}>
                        <input className="ui-input" aria-label={`Row ${i + 1} ${c.label.toLowerCase()}`} value={r[c.key]}
                          list={c.key === 'local' ? 'bulk-local-ports' : c.key === 'type' ? 'bulk-cable-types' : undefined}
                          onChange={(e) => edit(i, c.key, e.target.value)} onPaste={(e) => paste(i, e)} style={{ width: '100%', minWidth: 90 }} />
                      </td>
                    ))}
                    <td style={{ ...td, minWidth: 180 }} data-testid="bulk-row-result">
                      {res ? (res.ok
                        ? <span style={{ color: 'var(--ok)' }}><Icon name="check" size={12} /> Connected</span>
                        : <span role="alert" style={{ color: 'var(--danger-text)' }}>{res.message}</span>)
                        : chk ? (chk.c.problems.length
                          ? <span style={{ color: 'var(--danger-text)' }}>{chk.c.problems.join(' ')}</span>
                          : <span style={{ color: 'var(--ok)' }}>Ready{chk.c.far ? ` → ${chk.c.far.kind.replace(/_/g, ' ')}` : ''}</span>)
                          : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <button type="button" className="ui-btn sm ghost" style={{ marginTop: 8 }} onClick={() => setGrid((g) => [...g, emptyRow()])}>
          <Icon name="plus" size={12} />Add row
        </button>
      </div>
    </Modal>
  );
}

const th: React.CSSProperties = { textAlign: 'left', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', padding: '4px 6px', borderBottom: '1px solid var(--app-border)' };
const td: React.CSSProperties = { padding: '3px 4px', borderBottom: '1px solid var(--app-border)', verticalAlign: 'top' };
