// The bulk cable editor, as data (DCIM BUILD_PLAN row 3.4): paste a whole
// switch's cabling from a spreadsheet — local port, far asset, far port, cable
// type, label — and check every row before anything is written. Pure: the
// component resolves names to ids and calls these.
import { CABLE_TYPES, CABLE_TYPE_LABELS, cableCompatible, type CableType } from '@vistasecurity/primitives/dcim';
import type { CableIndex, CableTerminationKind } from '../dcim/cable-queries';
import type { FacePort } from './faceplate-model';

export interface BulkRow {
  local: string;
  farAsset: string;
  farPort: string;
  type: string;
  label: string;
}

export const BULK_COLUMNS: { key: keyof BulkRow; label: string }[] = [
  { key: 'local', label: 'Local port' },
  { key: 'farAsset', label: 'Far asset' },
  { key: 'farPort', label: 'Far port' },
  { key: 'type', label: 'Cable type' },
  { key: 'label', label: 'Label' },
];

export const emptyRow = (): BulkRow => ({ local: '', farAsset: '', farPort: '', type: '', label: '' });

export const isBlank = (r: BulkRow): boolean => !r.local.trim() && !r.farAsset.trim() && !r.farPort.trim() && !r.type.trim() && !r.label.trim();

/** Splits pasted spreadsheet text: tab-separated (what a spreadsheet copies),
 *  falling back to commas when no line has a tab. A first row whose first cell
 *  reads like the "Local port" header is dropped. Blank lines are skipped. */
export function parseCablePaste(text: string): BulkRow[] {
  const lines = text.replace(/\r\n?/g, '\n').split('\n').filter((l) => l.trim() !== '');
  if (lines.length === 0) return [];
  const sep = lines.some((l) => l.includes('\t')) ? '\t' : ',';
  const rows = lines.map((l) => {
    const c = l.split(sep).map((x) => x.trim().replace(/^"(.*)"$/, '$1'));
    return { local: c[0] ?? '', farAsset: c[1] ?? '', farPort: c[2] ?? '', type: c[3] ?? '', label: c[4] ?? '' };
  });
  if (/^local(\s|_)?port$/i.test(rows[0].local) || /^port$/i.test(rows[0].local)) rows.shift();
  return rows;
}

/** Pastes rows into the grid at `at`, growing it as needed. */
export function pasteInto(grid: BulkRow[], at: number, pasted: BulkRow[]): BulkRow[] {
  const out = [...grid];
  pasted.forEach((r, i) => { out[at + i] = r; });
  return out.map((r) => r ?? emptyRow());
}

/** A typed cable type: its key or its label, any case. '' = not recorded;
 *  null = not a cable type. */
export function normaliseCableType(s: string): CableType | '' | null {
  const v = s.trim().toLowerCase();
  if (!v) return '';
  const byKey = CABLE_TYPES.find((t) => t === v);
  if (byKey) return byKey;
  return CABLE_TYPES.find((t) => CABLE_TYPE_LABELS[t].toLowerCase() === v) ?? null;
}

/** A port on the far asset the editor can cable to. */
export interface FarPortChoice { kind: CableTerminationKind; id: string; name: string; cabled: boolean }

/** What name resolution found for the far assets. */
export type FarAssetMatch = { status: 'found'; id: string; name: string } | { status: 'missing' } | { status: 'ambiguous'; count: number } | { status: 'error'; message: string };

export interface BulkContext {
  localPorts: readonly FacePort[];
  cables: CableIndex | undefined;
  /** keyed by the lower-cased far asset name as typed */
  farAssets: ReadonlyMap<string, FarAssetMatch>;
  /** keyed by far asset id */
  farPorts: ReadonlyMap<string, readonly FarPortChoice[]>;
}

export interface CheckedRow {
  row: BulkRow;
  problems: string[];
  local?: FacePort;
  far?: FarPortChoice;
  type: CableType | '';
}

/** The far port a row names: same-named ports on the far asset, the ones the
 *  local port's kind can be cabled to, the same kind first. */
export function pickFarPort(localKind: CableTerminationKind, choices: readonly FarPortChoice[], name: string): { port?: FarPortChoice; incompatible: boolean } {
  const named = choices.filter((c) => c.name === name);
  const ok = named.filter((c) => cableCompatible(localKind, c.kind));
  const port = ok.find((c) => c.kind === localKind) ?? ok[0];
  return { port, incompatible: named.length > 0 && ok.length === 0 };
}

/** Checks every non-blank row; problems are per row, in the order a person
 *  would fix them. Duplicate local or far ports across rows are refused. */
export function checkRows(rows: readonly BulkRow[], ctx: BulkContext): CheckedRow[] {
  const byName = new Map(ctx.localPorts.map((p) => [p.name, p]));
  const out: CheckedRow[] = rows.filter((r) => !isBlank(r)).map((row) => {
    const problems: string[] = [];
    const local = byName.get(row.local.trim());
    if (!row.local.trim()) problems.push('No local port.');
    else if (!local) problems.push(`No port named “${row.local.trim()}” on this asset.`);
    else if (ctx.cables?.get(local.id) || local.cableId) problems.push(`${local.name} already has a cable.`);
    else if (local.markConnected) problems.push(`${local.name} is marked connected.`);
    let far: FarPortChoice | undefined;
    const assetName = row.farAsset.trim();
    if (!assetName) problems.push('No far asset.');
    else {
      const m = ctx.farAssets.get(assetName.toLowerCase());
      if (!m) problems.push('Far asset not checked yet.');
      else if (m.status === 'missing') problems.push(`No asset named “${assetName}”.`);
      else if (m.status === 'ambiguous') problems.push(`${m.count} assets are named “${assetName}”; use a unique name.`);
      else if (m.status === 'error') problems.push(`Couldn't look up “${assetName}”: ${m.message}`);
      else if (!row.farPort.trim()) problems.push('No far port.');
      else {
        const choices = ctx.farPorts.get(m.id);
        if (!choices) problems.push(`Couldn't load ${m.name}'s ports.`);
        else {
          const { port, incompatible } = pickFarPort(local?.kind ?? 'interface', choices, row.farPort.trim());
          if (incompatible) problems.push(`${row.farPort.trim()} on ${m.name} cannot be cabled to a ${local ? local.kind.replace(/_/g, ' ') : 'port'} (cable compatibility matrix).`);
          else if (!port) problems.push(`No port named “${row.farPort.trim()}” on ${m.name}.`);
          else if (port.cabled) problems.push(`${port.name} on ${m.name} already has a cable.`);
          far = port;
        }
      }
    }
    const type = normaliseCableType(row.type);
    if (type === null) problems.push(`“${row.type.trim()}” is not a cable type.`);
    if (row.label.length > 100) problems.push('A label is at most 100 characters.');
    return { row, problems, local, far, type: type ?? '' };
  });
  const seen = (key: (c: CheckedRow) => string | undefined, what: string) => {
    const count = new Map<string, number>();
    for (const c of out) { const k = key(c); if (k) count.set(k, (count.get(k) ?? 0) + 1); }
    for (const c of out) { const k = key(c); if (k && (count.get(k) ?? 0) > 1) c.problems.push(`${what} appears on more than one row.`); }
  };
  seen((c) => c.local?.id, 'This local port');
  seen((c) => c.far?.id, 'This far port');
  return out;
}

export const rowReady = (c: CheckedRow): boolean => c.problems.length === 0 && !!c.local && !!c.far;
