// Which assets a bulk action acts on — the selection model behind the
// checkbox column, the "Select all N matching" banner and the bulk action bar
// on Inventory → All assets and Stale.
//
// Two shapes, because they are two different promises:
//   • `ids`   — rows a person ticked. They survive paging, so a person can tick
//               across pages; the action touches exactly those rows.
//   • `query` — "every asset matching this query", N of them when the person
//               confirmed. The SERVER resolves the query (the same predicate
//               the list ran) and refuses with 409 if it now matches more than
//               N — the bar never acts on more than the person agreed to.
//
// Pure: no React, so the rules are tested without rendering.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type AssetSelectionRequest = inventoryComponents['schemas']['AssetSelectionRequest'];

export type AssetSelection =
  | { kind: 'none' }
  | { kind: 'ids'; ids: ReadonlySet<string> }
  | { kind: 'query'; query: string; count: number };

export const NO_SELECTION: AssetSelection = { kind: 'none' };

/** The server's caps (inventory-service MaxBulkScanAssets / MaxBulkAssets). */
export const MAX_BULK_SCAN = 1000;
export const MAX_BULK = 5000;

export type BulkAction = 'scan' | 'archive' | 'restore' | 'delete' | 'update' | 'export';

/** The cap an action is held to. Export is client-side and has its own. */
export function capFor(action: BulkAction): number {
  return action === 'scan' ? MAX_BULK_SCAN : MAX_BULK;
}

export function selectedCount(sel: AssetSelection): number {
  if (sel.kind === 'ids') return sel.ids.size;
  if (sel.kind === 'query') return sel.count;
  return 0;
}

/** Whether a row is ticked. Every row is, under an all-matching selection. */
export function isSelected(sel: AssetSelection, id: string): boolean {
  if (sel.kind === 'ids') return sel.ids.has(id);
  return sel.kind === 'query';
}

/** Tick or untick one row. Unticking a row of an all-matching selection
 *  cannot be expressed as a query, so it falls back to this page's rows
 *  minus that one — said plainly by the banner, which then offers
 *  "Select all N matching" again. */
export function toggleRow(sel: AssetSelection, id: string, pageIds: readonly string[]): AssetSelection {
  if (sel.kind === 'query') {
    const ids = new Set(pageIds.filter((p) => p !== id));
    return ids.size ? { kind: 'ids', ids } : NO_SELECTION;
  }
  const ids = new Set(sel.kind === 'ids' ? sel.ids : []);
  if (ids.has(id)) ids.delete(id);
  else ids.add(id);
  return ids.size ? { kind: 'ids', ids } : NO_SELECTION;
}

/** The header checkbox's state for the rows on this page. */
export function pageState(sel: AssetSelection, pageIds: readonly string[]): 'none' | 'some' | 'all' {
  if (pageIds.length === 0) return 'none';
  if (sel.kind === 'query') return 'all';
  if (sel.kind === 'none') return 'none';
  const n = pageIds.filter((id) => sel.ids.has(id)).length;
  return n === 0 ? 'none' : n === pageIds.length ? 'all' : 'some';
}

/** The header checkbox: ticks every row on this page, or — when all of them
 *  already are — unticks them (keeping rows ticked on other pages). */
export function togglePage(sel: AssetSelection, pageIds: readonly string[]): AssetSelection {
  if (sel.kind === 'query') return NO_SELECTION;
  const ids = new Set(sel.kind === 'ids' ? sel.ids : []);
  if (pageState(sel, pageIds) === 'all') pageIds.forEach((id) => ids.delete(id));
  else pageIds.forEach((id) => ids.add(id));
  return ids.size ? { kind: 'ids', ids } : NO_SELECTION;
}

/** "Select all N matching". */
export function selectAllMatching(query: string, total: number): AssetSelection {
  return total > 0 ? { kind: 'query', query, count: total } : NO_SELECTION;
}

/**
 * Whether to offer "Select all N matching": the whole page is ticked and the
 * query matches more than the page shows. `queryable` is false where the rows
 * on screen are NOT exactly what a query names (a lens filtering in the
 * browser), because "all matching" would then mean more than was shown.
 */
export function offerSelectAll(sel: AssetSelection, pageIds: readonly string[], total: number, queryable: boolean): boolean {
  return queryable && sel.kind === 'ids' && pageState(sel, pageIds) === 'all' && total > sel.ids.size;
}

/** The request body's selection half. */
export function selectionBody(sel: AssetSelection): AssetSelectionRequest {
  if (sel.kind === 'query') return { query: sel.query, expected_count: sel.count };
  if (sel.kind === 'ids') return { asset_ids: Array.from(sel.ids) };
  return { asset_ids: [] };
}

/** Why an action cannot run on this selection, or null when it can. */
export function overCapReason(sel: AssetSelection, action: BulkAction): string | null {
  const cap = capFor(action);
  const n = selectedCount(sel);
  if (n <= cap) return null;
  const what = action === 'scan' ? 'A scan' : 'A bulk action';
  return `${what} can cover at most ${cap.toLocaleString()} assets; ${n.toLocaleString()} are selected. Narrow the query.`;
}

/** "3 assets", "1 asset". */
export function assetsLabel(n: number): string {
  return `${n.toLocaleString()} asset${n === 1 ? '' : 's'}`;
}

/**
 * The API's refusal of a selection, in words a person can act on. Returns null
 * for any other failure so the caller can use its own message.
 */
export function selectionRefusal(status: number, error: unknown): string | null {
  const e = (error ?? {}) as { error?: string; count?: number; expected_count?: number; limit?: number };
  if (status === 409 && e.error === 'selection_changed') {
    return `The query now matches ${e.count?.toLocaleString() ?? 'more'} assets, more than the ${e.expected_count?.toLocaleString() ?? ''} you confirmed. Nothing was changed — review the list and try again.`;
  }
  if (status === 413 && e.error === 'selection_too_large') {
    return `The selection is over the limit of ${e.limit?.toLocaleString() ?? 'the'} assets. Nothing was changed — narrow the query.`;
  }
  return null;
}
