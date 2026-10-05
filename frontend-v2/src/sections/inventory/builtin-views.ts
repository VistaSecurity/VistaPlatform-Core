// Views every tenant has, beside the ones people save (ADR-0006 D2: a view is
// exactly its query text).
//
// "Never scanned" is what Discovery → Active Scan listed before it was folded
// into Inventory: every asset no active or automatic scan has reached.
// It is the query the API's `unscanned_only` parameter translates to
// (inventory-service legacyFilterTerms), so the view and that parameter can
// never disagree about which assets are unscanned.
export const NEVER_SCANNED_QUERY = 'not endpoint:(exists(last_scanned)) and not exists(last_scanned)';

export interface BuiltinView {
  name: string;
  query: string;
  description: string;
}

export const BUILTIN_VIEWS: readonly BuiltinView[] = [
  {
    name: 'Never scanned',
    query: NEVER_SCANNED_QUERY,
    description: 'Assets no active or automatic scan has reached yet. Tick them and choose Scan.',
  },
];

/** All assets with a query, as a link. */
export function assetsLensHref(query: string): string {
  return `/inventory?lens=assets&query=${encodeURIComponent(query)}`;
}

/** Where Discovery → Active Scan, and every link to it, goes now. */
export const NEVER_SCANNED_HREF = assetsLensHref(NEVER_SCANNED_QUERY);
