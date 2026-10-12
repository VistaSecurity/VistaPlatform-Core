/**
 * Page through a list endpoint instead of silently stopping at the first page.
 *
 * Several admin lists (tenants, staff, tenant health) used to ask for one page
 * of a hard-coded size and ignore `total`, so past that many rows the console
 * quietly omitted data. This loops until the server says there is nothing
 * more, with a hard ceiling so a runaway list cannot hammer the API.
 */

export const DEFAULT_MAX_ROWS = 5000;

export interface Page<T> {
  items: T[];
  /** The server's unpaginated count, when the endpoint reports one. */
  total?: number;
}

export interface Paged<T> {
  items: T[];
  /** The server's reported total, or `items.length` when it reports none. */
  total: number;
  /** True when the hard ceiling stopped the walk before the list ended. */
  truncated: boolean;
}

export interface FetchAllPagesOptions {
  /** Rows requested per page. With no `total`, a short page ends the walk. */
  pageSize: number;
  /** Hard ceiling on rows collected (default 5000). */
  maxRows?: number;
}

/** `fetchPage(page)` is 1-based and returns that page's rows (and `total` if known). */
export async function fetchAllPages<T>(
  fetchPage: (page: number) => Promise<Page<T>>,
  { pageSize, maxRows = DEFAULT_MAX_ROWS }: FetchAllPagesOptions,
): Promise<Paged<T>> {
  const items: T[] = [];
  let total: number | undefined;
  let more = true;
  for (let page = 1; more; page++) {
    const res = await fetchPage(page);
    items.push(...res.items);
    if (typeof res.total === 'number') total = res.total;
    if (res.items.length === 0) {
      more = false; // empty page: the list ended
    } else if (total !== undefined) {
      more = items.length < total;
    } else {
      more = res.items.length >= pageSize; // no total: a short page is the last
    }
    if (more && items.length >= maxRows) {
      return { items: items.slice(0, maxRows), total: total ?? items.length, truncated: true };
    }
  }
  return { items, total: total ?? items.length, truncated: false };
}
