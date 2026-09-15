// Typed query hooks for the software inventory (workstream 2.6b).
//
// Separate from asset-queries.ts because the software surface is its own
// resource family with its own cache keys — an asset's Software tab and the
// Inventory `software` lens read different endpoints and invalidate on
// different things (an SBOM upload invalidates both).
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import type { inventoryComponents, inventoryPaths } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { quoteValue } from './facet-query';

export type SoftwareInstall = inventoryComponents['schemas']['SoftwareInstall'];
export type SoftwareProduct = inventoryComponents['schemas']['SoftwareProduct'];

export const SOFTWARE_PAGE_SIZE = 50;

/** The catalogue sorts the endpoint offers, derived from the spec. */
export type SoftwareProductSort = NonNullable<
  NonNullable<inventoryPaths['/software/products']['get']['parameters']['query']>['sort']
>;

export interface SoftwarePage<T> {
  rows: T[];
  total: number;
}

/** Sorts the asset Software tab offers. `version` orders on the normalised
 *  key, never the raw string — as text, 1.10 sorts below 1.9. */
export type SoftwareSort = 'name' | 'version' | 'vendor' | 'last_seen' | 'first_seen';

/**
 * One asset's software installs.
 *
 * `status` is left unset by default so REMOVED rows are included. A removed
 * install is evidence — it is how "this library was here last month" is
 * answered — and hiding it by default would make the tab disagree with the
 * counts in the asset's own history.
 */
export function useAssetSoftware(
  assetId: string | undefined,
  opts: { q?: string; status?: string; sort?: SoftwareSort; page?: number } = {},
) {
  const { q = '', status = '', sort = 'name', page = 0 } = opts;
  return useQuery({
    queryKey: ['asset-software', assetId, q, status, sort, page],
    enabled: !!assetId,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<SoftwarePage<SoftwareInstall>> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/software', {
        params: {
          path: { id: assetId! },
          query: {
            ...(q ? { q } : {}),
            ...(status ? { status: status as 'active' | 'stale' | 'removed' } : {}),
            sort,
            limit: SOFTWARE_PAGE_SIZE,
            offset: page * SOFTWARE_PAGE_SIZE,
          },
        },
      });
      if (error || !data) throw new Error('Failed to load software');
      return { rows: data.software ?? [], total: data.total };
    },
  });
}

/** The tenant software catalogue — the Inventory `software` lens. */
export function useSoftwareProducts(
  // The sort union comes from the CONTRACT, so a key the endpoint does not
  // accept is a TypeScript error here rather than a 400 and an empty table.
  opts: { q?: string; sort?: SoftwareProductSort; page?: number } = {},
) {
  const { q = '', sort = 'name', page = 0 } = opts;
  return useQuery({
    queryKey: ['software-products', q, sort, page],
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<SoftwarePage<SoftwareProduct>> => {
      const { data, error } = await clients.inventory.GET('/software/products', {
        params: { query: { ...(q ? { q } : {}), sort, limit: SOFTWARE_PAGE_SIZE, offset: page * SOFTWARE_PAGE_SIZE } },
      });
      if (error || !data) throw new Error('Failed to load software products');
      return { rows: data.products ?? [], total: data.total };
    },
  });
}

/**
 * The strongest machine identifier a product carries, for the one column the
 * table has room for.
 *
 * purl beats CPE, the same order the catalogue's own identity rule uses: a purl
 * names an artefact and a CPE names a product line. Returning the weaker one
 * when both exist would show a different string from the one the row is keyed
 * on.
 */
export function productIdentifier(p: { purl?: string | null; cpe?: string | null }): { kind: 'purl' | 'cpe'; value: string } | null {
  if (p.purl) return { kind: 'purl', value: p.purl };
  if (p.cpe) return { kind: 'cpe', value: p.cpe };
  return null;
}

/**
 * The query the catalogue's install count drills through with: the assets that
 * carry this product.
 *
 * It walks the SAME ladder the catalogue keys on — purl, else CPE, else
 * name(+version) — so the link selects what the count counted rather than
 * something adjacent to it.
 *
 * # Why `version_sort`, and not `version`, decides whether the version is used
 *
 * `version` is a VERSION-typed field in the query language: the translator
 * compares it as a normalised sort key, and the validator REFUSES a literal it
 * cannot turn into one. A version with no numeric component — `latest`,
 * `stable`, `main`, `edge`, all of them ordinary in container and npm tags —
 * has no sort key, which is exactly the case `Product.VersionSort` reports as
 * absent and the writer stores as a NULL `version_sort`. Emitting
 * `version="latest"` produces `type_mismatch: "version" is a version field`,
 * so the user clicks a link that says "3 assets" and lands on an error instead
 * of a list.
 *
 * `version_sort` is the server's own answer to "is this version orderable",
 * carried on the row for exactly this kind of question. When it is null the
 * term falls back to the name alone, which over-matches — every version of the
 * product — rather than failing. A wider answer with the version in the search
 * box beats a query the parser rejects.
 */
export function productDrillThroughQuery(p: {
  name: string;
  version?: string | null;
  version_sort?: string | null;
  purl?: string | null;
  cpe?: string | null;
}): string {
  if (p.purl) return `software:(purl=${quoteValue(p.purl)})`;
  if (p.cpe) return `software:(cpe=${quoteValue(p.cpe)})`;
  if (p.version && p.version_sort) {
    return `software:(name=${quoteValue(p.name)} and version=${quoteValue(p.version)})`;
  }
  return `software:(name=${quoteValue(p.name)})`;
}

/**
 * How an install's provenance reads in the table.
 *
 * `imported` is spelled out as its source rather than shown raw: "imported"
 * alone invites a reader to think a person typed it, and the distinction
 * between what we measured and what a build system claimed is the whole point
 * of the column.
 */
export const SOURCE_KIND_LABEL: Readonly<Record<string, string>> = {
  measured: 'Measured',
  declared: 'Declared',
  imported: 'From SBOM',
  inferred: 'Inferred',
};

export function installSourceLabel(kind: string): string {
  return SOURCE_KIND_LABEL[kind] ?? kind;
}

/**
 * The tone an install status renders in.
 *
 * `removed` is muted rather than red: it is not a problem, it is a product that
 * is no longer listed. Colouring it as an alert would make a routine
 * dependency drop look like a finding.
 */
export function statusTone(status: string): 'ok' | 'warn' | 'muted' {
  switch (status) {
    case 'active':
      return 'ok';
    case 'stale':
      return 'warn';
    default:
      return 'muted';
  }
}
