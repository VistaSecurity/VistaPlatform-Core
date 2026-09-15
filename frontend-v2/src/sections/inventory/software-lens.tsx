import { useState } from 'react';
import { Link } from 'react-router';
import { Icon } from '../../components/ui';
import {
  SOFTWARE_PAGE_SIZE, productDrillThroughQuery, productIdentifier, useSoftwareProducts,
  type SoftwareProduct, type SoftwareProductSort,
} from './software-queries';
// Lifecycle and vulnerability state (workstream 3.8), rolled up per CATALOGUE
// ROW. A catalogue row is an identity — name, version, purl/cpe — so every
// install of it resolves identically for both producers.
import { eolCell, lastCheckedCell, productFindingsHref, vulnerabilityCell } from './software-state';

// Inventory → Software (workstream 2.6b).
//
// It anchors on the PRODUCT, not the asset, because the question this lens
// exists to answer is "who runs log4j 2.14?" — and a list of assets with a
// software column answers that only by being read sideways. Each row drills
// through to the assets that carry the product, which is where the answer
// actually lives.
//
// It is its own component for the reason AssetsLens is: it holds a table and a
// toolbar the crypto-anchored lenses do not want, and folding it into the page's
// branch chain would grow a second page's worth of chrome inside a fourteenth
// `if`.

// Typed against the CONTRACT's sort union, so adding an option here that the
// endpoint does not accept is a TypeScript error rather than a 400 and an empty
// table.
const SORTS: { key: SoftwareProductSort; label: string }[] = [
  { key: 'name', label: 'Name' },
  { key: 'version', label: 'Version' },
  { key: 'vendor', label: 'Vendor' },
  { key: 'installs', label: 'Most installed' },
  // The freshness question. `eol_assessed_at` reached the UI as a TOOLTIP and
  // nothing else, so "which of my products has nobody looked at lately?" could
  // only be answered by hovering every row. The server puts never-checked rows
  // FIRST — a weaker state than "checked a year ago", not a missing value.
  { key: 'eol_checked', label: 'Least recently checked' },
];


/**
 * The table's columns.
 *
 * A `sort` key makes the header a control. Only the columns the SERVER can
 * order by carry one: a header that sorted the fifty rows on screen would
 * silently reorder a page of a catalogue rather than the catalogue, which is
 * the page-capped-filter failure wearing a different hat.
 */
const COLUMNS: { label: string; sort?: SoftwareProductSort; hint?: string }[] = [
  { label: 'Product', sort: 'name' },
  { label: 'Vendor', sort: 'vendor' },
  { label: 'Version', sort: 'version' },
  { label: 'End of life' },
  { label: 'Vulnerabilities' },
  { label: 'Identifier' },
  { label: 'Licence' },
  {
    label: 'Last checked',
    sort: 'eol_checked',
    hint: 'When the lifecycle catalogue was last consulted for this product. '
      + 'Sorts least-recently-checked first, with never-checked rows ahead of them.',
  },
  // Deliberately NOT sortable. The column shows `asset_count` and the only
  // ordering the endpoint offers is `installs` (install_count) — one product
  // can have several installs on one asset, so the header would claim to order
  // by a number it is not ordering by. "Most installed" stays in the dropdown,
  // where it is named for what it actually does.
  { label: 'Assets' },
];

export function SoftwareLens() {
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<SoftwareProductSort>('name');
  const [page, setPage] = useState(0);
  const q = useSoftwareProducts({ q: search, sort, page });

  const rows = q.data?.rows ?? [];
  const total = q.data?.total ?? 0;
  const nothingAtAll = !q.isLoading && total === 0 && search === '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }} data-testid="software-lens">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 26px 12px', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name="package" size={17} style={{ color: 'var(--accent)' }} />Software
        </h2>
        <div style={{ position: 'relative', width: 230, marginLeft: 8 }}>
          <Icon name="search" size={14} style={{ position: 'absolute', left: 11, top: 9, color: 'var(--app-t3)' }} />
          <input
            value={search}
            data-testid="software-lens-search"
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            placeholder="Search name, vendor, purl, CPE…"
            style={{ width: '100%', height: 33, padding: '0 12px 0 33px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }}
          />
        </div>
        <select
          className="ui-input"
          value={sort}
          data-testid="software-lens-sort"
          onChange={(e) => { setSort(e.target.value as SoftwareProductSort); setPage(0); }}
          style={{ height: 33 }}
        >
          {SORTS.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
        </select>
        <span style={{ flex: 1 }} />
        <Link to="/discovery/sbom" className="ui-btn ghost" style={{ height: 31, fontSize: 12.5, textDecoration: 'none' }}>
          <Icon name="file-up" size={13} />Upload SBOM
        </Link>
        {!q.isLoading && <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{total}</span>}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '0 26px 30px' }}>
        {q.isError && (
          <Center
            icon="alert-triangle"
            title="Couldn't load the software catalogue"
            message={q.error instanceof Error ? q.error.message : 'Request failed'}
          />
        )}

        {q.isLoading && <Center icon="loader" title="Loading…" message="Reading the tenant software catalogue." />}

        {nothingAtAll && (
          <Center
            icon="package"
            title="No software in the inventory yet"
            message="This is not “no software found” — nothing has enumerated any. Upload a CycloneDX or SPDX bill of materials and its components land here, linked to the asset you filed it against."
            action={{ label: 'Upload an SBOM', to: '/discovery/sbom' }}
          />
        )}

        {!q.isLoading && !q.isError && total === 0 && !nothingAtAll && (
          <Center icon="search-x" title="Nothing matches" message="No product in the catalogue matches that search." />
        )}

        {total > 0 && (
          <>
            <div style={{ border: '1px solid var(--app-border)', borderRadius: 11, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
                <thead>
                  <tr style={{ background: 'var(--app-panel2)' }}>
                    {COLUMNS.map((h) => (
                      <th
                        key={h.label}
                        // On the CELL, which is where the accessibility tree
                        // reads it from — a role on the inner button would be
                        // announced as a property of the button, not the column.
                        aria-sort={h.sort && sort === h.sort ? 'ascending' : undefined}
                        style={{ textAlign: 'left', padding: '8px 11px', fontSize: 10.5, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)', whiteSpace: 'nowrap' }}
                      >
                        {h.sort ? (
                          // A sortable header is a BUTTON, not a styled div: it
                          // is reachable by keyboard and announced as a control,
                          // and the arrow says which way the list is already
                          // ordered rather than leaving the reader to guess.
                          <button
                            type="button"
                            data-testid={`software-lens-sort-${h.sort}`}
                            onClick={() => { setSort(h.sort!); setPage(0); }}
                            style={{
                              all: 'unset', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4,
                              color: sort === h.sort ? 'var(--app-t1)' : 'inherit',
                            }}
                            title={h.hint}
                          >
                            {h.label}
                            {sort === h.sort && <Icon name="arrow-up" size={10} />}
                          </button>
                        ) : h.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((p) => <ProductRow key={p.product_id} product={p} />)}
                </tbody>
              </table>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 10, fontSize: 12, color: 'var(--app-t3)' }}>
              <span className="mono">{total} products</span>
              <span style={{ flex: 1 }} />
              <button className="ui-btn ghost" disabled={page === 0} onClick={() => setPage((n) => Math.max(0, n - 1))}>Previous</button>
              <button className="ui-btn ghost" disabled={(page + 1) * SOFTWARE_PAGE_SIZE >= total} onClick={() => setPage((n) => n + 1)}>Next</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * One catalogue row.
 *
 * The install count drills THROUGH to the assets that carry the product, using
 * the query language's `software:(…)` sub-predicate — the same one the API and
 * the MCP tool speak, so the link and a hand-typed query cannot disagree.
 *
 * A count of ZERO is not a dead link and is not hidden: the product is in the
 * catalogue because it was there once, and "Unlinked" says so. It matches how
 * the keys lens reports a key no asset uses.
 */
function ProductRow({ product }: { product: SoftwareProduct }) {
  const ident = productIdentifier(product);
  // The drill-through term comes from productDrillThroughQuery, which walks the
  // catalogue's own identity ladder (purl, else CPE, else name+version) and
  // knows when the version may be used at all -- a version with no numeric
  // component has no sort key, and the validator refuses `version="latest"`.
  // It quotes with the query language's OWN rule (facet-query's quoteValue),
  // not JSON.stringify: they agree on backslash and double quote and disagree
  // on everything else.
  const term = productDrillThroughQuery(product);
  const eol = eolCell(product);
  const vuln = vulnerabilityCell(product);
  const checked = lastCheckedCell(product);
  return (
    <tr data-testid="software-product-row" style={{ borderTop: '1px solid var(--app-border)' }}>
      <td style={{ padding: '8px 11px', color: 'var(--app-t1)' }}>{product.name}</td>
      <td style={{ padding: '8px 11px', color: 'var(--app-t3)' }}>{product.vendor || '—'}</td>
      <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{product.version || '—'}</td>
      <ProductStateTd
        testId="software-lens-eol"
        cell={eol}
        href={productFindingsHref(product.name, 'eol')}
        // The install count is what the state was derived from, and showing it
        // is what makes "end of life" a claim a reader can check rather than
        // one they have to take on trust.
        detail={product.eol_install_count > 0
          ? `${product.eol_install_count} of ${product.install_count} installs`
          : undefined}
      />
      <ProductStateTd
        testId="software-lens-vuln"
        cell={vuln}
        href={productFindingsHref(product.name, 'vulnerability')}
        detail={product.vulnerable_install_count > 0
          ? `${product.vulnerable_install_count} of ${product.install_count} installs`
          : undefined}
      />
      <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t3)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ident?.value}>
        {ident ? `${ident.kind}: ${ident.value}` : '—'}
      </td>
      <td style={{ padding: '8px 11px', color: 'var(--app-t3)' }} title={product.license_id ?? undefined}>{product.license_id || '—'}</td>
      {/* When the lifecycle catalogue last had an answer for this row. "Never"
          rather than a dash: a dash reads as "nothing to report", and nobody
          having looked is a weaker state than an old answer, not an absent one. */}
      <td data-testid="software-lens-last-checked" className="mono" style={{ padding: '8px 11px', color: checked.tone, whiteSpace: 'nowrap' }} title={checked.title}>
        {checked.label}
      </td>
      <td style={{ padding: '8px 11px', whiteSpace: 'nowrap' }}>
        {product.asset_count > 0 ? (
          <Link
            to={`/inventory?lens=assets&query=${encodeURIComponent(term)}`}
            style={{ color: 'var(--accent)', textDecoration: 'none' }}
          >
            {product.asset_count} {product.asset_count === 1 ? 'asset' : 'assets'}
          </Link>
        ) : (
          <span style={{ color: 'var(--app-t3)' }} title="No asset currently lists this product. Its row is kept because it was in the inventory once.">Unlinked</span>
        )}
      </td>
    </tr>
  );
}

/**
 * One catalogue-row state cell.
 *
 * The link goes to the Findings page filtered by PRODUCER and searched by
 * product name, not by subject: a catalogue row may be installed on forty
 * assets and the producers write one finding per INSTALL, so there is no single
 * subject id to name. That is the closest honest target — the count came from N
 * installs and the page shows the findings on all of them.
 */
function ProductStateTd({ cell, href, testId, detail }: {
  cell: ReturnType<typeof eolCell>; href: string; testId: string; detail?: string;
}) {
  return (
    <td data-testid={testId} style={{ padding: '8px 11px', whiteSpace: 'nowrap' }} title={detail ? `${cell.title}\n\n${detail}.` : cell.title}>
      {cell.actionable ? (
        <Link to={href} style={{ color: cell.tone, textDecoration: 'none', fontWeight: 600 }}>{cell.label}</Link>
      ) : (
        <span style={{ color: cell.tone }}>{cell.label}</span>
      )}
    </td>
  );
}

function Center({ icon, title, message, action }: {
  icon: string; title: string; message: string; action?: { label: string; to: string };
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 9, padding: '48px 20px', textAlign: 'center' }}>
      <Icon name={icon} size={25} style={{ color: 'var(--app-t3)' }} />
      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 520, lineHeight: 1.6 }}>{message}</div>
      {action && <Link to={action.to} className="ui-btn sm" style={{ marginTop: 4, textDecoration: 'none' }}>{action.label}</Link>}
    </div>
  );
}
