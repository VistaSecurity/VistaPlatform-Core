// Reachability for the software surface (workstream 2.6b), in BOTH polarities.
//
// The feature framework's rule is that no layer ships without its consumer.
// Three layers arrived here — an upload page, an asset tab and an inventory
// lens — and each of them can fail in two opposite ways: it can be missing
// (built and unreachable), or it can be present while still declaring itself a
// placeholder (reachable and lying about being live). A test that only checks
// one direction would have passed unchanged through the state this workstream
// started in, where the tab and the lens both existed and both said "phase 3".
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SECTIONS } from '../../app/nav';
import { ASSET_TABS, assetTabPath, findAssetTab, isTabLive } from './asset-tabs';
import { INVENTORY_LENSES, findLens } from './lenses';
import {
  SOURCE_KIND_LABEL, installSourceLabel, productDrillThroughQuery, productIdentifier, statusTone,
} from './software-queries';

const here = new URL('.', import.meta.url).pathname;

describe('the asset Software tab', () => {
  it('is in the registry and is LIVE', () => {
    const tab = findAssetTab('software');
    expect(tab.key).toBe('software');
    expect(isTabLive(tab)).toBe(true);
  });

  it('carries no leftover placeholder', () => {
    // The other polarity. A tab that is in the registry, has a URL and renders a
    // "arrives in phase 3" card is reachable and useless, which is exactly what
    // this one was before 2.6b.
    const tab = ASSET_TABS.find((t) => t.key === 'software')!;
    expect(tab.placeholder).toBeUndefined();
  });

  it('has a URL a person can be sent', () => {
    expect(assetTabPath('abc', 'software')).toBe('/inventory/assets/abc/software');
  });
});

describe('the Inventory software lens', () => {
  it('is live, and is in the Assets group where the nav shows it', () => {
    const lens = findLens('software');
    expect(lens.live).toBe(true);
    expect(lens.placeholder).toBeUndefined();
    expect(lens.group).toBe('assets');
  });

  it('has a nav entry pointing at it', () => {
    // A lens with no nav home is a page nobody can reach without typing a URL.
    const inventory = SECTIONS.find((s) => s.id === 'inventory')!;
    const entry = (inventory.groups ?? []).flatMap((g) => g.items).find((i) => i.lens === 'software');
    expect(entry).toBeDefined();
    expect(entry!.path).toBe('/inventory?lens=software');
  });

  it('is still exactly one lens — the registry has no duplicate', () => {
    expect(INVENTORY_LENSES.filter((l) => l.key === 'software')).toHaveLength(1);
  });
});

describe('the Upload SBOM page', () => {
  it('has a nav home under Discovery → Sources, beside the other file intake', () => {
    // Sources is a nav GROUP, not a page, so this is a sibling of PCAP Upload
    // rather than a card on a page that does not exist.
    const discovery = SECTIONS.find((s) => s.id === 'discovery')!;
    const sources = (discovery.groups ?? []).find((g) => g.label === 'Sources')!;
    const labels = sources.items.map((i) => i.label);
    expect(labels).toContain('SBOM Upload');
    expect(labels).toContain('PCAP Upload');
    expect(sources.items.find((i) => i.label === 'SBOM Upload')!.path).toBe('/discovery/sbom');
  });
});

describe('software row helpers', () => {
  it('shows the STRONGEST identifier, the same order the catalogue keys on', () => {
    // purl beats CPE. Showing the weaker one when both exist would display a
    // different string from the one the row is deduplicated by.
    expect(productIdentifier({ purl: 'pkg:npm/left-pad@1.3.0', cpe: 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*' }))
      .toEqual({ kind: 'purl', value: 'pkg:npm/left-pad@1.3.0' });
    expect(productIdentifier({ cpe: 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*' }))
      .toEqual({ kind: 'cpe', value: 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*' });
    expect(productIdentifier({})).toBeNull();
  });

  it('names an imported install by its source rather than showing the raw kind', () => {
    expect(installSourceLabel('imported')).toBe('From SBOM');
    expect(installSourceLabel('measured')).toBe('Measured');
    // An unknown kind falls through verbatim rather than rendering blank: a
    // value we have not seen is still evidence.
    expect(installSourceLabel('something-new')).toBe('something-new');
    // Every provenance value the API can return has a label.
    for (const kind of ['measured', 'declared', 'imported', 'inferred']) {
      expect(SOURCE_KIND_LABEL[kind]).toBeTruthy();
    }
  });

  it('mutes a removed install rather than alarming about it', () => {
    // A product a later document did not list is not a finding. Colouring it as
    // one would make a routine dependency drop look like a problem.
    expect(statusTone('active')).toBe('ok');
    expect(statusTone('stale')).toBe('warn');
    expect(statusTone('removed')).toBe('muted');
  });
});

describe('the catalogue drill-through query', () => {
  // The link on an install count has to select what the count counted, and it
  // has to PARSE. Both have gone wrong here.
  it('walks the catalogue identity ladder: purl, then CPE, then name', () => {
    expect(productDrillThroughQuery({
      name: 'core', version: '17.0.0', version_sort: '00000017',
      purl: 'pkg:npm/%40angular/core@17.0.0', cpe: 'cpe:2.3:a:x:core:17.0.0:*:*:*:*:*:*:*',
    })).toBe('software:(purl="pkg:npm/%40angular/core@17.0.0")');

    // CPE is used when there is no purl, rather than being skipped in favour of
    // the weaker name+version. It is the second rung of the same ladder
    // software_products keys on.
    expect(productDrillThroughQuery({
      name: 'core', version: '17.0.0', version_sort: '00000017',
      cpe: 'cpe:2.3:a:x:core:17.0.0:*:*:*:*:*:*:*',
    })).toBe('software:(cpe="cpe:2.3:a:x:core:17.0.0:*:*:*:*:*:*:*")');

    expect(productDrillThroughQuery({ name: 'openssl', version: '3.0.13', version_sort: '00000003' }))
      .toBe('software:(name=openssl and version=3.0.13)');

    expect(productDrillThroughQuery({ name: 'openssl' })).toBe('software:(name=openssl)');
  });

  it('omits a version the query language cannot compare, instead of emitting a query that fails', () => {
    // `version` is a VERSION-typed field: the validator refuses a literal it
    // cannot turn into a sort key, with `type_mismatch: "version" is a version
    // field; "latest" is not a version`. A null `version_sort` is the server
    // saying exactly that about this row, so the term falls back to the name.
    //
    // Without this the user clicks a link reading "3 assets" and lands on a
    // parse error — a count that is right beside a link that cannot work.
    for (const version of ['latest', 'stable', 'main', 'edge']) {
      expect(productDrillThroughQuery({ name: 'mytool', version, version_sort: null }))
        .toBe('software:(name=mytool)');
    }
    // A version WITH a sort key is still used. Dropping it always would make
    // every row link to every version of its product.
    expect(productDrillThroughQuery({ name: 'mytool', version: '1.2.3', version_sort: '00000001' }))
      .toBe('software:(name=mytool and version=1.2.3)');
  });

  it('quotes with the query language rule, so an awkward name is still a valid query', () => {
    // A name with a space is not a bareword and has to be quoted, or the term
    // parses as two.
    expect(productDrillThroughQuery({ name: 'my tool' })).toBe('software:(name="my tool")');
    // `and` is a keyword; unquoted it would be read as the operator.
    expect(productDrillThroughQuery({ name: 'and' })).toBe('software:(name="and")');
  });
});

// ---------------------------------------------------------------------------
// The lifecycle / vulnerability columns (workstream 3.8)
// ---------------------------------------------------------------------------
//
// Two producers wrote findings on software installs in 3.3/3.4, and until now
// the only place a tenant could see them was the Findings page — which answers
// "what is wrong" but not "is THIS package a problem". A column with no
// consumer is a backend capability, not a tenant one; these assert both halves
// of each surface, and that the link out of a cell is a real filter rather than
// a page that opens on the whole tenant's findings.

describe('the software surfaces carry the two state columns', () => {
  const assetPage = readFileSync(join(here, 'asset-page.tsx'), 'utf8');
  const lens = readFileSync(join(here, 'software-lens.tsx'), 'utf8');

  it('are on the asset Software tab', () => {
    expect(assetPage).toContain("'End of life'");
    expect(assetPage).toContain("'Vulnerabilities'");
    expect(assetPage).toContain('eolCell(');
    expect(assetPage).toContain('vulnerabilityCell(');
  });

  it('are on the Inventory Software lens too', () => {
    // Both, deliberately. The tab answers "what is on this host" and the lens
    // answers "who runs log4j 2.14?" — a reader working either question needs
    // the same two answers, and shipping one surface only is how half a feature
    // becomes permanent.
    expect(lens).toContain("'End of life'");
    expect(lens).toContain("'Vulnerabilities'");
    expect(lens).toContain('eolCell(');
    expect(lens).toContain('vulnerabilityCell(');
  });

  it('link OUT to the findings that produced them', () => {
    expect(assetPage).toContain('installFindingsHref(');
    expect(lens).toContain('productFindingsHref(');
  });

  it('read the state off the list response rather than firing a call per row', () => {
    // The N+1 this rode along to avoid: fifty installs would otherwise be fifty
    // subject-filtered calls to compliance-engine, and the tab would be slower
    // than the answer is worth.
    expect(assetPage).not.toContain('useAssetFindings(asset.id, true)');
    expect(assetPage).toContain('useAssetSoftware(');
  });
});

describe('the Findings page can actually be filtered to one install', () => {
  const findingsPage = readFileSync(join(here, '..', 'findings', 'findings-page.tsx'), 'utf8');
  const findingsQueries = readFileSync(join(here, '..', 'findings', 'queries.ts'), 'utf8');

  it('reads BOTH halves of the subject filter out of the URL', () => {
    // A link that carried only half would be a 400 the page has no way to
    // explain — the endpoint refuses either alone.
    expect(findingsPage).toContain("params.get('subject_type')");
    expect(findingsPage).toContain("params.get('subject_id')");
  });

  it('sends them to the SERVER, not to a client-side filter', () => {
    // The list is page-capped. Filtering here would render an empty page under
    // a link that promised three findings, for any subject past the cap.
    expect(findingsQueries).toContain('subject_type: subject.subjectType');
    expect(findingsQueries).toContain('subject_id: subject.subjectId');
  });

  it('tells the reader the page is filtered, and offers a way out', () => {
    // A filter arriving from a link is one the reader never chose. A page
    // silently showing one package's findings while looking like the tenant's
    // is the "reads as applied and is not" failure pointed the other way.
    expect(findingsPage).toContain('findings-subject-filter');
    expect(findingsPage).toContain('Show all findings');
  });
});

// The freshness column and its sort (seeds part 3).
//
// `eol_assessed_at` reached the UI as a TOOLTIP and nothing else, so "which of
// my products has nobody looked at lately?" could only be answered by hovering
// every row in the catalogue. A backend field with no control is a gap, not a
// feature — so both polarities are pinned: the column EXISTS, and it is sorted
// by the SERVER rather than by reordering the fifty rows on screen.
describe('the "Last checked" column', () => {
  const lens = readFileSync(join(here, 'software-lens.tsx'), 'utf8');
  const queries = readFileSync(join(here, 'software-queries.ts'), 'utf8');

  it('is a column on the Inventory Software lens', () => {
    expect(lens).toContain("'Last checked'");
    expect(lens).toContain('lastCheckedCell(');
    expect(lens).toContain('software-lens-last-checked');
  });

  it('offers "least recently checked" as a sort a person can pick', () => {
    expect(lens).toContain("'eol_checked'");
    expect(lens).toContain('Least recently checked');
  });

  it('sends the sort to the SERVER', () => {
    // The other polarity. Reordering `rows` here would sort ONE PAGE of the
    // catalogue while claiming to have found its least recently checked
    // products — which is the page-capped-filter failure in a table header.
    expect(queries).toContain("clients.inventory.GET('/software/products'");
    expect(queries).toContain('sort,');
    expect(lens).not.toMatch(/rows[\s.]*\.sort\(/);
  });
});
