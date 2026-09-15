// The command palette's RESULT MODEL — one shape, shared by both of its modes.
//
// ADR-0006 D9: "the palette gains classes and relationships as result kinds,
// and the grounded query panel, when a provider is configured, opens from the
// same keystroke with a mode toggle and renders tool results as the same result
// rows, so a user learns one surface."
//
// The model lives here rather than inside command-palette.tsx for the reason the
// ADR gives: two modes producing two shapes would be two surfaces wearing one
// keystroke. Ask mode maps its rows through `assetItem`, the same builder search
// mode uses, so a row cannot render differently depending on how it was found.
//
// Everything in this file is pure. The palette's rendering is React; which rows
// exist, what they link to and how they are labelled is not, and pinning those
// without mounting a component is why they are here.

import type { inventoryComponents } from '@vistasecurity/api-contract';
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { assetIdentity, classLabel, primaryAddressPort } from '../sections/inventory/asset-shape';
import { levelFromScore } from '../components/ui';
import type { FeatureName } from '@vistasecurity/primitives/features';

export type Asset = inventoryComponents['schemas']['Asset'];
export type Relationship = inventoryComponents['schemas']['Relationship'];

/**
 * The result kinds.
 *
 * `class` and `relationship` are D9's two additions. They are not decoration:
 * the ops-engineer persona the ADR names arrives through this box — "a switch is
 * being replaced Friday; what is behind it?" — and the answer is a relationship.
 */
export type ResultKind = 'nav' | 'asset' | 'cert' | 'device' | 'sensor' | 'class' | 'relationship';

export interface CommandItem {
  id: string;
  kind: ResultKind;
  label: string;
  sublabel?: string;
  badge?: string;
  to: string;
  /** Entitlement key this quick-nav target requires; omitted = every edition. */
  feature?: FeatureName;
}

export const KIND_LABEL: Record<ResultKind, string> = {
  nav: 'Quick Navigation',
  asset: 'Infrastructure Assets',
  cert: 'Certificates',
  device: 'Devices',
  sensor: 'Sensors',
  class: 'Asset Classes',
  relationship: 'Relationships',
};

export const KIND_ICON: Record<ResultKind, string> = {
  nav: 'arrow-right',
  asset: 'server',
  cert: 'file-badge',
  device: 'monitor-smartphone',
  sensor: 'wifi',
  class: 'shapes',
  relationship: 'waypoints',
};

/**
 * A deep link into Inventory carrying a query-language PREDICATE.
 *
 * `?query=` and not `?q=`: they are different parameters and conflating them is
 * the kind of near-miss that renders a filtered page that silently filtered on
 * nothing. `q` seeds the free-text SEARCH box (what the palette's asset and
 * certificate rows have always used); `query` is the predicate the facet rail
 * writes, the query editor edits and a saved view stores.
 *
 * `lens=assets` because that is the lens carrying the query editor — landing on
 * a lens with no editor would show the rows and hide the thing the user came to
 * edit.
 */
export function inventoryQueryLink(query: string): string {
  const trimmed = query.trim();
  return trimmed
    ? `/inventory?lens=assets&query=${encodeURIComponent(trimmed)}`
    : '/inventory?lens=assets';
}

/** A deep link into Inventory carrying a free-text search term. */
export function inventorySearchLink(lens: string, term: string): string {
  return `/inventory?lens=${lens}${term ? `&q=${encodeURIComponent(term)}` : ''}`;
}

/**
 * One asset row.
 *
 * The SAME builder for both modes. Ask mode's rows arrive from `/ask` in the
 * list endpoint's own shape, so they go through this unchanged — which is what
 * makes "the same result rows" true rather than aspirational.
 */
export function assetItem(a: Asset): CommandItem {
  const ident = assetIdentity(a);
  // Only badge Medium+ risk (>=40). Every score maps to a level, so badging all
  // of them would print "Informational" on everything — and on a row nobody has
  // scored that would read as an assessment.
  const badge = typeof a.risk_score === 'number' && a.risk_score >= 40
    ? (a.risk_level || levelFromScore(a.risk_score))
    : undefined;
  return {
    id: `asset-${a.id}`,
    kind: 'asset',
    label: ident.primary,
    sublabel: [primaryAddressPort(a), classLabel(a.class_key), a.environment].filter(Boolean).join(' · ') || undefined,
    badge,
    to: `/inventory/assets/${a.id}`,
  };
}

/**
 * One asset-class row (D9).
 *
 * It links to the assets IN that class rather than to the taxonomy page,
 * because someone typing "switch" into a search box is looking for switches. The
 * predicate uses `class:` — the SUBTREE operator — so "hardware" finds
 * everything under it, which is what a person means by a class name and is the
 * distinction `class=` would silently lose.
 *
 * Classes come from the generated registry, not from an endpoint: the taxonomy
 * is `standards/asset-classes.yaml`, the client already ships it for the facet
 * rail and the class picker, and fetching a copy of a constant would add a
 * loading state to a list that cannot fail.
 */
export function classItem(key: AssetClassKey): CommandItem {
  const cls = ASSET_CLASSES[key];
  return {
    id: `class-${key}`,
    kind: 'class',
    label: cls.label,
    sublabel: cls.path,
    to: inventoryQueryLink(`class:${cls.path}`),
  };
}

/**
 * Every class whose label, key or dotted path matches the typed text.
 *
 * Matched on the PATH as well as the label so "hardware.computer" narrows the
 * way a user who has seen one path expects, and capped so a one-letter query
 * cannot push every other kind of result off the list.
 */
export function matchingClasses(text: string, limit = 4): CommandItem[] {
  const needle = text.trim().toLowerCase();
  if (!needle) return [];
  const out: CommandItem[] = [];
  for (const key of Object.keys(ASSET_CLASSES) as AssetClassKey[]) {
    const cls = ASSET_CLASSES[key];
    if (
      cls.label.toLowerCase().includes(needle)
      || key.toLowerCase().includes(needle)
      || cls.path.toLowerCase().includes(needle)
    ) {
      out.push(classItem(key));
      if (out.length >= limit) break;
    }
  }
  return out;
}

/**
 * The classes an ANSWER's rows are in, as class rows (D9).
 *
 * Ask mode rendered asset rows and nothing else, so D9's "renders the tool
 * results as the same result rows" was only two-thirds true: the same question
 * typed as a search offered classes and relationships alongside the assets, and
 * asked in words offered neither. A user who learns one surface found it had
 * two behaviours.
 *
 * Derived from the ANSWER rather than from the typed text, which is the one
 * thing that has to be different. `matchingClasses` substring-matches what was
 * typed, and what is typed in ask mode is a SENTENCE — "which switches are
 * end of life?" matches no class label, so reusing it would have quietly
 * rendered nothing and looked like the feature was there. The answer's own rows
 * carry the classes the question turned out to be about, which is the better
 * answer anyway: it reflects what was found, not what was asked.
 *
 * Deduplicated and capped, in FIRST-SEEN order — the answer's rows are already
 * ranked by the server, so the class of the best row comes first.
 */
export function classesOfAssets(assets: readonly Asset[], limit = 3): CommandItem[] {
  const seen = new Set<string>();
  const out: CommandItem[] = [];
  for (const a of assets) {
    const key = a.class_key;
    // A class the generated registry does not carry is skipped rather than
    // rendered from its raw key: `classItem` reads the registry for the label
    // and the path, and a tenant leaf subclass has neither here. A row with a
    // blank label linking to an empty predicate is worse than no row.
    if (!key || seen.has(key) || !(key in ASSET_CLASSES)) continue;
    seen.add(key);
    out.push(classItem(key as AssetClassKey));
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * One relationship row (D9): an edge read from the FROM asset's side.
 *
 * It links to the Relationships tab of the asset the edge was read from, not to
 * the peer: the user asked about this asset, and the tab is where the edge, its
 * provenance and the impact closure all are. `label` is the server's own reading
 * of the edge when it sent one — an edge is stored once in a canonical direction
 * and has to read correctly from both ends, so the server's sentence beats one
 * assembled here.
 */
export function relationshipItem(assetID: string, assetName: string, rel: Relationship): CommandItem {
  // Explicit emptiness checks rather than `||`: a peer whose display name is
  // the empty string is a peer with no name, and `??` would keep it. Both
  // operators are wrong here for opposite reasons, so neither is used.
  const peer = nonEmpty(rel.peer?.display_name) ?? nonEmpty(rel.peer?.primary_identifier) ?? 'an unnamed asset';
  const reads = nonEmpty(rel.label) ?? rel.type;
  return {
    id: `rel-${rel.id}`,
    kind: 'relationship',
    label: `${assetName} ${reads} ${peer}`,
    sublabel: [rel.source_kind, rel.status].filter(Boolean).join(' · ') || undefined,
    // The Relationships tab of the asset the search matched.
    to: `/inventory/assets/${assetID}/relationships`,
  };
}

/** The string, or undefined when it is absent or blank. */
function nonEmpty(v: string | undefined): string | undefined {
  return v !== undefined && v.trim() !== '' ? v : undefined;
}

/**
 * Contiguous runs of one kind, for the section headers.
 *
 * Contiguous rather than grouped: the order is the ranking, and re-grouping
 * would move a better match below a worse one to keep a header tidy.
 */
export function sectionsOf(items: CommandItem[]): { kind: ResultKind; start: number; count: number }[] {
  const out: { kind: ResultKind; start: number; count: number }[] = [];
  let last: ResultKind | null = null;
  items.forEach((it, i) => {
    if (it.kind !== last) {
      out.push({ kind: it.kind, start: i, count: 1 });
      last = it.kind;
    } else {
      out[out.length - 1].count++;
    }
  });
  return out;
}
