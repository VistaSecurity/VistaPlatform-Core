// The grammar's fixed vocabulary: the eight sub-predicate collections (§3) and
// the twenty relationship names (ADR-0003 D2 — ten canonical types and their
// ten reverse labels).
//
// These are part of the grammar, not of the generated field catalogue, because
// the parser must disambiguate `x:(…)` before any catalogue is consulted. A
// Catalog re-exports the relationship list so a production catalogue can still
// be asked for it.

import type { Direction } from './ast';

/** The sub-predicate names (§3 `collection`). */
export const COLLECTIONS: readonly string[] = [
  'endpoint',
  'software',
  'finding',
  'cert',
  'crypto',
  'identifier',
  'relationship',
  'asset',
];

/** Reports whether s names a sub-predicate collection, case-insensitively. */
export function isCollection(s: string): boolean {
  return COLLECTIONS.includes(s.toLowerCase());
}

/** The wildcard traversal name. */
export const ANY_REL = 'any_rel';

/** The head of the explicit traversal form `rel(type, dir, n)`. */
export const REL_KEYWORD = 'rel';

/**
 * One spelling of an edge type: either the canonical type or its reverse label,
 * with the direction that spelling walks the edge.
 */
export interface Relationship {
  /** The spelling, as it appears in a query. */
  name: string;
  /** The canonical edge type stored in asset_relationships.type. */
  type: string;
  /** The direction this spelling walks the canonical edge. */
  direction: Direction;
  /** Whether name is the reverse label. */
  reverse: boolean;
}

/** ADR-0003 D2's ten types with their reverse labels. */
const CANONICAL_PAIRS: readonly (readonly [string, string])[] = [
  ['runs_on', 'runs'],
  ['hosted_on', 'hosts'],
  ['virtualized_by', 'virtualizes'],
  ['depends_on', 'used_by'],
  ['connects_to', 'connected_from'],
  ['member_of', 'members'],
  ['contains', 'contained_by'],
  ['manages', 'managed_by'],
  ['sends_data_to', 'receives_data_from'],
  ['impacts', 'impacted_by'],
];

/** The flat list of all twenty names, canonical first. */
export const RELATIONSHIPS: readonly Relationship[] = [
  ...CANONICAL_PAIRS.map(([canonical]) => ({
    name: canonical,
    type: canonical,
    direction: 'out' as Direction,
    reverse: false,
  })),
  ...CANONICAL_PAIRS.map(([canonical, reverse]) => ({
    name: reverse,
    type: canonical,
    direction: 'in' as Direction,
    reverse: true,
  })),
];

/** The ten canonical type keys, in ADR-0003 D2 order. */
export const RELATIONSHIP_TYPES: readonly string[] = CANONICAL_PAIRS.map(([c]) => c);

/**
 * Resolves a name (canonical or reverse) to its edge type and direction,
 * case-insensitively.
 */
export function lookupRelationship(name: string): Relationship | null {
  const lower = name.toLowerCase();
  for (const r of RELATIONSHIPS) if (r.name === lower) return r;
  return null;
}

/**
 * Reports whether s is one of the ten canonical types, which is what the
 * explicit `rel(type, …)` form requires.
 */
export function isRelationshipType(s: string): boolean {
  return RELATIONSHIP_TYPES.includes(s.toLowerCase());
}

/** Parses the direction argument of the explicit form. */
export function parseDirection(s: string): Direction | null {
  switch (s.toLowerCase()) {
    case 'out':
      return 'out';
    case 'in':
      return 'in';
    case 'any':
      return 'any';
    default:
      return null;
  }
}
