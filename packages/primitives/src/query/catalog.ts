// The seam between the query language and the schema.
//
// The parser knows the grammar; the validator, the formatter and autocomplete
// know nothing about fields except what a Catalog tells them. Two catalogues
// ship here: `test-catalog.ts` is the static port of Go's
// `catalog/testcatalog`, which the conformance fixtures resolve against, and
// `registry-catalog.ts` is the production one over the generated registries.
// Both satisfy this interface, and nothing else changes when one is swapped for
// the other.

import type { Accessor, FieldRef, FieldType, Namespace, Op } from './ast';
import { isOrdering } from './ast';
import type { Relationship } from './vocabulary';

/**
 * A collection a query can be a predicate over (§4.1), together with the
 * physical shape a translator needs to build SQL for it.
 */
export interface Target {
  /** The target's name in the language: asset, endpoint, … */
  name: string;
  /** The physical table. Empty for an in-memory target. */
  table: string;
  /** The code-supplied alias a translator gives it. */
  alias: string;
  /** The primary key column. */
  idColumn: string;
  /** How a row reaches its owning asset; empty when the target is the asset. */
  assetIdColumn?: string;
  /**
   * The sub-predicate collections reachable from this target. A collection
   * outside the list is untranslatable rather than silently resolved against
   * the wrong table.
   */
  subs: string[];
  /**
   * Whether relationship traversal starts here. Edges join assets, so only
   * asset-shaped targets are traversable.
   */
  traversable: boolean;
  /**
   * Whether a term with no field has a meaning here. §5.4 defines free text
   * over an asset's display name, hostname, identifier values and tags; a
   * target without that column set rejects a free-text term rather than
   * silently searching something narrower.
   */
  freeTextable: boolean;
  /**
   * Marks a target that has no table: `observation` is evaluated by the
   * identification engine against an in-flight discovery, and `measurement` by
   * the measurement extractor, so the SQL translator refuses them rather than
   * inventing a table.
   */
  inMemory?: boolean;
}

/** One entry of a target's field catalogue. */
export interface FieldInfo {
  /** The field as a user writes it, including any namespace prefix. */
  name: string;
  /** Decides the legal operators and the SQL shape. */
  type: FieldType;
  /** How a translator reaches the value. */
  accessor: Accessor;
  /** When set, the closed value set the validator enforces. */
  enum?: string[];
  /** Autocomplete help text. */
  description?: string;
}

/** A class key and its materialised path (§5.3). */
export interface ClassInfo {
  key: string;
  path: string;
}

/** Why a path did not resolve, so the validator can write the right message. */
export type ResolveReason =
  /** A target the catalogue does not know. */
  | 'unknown_target'
  /** A bare path with no first-class field. */
  | 'unknown_field'
  /** A namespaced path whose key is not registered. */
  | 'unknown_key'
  /** A namespace prefix with nothing after it. */
  | 'empty_key';

/**
 * What `resolve` returns on failure. It is deliberately data, not prose: the
 * validator owns the wording.
 */
export interface ResolveError {
  target: string;
  path: string[];
  namespace: Namespace;
  reason: ResolveReason;
}

/** The outcome of resolving a field path. */
export type ResolveResult =
  | { ok: true; field: FieldRef }
  | { ok: false; error: ResolveError };

/**
 * Resolves field paths for a target and answers the closed-vocabulary questions
 * the validator asks.
 */
export interface Catalog {
  /** Lists the query targets this catalogue knows. */
  targets(): Target[];
  /**
   * Lists a target's resolvable fields, for suggestions and autocomplete.
   * Namespaced entries appear under their prefixed name.
   */
  fields(target: string): FieldInfo[];
  /**
   * Resolves a field path against a target. The returned FieldRef carries
   * namespace, key, type and accessor filled in.
   */
  resolve(target: string, path: string[]): ResolveResult;
  /** Lists the twenty relationship spellings. */
  relationshipNames(): readonly Relationship[];
  /** Resolves a class key to its path. */
  classExists(key: string): ClassInfo | null;
  /** Returns the closed value set of a resolved field, if it has one. */
  enumValues(field: FieldRef): string[] | null;
  /**
   * Optional: lists every class key, so an unknown class key gets a "did you
   * mean". Without it, the unknown class is still reported, just without a
   * suggestion.
   */
  classKeys?(): string[];
}

/** Returns the named target. */
export function findTarget(c: Catalog, name: string): Target | null {
  const lower = name.toLowerCase();
  for (const t of c.targets()) if (t.name.toLowerCase() === lower) return t;
  return null;
}

/** Lists the catalogue's target names, for error messages. */
export function targetNames(c: Catalog): string[] {
  return c.targets().map((t) => t.name);
}

/** Lists a target's field names, for suggestions. */
export function fieldNames(c: Catalog, target: string): string[] {
  return c.fields(target).map((f) => f.name);
}

/**
 * Maps a sub-predicate collection name (§3) to the target whose field catalogue
 * its inner predicate resolves against.
 */
export const COLLECTION_TARGET: Readonly<Record<string, string>> = {
  endpoint: 'endpoint',
  software: 'software_install',
  finding: 'finding',
  cert: 'certificate',
  crypto: 'crypto_configuration',
  identifier: 'identifier',
  relationship: 'relationship',
  asset: 'asset',
};

// ------------------------------------------------- the §4.4 operator matrix --

// The type → operator matrix of QUERY_LANGUAGE.md §4.4, in one table so the
// validator has exactly one opinion about what is legal.
//
// Two rows read as narrower than a glance suggests, and deliberately so: class
// names only `=` in the `= !=` column ("`=` exact only"), and keyword[] names
// only `=` ("`=` contains"). Neither accepts `!=`: "this asset's class is not
// exactly X" and "this array does not contain X" are both better written with
// `not`, where the three-valued rule (§5.2) is visible in the text rather than
// hidden in an operator.

interface Ops {
  colon: boolean;
  eq: boolean;
  ne: boolean;
  ordering: boolean;
  in: boolean;
  match: boolean;
  rng: boolean;
  wildcard: boolean;
}

function ops(p: Partial<Ops>): Ops {
  return {
    colon: false,
    eq: false,
    ne: false,
    ordering: false,
    in: false,
    match: false,
    rng: false,
    wildcard: false,
    ...p,
  };
}

const MATRIX: Readonly<Partial<Record<FieldType, Ops>>> = {
  keyword: ops({ colon: true, eq: true, ne: true, in: true, match: true, wildcard: true }),
  text: ops({ colon: true, eq: true, ne: true, in: true, match: true, wildcard: true }),
  number: ops({ colon: true, eq: true, ne: true, ordering: true, in: true, rng: true }),
  timestamp: ops({ colon: true, eq: true, ne: true, ordering: true, rng: true }),
  boolean: ops({ colon: true, eq: true, ne: true }),
  inet: ops({ colon: true, eq: true, ne: true, in: true, wildcard: true }),
  class: ops({ colon: true, eq: true, in: true }),
  band: ops({ colon: true, eq: true, ne: true, ordering: true, in: true, rng: true }),
  version: ops({ colon: true, eq: true, ne: true, ordering: true, in: true, wildcard: true }),
  uuid: ops({ colon: true, eq: true, ne: true, in: true }),
  'keyword[]': ops({ colon: true, eq: true, in: true }),
  // A json field accepts no operator at all — `exists(…)` is the only honest
  // question about an array or an object whose accessor yields raw text.
  json: ops({}),
};

/** Reports whether op may be applied to a field of type t. */
export function operatorAllowed(t: FieldType, op: Op): boolean {
  const o = MATRIX[t];
  if (o === undefined) return false;
  switch (op) {
    case ':':
      return o.colon;
    case '=':
      return o.eq;
    case '!=':
      return o.ne;
    default:
      return isOrdering(op) ? o.ordering : false;
  }
}

/** Reports whether `in (…)` may be applied to type t. */
export function inAllowed(t: FieldType): boolean {
  return MATRIX[t]?.in ?? false;
}

/** Reports whether `~ "regex"` may be applied to type t. */
export function matchAllowed(t: FieldType): boolean {
  return MATRIX[t]?.match ?? false;
}

/** Reports whether `[lo to hi]` may be applied to type t. */
export function rangeAllowed(t: FieldType): boolean {
  return MATRIX[t]?.rng ?? false;
}

/**
 * Reports whether a `*` value may be applied to type t. A bare `*` on its own
 * is the "present at all" spelling and is allowed for every type, which is why
 * the validator checks this only for a partial wildcard.
 */
export function wildcardAllowed(t: FieldType): boolean {
  return MATRIX[t]?.wildcard ?? false;
}

/**
 * Reports whether t is a type the matrix covers. An unresolved field has no
 * type and must never reach a translator.
 */
export function knownType(t: FieldType): boolean {
  return MATRIX[t] !== undefined;
}

/** Lists the operators legal on type t, for error messages and autocomplete. */
export function operatorsFor(t: FieldType): string[] {
  const o = MATRIX[t];
  const out: string[] = [];
  if (o === undefined) return ['exists'];
  if (o.colon) out.push(':');
  if (o.eq) out.push('=');
  if (o.ne) out.push('!=');
  if (o.ordering) out.push('<', '<=', '>', '>=');
  if (o.in) out.push('in');
  if (o.match) out.push('~');
  if (o.rng) out.push('[a to b]');
  out.push('exists');
  return out;
}

// ------------------------------------------------------------ band ladder --

/** One rung of a band ladder: a label and its inclusive lower bound. */
export interface Band {
  label: string;
  min: number;
}

/**
 * Supplies the score→label ladder a band-typed field is compared through
 * (§5.5).
 *
 * It is an interface because the one true ladder lives in
 * `services/inventory-service/internal/models/risk_bands.go`. The caller passes
 * it in; a translator generates every band predicate from it and never writes a
 * threshold of its own. That is the whole point: badges at >= 60 while facets
 * used >= 70 is the drift this indirection exists to make impossible.
 */
export interface BandLadder {
  /** The ladder ordered highest-first, each with its inclusive lower bound. */
  bands(): Band[];
}

/**
 * The pseudo-band meaning "nobody scored this" (§5.2). It is not a rung of the
 * ladder: `risk:informational` is assessed and scored zero, and
 * `risk:not_assessed` is a different set. Only a band field whose accessor
 * names an `assessedBy` column accepts it.
 */
export const NOT_ASSESSED = 'not_assessed';

/**
 * Returns the ladder's labels, highest-first, plus not_assessed when the field
 * supports it. Used for error messages and autocomplete.
 */
export function bandLabels(l: BandLadder, withNotAssessed: boolean): string[] {
  const out = l.bands().map((b) => b.label.toLowerCase());
  if (withNotAssessed) out.push(NOT_ASSESSED);
  return out;
}

/** Finds a band by label, case-insensitively. */
export function bandIndex(l: BandLadder, label: string): number {
  const bands = l.bands();
  for (let i = 0; i < bands.length; i++) {
    if (bands[i].label.toLowerCase() === label.toLowerCase()) return i;
  }
  return -1;
}
