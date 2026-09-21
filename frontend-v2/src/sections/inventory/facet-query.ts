// The facet rail ↔ query string round trip.
//
// ADR-0006 D2: "the facet rail writes the query for them and shows it, so the
// language is learned by reading." That makes the query string the single
// state, and the rail a BUILDER over it — not a parallel filter model that
// happens to be translated on its way out. There is exactly one predicate, it
// lives in the URL as `?query=`, and a saved view stores the same text.
//
// Two directions, and the second one is the one that is easy to get wrong:
//
//   facetsToQuery(state)  →  the canonical query text the rail produces
//   queryToFacets(text)   →  the facet state a query implies, PLUS the terms
//                            the rail cannot represent
//
// That second return value is the honest part. A user may type
// `depends_on:(class=database_instance)` into the editor, which no checkbox can
// show. Dropping it on the next checkbox click would silently discard their
// work; pretending the rail shows it would be a lie. So the reader keeps
// unrepresentable terms verbatim and the writer puts them back, and the rail
// tells the user they are there.
//
// Nothing here builds SQL. The server owns translation (see the query package's
// README: "a second translator would be a second opinion about what a query
// means").
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { format, parse, type Node, type Literal, type FieldRef } from '@vistasecurity/primitives/query';
import { OPEN_FINDINGS_QUERY } from '@vistasecurity/primitives/findings';

/**
 * Every facet the rail offers (ADR-0006 D2's v1 list). Each maps to one field
 * of the `asset` target in the generated catalogue.
 *
 * `findings` is back (workstream 3.1). It was withdrawn in Gate 1 because the
 * checkbox wrote `finding:(…)` over the unified `findings` table while the
 * number beside it came from a server facet level counting `compliance_findings`
 * — two tables, one question, and a user had no way to see the disagreement.
 * There is one findings table now, and the server produces its count by
 * COMPILING the very string this file writes (OPEN_FINDINGS_QUERY, generated
 * from standards/findings-registry.yaml), so the control and its number cannot
 * come apart again.
 */
export type FacetKey =
  | 'class'
  | 'status'
  | 'identity'
  | 'environment'
  | 'site'
  | 'segment'
  | 'owner'
  | 'business_unit'
  | 'tag'
  | 'risk'
  | 'provenance'
  | 'findings';

/** The query field each multi-select facet writes. `class`, `risk`, `tag` and
 *  `findings` are shaped differently and are handled on their own. */
export const FACET_FIELD: Readonly<Record<Exclude<FacetKey, 'class' | 'risk' | 'tag' | 'findings'>, string>> = {
  status: 'status',
  identity: 'identity_status',
  environment: 'environment',
  site: 'site',
  segment: 'segment_id',
  owner: 'owner_email',
  business_unit: 'business_unit',
  provenance: 'source',
};

/** Human labels for the rail's section headings. */
export const FACET_LABEL: Readonly<Record<FacetKey, string>> = {
  class: 'Class',
  status: 'Status',
  identity: 'Identity',
  environment: 'Environment',
  site: 'Site',
  segment: 'Segment',
  owner: 'Owner',
  business_unit: 'Business unit',
  tag: 'Tag',
  risk: 'Risk',
  provenance: 'Provenance',
  findings: 'Findings',
};

/**
 * The risk facet's rungs. `not_assessed` is NOT a rung of the ladder — it is
 * the absence of a score (QUERY_LANGUAGE §13 A2), which is why it is written
 * `risk:not_assessed` and never `risk >= not_assessed`. It is offered because
 * "nobody has looked at this" is the single most actionable slice in a fresh
 * tenant, and folding it into "Informational" is the exact dishonesty the
 * platform's score-0 convention exists to prevent.
 */
export const RISK_BANDS = ['critical', 'high', 'medium', 'low', 'informational', 'not_assessed'] as const;
export const RISK_BAND_LABEL: Readonly<Record<string, string>> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
  not_assessed: 'Not assessed',
};

/** The provenance facet's values — the four `class_source_kind`s. */
export const PROVENANCE_VALUES = ['measured', 'declared', 'imported', 'inferred', 'rule'] as const;
export const PROVENANCE_LABEL: Readonly<Record<string, string>> = {
  measured: 'Discovered',
  declared: 'Declared',
  imported: 'Imported',
  inferred: 'Proposed',
  rule: 'From a rule',
};

/**
 * The sub-predicate behind the "has open findings" facet.
 *
 * Re-exported rather than restated: OPEN_FINDINGS_QUERY is generated from
 * standards/findings-registry.yaml into both this package and Go's
 * findings.OpenQuery, and the inventory service's `has_findings` facet counts by
 * compiling that same text. One line of YAML, three consumers, no second
 * opinion about what "open" means.
 *
 * `detection_state` is the finding's own lifecycle (still detected?) and
 * `workflow_status` is the human one (has anyone dealt with it?). A finding is
 * open when both say so.
 */
export const OPEN_FINDINGS = OPEN_FINDINGS_QUERY;

/**
 * The identity facet's values — `assets_identity_status_check` ( D1).
 *
 * Identity is NOT approval: an asset can be monitored and still have an
 * identity nothing established, and a provisional item is pending approval by
 * construction. Two facets, because they answer two questions.
 *
 * The rail shows no counts beside these: the facets endpoint has no
 * `identity_status` level, and a zero beside every value would read as "you
 * have none of these" rather than as "nobody counted".
 */
export const IDENTITY_VALUES = ['established', 'operator_confirmed', 'provisional', 'legacy'] as const;
export const IDENTITY_LABEL: Readonly<Record<string, string>> = {
  established: 'Established',
  operator_confirmed: 'Operator-confirmed',
  provisional: 'Provisional',
  legacy: 'Not evaluated',
};

/** The status facet's values — the four `asset_status`es. */
export const STATUS_VALUES = ['monitoring', 'pending_approval', 'denied', 'archived'] as const;
export const STATUS_LABEL: Readonly<Record<string, string>> = {
  monitoring: 'Monitoring',
  pending_approval: 'Pending approval',
  denied: 'Denied',
  archived: 'Archived',
};

/** The rail's state. Multi-selects are OR-ed within a facet and AND-ed across
 *  facets, which is what every faceted search in the category does. */
export interface FacetState {
  /** A single class key, matched as a SUBTREE (`class:hardware` selects every
   *  hardware descendant). Picking one class replaces the previous pick — the
   *  taxonomy is a tree and a multi-select over it reads as nonsense. */
  class?: string;
  status: string[];
  /** `identity_status` values. A provisional item is found here and nowhere
   *  else — it is `pending_approval` like every other unapproved asset. */
  identity: string[];
  environment: string[];
  site: string[];
  segment: string[];
  owner: string[];
  business_unit: string[];
  /** `key` or `key=value` entries, written `tag:key` / `tag.key:value`. */
  tag: string[];
  risk: string[];
  provenance: string[];
  /** Tri-state. `true` → has at least one open finding; `false` → has none;
   *  undefined → the facet is off. `false` matters: "nothing found on this" is
   *  a different question from "nobody looked", and the risk facet's
   *  `not_assessed` answers the second. */
  findings?: boolean;
  /** Free-text terms the user typed (`payroll`), preserved in order. */
  text: string[];
}

export function emptyFacets(): FacetState {
  return {
    status: [], identity: [], environment: [], site: [], segment: [], owner: [],
    business_unit: [], tag: [], risk: [], provenance: [], text: [],
  };
}

/** True when no facet is set — the rail shows "no filters", and the query is
 *  the empty string (which matches everything under RLS). */
export function facetsEmpty(f: FacetState): boolean {
  return !f.class && f.findings === undefined
    && f.status.length === 0 && f.identity.length === 0 && f.environment.length === 0 && f.site.length === 0
    && f.segment.length === 0 && f.owner.length === 0 && f.business_unit.length === 0
    && f.tag.length === 0 && f.risk.length === 0 && f.provenance.length === 0
    && f.text.length === 0;
}

/** How many individual selections are active, for the "N filters" badge. */
export function facetCount(f: FacetState): number {
  return (f.class ? 1 : 0) + (f.findings === undefined ? 0 : 1)
    + f.status.length + f.identity.length + f.environment.length + f.site.length + f.segment.length
    + f.owner.length + f.business_unit.length + f.tag.length + f.risk.length
    + f.provenance.length + f.text.length;
}

// ------------------------------------------------------------------ write --

/**
 * §2/§10's quoting rule: a value is quoted iff it is not a safe bareword. We
 * apply the conservative half of it here and let `format` — which owns the
 * canonical form — decide the rest when it reparses. Over-quoting is safe;
 * under-quoting changes the parse.
 */
const SAFE_BAREWORD = /^[A-Za-z0-9_][A-Za-z0-9_.\-/@]*$/;
const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'to', 'exists', 'true', 'false']);
export function quoteValue(v: string): string {
  if (v === '') return '""';
  if (!SAFE_BAREWORD.test(v) || KEYWORDS.has(v.toLowerCase())) {
    return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return v;
}

/**
 * The bucket key GetAssetFacets uses for a NULL column
 * (`COALESCE(col, 'Unknown')`). Clicking it used to write `owner_email:Unknown`,
 * which matches the literal string — never the unset rows the count showed —
 * and on a closed enum (`environment:Unknown`) the server answers 400.
 *
 * The language spells NULL as `not exists(field)`; string columns also
 * need `field=""` to match the empty values counted in this bucket. Segment
 * uses a different sentinel because the SQL does.
 */
export const UNSET_BUCKET = 'Unknown';
export const UNSEGMENTED_BUCKET = 'Unsegmented';

// These facet columns group NULL and the empty string into the same bucket.
const EMPTY_IS_UNSET = new Set(['owner_email', 'business_unit', 'support_group', 'site', 'region', 'zone']);

function unsetBucketFor(field: string): string {
  return field === 'segment_id' ? UNSEGMENTED_BUCKET : UNSET_BUCKET;
}

function isUnsetBucket(field: string, value: string): boolean {
  return value === unsetBucketFor(field);
}

/**
 * `class:` matches a PREFIX of `class_path`. The rail stores the class KEY
 * (so the tree can highlight the picked node) and writes the PATH, which is
 * what the facet buckets, the dashboard hero and the command palette already
 * emit. Writing the key (`class:server`) happens to work in SQL because the
 * translator looks the key up and substitutes the path — but the in-memory
 * evaluator and a tenant subclass that is not in the generated registry both
 * prefix-match the literal, so the path is the one form that stays honest.
 */
function classSubtreeTerm(key: string): string {
  const path = ASSET_CLASSES[key as AssetClassKey]?.path ?? key;
  return `class:${quoteValue(path)}`;
}

/** Inverse of classSubtreeTerm: a path or a key both select that tree node. */
function classKeyFromQueryValue(value: string): string {
  if (Object.prototype.hasOwnProperty.call(ASSET_CLASSES, value)) return value;
  for (const [key, entry] of Object.entries(ASSET_CLASSES)) {
    if (entry.path === value) return key;
  }
  // Tenant-defined paths are not in the generated catalogue. Keep the entire
  // path so another facet click cannot silently change the selected subtree.
  return value;
}

/** `field:(a or b)` for many, `field:a` for one. The unset sentinel is written
 *  `not exists(field)` so the click matches the same rows the facet counted. */
function orTerm(field: string, values: string[]): string | null {
  const vs = values.filter((v) => v !== '');
  if (vs.length === 0) return null;
  const present = vs.filter((v) => !isUnsetBucket(field, v));
  const absent = vs.some((v) => isUnsetBucket(field, v));
  const parts: string[] = [];
  if (absent) {
    parts.push(`not exists(${field})`);
    if (EMPTY_IS_UNSET.has(field)) parts.push(`${field} = ""`);
  }
  if (present.length === 1) parts.push(`${field}:${quoteValue(present[0])}`);
  else if (present.length > 1) parts.push(`${field}:(${present.map(quoteValue).join(' or ')})`);
  if (parts.length === 0) return null;
  if (parts.length === 1) return parts[0];
  return `(${parts.join(' or ')})`;
}

/** A tag entry is either `key` (present at all) or `key=value`. */
function tagTerm(entry: string): string {
  const eq = entry.indexOf('=');
  if (eq < 0) return `tag:${quoteValue(entry)}`;
  return `tag.${entry.slice(0, eq)}:${quoteValue(entry.slice(eq + 1))}`;
}

/**
 * Writes the rail's state as a query string, appending any terms the rail could
 * not represent (`extra`) so a hand-edited traversal survives a checkbox click.
 *
 * The output is run through `format`, so what the rail produces is always
 * CANONICAL — which is what a saved view must store (§10) and what makes the
 * round-trip property testable at all.
 */
export function facetsToQuery(f: FacetState, extra: string[] = []): string {
  const terms: string[] = [];

  if (f.class) terms.push(classSubtreeTerm(f.class));

  // Ordered deliberately: clause order is preserved by the canonical form (§10),
  // so the query reads top-to-bottom in the same order as the rail's sections.
  const plain: Exclude<FacetKey, 'class' | 'risk' | 'tag' | 'findings'>[] =
    ['status', 'identity', 'environment', 'site', 'segment', 'owner', 'business_unit', 'provenance'];
  for (const key of plain) {
    const term = orTerm(FACET_FIELD[key], f[key]);
    if (term) terms.push(term);
  }

  for (const t of f.tag) terms.push(tagTerm(t));

  const risk = orTerm('risk', f.risk);
  if (risk) terms.push(risk);

  // "Has open findings" is an EXISTS over the child collection, not a column.
  //
  // OPEN has two halves and both are load-bearing: the finding is still
  // DETECTED (`detection_state:ACTIVE` — INACTIVE means the condition has gone
  // away) and a person has not closed it (`workflow_status` is neither RESOLVED
  // nor SUPPRESSED). Using only the first would count findings someone has
  // already signed off; using only the second would count findings that have
  // since been fixed.
  if (f.findings === true) terms.push(OPEN_FINDINGS);
  if (f.findings === false) terms.push(`not ${OPEN_FINDINGS}`);

  for (const t of f.text) terms.push(quoteValue(t));
  for (const e of extra) if (e.trim()) terms.push(e.trim());

  if (terms.length === 0) return '';
  const joined = terms.join(' and ');
  const canonical = parse(joined);
  return canonical.ok ? format(canonical.value.root) : joined;
}

/**
 * The query a facet change should produce — or `null` when the rail must not
 * write at all.
 *
 * When the typed text does not parse there is no `extra` to carry it in
 * (`queryToFacets` returns `extra: []`, because it has no tree to walk), so
 * writing the rail's state over the top DISCARDS whatever the user typed on
 * their next checkbox click. The rail refuses instead, and says why.
 */
export function applyFacetChange(read: FacetRead, next: FacetState): string | null {
  if (read.unparsed) return null;
  return facetsToQuery(next, read.extra);
}

// ------------------------------------------------------------------- read --

/** What a query says, split into what the rail can show and what it cannot. */
export interface FacetRead {
  facets: FacetState;
  /**
   * Top-level terms the rail has no control for, as canonical text. The rail
   * renders them read-only ("2 terms only the query editor can edit") and
   * `facetsToQuery` puts them back unchanged.
   */
  extra: string[];
  /** True when the text did not parse at all — the rail then shows nothing and
   *  defers entirely to the editor's error rendering. */
  unparsed: boolean;
}

/** Splits a tree into its top-level AND conjuncts. A single term is one
 *  conjunct; an `or` at the top is ONE conjunct, because the rail cannot
 *  represent a disjunction across facets. */
function conjuncts(root: Node | null): Node[] {
  if (!root) return [];
  return root.kind === 'and' ? root.children : [root];
}

function literalText(l: Literal): string {
  return l.value;
}

/** The field path as written, e.g. `environment`, `tag.env`, `attr.model`. */
function fieldPath(f: FieldRef): string {
  return f.segments.join('.');
}

/**
 * Recognises `field:(a or b)` — an Or whose children are all `cmp` with the `:`
 * operator on the SAME field. That is precisely the shape `orTerm` writes, and
 * recognising only that shape is deliberate: a looser reader would swallow
 * `environment:prod or risk:high` into the environment facet and change what
 * the query means.
 */
function sameFieldOr(node: Node): { field: string; values: string[] } | null {
  if (node.kind !== 'or') return null;
  let field: string | null = null;
  const values: string[] = [];
  for (const child of node.children) {
    if (child.kind !== 'cmp' || child.op !== ':') return null;
    const path = fieldPath(child.field);
    if (field === null) field = path;
    else if (field !== path) return null;
    values.push(literalText(child.value));
  }
  return field === null ? null : { field, values };
}

/** `not exists(field)` — the rail's spelling of the Unknown / Unsegmented bucket. */
function notExistsField(node: Node): string | null {
  if (node.kind !== 'not' || node.child.kind !== 'exists') return null;
  return fieldPath(node.child.field);
}

/**
 * A conjunct the rail wrote for one multi-select: either `field:a`,
 * `field:(a or b)`, `not exists(field)`, or a mix of the last two. Anything
 * else is extra.
 */
function fieldValues(node: Node): { field: string; values: string[] } | null {
  const absent = notExistsField(node);
  if (absent) return EMPTY_IS_UNSET.has(absent) ? null : { field: absent, values: [unsetBucketFor(absent)] };
  const grouped = sameFieldOr(node);
  if (grouped) return grouped;
  if (node.kind !== 'or') return null;
  let field: string | null = null;
  const values: string[] = [];
  let sawAbsent = false;
  let sawEmpty = false;
  const flattenOr = (n: Node): Node[] => n.kind === 'or' ? n.children.flatMap(flattenOr) : [n];
  for (const child of node.children.flatMap(flattenOr)) {
    const abs = notExistsField(child);
    if (abs) {
      if (field === null) field = abs;
      else if (field !== abs) return null;
      sawAbsent = true;
      continue;
    }
    if (child.kind !== 'cmp') return null;
    const path = fieldPath(child.field);
    const empty = child.op === '=' && literalText(child.value) === '' && EMPTY_IS_UNSET.has(path);
    if (child.op !== ':' && !empty) return null;
    if (field === null) field = path;
    else if (field !== path) return null;
    if (empty) sawEmpty = true;
    else values.push(literalText(child.value));
  }
  if (field === null) return null;
  if (EMPTY_IS_UNSET.has(field) && sawAbsent !== sawEmpty) return null;
  if (sawAbsent) values.push(unsetBucketFor(field));
  return { field, values };
}

/**
 * Recognises the findings facet's own sub-predicate.
 *
 * Rather than pattern-match the tree shape by hand — which would have to be
 * updated in step with `OPEN_FINDINGS` and would silently stop matching if it
 * were not — it compares CANONICAL TEXT against the canonical form of the one
 * string the writer emits. Formatting is idempotent and canonical (§10), so two
 * spellings of that predicate normalise to the same text and nothing else does.
 */
const OPEN_FINDINGS_CANONICAL = (() => {
  const parsed = parse(OPEN_FINDINGS);
  return parsed.ok ? format(parsed.value.root) : OPEN_FINDINGS;
})();

function isOpenFindings(node: Node): boolean {
  if (node.kind !== 'sub' || node.collection !== 'finding') return false;
  return format(node) === OPEN_FINDINGS_CANONICAL;
}

/**
 * Reads a query back into facet state.
 *
 * Only the shapes `facetsToQuery` writes are recognised. Everything else is
 * kept in `extra` verbatim, which is what makes the round trip lossless in both
 * directions — the property the tests pin.
 */
export function queryToFacets(text: string): FacetRead {
  const facets = emptyFacets();
  const extra: string[] = [];
  const source = text.trim();
  if (source === '') return { facets, extra, unparsed: false };

  const parsed = parse(source);
  if (!parsed.ok) return { facets, extra: [], unparsed: true };

  const byField: Record<string, keyof FacetState> = {
    status: 'status',
    identity_status: 'identity',
    environment: 'environment',
    site: 'site',
    segment_id: 'segment',
    owner_email: 'owner',
    business_unit: 'business_unit',
    source: 'provenance',
    risk: 'risk',
  };

  const push = (bucket: keyof FacetState, values: string[]) => {
    const target = facets[bucket] as string[];
    for (const v of values) if (!target.includes(v)) target.push(v);
  };

  for (const node of conjuncts(parsed.value.root)) {
    // `not finding:(…)` — the "no open findings" arm.
    if (node.kind === 'not' && isOpenFindings(node.child)) {
      facets.findings = false;
      continue;
    }
    if (isOpenFindings(node)) {
      facets.findings = true;
      continue;
    }
    // A `finding:(…)` the user wrote THEMSELVES, with any other predicate, is
    // still not a facet: it falls through to `extra` and is carried forward
    // untouched, so their query keeps meaning what it said.
    // `field:(a or b)` / `not exists(field)` / a mix of those two.
    const grouped = fieldValues(node);
    if (grouped) {
      const bucket = byField[grouped.field];
      if (bucket) { push(bucket, grouped.values); continue; }
      if (grouped.field.startsWith('tag.')) {
        push('tag', grouped.values.map((v) => `${grouped.field.slice(4)}=${v}`));
        continue;
      }
      extra.push(format(node));
      continue;
    }
    // `field:value`
    if (node.kind === 'cmp' && node.op === ':') {
      const path = fieldPath(node.field);
      const value = literalText(node.value);
      if (path === 'class') { facets.class = classKeyFromQueryValue(value); continue; }
      if (path === 'tag') { if (!facets.tag.includes(value)) facets.tag.push(value); continue; }
      if (path.startsWith('tag.')) {
        const entry = `${path.slice(4)}=${value}`;
        if (!facets.tag.includes(entry)) facets.tag.push(entry);
        continue;
      }
      const bucket = byField[path];
      if (bucket) { push(bucket, [value]); continue; }
      extra.push(format(node));
      continue;
    }
    // Free text
    if (node.kind === 'text') {
      const v = literalText(node.value);
      if (!facets.text.includes(v)) facets.text.push(v);
      continue;
    }
    extra.push(format(node));
  }

  return { facets, extra, unparsed: false };
}

// ----------------------------------------------------------------- toggles --

/** Toggles one value in a multi-select facet, returning a NEW state. */
export function toggleFacetValue(f: FacetState, key: Exclude<FacetKey, 'class' | 'findings'>, value: string): FacetState {
  const bucket = key as keyof FacetState;
  const current = f[bucket] as string[];
  const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  return { ...f, [bucket]: next };
}

/** Picks (or un-picks) the class facet. The taxonomy is a tree, so this is a
 *  single-select: clicking the active class clears it. */
export function setFacetClass(f: FacetState, classKey: string | undefined): FacetState {
  return { ...f, class: f.class === classKey ? undefined : classKey };
}

/**
 * The Inventory URL that lists exactly the assets `IdentitySummary.provisional`
 * counts ( D1), for the identity-coverage strip to link to.
 *
 * Two things make this less trivial than it looks, and both have bitten a count
 * link before:
 *
 * 1. `/infrastructure-assets` defaults to `asset_status = monitoring` when the
 *    caller constrains no status at all. A bare `identity_status:provisional`
 *    would therefore be AND-ed with `status:monitoring` server-side — and a
 *    provisional item is `pending_approval` by construction, so the link would
 *    land on an EMPTY list beside a non-zero number.
 * 2. The summary counts provisional assets that are "not archived or denied",
 *    which over the four statuses is exactly `pending_approval or monitoring`.
 *    Spelling that out is what makes the list and the number the same set.
 *
 * Written through `facetsToQuery` rather than hand-typed, so the rail reads it
 * straight back into ticked checkboxes and the canonical form cannot drift from
 * what the rail itself would write.
 */
export const PROVISIONAL_FACETS: FacetState = {
  ...emptyFacets(), identity: ['provisional'], status: ['pending_approval', 'monitoring'],
};
export const PROVISIONAL_INVENTORY_HREF = `/inventory?query=${encodeURIComponent(facetsToQuery(PROVISIONAL_FACETS))}`;

/** Cycles the findings facet: off → has open → has none → off. */
export function cycleFindings(f: FacetState): FacetState {
  if (f.findings === undefined) return { ...f, findings: true };
  if (f.findings === true) return { ...f, findings: false };
  return { ...f, findings: undefined };
}
