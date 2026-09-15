// The node types of the asset-inventory query language.
//
// The node set is fixed by QUERY_LANGUAGE.md §7.1 and is the cross-language
// contract: this port must produce the same tree as Go's `shared/query/ast` for
// the same text. Nothing here knows about SQL, the field catalogue, or the
// source text beyond the spans it carries.
//
// Spec: docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md
//
// One deliberate divergence from Go: a Span here is a half-open range of
// UTF-16 code units (a JavaScript string index), not UTF-8 bytes. Spans are not
// part of the cross-language contract — the compact JSON encoding omits them —
// and a text editor addresses its buffer in code units. The two places a length
// IS contractual keep Go's units exactly: the query cap is measured in UTF-8
// bytes and the regex cap in code points (see validate.ts).

/** A half-open range `[start, end)` of UTF-16 code units into the query source. */
export interface Span {
  start: number;
  end: number;
}

/** Returns the smallest span covering both inputs. */
export function mergeSpan(a: Span, b: Span): Span {
  return {
    start: b.start < a.start ? b.start : a.start,
    end: b.end > a.end ? b.end : a.end,
  };
}

/** Returns the smallest span covering every node in source order. */
export function spanOfNodes(nodes: Node[]): Span {
  if (nodes.length === 0) return { start: 0, end: 0 };
  let sp = nodes[0].span;
  for (let i = 1; i < nodes.length; i++) sp = mergeSpan(sp, nodes[i].span);
  return sp;
}

/**
 * A comparison operator. The `:=` spelling is normalised to `=` at parse time
 * (§10: canonical form writes `:=` as `=`).
 */
export type Op = ':' | '=' | '!=' | '<' | '<=' | '>' | '>=';

/** Reports whether op is one of `<` `<=` `>` `>=`. */
export function isOrdering(op: Op): boolean {
  return op === '<' || op === '<=' || op === '>' || op === '>=';
}

/** The traversal direction of a Traverse node. */
export type Direction = 'out' | 'in' | 'any';

/**
 * Which of the three surface spellings a traversal used, so the formatter can
 * write back the form the author chose (§3).
 *
 * - `named` is `depends_on:(…)` / `used_by(2):(…)`
 * - `rel` is `rel(connects_to, in, 2):(…)`
 * - `any` is `any_rel:(…)` / `any_rel(2):(…)`
 */
export type TraverseForm = 'named' | 'rel' | 'any';

/**
 * The prefix a field path carries (§4.2). A bare name resolves only against the
 * target's first-class columns, so a class attribute can never shadow a column.
 */
export type Namespace = '' | 'attr' | 'fact' | 'id' | 'tag';

/** The four namespace prefixes, for suggestions and docs. */
export const NAMESPACES: readonly Exclude<Namespace, ''>[] = ['attr', 'fact', 'id', 'tag'];

/** Resolves a string to a namespace prefix, case-insensitively. */
export function asNamespace(s: string): Namespace | null {
  switch (s.toLowerCase()) {
    case 'attr':
      return 'attr';
    case 'fact':
      return 'fact';
    case 'id':
      return 'id';
    case 'tag':
      return 'tag';
    default:
      return null;
  }
}

/**
 * The declared type of a field. It decides which operators are legal (§4.4) and
 * which SQL shape the server's translator emits (§7.2). `''` is the unresolved
 * zero value, before the validator resolves a field.
 *
 * `json` is a jsonb value that is not a scalar — an array or an object a
 * registry declares. It accepts NO operator, only `exists(…)`: the accessor for
 * a jsonb value yields its raw text, so `keyword[]` would generate
 * `unnest(text)` and `array_length(text)` — errors from Postgres, not answers.
 * `keyword[]` is for a real `text[]` COLUMN, and those are first-class fields.
 */
export type FieldType =
  | 'keyword'
  | 'text'
  | 'number'
  | 'timestamp'
  | 'boolean'
  | 'inet'
  | 'class'
  | 'band'
  | 'version'
  | 'uuid'
  | 'keyword[]'
  | 'json'
  | '';

/**
 * Picks the SQL shape a resolved field uses. Every accessor is built by the
 * catalogue, never from user text, which is what keeps a user-supplied
 * identifier out of SQL (§7.1).
 */
export type AccessorKind =
  | 'column'
  | 'jsonb'
  | 'fact'
  | 'identifier'
  | 'tag_any'
  | 'identifier_any'
  | 'derived';

/**
 * How the translator reaches a field's value. `column`, `jsonColumn` and
 * `derived` are code-supplied strings from the catalogue; `key` holds user text
 * and is always bound as a parameter server-side.
 */
export interface Accessor {
  kind: AccessorKind;
  /** The logical relation inside the SQL shape that owns the column. */
  rel?: string;
  /** The physical column name. */
  column?: string;
  /** The jsonb column, for kind `jsonb`. */
  jsonColumn?: string;
  /** The jsonb key, fact key or identifier kind. User text: bound. */
  key?: string;
  /** Names the translator's builder, for kind `derived`. */
  derived?: string;
  /** An optional SQL cast, for enum columns compared as text. */
  cast?: string;
  /** The materialised class-path column of a `class` field (§5.3). */
  pathColumn?: string;
  /** The stored band label of a `band` field, where the row carries one. */
  labelColumn?: string;
  /** The normalised component-wise sort key of a `version` field. */
  sortColumn?: string;
  /** The column proving a band field was assessed at all (§5.2). */
  assessedBy?: string;
}

/**
 * A field as it appears in the AST. The parser fills `segments`, `quoted`,
 * `text` and `span`; the validator fills the rest by resolving against the
 * catalogue. Only a resolved FieldRef may reach a translator.
 */
export interface FieldRef {
  /** Path segments as written: unquoted lowercased, quoted kept verbatim. */
  segments: string[];
  /** Marks which segments were written as quoted strings. */
  quoted: boolean[];
  /** The canonical rendering of the path. */
  text: string;
  /** The resolved prefix. */
  namespace: Namespace;
  /** The resolved key within the namespace. */
  key: string;
  /** The resolved field type. */
  type: FieldType;
  /** The resolved accessor. */
  accessor: Accessor;
  /** When non-empty, the closed value set the validator checks against. */
  enum?: string[];
  /** Whether the validator has resolved this reference. */
  resolved: boolean;
  span: Span;
}

/** The quoting form of a literal. */
export type LiteralForm = 'bare' | 'string';

/**
 * A value as written in the query. Classification into number, duration, date
 * and so on happens at validation time against the field's declared type, never
 * at parse time — the same text is a number for one field and a keyword for
 * another.
 */
export interface Literal {
  form: LiteralForm;
  value: string;
  span: Span;
}

// ------------------------------------------------------------------ nodes --

/** A conjunction. Juxtaposition in the source is an And (§2). */
export interface And {
  kind: 'and';
  children: Node[];
  span: Span;
}

/** A disjunction. */
export interface Or {
  kind: 'or';
  children: Node[];
  span: Span;
}

/** Negation. `-term` and `not term` both parse to this. */
export interface Not {
  kind: 'not';
  child: Node;
  span: Span;
}

/** A single field/operator/literal term. */
export interface Compare {
  kind: 'cmp';
  field: FieldRef;
  op: Op;
  value: Literal;
  span: Span;
}

/**
 * `field in (a, b)` and `field not in (a, b)`. Negation is kept on the node
 * rather than wrapped in a Not so the formatter can write back `not in`.
 */
export interface InSet {
  kind: 'in';
  field: FieldRef;
  values: Literal[];
  negated: boolean;
  span: Span;
}

/** `field:[lo to hi]`, inclusive at both ends (§3). */
export interface Range {
  kind: 'range';
  field: FieldRef;
  lo: Literal;
  hi: Literal;
  span: Span;
}

/** `field ~ "regex"`. The pattern is validated, never run, by the validator. */
export interface Match {
  kind: 'match';
  field: FieldRef;
  regex: string;
  span: Span;
}

/**
 * `exists(field)`. `exists(<collection>)` parses to a Sub with a null predicate
 * instead, because that is an EXISTS over a child table.
 */
export interface Exists {
  kind: 'exists';
  field: FieldRef;
  span: Span;
}

/** A term with no field (§5.4). */
export interface FreeText {
  kind: 'text';
  value: Literal;
  span: Span;
}

/**
 * An EXISTS over a child collection: `endpoint:(…)`. A null predicate means "at
 * least one row exists", the shape `exists(endpoint)` produces.
 */
export interface Sub {
  kind: 'sub';
  collection: string;
  predicate: Node | null;
  span: Span;
}

/**
 * A depth-bounded walk over asset relationships (§5.6).
 *
 * `name` is what the author wrote (a canonical type, a reverse label, or
 * `any_rel`); `type` and `direction` are the resolved canonical edge type and
 * the direction to walk it. Depth 1 is the grammar default.
 */
export interface Traverse {
  kind: 'traverse';
  form: TraverseForm;
  name: string;
  type: string;
  direction: Direction;
  depth: number;
  predicate: Node;
  span: Span;
}

/** One node of the parsed query. The set is closed — these eleven are the whole language (§7.1). */
export type Node =
  | And
  | Or
  | Not
  | Compare
  | InSet
  | Range
  | Match
  | Exists
  | FreeText
  | Sub
  | Traverse;

/** The stable node tags used by the compact JSON encoding. */
export type NodeKind = Node['kind'];

/**
 * Calls fn for n and, unless fn returns false, for every descendant in source
 * order.
 */
export function walk(n: Node | null, fn: (node: Node) => boolean): void {
  if (n === null) return;
  if (!fn(n)) return;
  switch (n.kind) {
    case 'and':
    case 'or':
      for (const c of n.children) walk(c, fn);
      return;
    case 'not':
      walk(n.child, fn);
      return;
    case 'sub':
      walk(n.predicate, fn);
      return;
    case 'traverse':
      walk(n.predicate, fn);
      return;
    default:
      return;
  }
}

/**
 * Calls fn for every FieldRef in the tree, by reference, so a resolver can fill
 * in namespace, type and accessor in place.
 */
export function walkFields(n: Node | null, fn: (f: FieldRef) => void): void {
  walk(n, (node) => {
    switch (node.kind) {
      case 'cmp':
      case 'in':
      case 'range':
      case 'match':
      case 'exists':
        fn(node.field);
        break;
      default:
        break;
    }
    return true;
  });
}
