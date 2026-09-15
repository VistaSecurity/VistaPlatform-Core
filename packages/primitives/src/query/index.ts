// The asset-inventory query language, in TypeScript.
//
// One predicate form for scopes, saved views, the inventory facet rail and URL,
// auto-approval rules, alert and rule triggers, compliance measurements, the
// MCP `query` argument, and the grounded-query seam's translation target.
//
// The contract is
// docsv4/internal/developer/design/asset-inventory/QUERY_LANGUAGE.md; the
// server implementation is `shared/query` and the two are held to the same
// 228-case fixture file (`shared/query/testdata/conformance.json`). Section
// references in this package (§2, §5.6, …) are to that document.
//
// This half parses, validates, formats and completes. It deliberately does NOT
// translate to SQL — the server owns that, and a second translator would be a
// second opinion about what a query means.
//
//	import { check, format, parse, suggest } from '@vistasecurity/primitives/query';
//
//	const outcome = check('environment:production and risk >= high', 'asset', cat, opts);
//	if (!outcome.ok) show(outcome.errors);   // {code, message, span, suggestion?}

import type { Node } from './ast';
import type { Catalog } from './catalog';
import type { QueryError } from './errors';
import { newError } from './errors';
import { format } from './format';
import type { ParsedQuery } from './parser';
import { parse } from './parser';
import type { Options, ValidateResult } from './validate';
import { defaultOptions, utf8ByteLength, validate } from './validate';

export type {
  Accessor,
  AccessorKind,
  And,
  Compare,
  Direction,
  Exists,
  FieldRef,
  FieldType,
  FreeText,
  InSet,
  Literal,
  LiteralForm,
  Match,
  Namespace,
  Node,
  NodeKind,
  Not,
  Op,
  Or,
  Range,
  Span,
  Sub,
  Traverse,
  TraverseForm,
} from './ast';
export { NAMESPACES, asNamespace, isOrdering, mergeSpan, walk, walkFields } from './ast';

export type { JSONValue } from './json';
export { equalJSON, marshalJSON, toJSON } from './json';

export type { ErrorCode, QueryError } from './errors';
export {
  ERROR_CODES,
  caret,
  errorCodes,
  errorText,
  hasCode,
  levenshtein,
  nearest,
  nearestValue,
  newError,
  sortErrors,
  withSuggestion,
} from './errors';

export type { Mode, Token, TokenKind } from './lexer';
export { Lexer } from './lexer';

export type { ParseResult, ParsedQuery } from './parser';
export { MAX_DEPTH, parse } from './parser';

export { format } from './format';

export type {
  Band,
  BandLadder,
  Catalog,
  ClassInfo,
  FieldInfo,
  ResolveError,
  ResolveReason,
  ResolveResult,
  Target,
} from './catalog';
export {
  COLLECTION_TARGET,
  NOT_ASSESSED,
  bandIndex,
  bandLabels,
  fieldNames,
  findTarget,
  inAllowed,
  knownType,
  matchAllowed,
  operatorAllowed,
  operatorsFor,
  rangeAllowed,
  targetNames,
  wildcardAllowed,
} from './catalog';

export type { Options, ValidateResult } from './validate';
export { defaultOptions, utf8ByteLength, validate, withLadder } from './validate';

export type { Duration, DurationUnit, DateLiteral } from './literal';
export {
  KEYWORD_LIST,
  MAX_DURATION_YEARS,
  applyDuration,
  canonicalDuration,
  canonicalText,
  dateText,
  isBareStar,
  isBareValueChar,
  isIdentifier,
  isKeyword,
  isSafeBareword,
  isSafeFreeText,
  isWildcard,
  parseBool,
  parseDate,
  parseDuration,
  parseInet,
  parseNumber,
  parseUUID,
  quote,
  quoteFreeText,
  quoteLiteral,
  quoteValue,
  resolveDate,
} from './literal';

export { looksLikeVersion, versionSortKey } from './versionsort';

export type { Relationship } from './vocabulary';
export {
  ANY_REL,
  COLLECTIONS,
  REL_KEYWORD,
  RELATIONSHIPS,
  RELATIONSHIP_TYPES,
  isCollection,
  isRelationshipType,
  lookupRelationship,
  parseDirection,
} from './vocabulary';

export type { RegexCheck } from './regex';
export { MAX_REPETITION_BOUND, REGEX_SUBSET_HELP, checkRegexSubset } from './regex';

export type { CatalogVocabulary, NamespaceKey } from './base-catalog';
export { BaseCatalog } from './base-catalog';

export {
  COLLECTOR_MINTED_KINDS,
  IDENTIFIER_ANY_KIND,
  IDENTIFIER_KINDS,
  IDENTIFIER_KIND_ALIASES,
  NAMESPACES_BY_TARGET,
  TARGETS,
  USER_ENTERABLE_IDENTIFIER_KINDS,
  WRITABLE_IDENTIFIER_KINDS,
} from './targets';
export { TEST_FIELDS_BY_TARGET } from './test-fields';
export {
  OPERATORS_BY_TYPE,
  REGISTRY_FIELDS_BY_TARGET,
  REGISTRY_TARGETS,
} from './registry-fields.gen';

export type { RegistryCatalogOptions } from './registry-catalog';
export {
  CVSS_LADDER,
  RegistryCatalog,
  newRegistryCatalog,
  registryFieldType,
} from './registry-catalog';

export { LADDER as TEST_LADDER, TestCatalog, newTestCatalog, testClassKeys } from './test-catalog';

export type { Completion, CompletionKind, SuggestOptions, SuggestResult } from './suggest';
export { suggest } from './suggest';

/** A query that parsed and validated. */
export interface CheckedQuery {
  /** The text as written. */
  source: string;
  /**
   * `source` in canonical form (§10). Store this, not `source`: it is what a
   * saved view, a scope and a rule should carry.
   */
  canonical: string;
  /** The collection the predicate is over. */
  target: string;
  /** The validated AST, with every field resolved. */
  root: Node | null;
}

/** The outcome of `check`. */
export type CheckResult =
  | { ok: true; value: CheckedQuery }
  | { ok: false; errors: QueryError[] };

/**
 * Parses and validates a query without translating it — which is all this side
 * ever does. Use it for the editor, the facet rail, a scope being saved and an
 * approval rule being edited.
 */
export function check(
  source: string,
  target: string,
  cat: Catalog,
  opts: Options = defaultOptions(),
): CheckResult {
  const tooLongError = tooLong(source, opts);
  if (tooLongError !== null) return { ok: false, errors: [tooLongError] };

  const parsed = parse(source);
  if (!parsed.ok) return { ok: false, errors: parsed.errors };

  const outcome: ValidateResult = validate(parsed.value, target, cat, opts);
  if (!outcome.ok) return { ok: false, errors: outcome.errors };

  return {
    ok: true,
    value: {
      source,
      canonical: format(outcome.root),
      target,
      root: outcome.root,
    },
  };
}

/**
 * Applies §6's query_too_long cap BEFORE the text reaches the parser.
 *
 * The validator applies the same cap, but it cannot run until the parser has
 * built a tree — and building a tree out of megabytes of nesting is the
 * expensive part. The cheapest check has to come first; the validator's copy
 * stays for callers that use `validate` directly.
 */
function tooLong(source: string, opts: Options): QueryError | null {
  const limit = opts.maxBytes > 0 ? opts.maxBytes : defaultOptions().maxBytes;
  const n = utf8ByteLength(source);
  if (n <= limit) return null;
  return newError(
    'query_too_long',
    { start: 0, end: source.length },
    `query is ${n} bytes; the limit is ${limit}`,
  );
}

/**
 * Returns the canonical form of a query without consulting any catalogue.
 * Formatting is syntactic, so the facet rail can round-trip text it is still
 * editing (§10).
 */
export function canonicalize(source: string): { ok: true; text: string } | { ok: false; errors: QueryError[] } {
  const parsed = parse(source);
  if (!parsed.ok) return { ok: false, errors: parsed.errors };
  return { ok: true, text: format(parsed.value.root) };
}

/**
 * Parses and formats in one step, for a caller that already knows the text
 * parses. Returns the input unchanged when it does not, so a half-written query
 * in a rail is never silently replaced.
 */
export function formatOrSelf(source: string): string {
  const out = canonicalize(source);
  return out.ok ? out.text : source;
}

/** Re-exported so a caller can hold a parsed query without importing ./parser. */
export type { ParsedQuery as Parsed };
