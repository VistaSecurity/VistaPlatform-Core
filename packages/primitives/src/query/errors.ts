// The structured error the query language reports.
//
// QUERY_LANGUAGE.md §10: errors are `{code, message, span, suggestion?}`.
// Messages are lowercase, name the offending span, and offer the fix — never
// "invalid query". §6 fixes the code vocabulary for validation; `syntax_error`
// is the one addition, for text that does not parse at all.

import type { Span } from './ast';

/**
 * The stable, machine-readable error code. Callers switch on it; the UI maps it
 * to help text.
 */
export type ErrorCode =
  /** Text that does not parse. Not in §6's table, which covers validation only. */
  | 'syntax_error'
  /** A field that resolves in no namespace for the target. */
  | 'unknown_field'
  /** An operator the field's type does not accept. */
  | 'operator_not_allowed'
  /** A literal that does not parse as the field's type. */
  | 'type_mismatch'
  /** A value outside a closed set: an enum member, a class key, a relationship name. */
  | 'unknown_value'
  /** A traversal budget over the configured or hard cap. */
  | 'depth_exceeded'
  /** A pattern outside the dialect, too long, or repeating too many times. */
  | 'regex_invalid'
  /** Query text over the byte cap. */
  | 'query_too_long'
  /** Any of the four size caps in §6. */
  | 'too_many_clauses'
  /** A node that maps to none of the five SQL shapes. Fail-closed. */
  | 'untranslatable';

/** Every code, for exhaustive handling in a UI. */
export const ERROR_CODES: readonly ErrorCode[] = [
  'syntax_error',
  'unknown_field',
  'operator_not_allowed',
  'type_mismatch',
  'unknown_value',
  'depth_exceeded',
  'regex_invalid',
  'query_too_long',
  'too_many_clauses',
  'untranslatable',
];

/** One structured diagnostic. */
export interface QueryError {
  code: ErrorCode;
  message: string;
  span: Span;
  suggestion?: string;
}

/** Builds an error, optionally with a suggestion. */
export function newError(
  code: ErrorCode,
  span: Span,
  message: string,
  suggestion?: string,
): QueryError {
  const e: QueryError = { code, message, span };
  if (suggestion !== undefined) e.suggestion = suggestion;
  return e;
}

/** Returns a copy of e carrying the given suggestion. */
export function withSuggestion(e: QueryError, suggestion: string): QueryError {
  return { ...e, suggestion };
}

/** Renders one diagnostic as a single line. */
export function errorText(e: QueryError): string {
  if (e.suggestion !== undefined && e.suggestion !== '') {
    return `${e.code}: ${e.message} (${e.suggestion})`;
  }
  return `${e.code}: ${e.message}`;
}

/**
 * Returns the list ordered by span start, then by code, so output is
 * deterministic regardless of walk order.
 */
export function sortErrors(list: QueryError[]): QueryError[] {
  return [...list].sort((a, b) => {
    if (a.span.start !== b.span.start) return a.span.start - b.span.start;
    return a.code < b.code ? -1 : a.code > b.code ? 1 : 0;
  });
}

/** Returns just the codes, in list order. */
export function errorCodes(list: QueryError[]): ErrorCode[] {
  return list.map((e) => e.code);
}

/** Reports whether the list contains an error with the given code. */
export function hasCode(list: QueryError[], code: ErrorCode): boolean {
  return list.some((e) => e.code === code);
}

/**
 * Returns the candidate closest to word by Levenshtein distance, when that
 * distance is at most maxDist. §6 fixes maxDist at 2 for the unknown_field
 * suggestion; the same helper builds every other "did you mean" in the package
 * so one notion of "close" is used everywhere.
 */
export function nearest(word: string, candidates: readonly string[], maxDist: number): string | null {
  const lower = word.toLowerCase();
  let best = '';
  let bestDist = maxDist + 1;
  for (const c of candidates) {
    const d = levenshtein(lower, c.toLowerCase());
    if (d < bestDist || (d === bestDist && best !== '' && c < best)) {
      best = c;
      bestDist = d;
    }
  }
  if (bestDist > maxDist) return null;
  return best;
}

/**
 * `nearest` with one extra fallback, for closed value sets: a candidate that
 * starts with the word (or that the word starts with) is offered even when the
 * edit distance is larger, because a value is often the short form of a longer
 * one — "pending" for "pending_approval". Field suggestions deliberately do NOT
 * use this: §6 fixes those at edit distance 2.
 */
export function nearestValue(word: string, candidates: readonly string[]): string | null {
  const near = nearest(word, candidates, 2);
  if (near !== null) return near;
  const lower = word.toLowerCase();
  let best = '';
  for (const c of candidates) {
    const lc = c.toLowerCase();
    if (lower === '' || lc === '') continue;
    if (!lc.startsWith(lower) && !lower.startsWith(lc)) continue;
    if (best === '' || c.length < best.length) best = c;
  }
  return best === '' ? null : best;
}

/** Returns the edit distance between a and b, counting code points. */
export function levenshtein(a: string, b: string): number {
  const ar = [...a];
  const br = [...b];
  let prev = new Array<number>(br.length + 1);
  let cur = new Array<number>(br.length + 1);
  for (let j = 0; j <= br.length; j++) prev[j] = j;
  for (let i = 1; i <= ar.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= br.length; j++) {
      const cost = ar[i - 1] === br[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    const swap = prev;
    prev = cur;
    cur = swap;
  }
  return prev[br.length];
}

/**
 * Renders the §10 error display: the query, a caret run under the span, and the
 * message.
 */
export function caret(src: string, e: QueryError): string {
  let start = e.span.start;
  let end = e.span.end;
  if (start < 0) start = 0;
  if (end > src.length) end = src.length;
  if (end <= start) end = start + 1;
  let b = src + '\n' + ' '.repeat(start) + '^'.repeat(end - start) + '\n' + e.code + ': ' + e.message;
  if (e.suggestion !== undefined && e.suggestion !== '') b += '\n' + e.suggestion;
  return b;
}
