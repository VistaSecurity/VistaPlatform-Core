// Autocomplete for the query editor and the facet rail.
//
// §1: "Learnable by reading. The facet rail writes the query and shows it; a
// user learns the language by watching the UI produce it." Autocomplete is the
// other half of that — it is how the vocabulary §4 generates becomes visible
// without a manual.
//
// This is the one part of the package with no Go counterpart and no conformance
// fixture: nothing about it crosses the wire. It is held instead to one rule —
// it may only ever offer what the validator would accept — which is why every
// list here comes from the catalogue or from the §4.4 matrix rather than from a
// literal written out again, and why `suggest.test.ts` substitutes every
// completion it produces back into a query and validates it.
//
// Where the cursor is, and what target it is inside, is `analyse.ts`.

import type { Analysis } from './analyse';
import { analyse } from './analyse';
import type { FieldType } from './ast';
import type { BandLadder, Catalog, FieldInfo } from './catalog';
import { NOT_ASSESSED, bandLabels, findTarget, operatorsFor } from './catalog';
import { levenshtein } from './errors';
import { ANY_REL, COLLECTIONS, REL_KEYWORD } from './vocabulary';

/** What a completion stands for, so the UI can icon and group it. */
export type CompletionKind =
  | 'field'
  | 'namespace'
  | 'operator'
  | 'value'
  | 'class'
  | 'relationship'
  | 'collection'
  | 'keyword';

/** One ranked completion. */
export interface Completion {
  /** The text to insert in place of `span`. */
  text: string;
  kind: CompletionKind;
  /** Help text: a field's description, a type name, what an operator means. */
  detail?: string;
  /**
   * Higher sorts first. Exact prefix matches outrank substring matches, which
   * outrank near-misses; within a kind, the more specific vocabulary outranks
   * the more general.
   */
  score: number;
}

/** The result of asking for completions at a cursor. */
export interface SuggestResult {
  /**
   * The half-open range of the source the completions replace. It is the token
   * being typed, which is empty when the cursor sits after a separator.
   */
  span: { start: number; end: number };
  /** Where the cursor is, for a UI that wants to label the list. */
  context: Analysis['kind'];
  /**
   * The target the cursor is INSIDE, which is not the one passed in once the
   * cursor is inside a sub-predicate or a traversal. A UI showing "completing a
   * field on endpoints" wants this one.
   */
  target: string;
  completions: Completion[];
}

/** What `suggest` needs beyond the catalogue. */
export interface SuggestOptions {
  /** The target the predicate is over; defaults to `asset`. */
  target?: string;
  /**
   * The band ladder, so `risk >= ` can offer the rungs by name. Without one,
   * band values are not offered rather than guessed.
   */
  ladder?: BandLadder;
  /** Caps the returned list. Default 50; pass 0 for no cap. */
  limit?: number;
}

/**
 * Returns ranked completions for the cursor position in text.
 *
 * `cursor` is an offset in UTF-16 code units — a plain JavaScript string index,
 * which is what a textarea's `selectionStart` gives you.
 */
export function suggest(
  text: string,
  cursor: number,
  cat: Catalog,
  opts: SuggestOptions = {},
): SuggestResult {
  const at = Math.max(0, Math.min(cursor, text.length));
  const a = analyse(text.slice(0, at), opts.target ?? 'asset', cat);

  let completions: Completion[];
  switch (a.kind) {
    case 'value':
      completions = valueCompletions(a, cat, opts);
      break;
    case 'operator':
      completions = operatorCompletions(a, cat);
      break;
    default:
      completions = headCompletions(a, cat);
      break;
  }

  const limit = opts.limit === undefined ? 50 : opts.limit;
  completions.sort(
    (x, y) => y.score - x.score || x.text.length - y.text.length || (x.text < y.text ? -1 : 1),
  );
  return {
    span: { start: a.start, end: at },
    context: a.kind,
    target: a.target,
    completions: limit > 0 ? completions.slice(0, limit) : completions,
  };
}

// --------------------------------------------------------------- the head --

/** Completions at the head of a term: fields, namespaces, vocabulary, keywords. */
function headCompletions(a: Analysis, cat: Catalog): Completion[] {
  const out: Completion[] = [];
  const written = a.written;
  const tgt = findTarget(cat, a.target);

  // §3: `exists(field)` takes a field path or a collection name and nothing
  // else. Offering an operator, a keyword or a traversal there would be
  // offering text that cannot parse.
  if (a.insideExists === true) {
    for (const f of cat.fields(a.target)) {
      const score = match(written, f.name);
      if (score !== 0) {
        out.push({ text: f.name, kind: 'field', score: score * 10 + 5, detail: f.description ?? f.type });
      }
    }
    for (const c of COLLECTIONS) {
      if (tgt === null || !tgt.subs.includes(c)) continue;
      const score = match(written, c);
      if (score !== 0) {
        out.push({ text: c, kind: 'collection', score: score * 10 + 3, detail: `at least one ${c}` });
      }
    }
    return out;
  }

  for (const f of cat.fields(a.target)) {
    const score = match(written, f.name);
    if (score === 0) continue;
    out.push({
      text: f.name,
      kind: 'field',
      score: score * 10 + 5,
      detail: f.description ?? f.type,
    });
  }

  // The four namespace prefixes, so `attr.` and `fact.` are discoverable before
  // a key is typed. They rank below the fields they stand in for, except when
  // the user has typed the prefix itself.
  if (tgt !== null) {
    for (const ns of ['attr', 'fact', 'id', 'tag']) {
      if (!cat.fields(a.target).some((f) => f.name.startsWith(ns + '.') || f.name === ns)) continue;
      const score = match(written, ns + '.');
      if (score === 0) continue;
      out.push({ text: ns + '.', kind: 'namespace', score: score * 10 + 4, detail: namespaceHelp(ns) });
    }

    for (const c of COLLECTIONS) {
      if (!tgt.subs.includes(c)) continue;
      const score = match(written, c);
      if (score === 0) continue;
      out.push({
        text: c + ':(',
        kind: 'collection',
        score: score * 10 + 3,
        detail: `at least one ${c} matching …`,
      });
    }

    if (tgt.traversable) {
      for (const r of cat.relationshipNames()) {
        const score = match(written, r.name);
        if (score === 0) continue;
        out.push({
          text: r.name + ':(',
          kind: 'relationship',
          score: score * 10 + 2,
          detail: r.reverse ? `the reverse of ${r.type}` : 'one hop, unless a count is given',
        });
      }
      for (const name of [ANY_REL, REL_KEYWORD]) {
        const score = match(written, name);
        if (score === 0) continue;
        out.push({
          text: name === ANY_REL ? ANY_REL + ':(' : REL_KEYWORD + '(',
          kind: 'relationship',
          score: score * 10 + 1,
          detail: name === ANY_REL ? 'traverse every type' : 'rel(type, direction, hops)',
        });
      }
    }
  }

  // `and` and `or` join two terms, so they are offered only where there is a
  // term to their left — never at the head of an empty predicate, and never
  // straight after another connective. Autocomplete may only offer what the
  // validator would accept.
  const keywords = a.afterTerm ? ['and', 'or', 'not', 'exists('] : ['not', 'exists('];
  for (const kw of keywords) {
    const score = match(written, kw);
    if (score === 0) continue;
    out.push({ text: kw, kind: 'keyword', score: score * 10, detail: keywordHelp(kw) });
  }
  return out;
}

function namespaceHelp(ns: string): string {
  switch (ns) {
    case 'attr':
      return 'a class attribute';
    case 'fact':
      return 'a registered fact key';
    case 'id':
      return 'an identifier kind; id.any matches any kind';
    default:
      return 'a tenant tag key';
  }
}

function keywordHelp(kw: string): string {
  switch (kw) {
    case 'and':
      return 'both — two terms side by side mean this too';
    case 'or':
      return 'either';
    case 'not':
      return 'negate the next term';
    default:
      return 'the field is present at all';
  }
}

// ----------------------------------------------------------- the operator --

/** The operators §4.4 allows on the field's type, and nothing else. */
function operatorCompletions(a: Analysis, cat: Catalog): Completion[] {
  const f = a.field === undefined ? null : lookupField(cat, a.target, a.field);
  if (f === null) return [];
  const out: Completion[] = [];
  for (const op of operatorsFor(f.type)) {
    if (op === 'exists') continue;
    const score = match(a.written, op);
    if (score === 0) continue;
    out.push({ text: op, kind: 'operator', score, detail: operatorHelp(op, f.type) });
  }
  return out;
}

function operatorHelp(op: string, t: FieldType): string {
  if (op === ':') {
    switch (t) {
      case 'text':
        return 'contains, case-insensitive';
      case 'class':
        return 'this class and everything under it';
      case 'inet':
        return 'equal, or inside this CIDR block';
      case 'keyword[]':
        return 'the array contains this';
      default:
        return 'equal, case-insensitive';
    }
  }
  switch (op) {
    case '=':
      return t === 'class' ? 'exactly this class, not its subtree' : 'equal, case-sensitive';
    case '!=':
      return 'not equal — and not "never measured"';
    case 'in':
      return 'any of';
    case '~':
      return 'matches this regular expression';
    case '[a to b]':
      return 'between, inclusive';
    default:
      return 'compare';
  }
}

// -------------------------------------------------------------- the value --

/** Completions in a value position, decided by the field's type. */
function valueCompletions(a: Analysis, cat: Catalog, opts: SuggestOptions): Completion[] {
  const f = a.field === undefined ? null : lookupField(cat, a.target, a.field);
  if (f === null) return [];
  const written = a.written;
  const op = a.op ?? ':';
  const out: Completion[] = [];

  if (f.enum !== undefined) {
    for (const v of f.enum) {
      const score = match(written, v);
      if (score !== 0) out.push({ text: v, kind: 'value', score: score * 10 + 1 });
    }
  }

  switch (f.type) {
    case 'class': {
      const keys = cat.classKeys === undefined ? [] : cat.classKeys();
      for (const key of keys) {
        const score = match(written, key);
        if (score === 0) continue;
        const info = cat.classExists(key);
        out.push({
          text: key,
          kind: 'class',
          score: score * 10 + 1,
          ...(info === null
            ? {}
            : { detail: op === ':' ? `${info.path} and everything under it` : info.path }),
        });
      }
      break;
    }
    case 'band': {
      if (opts.ladder === undefined) break;
      // §13 A2: not_assessed is the absence of a score, not a rung of the
      // ladder, so it is legal with `:` `=` `!=` and nothing else. Offering it
      // after `>=` would write a query the validator then refuses — autocomplete
      // teaching the user a rule that is not the rule.
      const ordering = op === '<' || op === '<=' || op === '>' || op === '>=';
      const coverage = (f.accessor.assessedBy ?? '') !== '' && !ordering;
      for (const label of bandLabels(opts.ladder, coverage)) {
        const score = match(written, label);
        if (score === 0) continue;
        out.push({
          text: label,
          kind: 'value',
          score: score * 10 + 1,
          ...(label === NOT_ASSESSED ? { detail: 'nobody has scored it' } : {}),
        });
      }
      break;
    }
    case 'boolean':
      for (const v of ['true', 'false']) {
        const score = match(written, v);
        if (score !== 0) out.push({ text: v, kind: 'value', score: score * 10 + 1 });
      }
      break;
    case 'timestamp':
      for (const v of ['now', 'now-7d', 'now-30d', 'now-90d', 'now+30d']) {
        const score = match(written, v);
        if (score !== 0) {
          out.push({ text: v, kind: 'value', score: score * 10 + 1, detail: 'relative to the query' });
        }
      }
      break;
    default:
      break;
  }

  // `field:*` is the "present at all" spelling and is legal on every type (§3
  // cheat sheet) — but only with ":", and never inside quotes, where it is an
  // ordinary asterisk.
  if (op === ':' && a.quoted !== true) {
    const score = match(written, '*');
    if (score !== 0) {
      out.push({ text: '*', kind: 'value', score, detail: 'present at all' });
    }
  }
  return out;
}

/**
 * Resolves a written field path to its catalogue entry.
 *
 * `fields()` is consulted first so the entry carries its description; a tag key
 * is free-form and is not published there, so the resolved reference is used to
 * synthesise one rather than losing the type.
 */
function lookupField(cat: Catalog, target: string, path: string): FieldInfo | null {
  const out = cat.resolve(target, path.toLowerCase().split('.'));
  if (!out.ok) return null;
  const name = path.toLowerCase();
  for (const f of cat.fields(target)) {
    if (f.name.toLowerCase() === name) return f;
  }
  return {
    name,
    type: out.field.type,
    accessor: out.field.accessor,
    ...(out.field.enum === undefined ? {} : { enum: out.field.enum }),
  };
}

/**
 * Scores a candidate against what has been typed: 3 for a prefix match, 2 for a
 * substring, 1 for a near-miss within the same edit distance §6 uses for "did
 * you mean", 0 for no match. An empty input matches everything.
 */
function match(written: string, candidate: string): number {
  if (written === '') return 3;
  const w = written.toLowerCase();
  const c = candidate.toLowerCase();
  if (c.startsWith(w)) return 3;
  if (c.includes(w)) return 2;
  if (w.length >= 3 && levenshtein(w, c) <= 2) return 1;
  return 0;
}

export type { Analysis };
