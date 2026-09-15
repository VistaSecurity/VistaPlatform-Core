// What is being typed at the cursor, and what it is being typed into.
//
// Autocomplete needs three things the parser cannot give it: half-written text
// is usually a parse error, and a parser that fails has nothing to say. So this
// walks the prefix with a loose scanner that mirrors §3's shape closely enough
// to answer:
//
//   - which TARGET the cursor is inside (a sub-predicate changes it, a
//     traversal makes it `asset`, a value group and an `in (…)` list do not);
//   - whether the cursor is at the head of a term, in the operator position
//     after a field, or in a value;
//   - the span of the token being completed.
//
// The scanner is forward rather than backward on purpose. Scanning back from
// the cursor cannot tell `risk >= ` (an operator, then a value) from three
// whitespace-separated words, and it cannot tell the `:` that separates a field
// from the `:` inside `id.mac:aa:bb:` — both of which are the difference
// between offering band labels and offering nothing useful.

import type { Catalog } from './catalog';
import { COLLECTION_TARGET, findTarget } from './catalog';
import { isBareValueChar } from './literal';
import { ANY_REL, REL_KEYWORD, isCollection, lookupRelationship } from './vocabulary';

/** Where the cursor is, and what would complete it. */
export interface Analysis {
  /**
   * `head` is the start of a term: a field name, a collection, a relationship,
   * a keyword. `operator` is after a complete field name. `value` is after an
   * operator.
   */
  kind: 'head' | 'operator' | 'value';
  /** The text typed so far at the cursor, which the completion replaces. */
  written: string;
  /** Where `written` starts. */
  start: number;
  /** The target the cursor is inside. */
  target: string;
  /** The field the operator or value belongs to, for `operator` and `value`. */
  field?: string;
  /** The operator that was written, for `value`. */
  op?: string;
  /** True when the cursor is inside an unterminated quoted string. */
  quoted?: boolean;
  /**
   * True when a complete term already precedes the cursor in this nesting
   * level, so `and` and `or` would have something to join. Offering them at the
   * head of an empty predicate — or straight after another `and` — would be
   * offering a query the validator then rejects.
   */
  afterTerm: boolean;
  /**
   * True inside `exists(…)`, where §3 allows a field path or a collection name
   * and nothing else.
   */
  insideExists?: boolean;
}

/** Longest first, so `:=` beats `:` and `<=` beats `<`. */
const OPERATORS = [':=', '!=', '<=', '>=', '~', '=', '<', '>', ':'];

/** Analyses `prefix` — the query text up to the cursor. */
export function analyse(prefix: string, root: string, cat: Catalog): Analysis {
  return new Scanner(prefix, root, cat).run();
}

/** One level of nesting: the target inside it, and what it accepts. */
interface Frame {
  target: string;
  /**
   * `terms` is a predicate. `values` is a value group, an `in (…)` list or a
   * range. `exists` is the inside of `exists(…)`. `args` is a hop count or the
   * argument list of `rel(…)`, where nothing is completable.
   */
  kind: 'terms' | 'values' | 'exists' | 'args';
  /** The field a value group, list or range belongs to. */
  field?: string;
  op?: string;
  /** Whether a complete term already precedes the cursor in this frame. */
  afterTerm: boolean;
}

/** A field name read in a term position, not yet spent on an operator. */
interface Pending {
  name: string;
  start: number;
}

/** A field and its operator, waiting for the value. */
interface Awaiting {
  field: string;
  op: string;
}

class Scanner {
  private i = 0;
  private readonly stack: Frame[];
  private pending: Pending | null = null;
  private awaiting: Awaiting | null = null;

  constructor(
    private readonly src: string,
    root: string,
    private readonly cat: Catalog,
  ) {
    this.stack = [{ target: root, kind: 'terms', afterTerm: false }];
  }

  private get top(): Frame {
    return this.stack[this.stack.length - 1];
  }

  private get atEnd(): boolean {
    return this.i >= this.src.length;
  }

  run(): Analysis {
    for (;;) {
      const before = this.i;
      this.skipSpace();
      const sawSpace = this.i > before;
      if (this.atEnd) return this.finish(sawSpace);

      const c = this.src[this.i];

      if (c === '(') {
        this.i++;
        this.openParen();
        this.pending = null;
        this.awaiting = null;
        continue;
      }
      if (c === ')' || c === ']') {
        this.i++;
        if (this.stack.length > 1) this.stack.pop();
        // A closed sub-predicate, group or list IS a completed term.
        this.top.afterTerm = true;
        this.pending = null;
        this.awaiting = null;
        continue;
      }
      if (c === '[') {
        // A range: `[lo to hi]`. The values inside belong to the same field.
        this.i++;
        // A range bound is checked the way `>=` and `<=` are, which is what
        // keeps `not_assessed` — the absence of a score, not a rung of the
        // ladder — from being offered as one (§13 A2).
        this.stack.push({
          target: this.top.target,
          kind: 'values',
          afterTerm: false,
          ...(this.awaiting === null ? {} : { field: this.awaiting.field, op: '>=' }),
        });
        this.pending = null;
        this.awaiting = null;
        continue;
      }
      if (c === ',') {
        // Still in the same list, so the next thing is another value.
        this.i++;
        continue;
      }
      if (c === '"' || c === "'") {
        const start = this.i;
        const end = skipString(this.src, this.i);
        if (end >= this.src.length && !isTerminated(this.src, start)) {
          // The cursor is inside the quotes; the text after them is what is
          // being completed.
          return this.completing(start + 1, this.src.slice(start + 1), true);
        }
        this.i = end;
        // A quoted field path segment continues with ".", which readPath knows;
        // anywhere else a string is a whole value or a whole free-text term.
        this.top.afterTerm = true;
        this.pending = null;
        this.awaiting = null;
        continue;
      }

      const op = this.readOperator();
      if (op !== null) {
        // A complete operator at the cursor puts the cursor in the value that
        // follows it, even though `:` could still become `:=` and `>` could
        // become `>=`. The value is what a user is reaching for; the operators
        // are offered one keystroke earlier, after the field and a space.
        if (this.pending !== null) {
          this.awaiting = { field: this.pending.name, op: op === ':=' ? '=' : op };
          this.pending = null;
        } else {
          this.awaiting = null;
        }
        continue;
      }

      if (this.awaiting !== null || this.top.kind === 'values' || this.top.kind === 'args') {
        const start = this.i;
        this.readBareValue();
        if (this.i === start) {
          this.i++; // never stall on a character the grammar has no place for
          this.pending = null;
          this.awaiting = null;
          continue;
        }
        if (this.atEnd) return this.completing(start, this.src.slice(start), false);
        // `to` inside a range joins two bounds; it does not end the term.
        if (this.src.slice(start, this.i).toLowerCase() !== 'to') this.top.afterTerm = true;
        this.pending = null;
        this.awaiting = null;
        continue;
      }

      // A term position: a field path, a collection, a relationship, a keyword.
      const start = this.i;
      const word = this.readPath();
      if (word === '') {
        this.i++;
        continue;
      }
      if (this.atEnd) {
        return {
          kind: 'head',
          written: word,
          start,
          target: this.top.target,
          afterTerm: this.top.afterTerm,
          ...(this.top.kind === 'exists' ? { insideExists: true } : {}),
        };
      }
      const lower = word.toLowerCase();
      if (lower === 'in' && this.pending !== null) {
        // `environment in (a, b)`: an in-list is checked value by value the way
        // a ":" comparison is, so it carries the same field and operator.
        this.awaiting = { field: this.pending.name, op: ':' };
        this.pending = null;
        continue;
      }
      if (lower === 'not' && this.pending !== null) {
        // `environment not in (…)` — the field survives the `not`.
        continue;
      }
      if (isKeywordWord(lower)) {
        // `and`, `or` and `not` join terms, so after one there is nothing for
        // another to join.
        this.top.afterTerm = false;
        this.pending = null;
        continue;
      }
      if (this.pending !== null) {
        // The previous word never took an operator, so it was a free-text term.
        this.top.afterTerm = true;
      }
      this.pending = { name: word, start };
    }
  }

  /** The cursor is at a token boundary; say what the next token would be. */
  private finish(sawSpace: boolean): Analysis {
    const at = this.src.length;
    const frame = this.top;

    if (this.awaiting !== null) {
      return {
        kind: 'value',
        written: '',
        start: at,
        target: frame.target,
        field: this.awaiting.field,
        op: this.awaiting.op,
        afterTerm: frame.afterTerm,
      };
    }
    if (this.pending !== null) {
      if (sawSpace) {
        // `risk_score ` — a complete field name and a space. An operator comes
        // next.
        return {
          kind: 'operator',
          written: '',
          start: at,
          target: frame.target,
          field: this.pending.name,
          afterTerm: frame.afterTerm,
        };
      }
      return {
        kind: 'head',
        written: this.pending.name,
        start: this.pending.start,
        target: frame.target,
        afterTerm: frame.afterTerm,
        ...(frame.kind === 'exists' ? { insideExists: true } : {}),
      };
    }
    if (frame.kind === 'values' && frame.field !== undefined) {
      // Inside a value group, an in-list or a range belonging to a field.
      return {
        kind: 'value',
        written: '',
        start: at,
        target: frame.target,
        field: frame.field,
        ...(frame.op === undefined ? {} : { op: frame.op }),
        afterTerm: frame.afterTerm,
      };
    }
    return {
      kind: 'head',
      written: '',
      start: at,
      target: frame.target,
      afterTerm: frame.afterTerm,
      ...(frame.kind === 'exists' ? { insideExists: true } : {}),
    };
  }

  /** The token running to the cursor is what is being completed. */
  private completing(start: number, written: string, quoted: boolean): Analysis {
    const frame = this.top;
    const field = this.awaiting?.field ?? frame.field;
    const op = this.awaiting?.op ?? frame.op;
    if (field !== undefined) {
      return {
        kind: 'value',
        written,
        start,
        target: frame.target,
        field,
        ...(op === undefined ? {} : { op }),
        ...(quoted ? { quoted: true } : {}),
        afterTerm: frame.afterTerm,
      };
    }
    return {
      kind: 'head',
      written,
      start,
      target: frame.target,
      afterTerm: frame.afterTerm,
      ...(quoted ? { quoted: true } : {}),
      ...(frame.kind === 'exists' ? { insideExists: true } : {}),
    };
  }

  /** Decides what the "(" just consumed opens. */
  private openParen(): void {
    const current = this.top.target;
    const awaiting = this.awaiting;
    const pending = this.pending;

    if (awaiting !== null && awaiting.op === ':') {
      const name = awaiting.field.toLowerCase();
      if (isCollection(name)) {
        const inner = COLLECTION_TARGET[name];
        const known = findTarget(this.cat, inner);
        this.stack.push({
          target: known === null ? current : inner,
          kind: 'terms',
          afterTerm: false,
        });
        return;
      }
      if (name === ANY_REL || name === REL_KEYWORD || lookupRelationship(name) !== null) {
        // §5.6: edges join assets, so a traversal predicate is over assets.
        this.stack.push({ target: 'asset', kind: 'terms', afterTerm: false });
        return;
      }
      // A value group or an in-list: `environment:(production or prod)`.
      this.stack.push({
        target: current,
        kind: 'values',
        field: awaiting.field,
        op: ':',
        afterTerm: false,
      });
      return;
    }
    if (awaiting !== null) {
      this.stack.push({
        target: current,
        kind: 'values',
        field: awaiting.field,
        op: awaiting.op,
        afterTerm: false,
      });
      return;
    }
    if (pending !== null) {
      const name = pending.name.toLowerCase();
      if (name === 'exists') {
        // §3: `exists(field)` takes a field path or a collection name, and
        // nothing else — no operator, no keyword, no nested predicate.
        this.stack.push({ target: current, kind: 'exists', afterTerm: false });
        return;
      }
      if (name === REL_KEYWORD || name === ANY_REL || lookupRelationship(name) !== null) {
        // The argument list of `rel(type, dir, n)` or the hop count of
        // `depends_on(3)`; neither position takes a field or a value.
        this.stack.push({ target: current, kind: 'args', afterTerm: false });
        return;
      }
    }
    // A grouping parenthesis. The target does not change and it takes terms.
    this.stack.push({ target: current, kind: 'terms', afterTerm: false });
  }

  private skipSpace(): void {
    while (this.i < this.src.length) {
      const c = this.src[this.i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        this.i++;
        continue;
      }
      return;
    }
  }

  private readOperator(): string | null {
    for (const op of OPERATORS) {
      if (this.src.startsWith(op, this.i)) {
        this.i += op.length;
        return op;
      }
    }
    return null;
  }

  /** Reads a field path: identifier segments and quoted segments, dotted. */
  private readPath(): string {
    const start = this.i;
    for (;;) {
      if (this.i < this.src.length && (this.src[this.i] === '"' || this.src[this.i] === "'")) {
        this.i = skipString(this.src, this.i);
      } else {
        const from = this.i;
        while (this.i < this.src.length && isIdentChar(this.src[this.i])) this.i++;
        if (this.i === from) break;
      }
      if (this.i < this.src.length && this.src[this.i] === '.') {
        this.i++;
        continue;
      }
      break;
    }
    return this.src.slice(start, this.i);
  }

  /** Reads a bare value: §2's character set, which includes ":" and "/". */
  private readBareValue(): void {
    while (this.i < this.src.length) {
      const cp = this.src.codePointAt(this.i);
      if (cp === undefined) break;
      const ch = String.fromCodePoint(cp);
      if (!isBareValueChar(ch)) break;
      this.i += ch.length;
    }
  }
}

function isIdentChar(c: string): boolean {
  return c === '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

function isKeywordWord(word: string): boolean {
  switch (word) {
    case 'and':
    case 'or':
    case 'not':
    case 'in':
    case 'to':
      return true;
    default:
      return false;
  }
}

/** Reports whether the string starting at i carries its closing quote. */
function isTerminated(s: string, i: number): boolean {
  const quoteChar = s[i];
  let j = i + 1;
  while (j < s.length) {
    if (s[j] === '\\') {
      j += 2;
      continue;
    }
    if (s[j] === quoteChar) return true;
    j++;
  }
  return false;
}

function skipString(s: string, i: number): number {
  const quoteChar = s[i];
  let j = i + 1;
  while (j < s.length) {
    if (s[j] === '\\') {
      j += 2;
      continue;
    }
    if (s[j] === quoteChar) return j + 1;
    j++;
  }
  return s.length;
}
