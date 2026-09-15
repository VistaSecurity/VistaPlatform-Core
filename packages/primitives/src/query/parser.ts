// Turns query text into an AST.
//
// Hand-written recursive descent over QUERY_LANGUAGE.md §3, with no generator
// and no dependencies. It knows the grammar's fixed vocabulary (the eight
// collections and the twenty relationship names, from ./vocabulary) but nothing
// about fields, types or SQL: every field is left unresolved for the validator,
// which is what keeps the parser catalogue-independent.
//
// The parser reports the first error it meets. A query is one line in a rail or
// a column; there is no useful recovery to do, and a cascade of follow-on
// errors from a single typo reads worse than the one that matters.

import type {
  And,
  Compare,
  Direction,
  Exists,
  FieldRef,
  InSet,
  Literal,
  Match,
  Node,
  Op,
  Or,
  Range,
  Span,
  Sub,
  Traverse,
  TraverseForm,
} from './ast';
import { mergeSpan, spanOfNodes } from './ast';
import type { QueryError } from './errors';
import { nearest, newError } from './errors';
import { Lexer, EOF } from './lexer';
import type { Token } from './lexer';
import { isIdentifier, isKeyword, quote } from './literal';
import {
  ANY_REL,
  COLLECTIONS,
  REL_KEYWORD,
  RELATIONSHIPS,
  isCollection,
  lookupRelationship,
  parseDirection,
} from './vocabulary';

/** A parsed query. */
export interface ParsedQuery {
  /**
   * The predicate. It is null for an empty query, which matches everything
   * under RLS (§8: "Empty predicate → empty string").
   */
  root: Node | null;
  /** The text that was parsed. */
  source: string;
  /**
   * The deepest nesting of parentheses in the source. The validator caps it
   * (§6); it is measured here because canonical form drops redundant
   * parentheses, so the AST no longer shows what was written.
   */
  maxParenDepth: number;
}

/** The outcome of a parse. */
export type ParseResult =
  | { ok: true; value: ParsedQuery }
  | { ok: false; errors: QueryError[] };

/**
 * The parser's own hard ceiling on how deeply a query may nest: parentheses,
 * value groups, sub-predicates, traversals and unary chains all count against
 * it.
 *
 * It exists because recursive descent recurses, and the validator's
 * configurable maxParenDepth (§6, default 16) cannot help — the validator runs
 * on a tree the parser has already had to build. A query arrives from a URL, a
 * saved view, a stored rule and an AI, so unbounded nesting is a denial of
 * service, not a tidiness problem.
 *
 * It is deliberately well above §6's 16 so the validator's configurable cap
 * stays the one users meet, and this one only ever catches an attack. The
 * numeric ceiling is implementation-defence, not contract — the Go
 * implementation picks the same 64, and a port needs *a* ceiling, not this one.
 */
export const MAX_DEPTH = 64;

/** Thrown internally and caught at the top of `parse`. */
class ParseFailure extends Error {
  readonly queryError: QueryError;

  constructor(e: QueryError) {
    super(e.message);
    this.name = 'ParseFailure';
    this.queryError = e;
  }
}

/**
 * Scans and parses src. On failure the result carries exactly one error, with
 * code `syntax_error` for text the grammar rejects and `too_many_clauses` for
 * text that nests past MAX_DEPTH.
 */
export function parse(src: string): ParseResult {
  const p = new Parser(src);
  try {
    const root = p.parseQuery();
    return { ok: true, value: { root, source: src, maxParenDepth: p.maxParen } };
  } catch (err) {
    if (err instanceof ParseFailure) return { ok: false, errors: [err.queryError] };
    throw err;
  }
}

class Parser {
  private readonly lex: Lexer;
  private paren = 0;
  maxParen = 0;
  private depth = 0;

  constructor(src: string) {
    this.lex = new Lexer(src);
  }

  private fail(span: Span, message: string): never {
    throw new ParseFailure(newError('syntax_error', span, message));
  }

  private failSuggest(span: Span, suggestion: string, message: string): never {
    throw new ParseFailure(newError('syntax_error', span, message, suggestion));
  }

  /**
   * Records one level of grammatical nesting and refuses to go past MAX_DEPTH.
   * Every recursive entry point calls it; `leave` pairs with it.
   */
  private enter(span: Span): void {
    this.depth++;
    if (this.depth > MAX_DEPTH) {
      throw new ParseFailure(
        newError(
          'too_many_clauses',
          span,
          `query nests more than ${MAX_DEPTH} levels deep`,
          'split it into smaller predicates',
        ),
      );
    }
  }

  private leave(): void {
    this.depth--;
  }

  private openParen(): void {
    this.paren++;
    if (this.paren > this.maxParen) this.maxParen = this.paren;
  }

  private closeParen(): void {
    this.paren--;
  }

  /** Parses a whole query and requires that the input is consumed. */
  parseQuery(): Node | null {
    if (this.lex.peekChar() === EOF) return null;
    const n = this.parseOr();
    const tok = this.lex.next('default');
    if (tok.kind !== 'eof') {
      this.fail(tok.span, `unexpected ${goQuote(tokenText(tok))} after the end of the query`);
    }
    return n;
  }

  private parseOr(): Node {
    const here = this.lex.mark();
    this.enter({ start: here, end: here });
    try {
      const first = this.parseAnd();
      let children: Node[] | null = null;
      for (;;) {
        const mark = this.lex.mark();
        const tok = this.lex.next('default');
        if (tok.kind !== 'ident' || tok.text.toLowerCase() !== 'or') {
          this.lex.reset(mark);
          break;
        }
        if (children === null) children = [first];
        children.push(this.parseAnd());
      }
      if (children === null) return first;
      const or: Or = { kind: 'or', children, span: spanOfNodes(children) };
      return or;
    } finally {
      this.leave();
    }
  }

  private parseAnd(): Node {
    const first = this.parseUnary();
    let children: Node[] | null = null;
    for (;;) {
      const r = this.lex.peekChar();
      if (r === EOF || r === ')' || r === ']' || r === ',') break;
      const mark = this.lex.mark();
      const tok = this.lex.next('default');
      if (tok.kind === 'ident' && tok.text.toLowerCase() === 'or') {
        this.lex.reset(mark);
        if (children === null) return first;
        return { kind: 'and', children, span: spanOfNodes(children) } satisfies And;
      }
      if (!(tok.kind === 'ident' && tok.text.toLowerCase() === 'and')) {
        // Juxtaposition is an implicit and (§2).
        this.lex.reset(mark);
      }
      if (children === null) children = [first];
      children.push(this.parseUnary());
    }
    if (children === null) return first;
    return { kind: 'and', children, span: spanOfNodes(children) } satisfies And;
  }

  private parseUnary(): Node {
    const mark = this.lex.mark();
    const tok = this.lex.next('default');
    if (tok.kind === '-' || (tok.kind === 'ident' && tok.text.toLowerCase() === 'not')) {
      // `not not not …` is a recursion path of its own, with no parenthesis to
      // be counted by openParen — count it here.
      this.enter(tok.span);
      const child = this.parseUnary();
      this.leave();
      return { kind: 'not', child, span: mergeSpan(tok.span, child.span) };
    }
    this.lex.reset(mark);
    return this.parsePrimary();
  }

  private parsePrimary(): Node {
    const mark = this.lex.mark();
    const tok = this.lex.next('default');
    if (tok.kind === '(') {
      this.openParen();
      const inner = this.parseOr();
      this.expect(')', ')');
      this.closeParen();
      return inner;
    }
    this.lex.reset(mark);
    return this.parseTerm();
  }

  /**
   * Parses one term: exists, a traversal, a sub-predicate, a field term or free
   * text.
   */
  private parseTerm(): Node {
    const mark = this.lex.mark();
    const r = this.lex.peekChar();
    if (r === EOF) {
      const pos = this.lex.skipSpace();
      this.fail({ start: pos, end: pos }, 'expected a term');
    }
    if (r === '"' || r === "'") {
      // §3's `segment = identifier | string` holds at the HEAD of a path too,
      // so `"hostname":web1` is a field term. Without this it silently became
      // two free-text terms — no error, just a different query.
      const quotedHead = this.tryQuotedHeadTerm(mark);
      if (quotedHead !== null) return quotedHead;
      return this.parseFreeText(mark);
    }
    if (!isIdentStartRune(r)) return this.parseFreeText(mark);

    const head = this.lex.next('default');
    if (head.kind !== 'ident') {
      this.lex.reset(mark);
      return this.parseFreeText(mark);
    }
    const name = head.text.toLowerCase();

    if (name === 'exists' && this.lex.peek('default').kind === '(') {
      return this.parseExists(head);
    }

    const field = this.tryFieldPath(head);
    if (field === null) {
      // The dotted name is not a field path (`web.01` — a digit is not an
      // identifier), so the term was free text all along. Only the path parse
      // is retried: an error after the operator is a real error and must not be
      // swallowed by re-reading the term as text.
      this.lex.reset(mark);
      return this.parseFreeText(mark);
    }

    // The one-segment forms that are not fields: traversals and sub-predicates.
    if (field.segments.length === 1) {
      const n = this.tryTraverseOrSub(field, name);
      if (n !== null) return n;
    }

    const tail = this.parseFieldTermTail(field);
    if (tail !== null) return tail;

    // No operator followed the name, so it was free text all along.
    this.lex.reset(mark);
    return this.parseFreeText(mark);
  }

  /**
   * Parses a field term whose first path segment is a quoted string
   * (`"hostname":web1`, `"cost center".sub:x`). It returns null — having
   * rewound — when the string is not followed by a path separator or an
   * operator, because then it is an ordinary quoted free-text term.
   *
   * A quoted head is never a relationship or collection name: quoting a segment
   * is how a tenant-supplied key is written, and `"endpoint":(…)` asking for a
   * field called "endpoint" is the only reading that makes the quotes mean
   * something.
   */
  private tryQuotedHeadTerm(mark: number): Node | null {
    const head = this.lex.next('default');
    if (head.kind !== 'string') {
      this.lex.reset(mark);
      return null;
    }
    const after = this.lex.peek('default').kind;
    if (after !== '.' && after !== ':' && after !== 'op') {
      this.lex.reset(mark);
      return null;
    }
    const field = this.tryFieldPath(head);
    if (field === null) {
      this.lex.reset(mark);
      return null;
    }
    const tail = this.parseFieldTermTail(field);
    if (tail !== null) return tail;
    this.lex.reset(mark);
    return null;
  }

  /**
   * Reads the operator and value that follow a field path. It returns null —
   * leaving the scanner where the caller can rewind it — when nothing that can
   * follow a field does.
   */
  private parseFieldTermTail(field: FieldRef): Node | null {
    const next = this.lex.peek('default');
    if (next.kind === ':') {
      this.lex.next('default');
      return this.parseColonForm(field);
    }
    if (next.kind === 'op') {
      this.lex.next('default');
      return this.parseOpForm(field, next);
    }
    if (next.kind === 'ident' && next.text.toLowerCase() === 'in') {
      const save = this.lex.mark();
      this.lex.next('default');
      if (this.listFollows()) return this.parseInList(field, false);
      this.lex.reset(save);
      return null;
    }
    if (next.kind === 'ident' && next.text.toLowerCase() === 'not') {
      const save = this.lex.mark();
      this.lex.next('default');
      const afterNot = this.lex.peek('default');
      if (afterNot.kind === 'ident' && afterNot.text.toLowerCase() === 'in') {
        this.lex.next('default');
        if (this.listFollows()) return this.parseInList(field, true);
      }
      this.lex.reset(save);
      return null;
    }
    return null;
  }

  /**
   * `parseFieldPath` with the failure turned into a null, so the caller can
   * fall back to free text instead of reporting a syntax error.
   */
  private tryFieldPath(head: Token): FieldRef | null {
    const mark = this.lex.mark();
    try {
      return this.parseFieldPath(head);
    } catch (err) {
      if (!(err instanceof ParseFailure)) throw err;
      this.lex.reset(mark);
      return null;
    }
  }

  /**
   * Reads `segment { "." segment }` after the head segment, which §3 allows to
   * be an identifier or a quoted string.
   */
  private parseFieldPath(head: Token): FieldRef {
    const segs: string[] = [head.text.toLowerCase()];
    const quoted: boolean[] = [false];
    if (head.kind === 'string') {
      // A quoted segment keeps its case, head or not: it is a tenant-supplied
      // key, not a language identifier.
      segs[0] = head.value;
      quoted[0] = true;
    }
    let span = head.span;
    for (;;) {
      const mark = this.lex.mark();
      const dot = this.lex.next('default');
      if (dot.kind !== '.') {
        this.lex.reset(mark);
        break;
      }
      const seg = this.lex.next('default');
      if (seg.kind === 'ident') {
        segs.push(seg.text.toLowerCase());
        quoted.push(false);
      } else if (seg.kind === 'string') {
        // A quoted segment keeps its case: it is a tenant-supplied key (a tag
        // or a fact key), not a language identifier.
        segs.push(seg.value);
        quoted.push(true);
      } else {
        this.fail(seg.span, 'expected a field name after "."');
      }
      span = mergeSpan(span, seg.span);
    }
    return {
      segments: segs,
      quoted,
      text: fieldText(segs, quoted),
      namespace: '',
      key: '',
      type: '',
      accessor: { kind: 'column' },
      resolved: false,
      span,
    };
  }

  /**
   * Handles `name(n):(…)`, `name:(…)`, `rel(…):(…)` and `any_rel:(…)`. It
   * returns null when the name is an ordinary field.
   */
  private tryTraverseOrSub(field: FieldRef, name: string): Node | null {
    const next = this.lex.peek('default');

    if (next.kind === '(') {
      if (name === REL_KEYWORD) return this.parseExplicitTraverse(field);
      if (name === ANY_REL) {
        const depth = this.parseDepthArg();
        return this.parseTraverseTail(field, 'any', name, '', 'any', depth, false);
      }
      const rel = lookupRelationship(name);
      if (rel !== null) {
        const depth = this.parseDepthArg();
        return this.parseTraverseTail(field, 'named', name, rel.type, rel.direction, depth, false);
      }
      return null;
    }

    if (next.kind !== ':') return null;
    // `x:(` — a sub-predicate, a one-hop traversal, or a value group.
    const save = this.lex.mark();
    this.lex.next('default');
    if (this.lex.peek('value').kind !== '(') {
      this.lex.reset(save);
      return null;
    }
    if (isCollection(name)) {
      this.lex.next('default');
      this.openParen();
      const inner = this.parseOr();
      const closing = this.expect(')', ')');
      this.closeParen();
      const sub: Sub = {
        kind: 'sub',
        collection: name,
        predicate: inner,
        span: mergeSpan(field.span, closing.span),
      };
      return sub;
    }
    if (name === ANY_REL) {
      return this.parseTraverseTail(field, 'any', name, '', 'any', 1, true);
    }
    const rel = lookupRelationship(name);
    if (rel !== null) {
      return this.parseTraverseTail(field, 'named', name, rel.type, rel.direction, 1, true);
    }
    this.lex.reset(save);
    return null;
  }

  /** Reads the optional `(n)` after a traversal name. */
  private parseDepthArg(): number {
    this.lex.next('default');
    this.openParen();
    const tok = this.lex.next('value');
    const n = this.intArg(tok);
    this.expect(')', ')');
    this.closeParen();
    return n;
  }

  private intArg(tok: Token): number {
    if (tok.kind !== 'bare') {
      this.fail(tok.span, `expected a hop count, found ${goQuote(tokenText(tok))}`);
    }
    const n = /^[0-9]+$/.test(tok.text) ? Number.parseInt(tok.text, 10) : Number.NaN;
    if (!Number.isInteger(n) || n < 1) {
      this.fail(
        tok.span,
        `hop count must be a positive whole number, found ${goQuote(tok.text)}`,
      );
    }
    return n;
  }

  /**
   * Reads the `:(predicate)` that every traversal form ends in. `colonEaten`
   * says whether the caller has already consumed the ":" — the `name:(…)` form
   * has, because the colon is what told it this was a traversal and not a
   * field.
   */
  private parseTraverseTail(
    field: FieldRef,
    form: TraverseForm,
    name: string,
    type: string,
    direction: Direction,
    depth: number,
    colonEaten: boolean,
  ): Node {
    if (!colonEaten) {
      if (this.lex.peek('default').kind !== ':') {
        const tok = this.lex.peek('default');
        this.fail(tok.span, 'expected ":" before the traversal predicate');
      }
      this.lex.next('default');
    }
    const open = this.expect('(', '(');
    void open;
    this.openParen();
    const inner = this.parseOr();
    const closing = this.expect(')', ')');
    this.closeParen();
    const t: Traverse = {
      kind: 'traverse',
      form,
      name,
      type,
      direction,
      depth,
      predicate: inner,
      span: mergeSpan(field.span, closing.span),
    };
    return t;
  }

  /** Reads `rel(type, direction[, depth]):(…)`. */
  private parseExplicitTraverse(field: FieldRef): Node {
    this.expect('(', '(');
    this.openParen();

    const typTok = this.lex.next('default');
    if (typTok.kind !== 'ident') {
      this.fail(typTok.span, `expected a relationship type, found ${goQuote(tokenText(typTok))}`);
    }
    // An unknown or reverse-label type is NOT a parse error: the explicit form
    // is unambiguous whatever the name is, so the name is vocabulary and
    // belongs to the validator, which reports it as unknown_value (§6).
    const typ = typTok.text.toLowerCase();

    this.expect(',', ',');
    const dirTok = this.lex.next('default');
    if (dirTok.kind !== 'ident') {
      this.fail(dirTok.span, `expected a direction, found ${goQuote(tokenText(dirTok))}`);
    }
    const dir = parseDirection(dirTok.text);
    if (dir === null) {
      this.failSuggest(
        dirTok.span,
        'direction is out, in or any',
        `unknown direction ${goQuote(dirTok.text)}`,
      );
    }

    let depth = 1;
    if (this.lex.peek('default').kind === ',') {
      this.lex.next('default');
      depth = this.intArg(this.lex.next('value'));
    }
    this.expect(')', ')');
    this.closeParen();
    return this.parseTraverseTail(field, 'rel', typ, typ, dir, depth, false);
  }

  /**
   * Reads `exists(field)`. A collection name inside becomes a Sub with no
   * predicate, because `exists(endpoint)` is an EXISTS over a child table (§8:
   * `has_certificates` → `exists(cert)`).
   */
  private parseExists(head: Token): Node {
    this.expect('(', '(');
    this.openParen();
    const inner = this.lex.next('default');
    if (inner.kind !== 'ident') {
      this.fail(
        inner.span,
        `expected a field name inside exists(), found ${goQuote(tokenText(inner))}`,
      );
    }
    const field = this.parseFieldPath(inner);
    const closing = this.expect(')', ')');
    this.closeParen();
    const span = mergeSpan(head.span, closing.span);
    if (field.segments.length === 1 && isCollection(field.segments[0])) {
      return { kind: 'sub', collection: field.segments[0], predicate: null, span } satisfies Sub;
    }
    return { kind: 'exists', field, span } satisfies Exists;
  }

  /** Reads everything that may follow a field's ":". */
  private parseColonForm(field: FieldRef): Node {
    const next = this.lex.peek('value');
    if (next.kind === '(') return this.parseValueGroup(field);
    if (next.kind === '[') return this.parseRange(field);
    if (next.kind === 'bare' && next.text.toLowerCase() === 'in') {
      const save = this.lex.mark();
      this.lex.next('value');
      if (this.listFollows()) return this.parseInList(field, false);
      // `status:in` and `status:in production` are not lists at all — they are
      // someone using the keyword as a value. Rewinding hands the token to
      // parseValue, which gives it the same "quote it" diagnostic every other
      // keyword gets, instead of an `expected "("` that names a parenthesis the
      // user never meant to write.
      this.lex.reset(save);
    }
    const lit = this.parseValue();
    const cmp: Compare = {
      kind: 'cmp',
      field,
      op: ':',
      value: lit,
      span: mergeSpan(field.span, lit.span),
    };
    return cmp;
  }

  /** Reads `op value`, `~ "regex"` and `= value`. */
  private parseOpForm(field: FieldRef, op: Token): Node {
    if (op.text === '~') {
      const tok = this.lex.next('value');
      if (tok.kind !== 'string') {
        this.failSuggest(
          tok.span,
          'write the pattern in double quotes: ~ "^web[0-9]+"',
          `the regex operator takes a quoted pattern, found ${goQuote(tokenText(tok))}`,
        );
      }
      const m: Match = {
        kind: 'match',
        field,
        regex: tok.value,
        span: mergeSpan(field.span, tok.span),
      };
      return m;
    }
    // ":=" is an accepted alias for "=" and is normalised here (§10).
    const text = op.text === ':=' ? '=' : op.text;
    const lit = this.parseValue();
    const cmp: Compare = {
      kind: 'cmp',
      field,
      op: text as Op,
      value: lit,
      span: mergeSpan(field.span, lit.span),
    };
    return cmp;
  }

  /**
   * Reports whether the just-consumed `in` is followed by the "(" that opens a
   * list. When it is not, the caller rewinds and lets the token be read as a
   * value, so `status:in` reports the keyword, not a missing bracket.
   */
  private listFollows(): boolean {
    return this.lex.peek('default').kind === '(';
  }

  /** Reads `in (a, b, c)`. */
  private parseInList(field: FieldRef, negated: boolean): Node {
    this.expect('(', '(');
    this.openParen();
    const values: Literal[] = [];
    for (;;) {
      values.push(this.parseValue());
      const tok = this.lex.next('default');
      if (tok.kind === ',') continue;
      if (tok.kind === ')') {
        this.closeParen();
        const n: InSet = {
          kind: 'in',
          field,
          values,
          negated,
          span: mergeSpan(field.span, tok.span),
        };
        return n;
      }
      this.fail(tok.span, `expected "," or ")" in a list, found ${goQuote(tokenText(tok))}`);
    }
  }

  /** Reads `[lo to hi]`, inclusive. */
  private parseRange(field: FieldRef): Node {
    this.expect('[', '[');
    const lo = this.parseValue();
    const kw = this.lex.next('value');
    if (kw.kind !== 'bare' || kw.text.toLowerCase() !== 'to') {
      this.failSuggest(
        kw.span,
        'a range is written [low to high]',
        `expected "to" in a range, found ${goQuote(tokenText(kw))}`,
      );
    }
    const hi = this.parseValue();
    const closing = this.expect(']', ']');
    const r: Range = {
      kind: 'range',
      field,
      lo,
      hi,
      span: mergeSpan(field.span, closing.span),
    };
    return r;
  }

  /**
   * Reads `field:(a or b and not c)` and desugars it against the same field.
   * §7.1's node set has no group node: the group is sugar for the boolean
   * combination it names, and the formatter writes the desugared form.
   */
  private parseValueGroup(field: FieldRef): Node {
    try {
      this.expect('(', '(');
      this.openParen();
      const node = this.parseValueOr(field);
      this.expect(')', ')');
      this.closeParen();
      return node;
    } catch (err) {
      // A misspelled relationship name reaches here, because `depand_on:(…)` is
      // syntactically a value group over a field called depand_on. The group
      // parse then fails on the first thing only a predicate may contain, and
      // the bare failure ("expected \")\"") hides the real mistake.
      if (!(err instanceof ParseFailure)) throw err;
      const e = err.queryError;
      if (field.segments.length === 1 && (e.suggestion === undefined || e.suggestion === '')) {
        const near = nearest(field.segments[0], vocabularyNames(), 2);
        if (near !== null) {
          throw new ParseFailure({
            ...e,
            suggestion: `${goQuote(field.segments[0])} is not a relationship or a collection; did you mean ${goQuote(near)}?`,
          });
        }
      }
      throw err;
    }
  }

  private parseValueOr(field: FieldRef): Node {
    const first = this.parseValueAnd(field);
    let children: Node[] | null = null;
    while (this.peekValueKeyword('or')) {
      this.lex.next('value');
      if (children === null) children = [first];
      children.push(this.parseValueAnd(field));
    }
    if (children === null) return first;
    return { kind: 'or', children, span: spanOfNodes(children) } satisfies Or;
  }

  private parseValueAnd(field: FieldRef): Node {
    const first = this.parseValueNot(field);
    let children: Node[] | null = null;
    while (this.peekValueKeyword('and')) {
      this.lex.next('value');
      if (children === null) children = [first];
      children.push(this.parseValueNot(field));
    }
    if (children === null) return first;
    return { kind: 'and', children, span: spanOfNodes(children) } satisfies And;
  }

  /**
   * Reads `[ "not" ] value`. The "not" binds to ONE value, exactly as the outer
   * grammar's `unary` binds to one term, so
   * `environment:(not production and not staging)` is And{Not, Not} and reads
   * the way it looks (§13 A3).
   */
  private parseValueNot(field: FieldRef): Node {
    if (this.peekValueKeyword('not')) {
      const tok = this.lex.next('value');
      const child = this.parseValueLeaf(field);
      return { kind: 'not', child, span: mergeSpan(tok.span, child.span) };
    }
    return this.parseValueLeaf(field);
  }

  private parseValueLeaf(field: FieldRef): Node {
    const lit = this.parseValue();
    const cmp: Compare = {
      kind: 'cmp',
      field,
      op: ':',
      value: lit,
      span: mergeSpan(field.span, lit.span),
    };
    return cmp;
  }

  /**
   * Reports whether the next value-mode token is the given bare keyword. A
   * quoted "or" is a value, not a keyword, which is how a value spelled like a
   * keyword is written.
   */
  private peekValueKeyword(kw: string): boolean {
    const tok = this.lex.peek('value');
    return tok.kind === 'bare' && tok.text.toLowerCase() === kw;
  }

  /** Reads one value literal. */
  private parseValue(): Literal {
    const tok = this.lex.next('value');
    if (tok.kind === 'string') {
      return { form: 'string', value: tok.value, span: tok.span };
    }
    if (tok.kind === 'bare') {
      if (isKeyword(tok.text)) {
        this.failSuggest(
          tok.span,
          'quote it to use it as a value: "' + tok.text + '"',
          `${goQuote(tok.text.toLowerCase())} is a keyword, not a value`,
        );
      }
      return { form: 'bare', value: tok.text, span: tok.span };
    }
    if (tok.kind === 'illegal') this.fail(tok.span, tok.text);
    this.fail(tok.span, `expected a value, found ${goQuote(tokenText(tok))}`);
  }

  /**
   * Re-scans the term as a value, which is what a term with no field is (§5.4).
   */
  private parseFreeText(mark: number): Node {
    this.lex.reset(mark);
    const lit = this.parseValue();
    return { kind: 'text', value: lit, span: lit.span };
  }

  private expect(kind: Token['kind'], what: string): Token {
    const tok = this.lex.next('default');
    if (tok.kind !== kind) {
      this.fail(tok.span, `expected ${goQuote(what)}, found ${goQuote(tokenText(tok))}`);
    }
    return tok;
  }
}

/** Renders a token for an error message. */
function tokenText(tok: Token): string {
  if (tok.kind === 'eof') return 'end of query';
  return tok.text;
}

/** Renders a string the way Go's %q verb does, for message parity. */
function goQuote(s: string): string {
  return quote(s);
}

/**
 * Renders a field path in canonical form: unquoted segments as written (already
 * lowercased), quoted segments re-quoted.
 */
export function fieldText(segs: string[], quoted: boolean[]): string {
  let b = '';
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (i > 0) b += '.';
    // A quoted segment loses its quotes only when it would re-lex to exactly
    // itself: an identifier that is already lowercase. Anything else — a space,
    // a dot, a capital letter the lexer would fold — stays quoted, or the
    // canonical form would name a different key.
    //
    // A keyword in HEAD position is the third case: `"not":foo` unquoted is
    // `not:foo`, which reparses as a negation of the free text ":foo". Later
    // segments are safe, because parseFieldPath takes any identifier after
    // a ".".
    const reLexesToItself =
      isIdentifier(s) && s === s.toLowerCase() && (i !== 0 || !isKeyword(s));
    if (i < quoted.length && quoted[i] && !reLexesToItself) {
      b += quote(s);
      continue;
    }
    b += s;
  }
  return b;
}

/** Every name that may head a `name:(…)` predicate. */
function vocabularyNames(): string[] {
  return [...COLLECTIONS, ...RELATIONSHIPS.map((r) => r.name), ANY_REL, REL_KEYWORD];
}

function isIdentStartRune(r: string | null): boolean {
  if (r === null) return false;
  return r === '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z');
}
