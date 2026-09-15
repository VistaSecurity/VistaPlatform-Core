// Checks a parsed query against the field catalogue and the safety rules, and
// resolves every field in place.
//
// It implements QUERY_LANGUAGE.md §6 — one rule, one error code — and is what
// decides a query is safe to send. It fails closed: a node it cannot account
// for is untranslatable rather than passed through.
//
// The server validates again before it translates. This copy exists so the
// editor and the facet rail can say what is wrong with a span and a suggestion
// as the user types, and it must agree with the server exactly — which is what
// `conformance.test.ts` holds it to.

import type { FieldRef, FieldType, Literal, Node, Op, Span, TraverseForm } from './ast';
import { isOrdering, walk } from './ast';
import type { BandLadder, Catalog, ResolveError, Target } from './catalog';
import {
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
import type { QueryError } from './errors';
import { nearest, nearestValue, newError, sortErrors, withSuggestion } from './errors';
import {
  isBareStar,
  isWildcard,
  parseBool,
  parseDate,
  parseInet,
  parseNumber,
  parseUUID,
  quoteValue,
} from './literal';
import type { ParsedQuery } from './parser';
import { REGEX_SUBSET_HELP, checkRegexSubset, compileCheck } from './regex';
import { looksLikeVersion } from './versionsort';
import { COLLECTIONS, RELATIONSHIPS, isRelationshipType, lookupRelationship } from './vocabulary';

/**
 * The caps from §6. Every one is a field rather than a constant so a deployment
 * can tighten them, and so a test can prove a cap is load bearing by moving it.
 */
export interface Options {
  /** Caps the query text in UTF-8 BYTES (§6 query_too_long). */
  maxBytes: number;
  /** The configured traversal budget (§5.6, default 3). */
  traversalBudget: number;
  /** The ceiling no configuration may exceed (§5.6: 6). */
  hardMaxTraversal: number;
  /** Caps leaf terms. */
  maxLeaves: number;
  /** Caps sub-predicates and traversals together. */
  maxSubs: number;
  /** Caps parenthesis nesting in the source. */
  maxParenDepth: number;
  /** Caps the values in one `in (…)` list. */
  maxInValues: number;
  /** Caps a regex pattern's length, in CODE POINTS. */
  maxRegexLen: number;
  /** Caps the effective regex repetition product. */
  maxRepetition: number;
  /**
   * The band ladder (§5.5). Without one, band fields are untranslatable rather
   * than guessed at.
   */
  ladder?: BandLadder;
}

/** Returns §6's caps and §5.6's default budget. */
export function defaultOptions(): Options {
  return {
    maxBytes: 4096,
    traversalBudget: 3,
    hardMaxTraversal: 6,
    maxLeaves: 64,
    maxSubs: 16,
    maxParenDepth: 16,
    maxInValues: 256,
    maxRegexLen: 256,
    maxRepetition: 1000,
  };
}

/** Returns a copy of o carrying the given band ladder. */
export function withLadder(o: Options, ladder: BandLadder): Options {
  return { ...o, ladder };
}

/** The outcome of validation. The root is only safe to send when ok is true. */
export type ValidateResult =
  | { ok: true; root: Node | null }
  | { ok: false; root: Node | null; errors: QueryError[] };

/**
 * The number of UTF-8 bytes in s. §6's query cap is in bytes — "the two caps in
 * these adjacent rows use different units on purpose" — so a query of accented
 * characters must be measured the way the server measures it, not by
 * `String.length`.
 */
export function utf8ByteLength(s: string): number {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (cp < 0x80) n += 1;
    else if (cp < 0x800) n += 2;
    else if (cp < 0x10000) n += 3;
    else n += 4;
  }
  return n;
}

/**
 * Checks a parsed query against the catalogue for target and resolves every
 * field reference in place.
 */
export function validate(
  res: ParsedQuery,
  target: string,
  cat: Catalog,
  opts: Options,
): ValidateResult {
  const v = new Validator(cat, opts);

  const n = utf8ByteLength(res.source);
  if (n > opts.maxBytes) {
    v.add(
      newError(
        'query_too_long',
        { start: 0, end: res.source.length },
        `query is ${n} bytes; the limit is ${opts.maxBytes}`,
      ),
    );
    return { ok: false, root: res.root, errors: v.errors };
  }
  if (res.maxParenDepth > opts.maxParenDepth) {
    v.add(
      newError(
        'too_many_clauses',
        { start: 0, end: res.source.length },
        `query nests ${res.maxParenDepth} levels of parentheses; the limit is ${opts.maxParenDepth}`,
      ),
    );
  }

  const tgt = findTarget(cat, target);
  if (tgt === null) {
    v.add(
      newError(
        'unknown_field',
        { start: 0, end: res.source.length },
        `unknown target ${q(target)}`,
        `targets: ${targetNames(cat).join(', ')}`,
      ),
    );
    return { ok: false, root: res.root, errors: v.errors };
  }

  if (res.root !== null) {
    v.node(res.root, tgt);
    v.checkCounts(res.root, res.source);
    v.checkBudget(res.root);
  }
  if (v.errors.length === 0) return { ok: true, root: res.root };
  return { ok: false, root: res.root, errors: sortErrors(v.errors) };
}

class Validator {
  readonly errors: QueryError[] = [];

  constructor(
    private readonly cat: Catalog,
    private readonly opts: Options,
  ) {}

  add(e: QueryError): void {
    this.errors.push(e);
  }

  /** Walks the tree, carrying the target the current scope resolves against. */
  node(n: Node, tgt: Target): void {
    switch (n.kind) {
      case 'and':
      case 'or':
        for (const c of n.children) this.node(c, tgt);
        return;
      case 'not':
        this.node(n.child, tgt);
        return;
      case 'cmp':
        this.compare(n.field, n.op, n.value, n.span, tgt);
        return;
      case 'in':
        this.inSet(n.field, n.values, n.span, tgt);
        return;
      case 'range':
        this.rangeTerm(n.field, n.lo, n.hi, n.span, tgt);
        return;
      case 'match':
        this.match(n.field, n.regex, n.span, tgt);
        return;
      case 'exists':
        if (this.resolve(n.field, tgt)) this.translatableField(n.field);
        return;
      case 'text':
        this.freeText(n.span, tgt);
        return;
      case 'sub':
        this.sub(n.collection, n.predicate, n.span, tgt);
        return;
      case 'traverse':
        this.traverse(n.form, n.name, n.predicate, n.span, tgt);
        return;
    }
  }

  /**
   * Fills in a field reference from the catalogue, or reports unknown_field
   * with the closest match (§6).
   */
  private resolve(f: FieldRef, tgt: Target): boolean {
    if (f.resolved) return true;
    const out = this.cat.resolve(tgt.name, f.segments);
    if (out.ok) {
      // The parser's text, span, segments and quoting are kept: the catalogue
      // knows the schema, the parser knows what the user wrote.
      f.namespace = out.field.namespace;
      f.key = out.field.key;
      f.type = out.field.type;
      f.accessor = out.field.accessor;
      if (out.field.enum !== undefined) f.enum = out.field.enum;
      f.resolved = true;
      return true;
    }
    this.add(this.unknownField(f, tgt, out.error));
    return false;
  }

  /**
   * Writes §10's worked error: name the span, name the closest match, and say
   * where the other namespaces live.
   */
  private unknownField(f: FieldRef, tgt: Target, re: ResolveError): QueryError {
    const base = newError('unknown_field', f.span, `no field ${q(f.text)} on ${plural(tgt.name)}`);
    if (re.reason === 'empty_key') {
      return newError(
        'unknown_field',
        f.span,
        `${q(f.text)} is a namespace, not a field`,
        `write the key after it, for example ${re.namespace}.<key>`,
      );
    }
    if (re.reason === 'unknown_key') {
      const msg = newError(
        'unknown_field',
        f.span,
        `no ${re.namespace} key ${q(f.segments.slice(1).join('.'))} is registered`,
      );
      const near = nearest(f.text, fieldNames(this.cat, tgt.name), 2);
      if (near !== null) return withSuggestion(msg, `did you mean ${q(near)}?`);
      return msg;
    }
    const near = nearest(f.text, fieldNames(this.cat, tgt.name), 2);
    if (near !== null) return withSuggestion(base, `did you mean ${q(near)}?`);
    // A misspelled relationship or collection reaches here rather than the
    // parser: `depands_on:(class:server)` is syntactically a value group over a
    // field called depands_on, because ':' is legal inside a bare value. The
    // name is the mistake, so the suggestion has to come from this side.
    if (f.segments.length === 1) {
      const rel = nearest(f.text, this.relationshipNames(), 2);
      if (rel !== null) {
        return withSuggestion(base, `did you mean the relationship ${q(rel)}? write ${rel}:(…)`);
      }
      const coll = nearest(f.text, COLLECTIONS, 2);
      if (coll !== null) {
        return withSuggestion(base, `did you mean the collection ${q(coll)}? write ${coll}:(…)`);
      }
      return withSuggestion(
        base,
        'class attributes are written "attr.<name>"; facts "fact.<key>"; identifiers "id.<kind>"; tags "tag.<key>"',
      );
    }
    return base;
  }

  /** Checks one field/operator/literal term. */
  private compare(f: FieldRef, op: Op, value: Literal, sp: Span, tgt: Target): void {
    if (!this.resolve(f, tgt)) return;
    if (!this.translatableField(f)) return;
    if (!operatorAllowed(f.type, op)) {
      this.add(this.operatorError(f, op, sp));
      return;
    }
    this.literal(tgt, f, value, op);
  }

  private inSet(f: FieldRef, values: Literal[], sp: Span, tgt: Target): void {
    if (!this.resolve(f, tgt)) return;
    if (!this.translatableField(f)) return;
    if (!inAllowed(f.type)) {
      this.add(this.operatorError(f, 'in', sp));
      return;
    }
    if (values.length > this.opts.maxInValues) {
      this.add(
        newError(
          'too_many_clauses',
          sp,
          `${values.length} values in one list; the limit is ${this.opts.maxInValues}`,
        ),
      );
      return;
    }
    for (const lit of values) this.literal(tgt, f, lit, ':');
  }

  private rangeTerm(f: FieldRef, lo: Literal, hi: Literal, sp: Span, tgt: Target): void {
    if (!this.resolve(f, tgt)) return;
    if (!this.translatableField(f)) return;
    if (!rangeAllowed(f.type)) {
      this.add(this.operatorError(f, '[a to b]', sp));
      return;
    }
    this.literal(tgt, f, lo, '>=');
    this.literal(tgt, f, hi, '<=');
  }

  private match(f: FieldRef, regex: string, sp: Span, tgt: Target): void {
    if (!this.resolve(f, tgt)) return;
    if (!this.translatableField(f)) return;
    if (!matchAllowed(f.type)) {
      this.add(this.operatorError(f, '~', sp));
      return;
    }
    this.regex(regex, sp);
  }

  /**
   * Enforces §6's three regex rules, plus §13 A6's dialect rule.
   *
   * The order matters. The subset scanner runs FIRST, because it is the check
   * that knows about the database: the pattern is handed to Postgres `~`, which
   * is ARE and not RE2 (see regex.ts).
   *
   * The length cap is in CODE POINTS, as §6's "256 chars" says. In Go it used
   * to be bytes, so a pattern of accented characters was refused at 128 of
   * them.
   */
  private regex(pattern: string, sp: Span): void {
    const n = [...pattern].length;
    if (n > this.opts.maxRegexLen) {
      this.add(
        newError(
          'regex_invalid',
          sp,
          `pattern is ${n} characters; the limit is ${this.opts.maxRegexLen}`,
        ),
      );
      return;
    }
    const { maxRepetition, problem } = checkRegexSubset(pattern);
    if (problem !== '') {
      this.add(newError('regex_invalid', sp, problem, REGEX_SUBSET_HELP));
      return;
    }
    if (maxRepetition > this.opts.maxRepetition) {
      this.add(
        newError(
          'regex_invalid',
          sp,
          `pattern repeats ${maxRepetition} times; the limit is ${this.opts.maxRepetition}`,
        ),
      );
      return;
    }
    const compileProblem = compileCheck(pattern);
    if (compileProblem !== '') {
      this.add(
        newError('regex_invalid', sp, `pattern is not valid: ${compileProblem}`, REGEX_SUBSET_HELP),
      );
    }
  }

  private freeText(sp: Span, tgt: Target): void {
    // §5.4 defines free text over an asset's display name, hostname, identifier
    // values and tags. No other target has that column set, so a free-text term
    // there is untranslatable rather than silently narrowed.
    if (!tgt.freeTextable) {
      this.add(
        newError(
          'untranslatable',
          sp,
          `a free-text term has no meaning on ${plural(tgt.name)}; name a field`,
          "free text searches an asset's name, hostname, identifiers and tags",
        ),
      );
    }
  }

  private sub(collection: string, predicate: Node | null, sp: Span, tgt: Target): void {
    const inner = COLLECTION_TARGET[collection];
    if (inner === undefined) {
      this.add(newError('untranslatable', sp, `unknown collection ${q(collection)}`));
      return;
    }
    if (!tgt.subs.includes(collection)) {
      this.add(
        newError(
          'untranslatable',
          sp,
          `${q(collection)} is not reachable from ${plural(tgt.name)}`,
          `from ${plural(tgt.name)} you can reach: ${tgt.subs.join(', ')}`,
        ),
      );
      return;
    }
    const innerTgt = findTarget(this.cat, inner);
    if (innerTgt === null) {
      this.add(
        newError(
          'untranslatable',
          sp,
          `the catalogue has no target for collection ${q(collection)}`,
        ),
      );
      return;
    }
    if (predicate !== null) this.node(predicate, innerTgt);
  }

  private traverse(
    form: TraverseForm,
    name: string,
    predicate: Node,
    sp: Span,
    tgt: Target,
  ): void {
    if (!tgt.traversable) {
      this.add(
        newError(
          'untranslatable',
          sp,
          `relationships join assets; traversal is not available on ${plural(tgt.name)}`,
          `wrap it: asset:(${name}:(…))`,
        ),
      );
      return;
    }
    if (form !== 'any') {
      if (!this.knownRelationship(name)) {
        const names = this.relationshipNames();
        const e = newError('unknown_value', sp, `unknown relationship ${q(name)}`);
        const near = nearest(name, names, 2);
        this.add(
          near !== null
            ? withSuggestion(e, `did you mean ${q(near)}?`)
            : withSuggestion(e, `relationships: ${names.join(', ')}`),
        );
        return;
      }
      if (form === 'rel' && !isRelationshipType(name)) {
        const rel = lookupRelationship(name);
        this.add(
          newError(
            'unknown_value',
            sp,
            `${q(name)} is a reverse label; the rel(…) form takes a canonical relationship type`,
            `write rel(${rel === null ? name : rel.type}, in, …) or use the label on its own: ${name}:(…)`,
          ),
        );
        return;
      }
    }
    // There is deliberately no `depth < 1` check here. The hop count is
    // grammar, not vocabulary: the parser refuses anything but a positive whole
    // number and defaults to 1 when the argument is absent, so a Traverse node
    // cannot reach the validator with a depth below one. A second copy of the
    // rule here could only ever disagree with the first.
    this.node(predicate, tgt);
  }

  private knownRelationship(name: string): boolean {
    const lower = name.toLowerCase();
    return this.cat.relationshipNames().some((r) => r.name.toLowerCase() === lower);
  }

  private relationshipNames(): string[] {
    return this.cat.relationshipNames().map((r) => r.name);
  }

  /**
   * Rejects a resolved field a translator could not build SQL for, before it
   * gets there (§6 untranslatable).
   */
  private translatableField(f: FieldRef): boolean {
    if (!knownType(f.type)) {
      this.add(
        newError('untranslatable', f.span, `field ${q(f.text)} has no usable type in the catalogue`),
      );
      return false;
    }
    if (f.type === 'version' && (f.accessor.sortColumn ?? '') === '') {
      this.add(
        newError(
          'untranslatable',
          f.span,
          `field ${q(f.text)} is a version with no normalised sort key, and a lexical comparison is forbidden`,
        ),
      );
      return false;
    }
    if (f.type === 'band' && this.opts.ladder === undefined) {
      this.add(
        newError(
          'untranslatable',
          f.span,
          `field ${q(f.text)} is a band and no band ladder was supplied`,
        ),
      );
      return false;
    }
    return true;
  }

  private operatorError(f: FieldRef, op: string, sp: Span): QueryError {
    return newError(
      'operator_not_allowed',
      sp,
      `${q(f.text)} is a ${f.type} field and does not accept ${q(op)}`,
      `${f.type} accepts: ${operatorsFor(f.type).join(' ')}`,
    );
  }

  /**
   * Checks a value against the field's type (§6 type_mismatch) and against any
   * closed value set (§6 unknown_value).
   */
  private literal(tgt: Target, f: FieldRef, lit: Literal, op: Op): void {
    if (isBareStar(lit)) {
      // `field:*` is the "present at all" spelling and is legal on every type;
      // there is nothing to type-check.
      if (op !== ':') {
        this.add(
          newError(
            'type_mismatch',
            lit.span,
            'a bare "*" means "present at all" and only works with ":"',
            `write exists(${f.text})`,
          ),
        );
      }
      return;
    }
    if (isWildcard(lit)) {
      if (!wildcardAllowed(f.type)) {
        this.add(
          newError(
            'operator_not_allowed',
            lit.span,
            `${q(f.text)} is a ${f.type} field and does not accept a "*" wildcard`,
            `${f.type} accepts: ${operatorsFor(f.type).join(' ')}`,
          ),
        );
        return;
      }
      if (isOrdering(op)) {
        this.add(
          newError('type_mismatch', lit.span, `a wildcard cannot be ordered against with ${q(op)}`),
        );
      }
      return;
    }

    switch (f.type) {
      case 'number':
        if (parseNumber(lit.value) === null) this.add(this.typeMismatch(f, lit, 'a number'));
        break;
      case 'timestamp':
        if (parseDate(lit.value) === null) {
          this.add(
            withSuggestion(
              this.typeMismatch(f, lit, 'a date'),
              'write 2026-09-11, 2026-09-11T14:30:00Z, now, or now-30d',
            ),
          );
        }
        break;
      case 'boolean':
        if (parseBool(lit.value) === null) this.add(this.typeMismatch(f, lit, 'true or false'));
        break;
      case 'uuid':
        if (!parseUUID(lit.value)) {
          let e = this.typeMismatch(f, lit, 'a uuid');
          // `id:"aa:bb:cc:dd:ee:ff"` was the cheat sheet's spelling for "an
          // identifier of any kind" before a bare `id` became the row's own
          // uuid (§13 A1). Anyone carrying the old form lands here, so say
          // where it went — asked of the catalogue, not hard-coded.
          const alt = this.anyIdentifierField(tgt, f);
          if (alt !== null) {
            e = withSuggestion(
              e,
              `for an identifier of any kind write ${alt}:${quoteValue(lit.value)}`,
            );
          }
          this.add(e);
        }
        break;
      case 'inet':
        if (parseInet(lit.value) === null) {
          this.add(this.typeMismatch(f, lit, 'an address or a CIDR block'));
        }
        break;
      case 'version':
        if (!looksLikeVersion(lit.value)) this.add(this.typeMismatch(f, lit, 'a version'));
        break;
      case 'class': {
        if (this.cat.classExists(lit.value) === null) {
          let e = newError('unknown_value', lit.span, `no class ${q(lit.value)}`);
          const near = nearestValue(lit.value, this.classNames());
          if (near !== null) e = withSuggestion(e, `did you mean ${q(near)}?`);
          this.add(e);
        }
        return;
      }
      case 'band':
        this.band(tgt, f, lit, op);
        return;
      default:
        break;
    }
    // Every other type may additionally carry a closed value set.
    this.checkEnum(f, lit);
  }

  /**
   * Checks a band label against the ladder, and not_assessed against the
   * field's coverage column (§5.2) and the operator it was written with.
   */
  private band(tgt: Target, f: FieldRef, lit: Literal, op: Op): void {
    const ladder = this.opts.ladder;
    if (ladder === undefined) return;
    if (lit.value.toLowerCase() === NOT_ASSESSED) {
      if ((f.accessor.assessedBy ?? '') === '') {
        this.add(
          newError(
            'unknown_value',
            lit.span,
            `${q(f.text)} does not record who assessed it, so ${q(NOT_ASSESSED)} has no meaning for it`,
            `bands: ${bandLabels(ladder, false).join(', ')}`,
          ),
        );
        return;
      }
      // not_assessed is NOT a rung of the ladder — it is the absence of a score
      // — so it cannot be ordered against or used as a range bound.
      // `risk < not_assessed` used to validate and then return every unassessed
      // asset, and `risk:[not_assessed to high]` validated and then failed
      // `untranslatable`, a code §6 reserves for a parser bug (§13 A2).
      if (op !== ':' && op !== '=' && op !== '!=') {
        this.add(
          newError(
            'operator_not_allowed',
            lit.span,
            `${q(NOT_ASSESSED)} is not a rung of the ladder, so it cannot be used with ${q(op)}`,
            `write ${f.text}:${NOT_ASSESSED}, or order against a band: ${bandLabels(ladder, false).join(', ')}`,
          ),
        );
      }
      return;
    }
    if (bandIndex(ladder, lit.value) >= 0) return;
    let e = newError(
      'type_mismatch',
      lit.span,
      `${q(f.text)} is a band (${bandLabels(ladder, (f.accessor.assessedBy ?? '') !== '').join(', ')})`,
    );
    if (parseNumber(lit.value) !== null) {
      const numeric = this.numericTwin(tgt, f);
      if (numeric !== null) {
        e = withSuggestion(e, `for the numeric score use ${q(`${numeric} >= ${lit.value}`)}`);
      }
    } else {
      const near = nearestValue(lit.value, bandLabels(ladder, true));
      if (near !== null) e = withSuggestion(e, `did you mean ${q(near)}?`);
    }
    this.add(e);
  }

  /**
   * Reports the catalogue's spelling for "an identifier of any kind", when the
   * field being complained about is the bare row id that spelling used to
   * collide with (§13 A1).
   */
  private anyIdentifierField(tgt: Target, f: FieldRef): string | null {
    if (f.text.toLowerCase() !== 'id') return null;
    for (const cand of this.cat.fields(tgt.name)) {
      if (cand.accessor.kind === 'identifier_any') return cand.name;
    }
    return null;
  }

  /**
   * Finds the number-typed field that shares a band field's column, so
   * "risk >= 70" can suggest "risk_score >= 70" without hard-coding the pair.
   */
  private numericTwin(tgt: Target, f: FieldRef): string | null {
    for (const cand of this.cat.fields(tgt.name)) {
      if (cand.type === 'number' && cand.accessor.column === f.accessor.column) return cand.name;
    }
    return null;
  }

  /** Checks a closed value set. */
  private checkEnum(f: FieldRef, lit: Literal): void {
    const values = this.cat.enumValues(f);
    if (values === null || values.length === 0) return;
    const lower = lit.value.toLowerCase();
    for (const val of values) if (val.toLowerCase() === lower) return;
    let e = newError('unknown_value', lit.span, `${q(lit.value)} is not a value of ${q(f.text)}`);
    const near = nearestValue(lit.value, values);
    e = withSuggestion(
      e,
      near !== null ? `did you mean ${q(near)}?` : `values: ${values.join(', ')}`,
    );
    this.add(e);
  }

  private typeMismatch(f: FieldRef, lit: Literal, want: string): QueryError {
    return newError(
      'type_mismatch',
      lit.span,
      `${q(f.text)} is a ${f.type} field; ${q(lit.value)} is not ${want}`,
    );
  }

  /**
   * Returns the class keys a catalogue publishes, if it publishes them. Without
   * them, an unknown class is still reported, just without a "did you mean".
   */
  private classNames(): string[] {
    return this.cat.classKeys === undefined ? [] : this.cat.classKeys();
  }

  /** Enforces the leaf, sub-predicate and traversal caps (§6). */
  checkCounts(root: Node, src: string): void {
    let leaves = 0;
    let subs = 0;
    walk(root, (n) => {
      switch (n.kind) {
        case 'cmp':
        case 'in':
        case 'range':
        case 'match':
        case 'exists':
        case 'text':
          leaves++;
          break;
        case 'sub':
        case 'traverse':
          subs++;
          break;
        default:
          break;
      }
      return true;
    });
    const whole: Span = { start: 0, end: src.length };
    if (leaves > this.opts.maxLeaves) {
      this.add(
        newError(
          'too_many_clauses',
          whole,
          `query has ${leaves} terms; the limit is ${this.opts.maxLeaves}`,
        ),
      );
    }
    if (subs > this.opts.maxSubs) {
      this.add(
        newError(
          'too_many_clauses',
          whole,
          `query has ${subs} sub-predicates and traversals; the limit is ${this.opts.maxSubs}`,
        ),
      );
    }
  }

  /**
   * Enforces the traversal budget: the sum of declared depths along the deepest
   * nested path (§5.6).
   */
  checkBudget(root: Node): void {
    let budget = this.opts.traversalBudget;
    if (budget > this.opts.hardMaxTraversal) budget = this.opts.hardMaxTraversal;
    const { cost, deepest } = traversalCost(root);
    if (cost <= budget) return;
    const sp = deepest === null ? root.span : deepest.span;
    let e = newError('depth_exceeded', sp, `traversal is ${cost} hops deep; the budget is ${budget}`);
    if (this.opts.traversalBudget > this.opts.hardMaxTraversal) {
      e = withSuggestion(
        e,
        `the configured budget of ${this.opts.traversalBudget} is above the hard maximum of ${this.opts.hardMaxTraversal}`,
      );
    } else {
      e = withSuggestion(e, 'the budget is the sum of declared depths along the deepest nested path');
    }
    this.add(e);
  }
}

/**
 * Returns the budget a tree consumes and the traversal that tops it, for the
 * error span.
 */
function traversalCost(n: Node | null): { cost: number; deepest: Node | null } {
  if (n === null) return { cost: 0, deepest: null };
  switch (n.kind) {
    case 'and':
    case 'or':
      return maxCost(n.children);
    case 'not':
      return traversalCost(n.child);
    case 'sub':
      return traversalCost(n.predicate);
    case 'traverse': {
      const inner = traversalCost(n.predicate);
      return { cost: n.depth + inner.cost, deepest: n };
    }
    default:
      return { cost: 0, deepest: null };
  }
}

function maxCost(children: Node[]): { cost: number; deepest: Node | null } {
  let best = 0;
  let node: Node | null = null;
  for (const c of children) {
    const { cost, deepest } = traversalCost(c);
    if (cost > best) {
      best = cost;
      node = deepest;
    }
  }
  return { cost: best, deepest: node };
}

/** Renders a string the way Go's %q verb does, for message parity. */
function q(s: string): string {
  return JSON.stringify(s);
}

function plural(target: string): string {
  switch (target) {
    case 'asset':
      return 'assets';
    case 'certificate':
      return 'certificates';
    case 'finding':
      return 'findings';
    case 'endpoint':
      return 'endpoints';
    case 'identifier':
      return 'identifiers';
    case 'relationship':
      return 'relationships';
    case 'observation':
      return 'observations';
    default:
      return target + 's';
  }
}

/** Re-exported so callers can name a field type without importing ./ast. */
export type { FieldType };
/** Re-exported so callers listing relationships need only this module. */
export { RELATIONSHIPS };
