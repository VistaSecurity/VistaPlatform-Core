// Renders an AST back to canonical query text.
//
// QUERY_LANGUAGE.md §10: format(q) rewrites any valid query to one text, and
// format(format(q)) === format(q). Formatting is syntactic normalisation, not
// algebraic rewriting — clause order is preserved, `a >= 1 and a <= 10` is not
// folded into a range, and terms are never sorted. The facet rail edits by
// position, and a user's order carries meaning they can read back.
//
// It runs on an unvalidated tree as happily as a validated one: everything here
// is decided by the shape of the node, never by a field's type.

import type { Literal, Node, Op } from './ast';
import { quote, quoteFreeText, quoteLiteral } from './literal';
import { REL_KEYWORD } from './vocabulary';

/**
 * Renders a node as canonical query text. A null node is the empty query, which
 * matches everything under RLS.
 */
export function format(n: Node | null): string {
  if (n === null) return '';
  return write(n, 'top');
}

/**
 * Says what the node is nested inside, which is all that decides whether it
 * needs parentheses.
 */
type Context = 'top' | 'or' | 'and' | 'not';

/**
 * Reports whether a node must be parenthesised in the given context. The rule
 * is not only precedence: an Or directly inside an Or, or an And inside an And,
 * would reparse as one flattened node — a different tree — so the parentheses
 * that produced the nesting are kept. §10 licenses removing a parenthesis only
 * when "the result reparses to an identical AST".
 */
function needsParens(n: Node, ctx: Context): boolean {
  switch (n.kind) {
    case 'or':
      // `or` binds loosest, so it needs parentheses anywhere but the top.
      return ctx !== 'top';
    case 'and':
      // `and` binds tighter than `or`, so `a or b and c` already reparses to
      // Or{a, And{b, c}} — no parentheses inside an Or. Inside another And they
      // preserve the nesting; inside a Not they preserve the scope.
      return ctx === 'and' || ctx === 'not';
    default:
      return false;
  }
}

function write(n: Node, ctx: Context): string {
  if (needsParens(n, ctx)) return '(' + writeBare(n) + ')';
  return writeBare(n);
}

function writeBare(n: Node): string {
  switch (n.kind) {
    case 'and':
      return n.children.map((c) => write(c, 'and')).join(' and ');
    case 'or':
      return n.children.map((c) => write(c, 'or')).join(' or ');
    case 'not':
      // `-term` is written `not term` (§10).
      return 'not ' + write(n.child, 'not');
    case 'cmp':
      return n.field.text + opSpelling(n.op) + value(n.value);
    case 'in':
      return (
        n.field.text +
        (n.negated ? ' not in (' : ' in (') +
        n.values.map(value).join(', ') +
        ')'
      );
    case 'range':
      return n.field.text + ':[' + value(n.lo) + ' to ' + value(n.hi) + ']';
    case 'match':
      return n.field.text + ' ~ ' + quote(n.regex);
    case 'exists':
      return 'exists(' + n.field.text + ')';
    case 'text':
      // A free-text term is quoted more eagerly than a value: see
      // isSafeFreeText.
      return quoteFreeText(n.value);
    case 'sub':
      if (n.predicate === null) return 'exists(' + n.collection + ')';
      return n.collection + ':(' + write(n.predicate, 'top') + ')';
    case 'traverse': {
      let head: string;
      if (n.form === 'rel') {
        head =
          REL_KEYWORD +
          '(' +
          n.name +
          ', ' +
          n.direction +
          (n.depth !== 1 ? ', ' + String(n.depth) : '') +
          ')';
      } else {
        // One hop is the grammar's default, so `depends_on(1)` canonicalises to
        // `depends_on`; anything else is written.
        head = n.name + (n.depth !== 1 ? '(' + String(n.depth) + ')' : '');
      }
      return head + ':(' + write(n.predicate, 'top') + ')';
    }
  }
}

/**
 * Renders an operator with §10's spacing: none around ":" and "=", one space
 * around every other comparison operator.
 */
function opSpelling(op: Op): string {
  if (op === ':') return ':';
  if (op === '=') return '=';
  return ' ' + op + ' ';
}

/**
 * Renders a literal: quoted iff it is not a safe bareword, and with a relative
 * date written in the largest unit that is exact (§10).
 */
function value(l: Literal): string {
  return quoteLiteral(l);
}
