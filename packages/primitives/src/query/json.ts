// The compact JSON encoding of the tree.
//
// This is the cross-language shape of the AST: it is what
// `shared/query/testdata/conformance.json` records, so this port can be held to
// the same trees as the Go parser. It is deliberately lossless about the things
// that change meaning — quoting, negation form, traversal form — and silent
// about the things that do not, notably spans.
//
//	and      {"and":[node, …]}
//	or       {"or":[node, …]}
//	not      {"not":node}
//	cmp      {"cmp":{"f":field,"op":op,"v":literal}}
//	in       {"in":{"f":field,"v":[literal, …],"neg":bool}}   (neg omitted when false)
//	range    {"range":{"f":field,"lo":literal,"hi":literal}}
//	match    {"match":{"f":field,"re":string}}
//	exists   {"exists":{"f":field}}
//	text     {"text":literal}
//	sub      {"sub":{"c":collection,"p":node}}                (p omitted for exists(c))
//	traverse {"traverse":{"form":form,"rel":name,"t":type,"dir":dir,"depth":int,"p":node}}
//
// A literal encodes as a JSON string when it was bare, and as {"s":string} when
// it was quoted AND unquoting it would change its meaning.

import type { Literal, Node } from './ast';
import { canonicalText } from './literal';

/** A plain JSON value, as produced by the compact encoding. */
export type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [key: string]: JSONValue };

/** Returns the compact encoding of n as plain JSON values. */
export function toJSON(n: Node | null): JSONValue {
  if (n === null) return null;
  switch (n.kind) {
    case 'and':
      return { and: n.children.map(toJSON) };
    case 'or':
      return { or: n.children.map(toJSON) };
    case 'not':
      return { not: toJSON(n.child) };
    case 'cmp':
      return { cmp: { f: n.field.text, op: n.op, v: literalJSON(n.value) } };
    case 'in': {
      const m: { [key: string]: JSONValue } = {
        f: n.field.text,
        v: n.values.map(literalJSON),
      };
      if (n.negated) m.neg = true;
      return { in: m };
    }
    case 'range':
      return {
        range: { f: n.field.text, lo: literalJSON(n.lo), hi: literalJSON(n.hi) },
      };
    case 'match':
      return { match: { f: n.field.text, re: n.regex } };
    case 'exists':
      return { exists: { f: n.field.text } };
    case 'text':
      // Free text is a substring search over a fixed column set (§5.4), so a
      // "*" in it is an ordinary character and quoting changes nothing. The
      // encoding says so, rather than recording a distinction the semantics do
      // not have. It is not date-canonicalised either — free text can never be
      // an instant, so `now-24h` is the eight characters it looks like.
      return { text: n.value.value };
    case 'sub': {
      const m: { [key: string]: JSONValue } = { c: n.collection };
      if (n.predicate !== null) m.p = toJSON(n.predicate);
      return { sub: m };
    }
    case 'traverse': {
      const m: { [key: string]: JSONValue } = {
        form: n.form,
        rel: n.name,
        dir: n.direction,
        depth: n.depth,
        p: toJSON(n.predicate),
      };
      if (n.type !== '') m.t = n.type;
      return { traverse: m };
    }
  }
}

/**
 * Encodes a literal. Quoting is lexical, not semantic — `plain` and `"plain"`
 * are the same value — with one exception: a quoted value containing `*` is a
 * literal asterisk where a bare one is a wildcard, so that case is marked.
 * Relative dates are encoded canonically, so `now-24h` and `now-1d` are one
 * tree.
 */
function literalJSON(l: Literal): JSONValue {
  if (l.form === 'string' && l.value.includes('*')) return { s: l.value };
  return canonicalText(l);
}

/**
 * Renders the compact encoding with sorted object keys, so two runs produce
 * byte-identical output and the bytes match Go's `encoding/json`, which sorts
 * map keys.
 */
export function marshalJSON(n: Node | null): string {
  return stringifyStable(toJSON(n));
}

function stringifyStable(v: JSONValue): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return '[' + v.map(stringifyStable).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort();
    return (
      '{' + keys.map((k) => JSON.stringify(k) + ':' + stringifyStable(v[k])).join(',') + '}'
    );
  }
  return JSON.stringify(v);
}

/**
 * Reports whether two nodes have the same compact encoding. Spans are not part
 * of the encoding, so this is tree equality modulo source position.
 */
export function equalJSON(a: Node | null, b: Node | null): boolean {
  return marshalJSON(a) === marshalJSON(b);
}
