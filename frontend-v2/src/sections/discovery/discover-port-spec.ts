// The Discover wizard's Custom-depth port fields (hole H8): the same
// rule, and the same sentences, as the platform's ParsePortSpec
// (shared/discovery/scan_ports.go), so a person is told what the server would
// tell them before they press Start.
//
// H8 was the old Ports box reading "8000-8100" as 8000 (parseInt stops at the
// '-') and dropping anything else it could not read, silently. A range means
// the range here, and an entry the server would refuse is refused here too,
// naming it.
//
// Parity is not by inspection: shared/discovery/testdata/port_specs.json is
// read by BOTH the Go test (scan_ports_vectors_test.go) and this file's test,
// error text compared word for word, so the two cannot drift apart unnoticed.
// The Go-isms below (byte length, Go's notion of whitespace, Go's %q quoting)
// exist only so those sentences match.

/** The most bytes of text the platform will read in one port field. */
export const MAX_PORT_SPEC_BYTES = 4096;
/** The most comma-separated entries the platform will read in one port field. */
export const MAX_PORT_SPEC_ENTRIES = 1024;

export type PortSpecResult =
  | { ok: true; ports: number[]; canonical: string }
  | { ok: false; error: string };

// Go's unicode.IsSpace, which strings.TrimSpace uses. JavaScript's trim()
// differs at the edges (it trims U+FEFF and not U+0085), and an edge is
// exactly where the two sentences would disagree.
const GO_SPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

function goTrimSpace(s: string): string {
  const cps = Array.from(s);
  let lo = 0;
  let hi = cps.length;
  while (lo < hi && GO_SPACE.has(cps[lo].codePointAt(0)!)) lo++;
  while (hi > lo && GO_SPACE.has(cps[hi - 1].codePointAt(0)!)) hi--;
  return cps.slice(lo, hi).join('');
}

// Go's %q (strconv.Quote): printable characters as they are, quotes and
// backslashes escaped, the short escapes, other ASCII controls as \xNN and any
// other non-printable code point as \uXXXX / \UXXXXXXXX. "Printable" is Go's
// unicode.IsPrint — letters, marks, numbers, punctuation, symbols and the
// ASCII space — i.e. not a control/format/unassigned (\p{C}) or separator
// (\p{Z}) character.
const SHORT_ESCAPES: Record<number, string> = { 0x07: '\\a', 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0b: '\\v', 0x0c: '\\f', 0x0d: '\\r' };
const NOT_PRINTABLE = /[\p{C}\p{Z}]/u;
export function goQuote(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === '"' || ch === '\\') out += '\\' + ch;
    else if (ch === ' ' || !NOT_PRINTABLE.test(ch)) out += ch;
    else if (SHORT_ESCAPES[cp]) out += SHORT_ESCAPES[cp];
    else if (cp < 0x20 || cp === 0x7f) out += '\\x' + cp.toString(16).padStart(2, '0');
    else if (cp < 0x10000) out += '\\u' + cp.toString(16).padStart(4, '0');
    else out += '\\U' + cp.toString(16).padStart(8, '0');
  }
  return out + '"';
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

function parseNumber(s: string): number | string {
  if (s === '') return 'missing port number';
  for (const ch of s) {
    if (ch < '0' || ch > '9') return `${goQuote(s)} is not a port number`;
  }
  if (s.length > 5) return `port ${s} is out of range 1-65535`;
  const n = Number(s);
  if (n < 1 || n > 65535) return `port ${n} is out of range 1-65535`;
  return n;
}

function parseToken(tok: string): [number, number] | string {
  if (tok.split('-').length - 1 > 1) return "a range has exactly one '-'";
  const dash = tok.indexOf('-');
  const lo = parseNumber(goTrimSpace(dash < 0 ? tok : tok.slice(0, dash)));
  if (typeof lo === 'string') return lo;
  if (dash < 0) return [lo, lo];
  const hi = parseNumber(goTrimSpace(tok.slice(dash + 1)));
  if (typeof hi === 'string') return hi;
  if (lo > hi) return `range start ${lo} is greater than its end ${hi}`;
  return [lo, hi];
}

/**
 * Parse a comma-separated list of ports and inclusive ranges ("22,80,8000-8100")
 * exactly as the platform does. The result is sorted and de-duplicated, with
 * the server's canonical spelling; an error is the server's sentence.
 */
export function parsePortSpec(spec: string): PortSpecResult {
  const bytes = utf8Length(spec);
  if (bytes > MAX_PORT_SPEC_BYTES) return { ok: false, error: `port spec is ${bytes} bytes; the limit is ${MAX_PORT_SPEC_BYTES}` };
  const trimmed = goTrimSpace(spec);
  if (trimmed === '') return { ok: false, error: 'port spec is empty' };
  const tokens = trimmed.split(',');
  if (tokens.length > MAX_PORT_SPEC_ENTRIES) {
    return { ok: false, error: `port spec has ${tokens.length} entries; the limit is ${MAX_PORT_SPEC_ENTRIES}` };
  }
  const seen = new Uint8Array(65536);
  for (let i = 0; i < tokens.length; i++) {
    const tok = goTrimSpace(tokens[i]);
    if (tok === '') return { ok: false, error: `port spec entry ${i + 1} is empty` };
    const r = parseToken(tok);
    if (typeof r === 'string') return { ok: false, error: `port spec entry ${goQuote(tok)}: ${r}` };
    for (let p = r[0]; p <= r[1]; p++) seen[p] = 1;
  }
  const ports: number[] = [];
  for (let p = 1; p <= 65535; p++) if (seen[p]) ports.push(p);
  return { ok: true, ports, canonical: formatPortSpec(ports) };
}

/** Sorted ports in the platform's spelling, runs collapsed: [22,80,81,82] → "22,80-82". */
export function formatPortSpec(sorted: number[]): string {
  const parts: string[] = [];
  for (let i = 0; i < sorted.length; ) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
    parts.push(j > i ? `${sorted[i]}-${sorted[j]}` : `${sorted[i]}`);
    i = j + 1;
  }
  return parts.join(',');
}
