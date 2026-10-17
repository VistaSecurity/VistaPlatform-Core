#!/usr/bin/env node
// Normalise pg_dump output read on stdin so that two databases holding the
// same objects print the same text, whatever order the objects were created
// in. Used by schema-normalised-dump.sh; see that file for the why.
//
//   pg_dump --schema-only ... | node normalise-pg-dump.mjs schema
//   pg_dump --data-only   ... | node normalise-pg-dump.mjs data
//
// pg_dump precedes every archive entry with a header comment
//   -- Name: <name>; Type: <type>; Schema: <schema>; Owner: -
// (or "-- Data for Name: ..." in a data dump). Each header starts a block;
// the block's key is "<type>|<schema>|<name>" and the output is the blocks
// sorted by key, each printed as "-- <key>" followed by its statement text.
//
// Removed: every other `--` comment line, SET / set_config preamble lines,
// pg_dump 17's \restrict / \unrestrict lines (their key is random per run),
// trailing whitespace and runs of blank lines. Kept verbatim: everything else
// — column order, defaults, constraints, enum label order, function bodies,
// policy expressions. Nothing inside a statement is reordered.
//
// Data mode additionally masks UUIDs and timestamps (they differ between any
// two runs) and sorts the COPY rows within a table, and prefixes each table
// with its row count.
import { readFileSync } from 'node:fs';

const mode = process.argv[2] || 'schema';
if (mode !== 'schema' && mode !== 'data') {
  console.error(`unknown mode ${mode}`);
  process.exit(2);
}
const text = readFileSync(0, 'utf8');
const header = /^-- (?:Data for )?Name: (.*); Type: (.*); Schema: (.*); Owner: .*$/;

const blocks = new Map();
let key = '~preamble';
let lines = [];
const flush = () => {
  const body = lines.join('\n').replace(/\n{2,}/g, '\n').trim();
  if (body) {
    // Two entries can share a key (e.g. pg_dump emits a table's ACL and a
    // comment under one name in some versions); keep both, in a stable order.
    let k = key;
    let n = 1;
    while (blocks.has(k)) k = `${key}#${++n}`;
    blocks.set(k, body);
  }
  lines = [];
};

for (const raw of text.split('\n')) {
  const line = raw.replace(/\s+$/, '');
  const m = header.exec(line);
  if (m) {
    flush();
    key = `${m[2]}|${m[3]}|${m[1]}`;
    continue;
  }
  if (/^--/.test(line)) continue;
  if (/^\\(un)?restrict /.test(line)) continue;
  if (/^SET [a-z_]+ = /.test(line)) continue;
  if (/^SELECT pg_catalog\.set_config\('search_path'/.test(line)) continue;
  lines.push(line);
}
flush();

const uuid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ts = /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}(?::\d{2})?|Z)?/g;

const out = [];
for (const k of [...blocks.keys()].sort()) {
  let body = blocks.get(k);
  if (mode === 'data' && /^COPY /.test(body)) {
    const ls = body.split('\n');
    const copy = ls[0];
    const end = ls.lastIndexOf('\\.');
    const rows = ls.slice(1, end < 0 ? undefined : end).map((r) => r.replace(uuid, '<uuid>').replace(ts, '<ts>'));
    rows.sort();
    body = [`${copy}  -- ${rows.length} rows`, ...rows].join('\n');
  }
  out.push(`-- ${k}\n${body}`);
}
process.stdout.write(out.join('\n') + '\n');
