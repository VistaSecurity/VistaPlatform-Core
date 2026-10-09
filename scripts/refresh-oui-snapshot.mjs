#!/usr/bin/env node
// Refreshes the vendored IEEE OUI registry snapshot under standards/oui/.
// Run by an operator via `make refresh-oui`. Deliberately NOT part of
// `make generate` or `make audit`: both must stay offline and deterministic,
// and a weekly-changing upstream file would make every unrelated commit drift.
//
// Downloads the three IEEE registries and rewrites each as a two-column TSV:
//
//   standards/oui/ieee-mal.tsv   MA-L, 24-bit, 6 hex digits
//   standards/oui/ieee-mam.tsv   MA-M, 28-bit, 7 hex digits
//   standards/oui/ieee-mas.tsv   MA-S, 36-bit, 9 hex digits
//
// Only the assignment and the registrant name are kept (the address column is
// dropped) so the files stay small and a refresh diff reads as "who changed",
// not as a postal-address churn. Registrant names are whitespace-normalised.
//
// After a refresh, run `make generate`: scripts/generate-oui-registry.mjs fails
// if a registrant named in standards/oui/vendors.yaml no longer matches any
// row, which is the cue to update the vendor map.
//
// Fails loudly on an HTTP error, an empty body, a malformed row, or an MA-L
// parse with fewer than MIN_MAL_ROWS rows: a truncated download that quietly
// replaced the snapshot would silently un-resolve thousands of prefixes.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const outDir = path.join(root, 'standards', 'oui');

export const MIN_MAL_ROWS = 30000;

export const SOURCES = [
  { file: 'ieee-mal.tsv', registry: 'MA-L', bits: 24, hex: 6, url: 'https://standards-oui.ieee.org/oui/oui.csv' },
  { file: 'ieee-mam.tsv', registry: 'MA-M', bits: 28, hex: 7, url: 'https://standards-oui.ieee.org/oui28/mam.csv' },
  { file: 'ieee-mas.tsv', registry: 'MA-S', bits: 36, hex: 9, url: 'https://standards-oui.ieee.org/oui36/oui36.csv' },
];

function fail(msg) {
  console.error(`❌ refresh-oui: ${msg}`);
  process.exit(1);
}

/**
 * Parses RFC 4180 CSV (quoted fields may hold commas, doubled quotes and line
 * breaks) into an array of string arrays.
 */
export function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"') {
      quoted = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (quoted) throw new Error('unterminated quoted field at end of input');
  if (field !== '' || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/**
 * Normalises a registrant name: full-width commas become ASCII ones, every run
 * of whitespace (incl. CR/LF, tabs and no-break spaces) becomes one space, and
 * the ends are trimmed. A tab or newline can therefore never reach the TSV.
 */
export function cleanName(name) {
  return String(name)
    .replace(/，/g, ', ')
    .replace(/\s+/gu, ' ')
    .replace(/ ,/g, ',')
    .trim();
}

/**
 * Converts one IEEE CSV body into sorted [assignment, registrant] pairs.
 * Throws on anything malformed rather than skipping it.
 */
export function convert(source, body) {
  if (!body || !body.trim()) throw new Error(`${source.url}: empty body`);
  const rows = parseCSV(body.replace(/^﻿/, ''));
  const header = rows.shift() ?? [];
  if (header[0] !== 'Registry' || header[1] !== 'Assignment' || header[2] !== 'Organization Name') {
    throw new Error(`${source.url}: unexpected header ${JSON.stringify(header)}`);
  }
  const re = new RegExp(`^[0-9A-F]{${source.hex}}$`);
  // The IEEE lists a handful of legacy MA-L assignments more than once with
  // different registrants (080030 has three). Every row is kept, verbatim; the
  // generator decides what an ambiguous assignment resolves to, so the
  // snapshot never encodes a choice nobody can see.
  const seen = new Set();
  const pairs = [];
  rows.forEach((r, i) => {
    const line = i + 2;
    if (r.length < 3) throw new Error(`${source.url}: row ${line} has ${r.length} fields`);
    const registry = r[0].trim();
    const assignment = r[1].trim().toUpperCase();
    const name = cleanName(r[2]);
    if (registry !== source.registry) {
      throw new Error(`${source.url}: row ${line} registry ${JSON.stringify(registry)}, want ${source.registry}`);
    }
    if (!re.test(assignment)) {
      throw new Error(`${source.url}: row ${line} bad assignment ${JSON.stringify(r[1])}`);
    }
    if (!name) throw new Error(`${source.url}: row ${line} (${assignment}) has an empty registrant`);
    const key = `${assignment}\t${name}`;
    if (seen.has(key)) return; // an exact duplicate row carries no information
    seen.add(key);
    pairs.push([assignment, name]);
  });
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  return pairs.sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]));
}

export function renderTSV(source, pairs, fetchedOn) {
  const header = [
    `# IEEE ${source.registry} (${source.bits}-bit) registry snapshot. Source: ${source.url}`,
    `# Fetched: ${fetchedOn}. ${pairs.length} rows.`,
    '# Columns: assignment (upper-case hex, no separators) <TAB> registrant (whitespace-normalised; address dropped).',
    '# Refresh with `make refresh-oui`; do not hand-edit.',
  ];
  return `${header.join('\n')}\n${pairs.map(([a, n]) => `${a}\t${n}`).join('\n')}\n`;
}

async function download(url) {
  let res;
  try {
    res = await fetch(url, { redirect: 'follow' });
  } catch (err) {
    fail(`${url}: ${err.message}`);
  }
  if (!res.ok) fail(`${url}: HTTP ${res.status} ${res.statusText}`);
  const body = await res.text();
  if (!body.trim()) fail(`${url}: empty body`);
  if (/^\s*</.test(body)) fail(`${url}: got HTML instead of CSV (WAF rejection?): ${body.slice(0, 120)}`);
  return body;
}

async function main() {
  const fetchedOn = new Date().toISOString().slice(0, 10);
  const results = [];
  // Download and validate all three before writing any, so a failure leaves
  // the committed snapshot internally consistent.
  for (const source of SOURCES) {
    const body = await download(source.url);
    let pairs;
    try {
      pairs = convert(source, body);
    } catch (err) {
      fail(err.message);
    }
    if (source.registry === 'MA-L' && pairs.length < MIN_MAL_ROWS) {
      fail(`${source.url}: only ${pairs.length} MA-L rows parsed (want >= ${MIN_MAL_ROWS}); refusing to replace the snapshot`);
    }
    if (!pairs.length) fail(`${source.url}: no rows parsed`);
    results.push({ source, pairs });
  }
  await fs.mkdir(outDir, { recursive: true });
  for (const { source, pairs } of results) {
    const out = path.join(outDir, source.file);
    await fs.writeFile(out, renderTSV(source, pairs, fetchedOn));
    console.log(`Wrote ${path.relative(root, out)} (${pairs.length} ${source.registry} rows)`);
  }
  console.log('Now run `make generate` to rebuild shared/ouiregistry from the new snapshot.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => fail(err.stack || String(err)));
}
