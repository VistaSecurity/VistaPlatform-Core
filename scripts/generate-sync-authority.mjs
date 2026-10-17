#!/usr/bin/env node
// Generates the sync field-authority registry from standards/sync-authority.yaml
// (asset-inventory ADR-0010 D7; DCIM SYNC_MODEL §2; BUILD_PLAN row 1.9).
//
// Output:
//   shared/syncauthority/authority_gen.go   (whole file)
//
// Validation (fails generation and `--check`):
//   - every kind is an ObjectKind in standards/vocabulary.yaml;
//   - every field and identity column is a column of the kind's table in
//     scripts/database/schema.sql (a renamed column must not leave a field the
//     sync silently never reads);
//   - every authority is one of the five classes;
//   - an identity column is never also a synced field;
//   - a `computed` name (a kind's API shape beyond its table: a cable's ends,
//     row 3.5) is NOT a column of the table, and is used as an identity
//     column or a field.
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
// `--root <dir>` points the generator at another tree (the tests use it).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { loadVocabulary, pascal } from './generate-vocabulary.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const AUTHORITIES = ['observed', 'declared_here', 'peer', 'merge', 'newest'];
const NETBOX_ENDPOINT = /^[a-z]+\/[a-z][a-z0-9-]*$/; // vpn/l2vpns
const COLUMN = /^[a-z][a-z0-9_]*$/;

// tableColumns reads the column names of `CREATE TABLE IF NOT EXISTS
// public.<table> (` … `);` from the schema text. Constraint lines are skipped.
export function tableColumns(schema, table) {
  const start = schema.indexOf(`CREATE TABLE IF NOT EXISTS public.${table} (`);
  if (start < 0) return null;
  const body = schema.slice(start, schema.indexOf('\n)', start));
  const cols = new Set();
  for (const line of body.split('\n').slice(1)) {
    const m = /^\s+"?([a-z_][a-z0-9_]*)"?\s+/.exec(line); // a quoted name: ike_proposals."group"
    if (!m || ['constraint', 'primary', 'unique', 'check', 'foreign', 'exclude'].includes(m[1].toLowerCase())) continue;
    cols.add(m[1]);
  }
  return cols;
}

export function loadAuthority(root) {
  const errors = [];
  const reg = yaml.parse(fs.readFileSync(path.join(root, 'standards', 'sync-authority.yaml'), 'utf8')) || {};
  if (reg.version !== 1) errors.push('version must be 1');
  const window = reg.newest_window_seconds;
  if (!Number.isInteger(window) || window <= 0) errors.push('newest_window_seconds must be a positive integer');
  const vocab = loadVocabulary(root);
  const tables = new Map(vocab.kinds.map((k) => [k.key, k.table]));
  const schema = fs.readFileSync(path.join(root, 'scripts', 'database', 'schema.sql'), 'utf8');

  const kinds = [];
  const seen = new Set();
  for (const k of reg.kinds || []) {
    const where = `kind ${JSON.stringify(k?.kind)}`;
    if (!tables.has(k?.kind)) { errors.push(`${where}: not an object kind in standards/vocabulary.yaml`); continue; }
    if (seen.has(k.kind)) errors.push(`${where}: listed twice`);
    seen.add(k.kind);
    const table = tables.get(k.kind);
    const cols = table ? tableColumns(schema, table) : null;
    if (!cols) { errors.push(`${where}: table ${table} not found in scripts/database/schema.sql`); continue; }
    if (!NETBOX_ENDPOINT.test(k.netbox || '')) errors.push(`${where}: netbox endpoint ${JSON.stringify(k.netbox)} (module/object)`);
    if (!Number.isInteger(k.order) || k.order <= 0) errors.push(`${where}: order must be a positive integer`);
    const computed = new Set(Array.isArray(k.computed) ? k.computed : []);
    for (const c of computed) {
      if (!COLUMN.test(c)) errors.push(`${where}: computed name ${JSON.stringify(c)} is not a valid name`);
      else if (cols.has(c)) errors.push(`${where}: computed name ${JSON.stringify(c)} is a column of ${table}; list it as a column, not computed`);
    }
    const known = (c) => cols.has(c) || computed.has(c);
    const identity = Array.isArray(k.identity) ? k.identity : [];
    if (identity.length === 0) errors.push(`${where}: identity must name at least one column`);
    for (const c of identity) {
      if (!COLUMN.test(c) || !known(c)) errors.push(`${where}: identity column ${JSON.stringify(c)} is not a column of ${table}`);
    }
    for (const c of computed) {
      if (!identity.includes(c) && !Object.hasOwn(k.fields || {}, c)) errors.push(`${where}: computed name ${JSON.stringify(c)} is neither an identity column nor a field`);
    }
    const fields = [];
    for (const [field, authority] of Object.entries(k.fields || {})) {
      if (!known(field)) errors.push(`${where}: field ${JSON.stringify(field)} is not a column of ${table}`);
      if (!AUTHORITIES.includes(authority)) errors.push(`${where}: field ${field}: authority ${JSON.stringify(authority)} (one of ${AUTHORITIES.join(', ')})`);
      if (identity.includes(field)) errors.push(`${where}: ${field} is an identity column and cannot also be a synced field`);
      fields.push({ field, authority });
    }
    if (fields.length === 0) errors.push(`${where}: no fields`);
    kinds.push({ kind: k.kind, netbox: k.netbox, identity, order: k.order, fields });
  }
  if (errors.length) throw new Error(errors.join('\n'));
  kinds.sort((a, b) => a.order - b.order || a.kind.localeCompare(b.kind));
  return { window, kinds };
}

const HEADER = 'Code generated by scripts/generate-sync-authority.mjs from standards/sync-authority.yaml. DO NOT EDIT — edit the YAML and run `make generate`.';

function authorityConst(a) {
  return pascal(a);
}

export function emitGo(d) {
  const q = (s) => JSON.stringify(s);
  const lines = [];
  lines.push(`// ${HEADER}`, '', 'package syncauthority', '', 'import (', '\t"time"', '', '\t"github.com/vistasecurity/vistaplatform/shared/dcim"', ')', '');
  lines.push('// The authority classes (SYNC_MODEL §2).', 'const (');
  const width = Math.max(...AUTHORITIES.map((a) => authorityConst(a).length));
  for (const a of AUTHORITIES) lines.push(`\t${authorityConst(a).padEnd(width)} Authority = ${q(a)}`);
  lines.push(')', '');
  lines.push('// AllAuthorities lists the classes in the YAML\'s order.');
  lines.push(`var AllAuthorities = []Authority{${AUTHORITIES.map(authorityConst).join(', ')}}`, '');
  lines.push('// NewestWindow is how close two changes of a `newest` field must be to');
  lines.push('// be a conflict rather than the newer one winning.');
  lines.push(`const NewestWindow = ${d.window} * time.Second`, '');
  lines.push('// kinds is every synced object kind, in dependency (apply) order.');
  lines.push('var kinds = []KindSpec{');
  for (const k of d.kinds) {
    lines.push('\t{');
    lines.push(`\t\tKind: dcim.ObjectKind(${q(k.kind)}), NetBox: ${q(k.netbox)}, Order: ${k.order},`);
    lines.push(`\t\tIdentity: []string{${k.identity.map(q).join(', ')}},`);
    lines.push('\t\tFields: []FieldSpec{');
    for (const f of k.fields) lines.push(`\t\t\t{Field: ${q(f.field)}, Authority: ${authorityConst(f.authority)}},`);
    lines.push('\t\t},');
    lines.push('\t},');
  }
  lines.push('}', '');
  return lines.join('\n');
}

export function buildOutputs(root) {
  const d = loadAuthority(root);
  return [[path.join(root, 'shared', 'syncauthority', 'authority_gen.go'), emitGo(d)]];
}

function main() {
  const argv = process.argv.slice(2);
  const checkOnly = argv.includes('--check');
  const ri = argv.indexOf('--root');
  const root = ri >= 0 ? path.resolve(argv[ri + 1]) : path.resolve(__dirname, '..');
  let outputs;
  try {
    outputs = buildOutputs(root);
  } catch (e) {
    console.error(`sync-authority: ${e.message}`);
    process.exit(1);
  }
  if (checkOnly) {
    const stale = outputs
      .filter(([p, c]) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '') !== c)
      .map(([p]) => path.relative(root, p));
    if (stale.length) {
      console.error(`sync-authority: out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
      process.exit(1);
    }
    console.log(`sync-authority check OK (${outputs.length} artefact)`);
    return;
  }
  for (const [p, c] of outputs) {
    fs.ensureDirSync(path.dirname(p));
    fs.writeFileSync(p, c);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
