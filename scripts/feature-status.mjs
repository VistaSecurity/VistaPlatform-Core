#!/usr/bin/env node
/**
 * Feature status feed (schema version 2) for the website's release-status page.
 *
 * Source: standards/feature-status.yaml — a curated list of the capabilities a
 * customer would look for, each with a status. This turns it, as it stands at a
 * release tag, into the JSON the website reads, and refuses a catalogue that
 * would publish something wrong (a duplicate id, an unknown status, a docs link
 * to a page that does not exist).
 *
 *   node scripts/feature-status.mjs validate
 *   node scripts/feature-status.mjs build --tag vX.Y.Z --commit <sha> \
 *       --published-at <iso> --release-url <url> --run-url <url> --out <file>
 *
 * Published by .github/workflows/release-status.yml.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

export const SCHEMA_VERSION = 2;
export const STATUSES = Object.freeze(['available', 'in_progress', 'planned']);
export const EDITIONS = Object.freeze(['core', 'enterprise', 'msp']);
export const DOCS_BASE = 'https://vistasecurity.io/docs/';
export const MAX_BYTES = 100 * 1024;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CATALOGUE = path.join(ROOT, 'standards', 'feature-status.yaml');
const DOCS_ROOT = path.join(ROOT, 'docsv4', 'core');

const ID_RE = /^[a-z][a-z0-9_]{1,47}$/;
const TAG_RE = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ISO_Z_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

// The website renders docsv4/core/<path>.md at /docs/<slug>/, lowercasing and
// turning underscores into hyphens (features/SENSOR_REGISTRATION →
// features/sensor-registration).
export function docsUrl(docPath) {
  return `${DOCS_BASE}${docPath.toLowerCase().replaceAll('_', '-')}/`;
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Validate a parsed catalogue. `docExists(path)` is injectable for tests. */
export function validateCatalogue(cat, docExists = (p) => fs.existsSync(path.join(DOCS_ROOT, `${p}.md`))) {
  const errs = [];
  if (!isPlainObject(cat)) return ['catalogue is not a mapping'];
  const groups = Array.isArray(cat.groups) ? cat.groups : [];
  if (groups.length === 0) errs.push('no groups');
  const groupIds = new Set();
  for (const g of groups) {
    if (!isPlainObject(g) || !ID_RE.test(g.id ?? '') || typeof g.name !== 'string' || !g.name.trim()) {
      errs.push(`group ${JSON.stringify(g)}: needs a snake_case id and a name`);
      continue;
    }
    if (groupIds.has(g.id)) errs.push(`duplicate group id "${g.id}"`);
    groupIds.add(g.id);
  }
  const features = Array.isArray(cat.features) ? cat.features : [];
  if (features.length === 0) errs.push('no features');
  const ids = new Set();
  const used = new Set();
  const allowed = new Set(['id', 'group', 'name', 'summary', 'status', 'edition', 'docs']);
  for (const f of features) {
    const where = `feature ${isPlainObject(f) && f.id ? `"${f.id}"` : JSON.stringify(f)}`;
    if (!isPlainObject(f)) { errs.push(`${where}: not a mapping`); continue; }
    const extra = Object.keys(f).filter((k) => !allowed.has(k));
    if (extra.length) errs.push(`${where}: unknown field(s) ${extra.join(', ')}`);
    if (!ID_RE.test(f.id ?? '')) errs.push(`${where}: id must be snake_case`);
    else if (ids.has(f.id)) errs.push(`${where}: duplicate id`);
    ids.add(f.id);
    if (!groupIds.has(f.group)) errs.push(`${where}: unknown group "${f.group}"`);
    used.add(f.group);
    for (const k of ['name', 'summary']) {
      if (typeof f[k] !== 'string' || !f[k].trim()) errs.push(`${where}: ${k} is required`);
    }
    if (typeof f.summary === 'string' && f.summary.length > 160) errs.push(`${where}: summary over 160 characters`);
    if (!STATUSES.includes(f.status)) errs.push(`${where}: status must be one of ${STATUSES.join(' | ')}`);
    if (!EDITIONS.includes(f.edition)) errs.push(`${where}: edition must be one of ${EDITIONS.join(' | ')}`);
    if (f.docs !== undefined) {
      if (typeof f.docs !== 'string' || f.docs.startsWith('/') || f.docs.endsWith('.md') || f.docs.includes('..')) {
        errs.push(`${where}: docs is a path under docsv4/core/ without ".md"`);
      } else if (!docExists(f.docs)) {
        errs.push(`${where}: docs page docsv4/core/${f.docs}.md does not exist`);
      }
    }
  }
  for (const g of groupIds) if (!used.has(g)) errs.push(`group "${g}" has no features`);
  return errs;
}

export function loadCatalogue(file = CATALOGUE) {
  return yaml.parse(fs.readFileSync(file, 'utf8'));
}

/** The published document. Order follows the catalogue. */
export function buildFeed(cat, { tag, commit, publishedAt, releaseUrl, runUrl, generatedAt }) {
  return {
    schema_version: SCHEMA_VERSION,
    release: { tag, commit, published_at: publishedAt, url: releaseUrl },
    generated_at: generatedAt,
    run_url: runUrl,
    groups: cat.groups.map((g) => ({ id: g.id, name: g.name })),
    features: cat.features.map((f) => ({
      id: f.id,
      group: f.group,
      name: f.name,
      summary: f.summary,
      status: f.status,
      edition: f.edition,
      docs_url: f.docs ? docsUrl(f.docs) : null,
    })),
  };
}

export function validateFeed(feed, text = JSON.stringify(feed, null, 2) + '\n') {
  const errs = [];
  const r = feed?.release ?? {};
  if (feed?.schema_version !== SCHEMA_VERSION) errs.push(`schema_version must be ${SCHEMA_VERSION}`);
  if (!TAG_RE.test(r.tag ?? '')) errs.push('release.tag is not vX.Y.Z[-pre]');
  if (!/^[0-9a-f]{40}$/.test(r.commit ?? '')) errs.push('release.commit is not a 40-hex commit');
  if (!ISO_Z_RE.test(r.published_at ?? '')) errs.push('release.published_at is not UTC ISO 8601');
  if (!ISO_Z_RE.test(feed?.generated_at ?? '')) errs.push('generated_at is not UTC ISO 8601');
  for (const [k, v] of [['release.url', r.url], ['run_url', feed?.run_url]]) {
    let ok = false;
    try { const u = new URL(v); ok = u.protocol === 'https:' && u.hostname === 'github.com' && !u.search; } catch { /* not a URL */ }
    if (!ok) errs.push(`${k} is not a public https://github.com URL`);
  }
  if (typeof r.url === 'string' && typeof r.tag === 'string' && !r.url.endsWith(`/releases/tag/${r.tag}`)) {
    errs.push('release.url does not name release.tag');
  }
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_BYTES) errs.push(`feed is ${bytes} bytes, over the ${MAX_BYTES}-byte cap`);
  return errs;
}

export const serialise = (feed) => JSON.stringify(feed, null, 2) + '\n';

// ─── CLI ─────────────────────────────────────────────────────────────────────

function fail(errs) {
  for (const e of errs) console.error(`::error::${e}`);
  process.exit(1);
}

function main([cmd, ...rest]) {
  const cat = loadCatalogue();
  const cerrs = validateCatalogue(cat);
  if (cmd === 'validate') {
    if (cerrs.length) fail(cerrs);
    const n = (s) => cat.features.filter((f) => f.status === s).length;
    console.log(`feature-status: ${cat.features.length} features (${n('available')} available, ${n('in_progress')} in progress, ${n('planned')} planned)`);
    return;
  }
  if (cmd !== 'build') {
    console.error('usage: feature-status.mjs validate | build --tag … --commit … --published-at … --release-url … --run-url … --out …');
    process.exit(2);
  }
  if (cerrs.length) fail(cerrs);
  const a = {};
  for (let i = 0; i < rest.length; i += 2) a[rest[i].replace(/^--/, '')] = rest[i + 1];
  for (const k of ['tag', 'commit', 'published-at', 'release-url', 'run-url', 'out']) if (!a[k]) fail([`--${k} is required`]);
  const feed = buildFeed(cat, {
    tag: a.tag, commit: a.commit, publishedAt: a['published-at'], releaseUrl: a['release-url'], runUrl: a['run-url'],
    generatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });
  const text = serialise(feed);
  const errs = validateFeed(feed, text);
  if (errs.length) fail(errs);
  fs.writeFileSync(a.out, text);
  console.log(`wrote ${a.out}: ${feed.features.length} features for ${a.tag}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main(process.argv.slice(2));
}
