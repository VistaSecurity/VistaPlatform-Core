#!/usr/bin/env node
/**
 * The public release-status feed, schema version 1.
 *
 * The project website reads `latest.json` from the `release-status` branch of
 * the public repository and shows, for the latest stable release, which
 * product capabilities were verified end to end for that exact version. This
 * module is the one definition of that document: the check catalogue, the
 * allowed results, and the validator every writer runs before publishing.
 *
 * It has no dependencies on purpose — the publishing workflow runs it on a
 * bare runner before any `npm install`.
 *
 * Contract highlights (the website relies on every one of these):
 *   - `result` is exactly one of passed | failed | not_run. A check that is
 *     absent means not_run, so a writer that has nothing to say about a check
 *     says not_run rather than guessing.
 *   - `release.tag` is the GitHub Release tag. The site shows results only when
 *     it equals GitHub's latest stable release, so a feed can never lend an
 *     older version's green to a newer one.
 *   - Every URL is a public https://github.com URL. `evidence_url` may be null.
 *   - Dates are UTC ISO 8601 with a trailing Z. The document is at most 100 KB.
 *
 *   node scripts/release-status-feed.mjs validate-payload <payload.json>
 *   node scripts/release-status-feed.mjs build --payload <payload.json> \
 *       --commit <sha> --published-at <iso> --release-url <url> --run-url <url> \
 *       --out <feed.json>
 *   node scripts/release-status-feed.mjs validate <feed.json>
 */

import fs from 'fs';
import { fileURLToPath } from 'url';

export const SCHEMA_VERSION = 1;
export const EDITION = 'core';
export const MAX_BYTES = 100 * 1024;
export const RESULTS = Object.freeze(['passed', 'failed', 'not_run']);

// The website's stable check IDs, in its display order. Adding one here is a
// contract change: the site ignores IDs it does not know, so a new ID shows
// nothing until the site's catalogue carries it too. Renaming one silently
// turns its row into "Not yet checked" on the site — do not.
export const CHECK_GROUPS = Object.freeze({
  'Deploy & operate': ['self_hosted_install', 'sensor_collection', 'access_control', 'audit_log'],
  'Discover & inventory': [
    'passive_discovery', 'selected_asset_scan', 'cloud_discovery', 'canonical_inventory',
    'software_inventory', 'crypto_inventory', 'coverage_freshness',
  ],
  'Evaluate & prove': ['crypto_assessment', 'pqc_exposure', 'compliance_findings', 'cbom_generation', 'cbom_cyclonedx'],
});
export const CHECK_IDS = Object.freeze(Object.values(CHECK_GROUPS).flat());

// vX.Y.Z or vX.Y.Z-<prerelease>. The same shape release-core.yml accepts.
export const TAG_RE = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ISO_Z_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SHA_RE = /^[0-9a-f]{40}$/;

export const isPrerelease = (tag) => tag.includes('-');

function isIsoUtc(v) {
  return typeof v === 'string' && ISO_Z_RE.test(v) && !Number.isNaN(Date.parse(v));
}

// Public GitHub only: no other host, no credentials, no query string (an
// Actions artifact download URL carries a signed query and expires).
export function isPublicGithubUrl(v) {
  if (typeof v !== 'string') return false;
  let u;
  try { u = new URL(v); } catch { return false; }
  return u.protocol === 'https:' && u.hostname === 'github.com' && !u.username && !u.password
    && !u.search && !u.hash && u.pathname.length > 1;
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The payload the private verification run sends. It carries ONLY what that
 * run knows first-hand — which tag it verified, when, and the result of each
 * check. Everything describing the release itself (commit, publication date,
 * URL) is looked up by the publisher from GitHub, never taken on trust.
 */
export function validatePayload(p) {
  const errs = [];
  if (!isPlainObject(p)) return ['payload is not an object'];
  if (typeof p.tag !== 'string' || !TAG_RE.test(p.tag)) errs.push(`tag ${JSON.stringify(p.tag)} is not vX.Y.Z[-pre]`);
  if (!isIsoUtc(p.verified_at)) errs.push(`verified_at ${JSON.stringify(p.verified_at)} is not UTC ISO 8601`);
  else if (Date.parse(p.verified_at) > Date.now() + 5 * 60 * 1000) errs.push('verified_at is in the future');
  errs.push(...validateChecks(p.checks));
  return errs;
}

function validateChecks(checks) {
  const errs = [];
  if (!isPlainObject(checks)) return ['checks is not an object'];
  for (const [id, c] of Object.entries(checks)) {
    if (!CHECK_IDS.includes(id)) { errs.push(`unknown check id "${id}"`); continue; }
    if (!isPlainObject(c)) { errs.push(`${id}: not an object`); continue; }
    const extra = Object.keys(c).filter((k) => k !== 'result' && k !== 'evidence_url');
    if (extra.length) errs.push(`${id}: unexpected field(s) ${extra.join(', ')}`);
    if (!RESULTS.includes(c.result)) errs.push(`${id}: result ${JSON.stringify(c.result)} is not one of ${RESULTS.join('|')}`);
    if (c.evidence_url !== null && c.evidence_url !== undefined && !isPublicGithubUrl(c.evidence_url)) {
      errs.push(`${id}: evidence_url is not a public https://github.com URL`);
    }
  }
  return errs;
}

/** Assemble the feed. Every catalogue ID is written, absent ones as not_run. */
export function buildFeed({ payload, commit, publishedAt, releaseUrl, runUrl }) {
  const checks = {};
  for (const id of CHECK_IDS) {
    const c = payload.checks?.[id];
    checks[id] = c
      ? { result: c.result, evidence_url: c.evidence_url ?? null }
      : { result: 'not_run', evidence_url: null };
  }
  return {
    schema_version: SCHEMA_VERSION,
    edition: EDITION,
    release: { tag: payload.tag, commit, published_at: publishedAt, url: releaseUrl },
    verified_at: payload.verified_at,
    run_url: runUrl,
    checks,
  };
}

/** Validate a finished feed document (object) and its serialised size. */
export function validateFeed(feed, text = JSON.stringify(feed, null, 2) + '\n') {
  const errs = [];
  if (!isPlainObject(feed)) return ['feed is not an object'];
  const top = ['schema_version', 'edition', 'release', 'verified_at', 'run_url', 'checks'];
  const extra = Object.keys(feed).filter((k) => !top.includes(k));
  if (extra.length) errs.push(`unexpected top-level field(s) ${extra.join(', ')}`);
  if (feed.schema_version !== SCHEMA_VERSION) errs.push(`schema_version must be ${SCHEMA_VERSION}`);
  if (feed.edition !== EDITION) errs.push(`edition must be "${EDITION}"`);
  const r = feed.release;
  if (!isPlainObject(r)) errs.push('release is not an object');
  else {
    if (typeof r.tag !== 'string' || !TAG_RE.test(r.tag)) errs.push('release.tag is not vX.Y.Z[-pre]');
    if (typeof r.commit !== 'string' || !SHA_RE.test(r.commit)) errs.push('release.commit is not a 40-hex commit');
    if (!isIsoUtc(r.published_at)) errs.push('release.published_at is not UTC ISO 8601');
    if (!isPublicGithubUrl(r.url)) errs.push('release.url is not a public https://github.com URL');
    else if (typeof r.tag === 'string' && !r.url.endsWith(`/releases/tag/${r.tag}`)) errs.push('release.url does not name release.tag');
  }
  if (!isIsoUtc(feed.verified_at)) errs.push('verified_at is not UTC ISO 8601');
  if (!isPublicGithubUrl(feed.run_url)) errs.push('run_url is not a public https://github.com URL');
  errs.push(...validateChecks(feed.checks));
  if (isPlainObject(feed.checks)) {
    const missing = CHECK_IDS.filter((id) => !(id in feed.checks));
    if (missing.length) errs.push(`checks missing: ${missing.join(', ')}`);
  }
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_BYTES) errs.push(`feed is ${bytes} bytes, over the ${MAX_BYTES}-byte cap`);
  return errs;
}

export const serialise = (feed) => JSON.stringify(feed, null, 2) + '\n';

// ─── CLI ─────────────────────────────────────────────────────────────────────

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) throw new Error(`unexpected argument ${argv[i]}`);
    out[argv[i].slice(2)] = argv[i + 1];
    i++;
  }
  return out;
}

function fail(errs) {
  for (const e of errs) console.error(`::error::${e}`);
  process.exit(1);
}

function main([cmd, ...rest]) {
  if (cmd === 'validate-payload') {
    const errs = validatePayload(readJson(rest[0]));
    if (errs.length) fail(errs);
    console.log('payload valid');
  } else if (cmd === 'build') {
    const a = args(rest);
    for (const k of ['payload', 'commit', 'published-at', 'release-url', 'run-url', 'out']) {
      if (!a[k]) fail([`--${k} is required`]);
    }
    const payload = readJson(a.payload);
    const perrs = validatePayload(payload);
    if (perrs.length) fail(perrs);
    const feed = buildFeed({
      payload, commit: a.commit, publishedAt: a['published-at'], releaseUrl: a['release-url'], runUrl: a['run-url'],
    });
    const text = serialise(feed);
    const errs = validateFeed(feed, text);
    if (errs.length) fail(errs);
    fs.writeFileSync(a.out, text);
    console.log(`wrote ${a.out} (${Buffer.byteLength(text)} bytes)`);
  } else if (cmd === 'validate') {
    const text = fs.readFileSync(rest[0], 'utf8');
    const errs = validateFeed(JSON.parse(text), text);
    if (errs.length) fail(errs);
    console.log(`${rest[0]} valid`);
  } else {
    console.error('usage: release-status-feed.mjs validate-payload <file> | build --payload … | validate <file>');
    process.exit(2);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main(process.argv.slice(2));
}
