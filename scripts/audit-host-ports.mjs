#!/usr/bin/env node
/**
 * Host-port publication audit.
 *
 * Every `ports:` entry in a compose file is of the form
 * "${SOME_HOST_PORT:-<default>}:<container>". env.example moves all of them
 * into the 4xxxx range so the stack can start beside whatever else is already
 * listening on a developer's machine. The default is the bare low port.
 *
 * Two ways that rots, both of which produce the same failure — a
 * `docker compose up` that dies partway through with "address already in use",
 * after several containers have already started:
 *
 *   1. A new published port is added to a compose file with no matching entry
 *      in env.example. It then falls back to its low compose default. This is
 *      how PROMETHEUS_HOST_PORT ended up defaulting to 9091, which calico-node
 *      holds on every Kubernetes node.
 *   2. Two env.example entries are given the same host port. Whichever
 *      container binds second fails. (MONITORING_SERVICE_HOST_PORT and
 *      PORTAINER_HTTPS_HOST_PORT were both 48091.)
 *
 * This audit fails on either. Run strict from `make audit`.
 *
 *   node scripts/audit-host-ports.mjs [--strict]
 *
 * Mutation-test it: publish a port with a fresh variable name in
 * docker-compose.yml and check A fails; point two env.example entries at the
 * same number and check B fails. If neither happens, this file is decoration.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

// The compose files a developer or a Core user actually brings up locally.
// The prod/dist/test/ec2 variants are deployed, not run beside a desktop, and
// deliberately publish plain ports.
const COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.override.yml'];

const problems = [];

// ─── What env.example declares ─────────────────────────────────────────────

const envExample = fs.readFileSync(path.join(ROOT, 'env.example'), 'utf8');

/** @type {Map<string, {port: string, line: number}>} */
const declared = new Map();
envExample.split('\n').forEach((raw, i) => {
  // Commented-out entries do not count: docker compose never sees them, so the
  // variable still falls back to its low default.
  const m = /^([A-Z0-9_]+_HOST_PORT)=(\d+)\s*$/.exec(raw);
  if (m) declared.set(m[1], { port: m[2], line: i + 1 });
});

// ─── Check A: every published port has an entry ────────────────────────────

/** @type {Map<string, string[]>} */
const published = new Map();
for (const file of COMPOSE_FILES) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) continue;
  const text = fs.readFileSync(full, 'utf8');
  for (const m of text.matchAll(/\$\{([A-Z0-9_]+_HOST_PORT):-(\d+)\}:/g)) {
    const [, variable, fallback] = m;
    if (!published.has(variable)) published.set(variable, []);
    published.get(variable).push(`${file} (compose default ${fallback})`);
  }
}

const missing = [...published.keys()].filter((v) => !declared.has(v)).sort();
if (missing.length) {
  problems.push(
    'published host port(s) with no uncommented entry in env.example — each ' +
      'falls back to its low compose default and will collide on a busy host:\n' +
      missing.map((v) => `  ${v}  ${published.get(v).join(', ')}`).join('\n')
  );
}

// ─── Check B: no two entries claim the same host port ──────────────────────

/** @type {Map<string, string[]>} */
const byPort = new Map();
for (const [variable, { port, line }] of declared) {
  if (!byPort.has(port)) byPort.set(port, []);
  byPort.get(port).push(`${variable} (env.example:${line})`);
}
const dupes = [...byPort.entries()].filter(([, vars]) => vars.length > 1);
if (dupes.length) {
  problems.push(
    'env.example assigns the same host port to more than one service:\n' +
      dupes.map(([port, vars]) => `  ${port}: ${vars.join(', ')}`).join('\n')
  );
}

// ─── Report ────────────────────────────────────────────────────────────────

console.log('Host-port audit');
console.log(`  ${published.size} published port(s) across ${COMPOSE_FILES.join(', ')}`);
console.log(`  ${declared.size} host-port override(s) declared in env.example`);

if (problems.length) {
  console.error('\n' + problems.map((p) => `FAIL: ${p}`).join('\n\n'));
  process.exit(STRICT ? 1 : 0);
}
console.log('OK: every published host port is pinned in env.example, no collisions.');
