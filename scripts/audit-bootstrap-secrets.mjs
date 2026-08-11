#!/usr/bin/env node
/**
 * Quickstart-secret audit.
 *
 * `public/bootstrap-env.sh` is the only thing standing between a Core user and
 * a deployment whose passwords are published in this repository. It copies
 * env.example and replaces each known placeholder with a random value.
 *
 * It replaces them BY LITERAL. When a literal in the script and the value in
 * env.example drift apart, the rotation silently stops happening: the script
 * prints its cheerful list of rotated secrets, omits the one that failed, and
 * exits 0. That is how INFLUXDB_PASSWORD shipped as the published string
 * `adminpass123` in every deployment — the script had been looking for
 * `influx_pass_dev`, which env.example had never contained.
 *
 * Two failure modes, both checked here:
 *
 *   1. A rotate line whose placeholder does not appear in env.example — a stale
 *      literal, rotating nothing.
 *   2. A secret-shaped assignment in env.example with no rotate line at all —
 *      a new credential that nobody wired into the bootstrap.
 *
 *   node scripts/audit-bootstrap-secrets.mjs [--strict]
 *
 * Mutation-test it: change one placeholder in bootstrap-env.sh and check A
 * fails; add `FOO_PASSWORD=hunter2` to env.example and check B fails.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

// In this repo the script lives at public/; the export installs it at scripts/.
// Check whichever is present so the audit works in both trees.
const SCRIPT_REL = ['public/bootstrap-env.sh', 'scripts/bootstrap-env.sh'].find((p) =>
  fs.existsSync(path.join(ROOT, p))
);
if (!SCRIPT_REL) {
  console.error('FAIL: no bootstrap-env.sh found in public/ or scripts/ — the quickstart ships weak secrets.');
  process.exit(STRICT ? 1 : 0);
}

const script = fs.readFileSync(path.join(ROOT, SCRIPT_REL), 'utf8');
const envExample = fs.readFileSync(path.join(ROOT, 'env.example'), 'utf8');

// Values that are not credentials despite matching the name pattern: ports,
// hostnames, feature switches, and anything explicitly blank.
const NOT_A_SECRET = /^(|0|1|true|false|localhost|\d+)$/i;

// ─── env.example: what looks like a credential ──────────────────────────────

const declared = new Map(); // VAR -> value
for (const line of envExample.split('\n')) {
  const m = /^([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY))=(.*)$/.exec(line);
  if (!m) continue;
  const [, name, value] = m;
  if (NOT_A_SECRET.test(value.trim())) continue; // blank//numeric — nothing to leak
  declared.set(name, value.trim());
}

// ─── the script: what it claims to rotate ───────────────────────────────────

const rotates = new Map(); // VAR -> placeholder
for (const line of script.split('\n')) {
  const m = /^rotate\s+([A-Z0-9_]+)\s+(\S+)/.exec(line);
  if (m) rotates.set(m[1], m[2]);
}

const problems = [];

// A: every rotate line points at a literal env.example actually contains.
for (const [name, placeholder] of rotates) {
  const actual = declared.get(name);
  if (actual === undefined) {
    problems.push(
      `${SCRIPT_REL} rotates ${name}, but env.example has no such credential — the line rotates nothing.`
    );
  } else if (actual !== placeholder) {
    problems.push(
      `${name}: ${SCRIPT_REL} expects the placeholder '${placeholder}', env.example has '${actual}'.\n` +
        `    The rotation silently no-ops and the published value ships to every deployment.`
    );
  }
}

// B: every credential in env.example is rotated by the script.
for (const [name, value] of declared) {
  if (!rotates.has(name)) {
    problems.push(
      `${name}=${value} is a credential in env.example that ${SCRIPT_REL} never rotates.\n` +
        `    Its value is published in this repository; add a rotate line for it.`
    );
  }
}

console.log('Quickstart-secret audit');
console.log(`  ${declared.size} credential(s) in env.example, ${rotates.size} rotate line(s) in ${SCRIPT_REL}`);

if (problems.length) {
  console.error('\n' + problems.map((p) => `FAIL: ${p}`).join('\n\n'));
  process.exit(STRICT ? 1 : 0);
}
console.log('OK: every published credential placeholder is rotated by the quickstart.');
