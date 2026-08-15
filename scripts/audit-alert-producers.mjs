#!/usr/bin/env node
// Audits standards/alert-registry.yaml against the Go source: every
// `status: live` alert type must actually have a PRODUCER — a site that
// constructs an events.AlertRaiseEvent naming that type.
//
// Why this exists: the registry's own generator only checks YAML ↔ generated-Go
// drift, so the catalog could claim `status: live` (which the product reads as
// "a detector is active and this forms a real alert in the alerts table with
// dedupe/escalation/auto-resolve, visible at Remediation → Alerts") for a type
// nothing ever raises. That is exactly what happened to failed_login_burst and
// metric_threshold: both were detected, both notified, neither ever reached the
// alerts table — and every gate stayed green.
//
// The producer set is DERIVED from the source on every run. There is
// deliberately no hand-maintained list of live types here: a second copy of the
// answer is a copy that drifts, and the drift would be invisible precisely
// because this file is what is supposed to notice it.
//
// Run via `make audit` (strict). Mutation-test any change to it: flip a
// `planned` type to `live` (must FAIL), comment out a raise site (must FAIL),
// clean tree (must PASS).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

// Directories scanned for producers. The rail is deliberately open to any
// service, so scan them all plus shared/.
const SCAN_DIRS = ['services', 'shared'];

function fail(msg) {
  console.error(`alert-producers: ${msg}`);
  process.exit(1);
}

async function goFiles(dir) {
  const out = [];
  async function walk(d) {
    let entries;
    try {
      entries = await fs.readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === 'vendor' || e.name === '.git') continue;
        await walk(p);
      } else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) {
        // The generated catalog names every id but produces nothing.
        if (e.name === 'registry_gen.go') continue;
        out.push(p);
      }
    }
  }
  await walk(dir);
  return out;
}

// stripComments removes Go line and block comments (string literals preserved).
// Without this the audit is INERT against the commonest way a producer dies:
// commenting the raise site out leaves the text `AlertRaiseEvent{` in the file,
// and a text scan happily credits a producer that no longer runs. Verified by
// mutation test — see the header.
function stripComments(src) {
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === '`' || c === "'") {
      const quote = c;
      out += c;
      i++;
      for (; i < src.length; i++) {
        out += src[i];
        if (src[i] === '\\' && quote !== '`') {
          i++;
          if (i < src.length) out += src[i];
          continue;
        }
        if (src[i] === quote) break;
      }
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i++;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}

// extractRaiseBlocks returns the source text of every AlertRaiseEvent composite
// literal in `src`, by brace matching from the opening `{`.
function extractRaiseBlocks(src) {
  const blocks = [];
  const marker = 'AlertRaiseEvent{';
  let from = 0;
  for (;;) {
    const i = src.indexOf(marker, from);
    if (i === -1) break;
    let depth = 0;
    let j = i + marker.length - 1; // at the '{'
    let end = -1;
    for (; j < src.length; j++) {
      const c = src[j];
      if (c === '"') {
        // skip string literal
        j++;
        while (j < src.length && !(src[j] === '"' && src[j - 1] !== '\\')) j++;
        continue;
      }
      if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    if (end === -1) break;
    blocks.push(src.slice(i, end + 1));
    from = end + 1;
  }
  return blocks;
}

// resolveAlertType maps the RHS of an `AlertType:` field onto the alert-type
// string(s) it can carry: a quoted literal resolves to itself; an identifier
// (const, struct field such as j.spec.alertType) resolves to every string
// literal bound to that name in the same file — which is how one generic job
// serving two registry types (sensor_offline / discovery_agent_offline) is
// credited with both.
// A value the caller reads out of a map or a parameter (`alertType` bound by
// `alertType, ok := someMap[...]`) cannot be traced by name, so the last resort
// is every registry id bound as a string literal in the same file. That cannot
// invent a producer out of nothing — the file must both construct an
// AlertRaiseEvent and contain the id as a literal — it only loses the ability to
// tell two ids apart within one file.
function resolveAlertType(rhs, fileSrc, knownIDs) {
  const literal = rhs.match(/^"([a-z0-9_]+)"$/);
  if (literal) return [literal[1]];

  const ident = rhs.match(/([A-Za-z_][A-Za-z0-9_]*)$/);
  if (ident) {
    const found = new Set();
    const re = new RegExp(`\\b${ident[1]}\\s*[:=]+\\s*"([a-z0-9_]+)"`, 'g');
    let m;
    while ((m = re.exec(fileSrc)) !== null) found.add(m[1]);
    if (found.size) return [...found];
  }

  const fallback = new Set();
  const lit = /[:=(]\s*"([a-z0-9_]+)"/g;
  let m;
  while ((m = lit.exec(fileSrc)) !== null) {
    if (knownIDs.has(m[1])) fallback.add(m[1]);
  }
  return [...fallback];
}

async function main() {
  const registryPath = path.resolve(root, 'standards', 'alert-registry.yaml');
  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const types = registry.alert_types || [];
  if (!types.length) fail('no alert_types defined');

  const knownIDs = new Set(types.map((t) => t.id));
  const statusByID = new Map(types.map((t) => [t.id, t.status]));

  // producers: alert type id -> [source locations]
  const producers = new Map();
  const unresolved = [];

  for (const dir of SCAN_DIRS) {
    for (const file of await goFiles(path.resolve(root, dir))) {
      const src = stripComments(await fs.readFile(file, 'utf8'));
      if (!src.includes('AlertRaiseEvent{')) continue;
      const rel = path.relative(root, file);
      for (const block of extractRaiseBlocks(src)) {
        const field = block.match(/\bAlertType:\s*([^,\n]+?),?\s*\n/);
        if (!field) {
          unresolved.push(`${rel}: AlertRaiseEvent literal with no AlertType field`);
          continue;
        }
        const ids = resolveAlertType(field[1].trim(), src, knownIDs);
        if (!ids.length) {
          unresolved.push(`${rel}: could not resolve AlertType value ${field[1].trim()}`);
          continue;
        }
        for (const id of ids) {
          if (!producers.has(id)) producers.set(id, []);
          producers.get(id).push(rel);
        }
      }
    }
  }

  const errors = [];

  // 1. Every live type must have a producer. This is the defect this audit exists for.
  for (const t of types) {
    if (t.status !== 'live') continue;
    if (!producers.has(t.id)) {
      errors.push(
        `${t.id}: status is 'live' but no Go source raises it. ` +
          `Either wire a producer that publishes/raises events.AlertRaiseEvent{AlertType: "${t.id}"}, ` +
          `or set status: planned in standards/alert-registry.yaml.`
      );
    }
  }

  // 2. The inverse: a producer for a 'planned' type means the registry greys out
  //    a detector that is in fact running.
  for (const [id, where] of producers) {
    if (statusByID.get(id) === 'planned') {
      errors.push(`${id}: status is 'planned' but ${where[0]} raises it — mark it live.`);
    }
  }

  // 3. A raise naming an id the registry doesn't know is a typo or a missing
  //    catalog entry; either way the alert can never be shown or toggled.
  for (const [id, where] of producers) {
    if (!knownIDs.has(id)) {
      errors.push(`${where[0]} raises unknown alert type "${id}" (not in standards/alert-registry.yaml).`);
    }
  }

  // 4. An AlertType this audit cannot resolve is a blind spot, not a pass.
  for (const u of unresolved) errors.push(u);

  if (errors.length) {
    for (const e of errors) console.error(`alert-producers: ${e}`);
    process.exit(1);
  }

  const live = types.filter((t) => t.status === 'live').length;
  console.log(`alert-producers check OK (${live} live types, all with a raise site; ${producers.size} produced)`);
}

main().catch((e) => fail(e.message));
