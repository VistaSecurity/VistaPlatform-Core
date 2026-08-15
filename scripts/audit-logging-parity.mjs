#!/usr/bin/env node
// Audits every backend service in standards/service-registry.yaml against the
// Go source: a service that serves a tenant- or admin-facing HTTP surface must
// actually WRITE to the audit trail.
//
// Why this exists: audit logging is per-service opt-in and, until this guard,
// nothing enforced it. Seven services shipped with none at all — including
// monitoring-service, whose /logs surface IS the compliance-log read path, and
// audit-service, whose own trail-export endpoint was unrecorded. Every gate
// stayed green the entire time, because there was no gate.
//
// The service list is DERIVED from the registry on every run. There is
// deliberately no hand-maintained list of services here: a second copy of the
// answer is a copy that drifts, and the drift would be invisible precisely
// because this file is what is supposed to notice it. A new service added to
// the registry is unwired-by-default and fails this audit until someone either
// wires it or writes down why it does not need wiring.
//
// Run via `make audit` (strict). Mutation-test any change to it: delete a
// LogRequest mount (must FAIL), COMMENT OUT a LogRequest mount (must FAIL —
// commented-out code still contains the text), blank an exemption reason (must
// FAIL), clean tree (must PASS).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

// The import every wiring form goes through. Requiring it alongside a marker
// keeps the scan from crediting a same-named method that has nothing to do with
// auditing — audit-service's own ingest handler is literally called
// LogActivity, and it RECEIVES entries rather than writing any.
const AUDIT_IMPORT = 'shared/middleware/audit';

// The three ways a service writes to the audit trail. Each is a real, shipped
// pattern, not a hypothetical:
//
//   LogRequest()       — the gin middleware, for HTTP surfaces.
//   LogConsumerEvent(  — for NATS consumers and pollers whose only HTTP
//                        surface is /health (discovery-processor, pcap-processor).
//   LogActivity(       — a direct per-event write, for services where one
//                        HTTP request is the wrong unit: mcp-service records the
//                        tool invocation, admin-service records the mutation.
const WIRING_MARKERS = [
  { marker: '.LogRequest()', kind: 'LogRequest middleware' },
  { marker: 'LogConsumerEvent(', kind: 'LogConsumerEvent' },
  { marker: '.LogActivity(', kind: 'LogActivity' },
];

// EXEMPTIONS: services that legitimately write nothing to the audit trail.
//
// Every entry needs a `reason` that says why the service has nothing auditable,
// in terms a reviewer can check. An entry whose reason is missing or blank
// FAILS this audit — an exemption nobody had to justify is how a real gap gets
// parked forever behind a green check. Likewise an exemption naming a service
// that IS wired fails, so the list cannot outlive its subject.
//
// Keep this list as short as the truth allows. If a service needs wiring, wire
// it; do not add it here to make the guard green.
export const EXEMPTIONS = [
  // (empty — every registry service currently writes to the audit trail)
];

function fail(msg) {
  console.error(`audit-logging-parity: ${msg}`);
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
        // A test may mount audit logging on a throwaway router; that proves
        // nothing about the running service.
        out.push(p);
      }
    }
  }
  await walk(dir);
  return out;
}

// stripComments removes Go line and block comments (string literals preserved).
// Without this the audit is INERT against the commonest way wiring dies:
// commenting the mount out leaves the text `.LogRequest()` in the file, and a
// text scan happily credits wiring that no longer runs. The sibling guard
// scripts/audit-alert-producers.mjs was mutation-tested into exactly this;
// see the header for the mutation tests that must pass here too.
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

async function main() {
  const { errors, wiring, services, exemptNames } = await auditTree({ root, exemptions: EXEMPTIONS });

  if (errors.length) {
    for (const e of errors) console.error(`audit-logging-parity: ${e}`);
    process.exit(1);
  }

  console.log(
    `audit-logging-parity check OK (${wiring.size}/${services.length} services write to the audit trail; ` +
      `${exemptNames.size} exempt)`
  );
}

// auditTree is the whole check, parameterised by tree root and exemption list
// so scripts/test-audit-logging-parity.mjs can drive it against fixtures. The
// mutation tests in the header live there; keeping them runnable is the only
// thing that stops this guard going inert the way three others already have.
export async function auditTree({ root: treeRoot, exemptions }) {
  const registryPath = path.resolve(treeRoot, 'standards', 'service-registry.yaml');
  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const services = (registry.services || []).filter((s) => s.status !== 'retired');
  if (!services.length) fail('no services defined in standards/service-registry.yaml');
  const root = treeRoot;

  const byName = new Map();
  for (const s of services) byName.set(s.name, s);

  // 1. Exemption hygiene, checked BEFORE anything else so a malformed list can
  //    never silently widen the audit.
  const errors = [];
  const exemptNames = new Set();
  for (const [i, ex] of exemptions.entries()) {
    const name = ex && ex.service;
    if (!name) {
      errors.push(`EXEMPTIONS[${i}] has no service name.`);
      continue;
    }
    if (typeof ex.reason !== 'string' || ex.reason.trim() === '') {
      errors.push(
        `EXEMPTIONS entry "${name}" has no reason. Every exemption must state, in checkable terms, ` +
          `why the service writes nothing to the audit trail.`
      );
      continue;
    }
    if (!byName.has(name)) {
      errors.push(`EXEMPTIONS entry "${name}" is not a service in standards/service-registry.yaml.`);
      continue;
    }
    exemptNames.add(name);
  }

  // 2. Derive the wiring from the source.
  const wiring = new Map(); // service name -> [{ kind, file }]
  for (const svc of services) {
    const dir = path.resolve(root, svc.dir || path.join('services', svc.name));
    if (!(await fs.pathExists(dir))) {
      errors.push(`${svc.name}: registry dir "${svc.dir}" does not exist.`);
      continue;
    }
    const hits = [];
    for (const file of await goFiles(dir)) {
      const raw = await fs.readFile(file, 'utf8');
      if (!raw.includes(AUDIT_IMPORT)) continue;
      const src = stripComments(raw);
      // The import itself lives in a string literal, which stripComments keeps.
      if (!src.includes(AUDIT_IMPORT)) continue;
      for (const { marker, kind } of WIRING_MARKERS) {
        if (src.includes(marker)) hits.push({ kind, file: path.relative(root, file) });
      }
    }
    if (hits.length) wiring.set(svc.name, hits);
  }

  // 3. Every non-exempt service must be wired.
  for (const svc of services) {
    if (exemptNames.has(svc.name)) continue;
    if (!wiring.has(svc.name)) {
      errors.push(
        `${svc.name}: nothing in ${svc.dir} writes to the audit trail. ` +
          `Mount shared/middleware/audit's LogRequest() on the API router (see ` +
          `services/tenant-health-service/cmd/audit.go), call audit.LogConsumerEvent for ` +
          `NATS/poller work, or record events directly with LogActivity — or add an ` +
          `EXEMPTIONS entry in scripts/audit-logging-parity.mjs with a written reason.`
      );
    }
  }

  // 4. The inverse: an exemption for a service that IS wired is stale, and a
  //    stale exemption is a hole waiting for the next person who deletes the
  //    wiring and sees the guard stay green.
  for (const name of exemptNames) {
    if (wiring.has(name)) {
      errors.push(
        `${name}: exempted, but ${wiring.get(name)[0].file} writes to the audit trail. ` +
          `Remove the EXEMPTIONS entry.`
      );
    }
  }

  return { errors, wiring, services, exemptNames };
}

// Run only when invoked as a script; the regression test imports auditTree.
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch((e) => fail(e.message));
}
