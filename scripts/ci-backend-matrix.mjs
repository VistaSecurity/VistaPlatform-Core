#!/usr/bin/env node
// Emits the PR gate's backend-check matrix: which Go modules this change needs
// checked, as GitHub Actions matrix JSON.
//
// Why: backend-check used to be a static 22-leg matrix that decided whether to
// skip INSIDE each leg, after a runner had been allocated and the repo checked
// out. On a PR touching one service, 21 runners started only to print
// "unchanged — skipping" and exit. In the 120 PR-gate runs sampled before this
// change, 880 of the 1,792 legs scheduled (~49%) did no work. That is ~3.2
// runner-hours holding one of the nine shared self-hosted runners that other
// jobs were queued behind. The
// decision now happens once, in detect-changes, and the job's matrix only
// contains the legs that will actually run.
//
// ONE SOURCE. The full leg list is derived from go.work's `use` block on every
// run. There is no second, hand-kept list of modules to drift from it: a
// module added to go.work gets a leg automatically, and a module that cannot
// be named (a go.work entry this file cannot map to a leg) is an ERROR, not a
// silent omission. scripts/audit-ci-matrix-coverage.mjs checks the other
// direction — every services/*/go.mod on disk must be in this list — so a
// module dropped from go.work cannot quietly lose its leg either.
//
// Selection, identical to the per-leg logic it replaces:
//   * workflow_dispatch                  → every leg
//   * shared/ changed (count != 0)       → every leg (every module imports shared)
//     — this includes the detector's FAIL-OPEN path (base commit unreachable),
//       which reports shared=1 precisely so that everything runs
//   * otherwise                          → the legs named in `services`
//   * a name in `services` with no leg:
// - its directory has no go.mod (the PR DELETED that service, as
//         did artifact-service) → ignored, with a notice. There is nothing
//         left to check, and the old per-leg logic skipped it too.
//       - its directory HAS a go.mod that go.work does not list → ERROR. That
//         is a module outside the workspace: it would arm nothing and pass.
//
// Each emitted leg also carries `ee`: whether the module has an Enterprise
// (-tags ee) build (scripts/go-module-has-ee.sh, the same definition nightly.yml
// asks). backend-check runs its vet/build/test passes under `-tags ee` for
// exactly those legs. Before this, CI compiled and tested NO -tags ee build, so
// the linked Enterprise binaries and their *_ee_test.go suites could break with
// every check green.
//
// Usage (CI):   EVENT_NAME=… SERVICES=a,b SHARED=<n> node scripts/ci-backend-matrix.mjs >> "$GITHUB_OUTPUT"
//   prints:     backend_matrix={"include":[{"service":"…","path":"…","ee":false},…]}
//               backend_count=<n>
// Usage (list): node scripts/ci-backend-matrix.mjs --list   → every leg, one "name path" per line
//
// Regression test: scripts/test-ci-backend-matrix.mjs (`make ci-backend-matrix-test`).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..');

// Leg names for go.work modules that are not services/<name>. The names are
// the ones detect-changed-files.sh emits and the ones ci.yml's per-leg `if:`s
// (libpcap, Node, the test allowlist) and nightly.yml's matrix use.
export const NON_SERVICE_LEGS = new Map([
  ['sensor', 'sensor'],
  ['device-agent', 'device-agent'],
  ['shared', 'shared'],
  ['shared/rbac', 'shared-rbac'],
  ['tools/license-issue', 'license-issue'],
]);

/** The module directories in go.work's `use` directive(s), repo-relative, in file order. */
export function goWorkModules(goWorkText) {
  const out = [];
  const lines = goWorkText.split('\n').map((l) => l.replace(/\/\/.*$/, '').trim());
  let inBlock = false;
  for (const line of lines) {
    if (inBlock) {
      if (line === ')') { inBlock = false; continue; }
      if (line) out.push(line);
      continue;
    }
    if (/^use\s*\($/.test(line)) { inBlock = true; continue; }
    const single = line.match(/^use\s+(\S+)$/);
    if (single) out.push(single[1]);
  }
  return out.map((m) => m.replace(/^\.\//, '').replace(/\/$/, ''));
}

/** Map a module dir to its leg name, or throw. */
export function legName(dir) {
  if (NON_SERVICE_LEGS.has(dir)) return NON_SERVICE_LEGS.get(dir);
  const m = dir.match(/^services\/([^/]+)$/);
  if (m) return m[1];
  throw new Error(
    `go.work module "${dir}" has no backend-check leg name. Add it to NON_SERVICE_LEGS in ` +
      `scripts/ci-backend-matrix.mjs (and teach scripts/detect-changed-files.sh to name it) — ` +
      `a module in the workspace must never silently fall out of the PR gate.`
  );
}

/** Every leg: [{ service, path }] derived from go.work. */
export function allLegs(rootDir = ROOT) {
  const text = fs.readFileSync(path.join(rootDir, 'go.work'), 'utf8');
  const mods = goWorkModules(text);
  if (mods.length === 0) throw new Error('go.work lists no modules — refusing to emit an empty backend matrix from a parse failure');
  const legs = mods.map((dir) => ({ service: legName(dir), path: dir }));
  const seen = new Set();
  for (const l of legs) {
    if (seen.has(l.service)) throw new Error(`two go.work modules map to the leg name "${l.service}"`);
    seen.add(l.service);
  }
  return legs;
}

/**
 * Does this module have an -tags ee build? Asks scripts/go-module-has-ee.sh
 * (exit 0 yes, 1 no); a missing directory is `false` here because the leg's own
 * "Resolve module path" step reports it with a better message. Any other exit is
 * an error: guessing `false` would switch the Enterprise passes off silently.
 */
export function moduleHasEE(dir, rootDir = ROOT) {
  const abs = path.join(rootDir, dir);
  if (!fs.existsSync(abs)) return false;
  const r = spawnSync('bash', [path.join(ROOT, 'scripts/go-module-has-ee.sh'), abs], { encoding: 'utf8' });
  if (r.status === 0) return true;
  if (r.status === 1) return false;
  throw new Error(`scripts/go-module-has-ee.sh ${dir} failed (exit ${r.status}): ${(r.stderr || r.error || '').toString().trim()}`);
}

/** Legs with their `ee` flag (see moduleHasEE). */
export function withEE(legs, rootDir = ROOT, has = moduleHasEE) {
  return legs.map((l) => ({ ...l, ee: has(l.path, rootDir) }));
}

/** Default probe: does the directory detect-changed-files.sh names still hold a Go module? */
export function namedModuleExists(name, rootDir = ROOT) {
  const dir = [...NON_SERVICE_LEGS].find(([, leg]) => leg === name)?.[0] ?? `services/${name}`;
  return fs.existsSync(path.join(rootDir, dir, 'go.mod'));
}

/** The legs this change needs. `ignored` collects names dropped because their module is gone. */
export function selectLegs({ legs, eventName, services, shared, moduleExists = namedModuleExists, ignored = [] }) {
  if (eventName === 'workflow_dispatch') return legs;
  const sharedCount = Number.parseInt(String(shared ?? '').trim() || 'NaN', 10);
  if (!Number.isFinite(sharedCount)) {
    // An absent or garbled `shared` is not "nothing changed". Fail open.
    return legs;
  }
  if (sharedCount !== 0) return legs;
  const names = String(services ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const byName = new Map(legs.map((l) => [l.service, l]));
  const unknown = names.filter((n) => !byName.has(n) && moduleExists(n));
  for (const n of names) if (!byName.has(n) && !moduleExists(n)) ignored.push(n);
  if (unknown.length) {
    throw new Error(
      `detect-changed-files.sh named ${unknown.map((u) => `"${u}"`).join(', ')}: a directory with a go.mod that no ` +
        `go.work module maps to. That change would arm nothing and the gate would pass having checked nothing. ` +
        `Add the module to go.work.`
    );
  }
  return legs.filter((l) => names.includes(l.service));
}

export function main(argv = process.argv, env = process.env) {
  const legs = allLegs();
  if (argv.includes('--list')) {
    for (const l of legs) console.log(`${l.service} ${l.path}`);
    return;
  }
  const ignored = [];
  const chosen = withEE(selectLegs({ legs, eventName: env.EVENT_NAME, services: env.SERVICES, shared: env.SHARED, ignored }));
  for (const n of ignored) console.error(`::notice::ci-backend-matrix: "${n}" changed but has no go.mod any more (deleted module) — no leg to run`);
  console.log(`backend_matrix=${JSON.stringify({ include: chosen })}`);
  console.log(`backend_count=${chosen.length}`);
  console.error(`backend-check: ${chosen.length} of ${legs.length} leg(s): ${chosen.map((l) => l.service + (l.ee ? ' (+ee)' : '')).join(', ') || '(none)'}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    main();
  } catch (e) {
    console.error(`::error::ci-backend-matrix: ${e.message}`);
    process.exit(1);
  }
}
