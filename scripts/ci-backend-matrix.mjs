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
// Selection:
//   * workflow_dispatch                  → every leg
//   * matrix_full != 0                   → every leg. The detector counts the
//     inputs the import graph cannot reason about: go.work, shared/go.{mod,sum},
//     any non-.go file under shared/ (embedded assets, fixtures, SQL), any
//     testdata/ under shared/, and this script, the detector and the deps
//     script themselves (a change to the selection logic runs everything once).
//   * shared/ changed (count != 0)       → the legs whose IMPORT CLOSURE contains
//     a changed shared package (scripts/ci-go-module-deps.sh asks `go list
//     -deps -test`, default and -tags ee, for every go.work module), plus the
//     legs named in `services`. In the 30 PR-gate runs sampled before this
//     rule, 21 touched shared/ and each scheduled all 23 legs; most touched
//     one or two packages that a handful of modules import.
//     FAIL OPEN to every leg when: the detector reported no package list
//     (its own fail-open path reports shared=1 with no packages, precisely
//     so that everything runs), the deps script fails or omits a module, or
//     any input is garbled. Running too much wastes runner time; running
//     too little while reporting success is how a PR merges unverified.
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
// Usage (CI):   EVENT_NAME=… SERVICES=a,b SHARED=<n> SHARED_PACKAGES=findings,identity MATRIX_FULL=<n> \
//                 node scripts/ci-backend-matrix.mjs >> "$GITHUB_OUTPUT"
//   prints:     backend_matrix={"include":[{"service":"…","path":"…","ee":false},…]}
//               backend_count=<n>
//   GO_DEPS_FILE=<path> reads a precomputed deps map instead of running
//   scripts/ci-go-module-deps.sh (a test seam; CI never sets it).
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
  ['tools/devicetype-import', 'devicetype-import'],
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

export const IMPORT_PREFIX = 'github.com/vistasecurity/vistaplatform/';

/** The import path of a shared package dir as the detector names it (`.` = shared's root). */
export function sharedImportPath(pkgDir) {
  const p = String(pkgDir).trim().replace(/^\.\/?/, '').replace(/\/$/, '');
  return `${IMPORT_PREFIX}shared${p ? `/${p}` : ''}`;
}

/**
 * The import-closure map: { "<module dir>": [import paths…] }, from
 * scripts/ci-go-module-deps.sh (or GO_DEPS_FILE). Returns null — never a
 * partial map — when it cannot be obtained; the caller fails open on null.
 */
export function loadDeps(env = process.env, rootDir = ROOT, notes = []) {
  try {
    if (env.GO_DEPS_FILE) return JSON.parse(fs.readFileSync(env.GO_DEPS_FILE, 'utf8'));
    const r = spawnSync('bash', [path.join(rootDir, 'scripts/ci-go-module-deps.sh')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) {
      notes.push(`::warning::ci-backend-matrix: scripts/ci-go-module-deps.sh failed (exit ${r.status}) — running every leg. ${(r.stderr || '').trim().split('\n').slice(0, 3).join(' | ')}`);
      return null;
    }
    return JSON.parse(r.stdout);
  } catch (e) {
    notes.push(`::warning::ci-backend-matrix: could not load the import-closure map (${e.message}) — running every leg`);
    return null;
  }
}

/** The leg whose module CONTAINS shared/<pkgDir> (longest path prefix), or undefined. */
export function owningLeg(legs, pkgDir) {
  const dir = `shared${pkgDir === '.' ? '' : `/${pkgDir}`}`;
  return legs
    .filter((l) => dir === l.path || dir.startsWith(`${l.path}/`))
    .sort((a, b) => b.path.length - a.path.length)[0];
}

/**
 * The legs whose closure contains any of the changed shared packages — plus
 * the module that CONTAINS each changed package, whether or not anything
 * imports it yet: its own build/vet/test must run (a brand-new package, or
 * one only its own tests reach, is in nobody's closure). Returns null (fail
 * open) if a module is missing from the map.
 */
export function affectedLegs(legs, pkgDirs, deps, notes = []) {
  const wanted = pkgDirs.map(sharedImportPath);
  const out = new Map();
  for (const l of legs) {
    const closure = deps?.[l.path];
    if (!Array.isArray(closure) || closure.length === 0) {
      notes.push(`::warning::ci-backend-matrix: no import closure for module "${l.path}" — running every leg`);
      return null;
    }
    const set = new Set(closure);
    if (wanted.some((w) => set.has(w))) out.set(l.service, l);
  }
  for (const p of pkgDirs) {
    const owner = owningLeg(legs, p);
    if (!owner) {
      notes.push(`::warning::ci-backend-matrix: shared package "${p}" belongs to no go.work module — running every leg`);
      return null;
    }
    out.set(owner.service, owner);
  }
  return legs.filter((l) => out.has(l.service));
}

/** The legs this change needs. `ignored` collects names dropped because their module is gone; `notes` collects fail-open reasons. */
export function selectLegs({
  legs, eventName, services, shared, sharedPackages, matrixFull, deps,
  moduleExists = namedModuleExists, ignored = [], notes = [],
}) {
  if (eventName === 'workflow_dispatch') return legs;
  const count = (v) => Number.parseInt(String(v ?? '').trim() || 'NaN', 10);
  const sharedCount = count(shared);
  if (!Number.isFinite(sharedCount)) {
    // An absent or garbled `shared` is not "nothing changed". Fail open.
    notes.push('::warning::ci-backend-matrix: `shared` missing or garbled — running every leg');
    return legs;
  }
  const full = count(matrixFull);
  if (!Number.isFinite(full)) {
    notes.push('::warning::ci-backend-matrix: `matrix_full` missing or garbled — running every leg');
    return legs;
  }
  if (full !== 0) {
    notes.push(`::notice::ci-backend-matrix: ${full} change(s) outside the import graph's reach (go.work, shared/go.mod, non-Go or testdata under shared/, or the matrix scripts) — running every leg`);
    return legs;
  }

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
  const named = legs.filter((l) => names.includes(l.service));
  if (sharedCount === 0) return named;

  // shared/ changed: narrow to the modules that import the changed packages.
  const pkgDirs = String(sharedPackages ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (pkgDirs.length === 0) {
    notes.push('::warning::ci-backend-matrix: shared/ changed but the detector named no package (its fail-open path, or a wiring mistake) — running every leg');
    return legs;
  }
  const resolved = deps === undefined ? loadDeps(process.env, ROOT, notes) : deps;
  if (!resolved) return legs;
  const affected = affectedLegs(legs, pkgDirs, resolved, notes);
  if (affected === null) return legs;
  const chosen = new Map(affected.map((l) => [l.service, l]));
  for (const l of named) chosen.set(l.service, l);
  notes.push(`::notice::ci-backend-matrix: shared package(s) ${pkgDirs.join(', ')} → ${affected.length} importing module(s)${named.length ? ` + ${named.length} named` : ''}`);
  return legs.filter((l) => chosen.has(l.service));
}

/** The content key of a leg's inputs at HEAD (scripts/ci-leg-input-hash.sh), or null if it cannot be computed. */
export function legInputKey(leg, rootDir = ROOT) {
  const r = spawnSync('bash', [path.join(rootDir, 'scripts/ci-leg-input-hash.sh'), leg.service, leg.path], { cwd: rootDir, encoding: 'utf8' });
  if (r.status !== 0) return null;
  const key = r.stdout.trim();
  return /^verified-v\d+-[A-Za-z0-9_.-]+-[0-9a-f]{64}$/.test(key) ? key : null;
}

/**
 * Is there an Actions-cache marker under exactly this key? Asks the REST API
 * (an exact-key query; `?key=` is a prefix filter, so the returned key is
 * compared in full). Returns true / false, or null when the answer could not
 * be obtained — the caller fails OPEN on null.
 */
export function markerExists(key, env = process.env) {
  if (env.VERIFIED_KEYS_FILE) {
    try { return fs.readFileSync(env.VERIFIED_KEYS_FILE, 'utf8').split('\n').map((s) => s.trim()).includes(key); } catch { return null; }
  }
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPOSITORY) return null;
  const url = `${env.GITHUB_API_URL || 'https://api.github.com'}/repos/${env.GITHUB_REPOSITORY}/actions/caches?key=${encodeURIComponent(key)}&per_page=10`;
  const r = spawnSync('curl', ['-sS', '--fail', '--max-time', '20', '-H', `Authorization: Bearer ${env.GITHUB_TOKEN}`, '-H', 'Accept: application/vnd.github+json', url], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  try {
    const body = JSON.parse(r.stdout);
    return Array.isArray(body.actions_caches) && body.actions_caches.some((c) => c.key === key);
  } catch { return null; }
}

/**
 * Drop the legs whose exact input trees a green run already verified
 * (VERIFIED_SKIP=1 in CI). A leg is dropped only on a positive answer; a
 * key that cannot be computed or a lookup that fails keeps the leg and says
 * so. `skipped` collects what was dropped, with its key, for the job log.
 */
export function dropVerified(legs, env = process.env, notes = [], skipped = [], exists = markerExists, keyOf = legInputKey) {
  if (env.VERIFIED_SKIP !== '1') return legs;
  const keep = [];
  let lookupFailed = false;
  for (const l of legs) {
    const key = keyOf(l);
    if (!key) { notes.push(`::warning::ci-backend-matrix: could not compute the input key of "${l.service}" — running it`); keep.push(l); continue; }
    const found = exists(key, env);
    if (found === true) { skipped.push({ service: l.service, key }); continue; }
    if (found === null) lookupFailed = true;
    keep.push(l);
  }
  if (lookupFailed) notes.push('::warning::ci-backend-matrix: the verified-marker lookup failed for at least one leg — those legs run');
  return keep;
}

export function main(argv = process.argv, env = process.env) {
  const legs = allLegs();
  if (argv.includes('--list')) {
    for (const l of legs) console.log(`${l.service} ${l.path}`);
    return;
  }
  const ignored = [];
  const notes = [];
  const skipped = [];
  const selected = selectLegs({
    legs, eventName: env.EVENT_NAME, services: env.SERVICES, shared: env.SHARED,
    sharedPackages: env.SHARED_PACKAGES, matrixFull: env.MATRIX_FULL, ignored, notes,
  });
  const chosen = withEE(dropVerified(selected, env, notes, skipped));
  for (const n of notes) console.error(n);
  for (const n of ignored) console.error(`::notice::ci-backend-matrix: "${n}" changed but has no go.mod any more (deleted module) — no leg to run`);
  for (const s of skipped) console.error(`::notice::ci-backend-matrix: "${s.service}" skipped — its exact input trees were already verified green (${s.key})`);
  console.log(`backend_matrix=${JSON.stringify({ include: chosen })}`);
  console.log(`backend_count=${chosen.length}`);
  console.log(`verified_skipped=${skipped.map((s) => s.service).join(',')}`);
  console.error(`backend-check: ${chosen.length} of ${legs.length} leg(s): ${chosen.map((l) => l.service + (l.ee ? ' (+ee)' : '')).join(', ') || '(none)'}${skipped.length ? `; ${skipped.length} already verified` : ''}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    main();
  } catch (e) {
    console.error(`::error::ci-backend-matrix: ${e.message}`);
    process.exit(1);
  }
}
