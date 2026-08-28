#!/usr/bin/env node
// Audits that every Go module which ships as a product artefact appears in the
// CI matrices that build, lint and test it.
//
// Why this exists: mcp-service shipped for months with ZERO pre-release CI. It
// is a real service — 16 Go files, its own tests, in go.work, in the service
// registry, in the chart, and built by BOTH release workflows — but it appeared
// in neither ci.yml nor nightly.yml. Nothing verified it compiled, linted or
// passed its own tests until someone cut a release, at which point
// release-core.yml's image build would fail and block the release. Its tests
// had never run, anywhere. Every gate was green the whole time, because for
// that service there was no gate.
//
// The module list is DERIVED from the filesystem and go.work on every run.
// There is deliberately no hand-maintained list of services here: a second copy
// of the answer is a copy that drifts, and the drift would be invisible
// precisely because this file is what is supposed to notice it. A new service
// is unwired-by-default and fails this audit until someone either adds it to
// the matrices or records why it does not belong there.
//
// The same hole exists on the JS side and cost real time: tools/qa-platform/ui
// is a standalone Vite app with its own package-lock.json (not an npm-workspace
// member), so the root `npm ci` never installed it and the frontend matrix never
// built it. Dependabot PRs and both merged-ready green while
// breaking `npm run build` outright. So this audit also asserts that every JS
// package carrying a `build` script is referenced by ci.yml — see
// auditJsPackageCoverage below.
//
// Run via `make audit` (strict). Mutation-test any change: remove a service
// from a matrix (must FAIL), add a matrix entry with no module on disk (must
// FAIL), drop a built JS package's directory from ci.yml (must FAIL), clean
// tree (must PASS).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

// The workflows whose `service:` matrix must cover every shipping module, and
// what each is for. Both are per-module fan-outs over the same name space.
export const MATRIX_WORKFLOWS = [
  { file: '.github/workflows/ci.yml', label: 'PR gate' },
  { file: '.github/workflows/nightly.yml', label: 'nightly' },
];

// Matrix names that are NOT services/<name> directories. These are resolved by
// the `case` in each workflow's "Resolve path" step; keep in step with it.
export const NON_SERVICE_ENTRIES = new Map([
  ['sensor', 'sensor'],
  ['shared', 'shared'],
  ['shared-rbac', 'shared/rbac'],
  ['license-issue', 'tools/license-issue'],
]);

// ---- what SHOULD be covered: every services/*/ with a go.mod -----------------
export function discoverShippingModules(rootDir = root) {
  const servicesDir = path.join(rootDir, 'services');
  return fs
    .readdirSync(servicesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((n) => fs.existsSync(path.join(servicesDir, n, 'go.mod')))
    .sort();
}

// ---- what IS covered: the `service:` matrix list in each workflow -----------
export function matrixEntries(file, rootDir = root) {
  const abs = path.join(rootDir, file);
  if (!fs.existsSync(abs)) return null;
  const lines = fs.readFileSync(abs, 'utf8').split('\n');
  const out = [];
  let inMatrix = false;
  let indent = null;
  for (const line of lines) {
    if (/^\s*service:\s*$/.test(line)) {
      inMatrix = true;
      indent = null;
      continue;
    }
    if (!inMatrix) continue;
    const m = line.match(/^(\s+)-\s+([A-Za-z0-9_-]+)\s*$/);
    if (m) {
      if (indent === null) indent = m[1].length;
      if (m[1].length === indent) {
        out.push(m[2]);
        continue;
      }
    }
    if (line.trim() !== '') inMatrix = false;
  }
  return out;
}

// ── JS/TS package coverage ───────────────────────────────────────────────────
// The workflow that must reference every buildable JS package. Unlike the Go
// side there is no per-module matrix to parse — the legs are heterogeneous
// (a `path:` matrix for the two UIs, a plain `working-directory:` job for
// qa-platform/ui) — so coverage is "this directory is named somewhere in the PR
// gate", which is what actually makes a leg exist.
export const JS_COVERAGE_WORKFLOW = '.github/workflows/ci.yml';

// Packages with NO `build` script, and why that is legitimate. Anything not
// listed here and not built is a finding. Keep the reasons honest: an
// exemption is a claim that nothing ships from this directory.
export const UNBUILT_JS_PACKAGES = new Map([
  ['api', 'npm-workspace member; emits generated .d.ts only. `typecheck` runs transitively in both UI legs, and `make api-contract` regenerates + diffs it.'],
  ['packages/primitives', 'npm-workspace member; consumed as source by both UIs, so their `tsc -b` type-checks it.'],
  ['scripts', 'repo tooling only (audit/generator node scripts run directly); nothing here is bundled or shipped.'],
]);

// Every package.json outside node_modules, excluding the workspace root.
export function discoverJsPackages(rootDir = root) {
  const found = [];
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', '.claude']);
  const walk = (abs, rel) => {
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() || skipDirs.has(e.name)) continue;
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      const childAbs = path.join(abs, e.name);
      if (fs.existsSync(path.join(childAbs, 'package.json'))) found.push(childRel);
      walk(childAbs, childRel);
    }
  };
  walk(rootDir, '');
  return found.sort();
}

function readJson(abs) {
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch {
    return null;
  }
}

export function auditJsPackageCoverage({
  rootDir = root,
  workflowFile = JS_COVERAGE_WORKFLOW,
  exemptions = UNBUILT_JS_PACKAGES,
} = {}) {
  const errors = [];
  const notes = [];

  const workflowAbs = path.join(rootDir, workflowFile);
  if (!fs.existsSync(workflowAbs)) {
    errors.push(`${workflowFile} not found — JS package coverage cannot be audited.`);
    return { errors, notes, packages: [] };
  }
  const workflow = fs.readFileSync(workflowAbs, 'utf8');

  const packages = discoverJsPackages(rootDir);
  if (packages.length === 0) {
    errors.push('js-package coverage: found no package.json outside the root — the audit cannot be right about nothing.');
    return { errors, notes, packages };
  }

  let built = 0;
  for (const pkg of packages) {
    const manifest = readJson(path.join(rootDir, pkg, 'package.json'));
    if (!manifest) {
      errors.push(`${pkg}/package.json could not be parsed — a package that cannot be read cannot be audited.`);
      continue;
    }
    const hasBuild = Boolean(manifest.scripts && manifest.scripts.build);

    if (!hasBuild) {
      if (!exemptions.has(pkg)) {
        errors.push(
          `${pkg} has a package.json with no \`build\` script and no recorded reason — ` +
            `nothing in the PR gate compiles it. Give it a build script and a ci.yml leg, ` +
            `or add it to UNBUILT_JS_PACKAGES with why it ships nothing.`
        );
      }
      continue;
    }

    built++;
    if (exemptions.has(pkg)) {
      errors.push(
        `${pkg} is listed in UNBUILT_JS_PACKAGES but now HAS a \`build\` script — ` +
          `the exemption is stale and is hiding it from this audit. Remove the entry.`
      );
    }
    if (!workflow.includes(pkg)) {
      errors.push(
        `${pkg} has a \`build\` script but is never named in ${workflowFile} — ` +
          `no PR-gate job builds it. This is how tools/qa-platform/ui shipped two ` +
          `build-breaking Dependabot bumps with every check green (#1525, #1526).`
      );
    }
  }

  // A stale exemption for a directory that no longer exists is a dead entry
  // that would silently absolve a future package sharing its path.
  for (const pkg of exemptions.keys()) {
    if (!fs.existsSync(path.join(rootDir, pkg, 'package.json'))) {
      errors.push(`UNBUILT_JS_PACKAGES lists "${pkg}", which has no package.json — remove the stale exemption.`);
    }
  }

  notes.push(
    `  PR gate  ${packages.length} JS package(s): ${built} with a build script, ${packages.length - built} exempt`
  );
  return { errors, notes, packages };
}

export function auditCiMatrixCoverage({
  rootDir = root,
  workflows = MATRIX_WORKFLOWS,
  nonServiceEntries = NON_SERVICE_ENTRIES,
} = {}) {
  const errors = [];
  const notes = [];
  const shippingModules = discoverShippingModules(rootDir);

  if (shippingModules.length === 0) {
    errors.push('ci-matrix coverage: found no services/*/go.mod — the audit cannot be right about nothing.');
    return { errors, notes, shippingModules };
  }

  for (const { file, label } of workflows) {
    const entries = matrixEntries(file, rootDir);
    if (entries === null) {
      errors.push(`${file} not found — the ${label} matrix cannot be audited.`);
      continue;
    }
    if (entries.length === 0) {
      errors.push(`${file}: could not parse any \`service:\` matrix entries. If the matrix moved, fix this parser — an audit that finds nothing passes vacuously.`);
      continue;
    }

    // Every shipping module must appear.
    for (const svc of shippingModules) {
      if (!entries.includes(svc)) {
        errors.push(
          `${file}: services/${svc} ships (has go.mod) but is absent from the ${label} matrix — ` +
            `nothing builds, lints or tests it before a release.`
        );
      }
    }

    // Every entry must resolve to a real module, or the leg silently self-skips
    // ("go.mod not found — skipping"), which reads as a pass.
    for (const e of entries) {
      const rel = nonServiceEntries.get(e) ?? `services/${e}`;
      if (!fs.existsSync(path.join(rootDir, rel, 'go.mod'))) {
        errors.push(
          `${file}: matrix entry "${e}" resolves to ${rel}, which has no go.mod — ` +
            `that leg skips itself at runtime and reports success.`
        );
      }
    }

    notes.push(`  ${label.padEnd(8)} ${entries.length} matrix entr(ies), ${shippingModules.length} shipping module(s)`);
  }

  return { errors, notes, shippingModules };
}

export function main(argv = process.argv) {
  const strict = argv.includes('--strict');
  const go = auditCiMatrixCoverage();
  const js = auditJsPackageCoverage();
  const errors = [...go.errors, ...js.errors];
  const notes = [...go.notes, ...js.notes];

  console.log('CI matrix coverage audit (every shipping Go module and buildable JS package must be in CI)');
  notes.forEach((n) => console.log(n));

  if (errors.length) {
    console.error('');
    errors.forEach((e) => console.error(`  ❌ ${e}`));
    console.error('');
    console.error('  Fix by adding the module to the `service:` matrix, or the JS package to a job, in the named workflow.');
    process.exit(strict ? 1 : 0);
  }

  console.log('✅ ci-matrix coverage: every shipping module and buildable JS package is built before release.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
