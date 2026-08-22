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
// Run via `make audit` (strict). Mutation-test any change: remove a service
// from a matrix (must FAIL), add a matrix entry with no module on disk (must
// FAIL), clean tree (must PASS).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const strict = process.argv.includes('--strict');

// The workflows whose `service:` matrix must cover every shipping module, and
// what each is for. Both are per-module fan-outs over the same name space.
const MATRIX_WORKFLOWS = [
  { file: '.github/workflows/ci.yml', label: 'PR gate' },
  { file: '.github/workflows/nightly.yml', label: 'nightly' },
];

// Matrix names that are NOT services/<name> directories. These are resolved by
// the `case` in each workflow's "Resolve path" step; keep in step with it.
const NON_SERVICE_ENTRIES = new Map([
  ['sensor', 'sensor'],
  ['shared', 'shared'],
  ['shared-rbac', 'shared/rbac'],
  ['license-issue', 'tools/license-issue'],
]);

const errors = [];
const notes = [];

// ---- what SHOULD be covered: every services/*/ with a go.mod -----------------
const servicesDir = path.join(root, 'services');
const shippingModules = fs
  .readdirSync(servicesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .filter((n) => fs.existsSync(path.join(servicesDir, n, 'go.mod')))
  .sort();

if (shippingModules.length === 0) {
  console.error('❌ ci-matrix coverage: found no services/*/go.mod — the audit cannot be right about nothing.');
  process.exit(1);
}

// ---- what IS covered: the `service:` matrix list in each workflow -----------
function matrixEntries(file) {
  const abs = path.join(root, file);
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

for (const { file, label } of MATRIX_WORKFLOWS) {
  const entries = matrixEntries(file);
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
    const rel = NON_SERVICE_ENTRIES.get(e) ?? `services/${e}`;
    if (!fs.existsSync(path.join(root, rel, 'go.mod'))) {
      errors.push(
        `${file}: matrix entry "${e}" resolves to ${rel}, which has no go.mod — ` +
          `that leg skips itself at runtime and reports success.`
      );
    }
  }

  notes.push(`  ${label.padEnd(8)} ${entries.length} matrix entr(ies), ${shippingModules.length} shipping module(s)`);
}

console.log('CI matrix coverage audit (every shipping Go module must be in the build/test matrices)');
notes.forEach((n) => console.log(n));

if (errors.length) {
  console.error('');
  errors.forEach((e) => console.error(`  ❌ ${e}`));
  console.error('');
  console.error('  Fix by adding the module to the `service:` matrix in the named workflow.');
  if (strict) process.exit(1);
  process.exit(0);
}

console.log('✅ ci-matrix coverage: every shipping module is built and tested before release.');
