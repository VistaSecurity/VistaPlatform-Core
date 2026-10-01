#!/usr/bin/env node
// Audits that no job on a SELF-HOSTED runner restores a tarball cache into the
// runners' shared $HOME.
//
// Why this exists: every self-hosted host runs several `actions-runner-N`
// instances that share one $HOME, so ~/.npm, ~/go/pkg/mod, ~/.cache/go-build
// and ~/.cache/golangci-lint are single, persistent, already-warm caches.
// Restoring an Actions-cache tarball over them buys nothing and costs twice:
//
//   * setup-node `cache: npm` downloaded and untarred a ~1.8 GB archive of
//     ~/.npm on every frontend job — a median ~55s, against ~3s for the
//     `npm ci` it was meant to speed up — and its four ~1.8 GB entries filled
//     the repository's 10 GB Actions cache.
//   * setup-go's cache (ON by default — omitting `cache:` enables it) and
//     golangci-lint-action's cache untar over files a sibling runner is using,
// and die with "/usr/bin/tar:... Cannot open: File exists". That is
//     why ci.yml turns both off, with comments saying so.
//
// Those comments are the only thing stopping a well-meaning edit (or a
// Dependabot bump of an action whose default flips) from putting a cache back,
// and a comment cannot fail a build. This audit can.
//
// Rules, for every job whose `runs-on` can resolve to a self-hosted runner:
//   actions/setup-node          must not set `cache`
//   actions/setup-go            must set `cache: false` (its default is true)
//   golangci/golangci-lint-action must set `skip-cache: true`
//   actions/cache[/restore]     must only cache paths under ${{ runner.temp }}
//                               (per-runner-instance, not the shared $HOME)
// GitHub-hosted jobs (ubuntu-*, macos-*, windows-*) are exempt: each gets a
// fresh VM, which is exactly what the Actions cache is for.
//
// A `runs-on` expression is resolved against the job's matrix; if it cannot be
// resolved the job is treated as self-hosted — an audit that cannot tell must
// not pass by default.
//
// Run via `make audit` (strict) and ci.yml's workflow-guards job. Regression
// tests: scripts/test-workflow-caches-audit.mjs (`make workflow-caches-test`).
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(__filename), '..');

const GITHUB_HOSTED = /^(ubuntu|macos|windows)-/;

function labelsSelfHosted(value) {
  if (Array.isArray(value)) return value.some((v) => labelsSelfHosted(v));
  if (value && typeof value === 'object') {
    // { group: ..., labels: [...] } form — a runner group is self-hosted
    // unless its labels say otherwise.
    if (value.labels !== undefined) return labelsSelfHosted(value.labels) || !!value.group;
    return true;
  }
  const s = String(value ?? '').trim();
  if (s === '') return true;
  if (s === 'self-hosted') return true;
  return !GITHUB_HOSTED.test(s);
}

/** Returns true when the job can run on a self-hosted runner. */
export function jobIsSelfHosted(job) {
  const runsOn = job && job['runs-on'];
  if (runsOn === undefined) return true; // reusable-workflow call or malformed: fail closed
  if (typeof runsOn === 'string') {
    const m = runsOn.match(/^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$/);
    if (m) {
      const key = m[1];
      const matrix = (job.strategy && job.strategy.matrix) || {};
      const values = [];
      if (Array.isArray(matrix[key])) values.push(...matrix[key]);
      for (const inc of matrix.include || []) if (inc && inc[key] !== undefined) values.push(inc[key]);
      if (values.length === 0) return true;
      return values.some((v) => labelsSelfHosted(v));
    }
    if (runsOn.includes('${{')) return true;
  }
  return labelsSelfHosted(runsOn);
}

const isFalse = (v) => v === false || String(v).trim().toLowerCase() === 'false';
const isTrue = (v) => v === true || String(v).trim().toLowerCase() === 'true';

/** Findings for one workflow's parsed YAML. */
export function auditWorkflowDoc(doc, label) {
  const errors = [];
  let checked = 0;
  const jobs = (doc && doc.jobs) || {};
  for (const [jobName, job] of Object.entries(jobs)) {
    if (!job || !jobIsSelfHosted(job)) continue;
    for (const [i, step] of (job.steps || []).entries()) {
      const uses = step && typeof step.uses === 'string' ? step.uses : '';
      if (!uses) continue;
      const action = uses.split('@')[0];
      const w = (step && step.with) || {};
      const where = `${label}: job "${jobName}" step ${i + 1}${step.name ? ` ("${step.name}")` : ''} (${action})`;
      if (action === 'actions/setup-node') {
        checked++;
        if (w.cache !== undefined && w.cache !== null && String(w.cache).trim() !== '') {
          errors.push(
            `${where} sets \`cache: ${w.cache}\` on a self-hosted runner. ~/.npm is already a persistent, ` +
              `shared, warm cache there; restoring a ~1.8 GB tarball over it cost ~55s per job for nothing. ` +
              `Remove \`cache\` (and \`cache-dependency-path\`).`
          );
        }
      } else if (action === 'actions/setup-go') {
        checked++;
        if (!isFalse(w.cache)) {
          errors.push(
            `${where} does not set \`cache: false\`. setup-go caches by DEFAULT, and on a self-hosted runner ` +
              `that untars over the shared, persistent ~/go/pkg/mod and ~/.cache/go-build, colliding with ` +
              `sibling runners ("tar: Cannot open: File exists", #952).`
          );
        }
      } else if (action === 'golangci/golangci-lint-action') {
        checked++;
        if (!isTrue(w['skip-cache'])) {
          errors.push(
            `${where} does not set \`skip-cache: true\`. Its cache restore untars over the shared Go caches ` +
              `on self-hosted runners and fails the lint step intermittently (#952).`
          );
        }
      } else if (action === 'actions/cache' || action === 'actions/cache/restore') {
        checked++;
        const paths = String(w.path ?? '')
          .split('\n')
          .map((p) => p.trim())
          .filter(Boolean);
        const shared = paths.filter((p) => !/^\$\{\{\s*runner\.temp\s*\}\}/.test(p));
        if (paths.length === 0 || shared.length > 0) {
          errors.push(
            `${where} caches ${shared.length ? shared.join(', ') : '(no path)'} on a self-hosted runner. ` +
              `Anything outside \${{ runner.temp }} is shared by every runner instance on the host (#952).`
          );
        }
      }
    }
  }
  return { errors, checked };
}

export function auditWorkflowCaches({ rootDir = root, dir = '.github/workflows' } = {}) {
  const errors = [];
  const notes = [];
  const abs = path.join(rootDir, dir);
  const files = fs.existsSync(abs)
    ? fs.readdirSync(abs).filter((f) => /\.ya?ml$/.test(f)).sort()
    : [];
  if (files.length === 0) {
    errors.push(`${dir}: no workflow files found — an audit that reads nothing passes vacuously.`);
    return { errors, notes };
  }
  let checked = 0;
  for (const f of files) {
    const rel = path.join(dir, f);
    let doc;
    try {
      doc = YAML.parse(fs.readFileSync(path.join(rootDir, rel), 'utf8'));
    } catch (e) {
      errors.push(`${rel}: could not be parsed (${e.message}) — a workflow that cannot be read cannot be audited.`);
      continue;
    }
    const r = auditWorkflowDoc(doc, rel);
    errors.push(...r.errors);
    checked += r.checked;
  }
  if (checked === 0) {
    errors.push(`${dir}: found no setup-node/setup-go/golangci-lint/cache steps on self-hosted jobs — the parser is not reading the workflows.`);
  }
  notes.push(`  ${files.length} workflow file(s), ${checked} cache-capable step(s) on self-hosted jobs checked`);
  return { errors, notes };
}

export function main(argv = process.argv) {
  const strict = argv.includes('--strict');
  const { errors, notes } = auditWorkflowCaches();
  console.log('Workflow cache audit (no tarball cache into the shared $HOME of self-hosted runners)');
  notes.forEach((n) => console.log(n));
  if (errors.length) {
    console.error('');
    errors.forEach((e) => console.error(`  ❌ ${e}`));
    console.error('');
    process.exit(strict ? 1 : 0);
  }
  console.log('✅ workflow caches: no self-hosted job restores a tarball cache into the shared $HOME.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}
