#!/usr/bin/env node
// Edition-boundary audit for the open-core carve.
//
// Enterprise/MSP code lives at services/<svc>/ee/ and is deleted wholesale
// when the open-source repository is cut. The Core build must therefore never
// reference it except from files the Core build does not compile.
//
// Invariants, all of which fail the build if broken:
//
//   1. Every Go file importing services/<svc>/ee/... is guarded by
//      `//go:build ee`. Otherwise deleting ee/ breaks the Core build — a
//      failure that would only surface at repo-cut time, which is the worst
//      possible moment to discover it.
//   2. Every ee/-guarded file lives under a service that actually has an ee/
//      tree, catching a stale guard left behind after a feature moved back.
//   3. A carved service's commercial images actually build with `-tags ee`.
//   4. The Enterprise CONTENT boundary: the five regulated compliance
//      frameworks live only in the content bundle, the six free ones live only
//      in the Core seed, the chart gates the bundle off by default, and the
//      staged chart copy is gitignored (charts/ survives the repo cut).
//
// Run standalone for advisory output; `make audit` runs it strict.
//
// See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const servicesDir = join(repoRoot, 'services');
const strict = process.argv.includes('--strict');

const EE_IMPORT = /"github\.com\/vistasecurity\/vistaplatform\/[a-z0-9-]+\/ee\//;

function walkGoFiles(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (entry === 'vendor' || entry === 'node_modules') continue;
      walkGoFiles(p, out);
    } else if (entry.endsWith('.go')) {
      out.push(p);
    }
  }
  return out;
}

/** Files under an ee/ tree are Enterprise by location and need no build tag. */
function isInsideEeTree(path) {
  return relative(repoRoot, path).split('/').includes('ee');
}

function hasEeBuildTag(src) {
  // Only the build-constraint prologue counts: a `//go:build ee` further down
  // the file is an ordinary comment and constrains nothing.
  for (const line of src.split('\n')) {
    const t = line.trim();
    if (t.startsWith('//go:build')) return /\bee\b/.test(t);
    if (t === '' || t.startsWith('//')) continue;
    return false;
  }
  return false;
}

const violations = [];
const guarded = [];

for (const svc of existsSync(servicesDir) ? readdirSync(servicesDir) : []) {
  const svcPath = join(servicesDir, svc);
  if (!statSync(svcPath).isDirectory()) continue;

  for (const file of walkGoFiles(svcPath)) {
    if (isInsideEeTree(file)) continue; // Enterprise code may import Enterprise code
    const src = readFileSync(file, 'utf8');
    if (!EE_IMPORT.test(src)) continue;

    if (hasEeBuildTag(src)) {
      guarded.push(relative(repoRoot, file));
    } else {
      violations.push({
        file: relative(repoRoot, file),
        reason: 'imports an ee/ package without a `//go:build ee` guard — ' +
          'deleting ee/ for the open-source cut would break the Core build',
      });
    }
  }
}

// Invariant 2: a guard with no ee/ tree behind it is stale.
for (const f of guarded) {
  const svc = f.split('/')[1];
  if (!existsSync(join(servicesDir, svc, 'ee'))) {
    violations.push({
      file: f,
      reason: `carries a \`//go:build ee\` guard but services/${svc}/ee/ does not exist — stale guard`,
    });
  }
}

// Invariant 3: a carved service's COMMERCIAL images must actually select the
// Enterprise edition. Dockerfile.dist / Dockerfile.licensed build the images we
// ship and run; if they don't pass `-tags ee`, the release silently contains the
// Core build and paying customers lose the features they bought. This failure is
// invisible — the image builds, starts, and serves; the paid routes are just
// absent — so it has to be caught mechanically rather than by review.
for (const svc of existsSync(servicesDir) ? readdirSync(servicesDir) : []) {
  const svcPath = join(servicesDir, svc);
  if (!statSync(svcPath).isDirectory()) continue;
  if (!existsSync(join(svcPath, 'ee'))) continue; // not carved — nothing to select

  for (const variant of ['Dockerfile.dist', 'Dockerfile.licensed']) {
    const dockerfile = join(svcPath, variant);
    if (!existsSync(dockerfile)) continue; // e.g. pcap-processor has no .dist
    const src = readFileSync(dockerfile, 'utf8');
    const buildLines = src
      .split('\n')
      .filter((l) => /^RUN .*(go build|garble .*build)/.test(l));
    if (!buildLines.length) continue;
    if (!buildLines.some((l) => /-tags\s+"[^"]*\bee\b[^"]*"|-tags\s+ee\b/.test(l))) {
      violations.push({
        file: `services/${svc}/${variant}`,
        reason:
          'builds a carved service without `-tags ee` — this image would ship the ' +
          'Core edition, silently dropping the paid features it is supposed to contain',
      });
    }
  }
}

// Invariant 4: the Enterprise CONTENT boundary.
//
// Code is not the only thing the carve splits. The five regulated compliance
// frameworks are licensed CONTENT delivered as a signed SQL bundle. Two ways
// that boundary breaks silently:
//
//   * a regulated framework drifts back into scripts/database/seed.sql, which
//     publishes it in the open-source repo and hands it to every free install;
//   * a free framework drifts into the bundle, so a Core install quietly loses
//     a framework it is entitled to.
//
// Neither is visible in review of a 3,000-line seed file, so it is checked here.
const REGULATED_FRAMEWORKS = ['soc2', 'pci-dss', 'iso27001', 'nist-csf', 'iec-62351-3'];
const FREE_FRAMEWORKS = [
  'best-practices',
  'pqc-readiness',
  'cert-hygiene',
  'cert-expiry-not-expired',
  'cert-expiry-30-day',
  'cert-expiry-90-day',
];

const contentDir = join(servicesDir, 'compliance-engine', 'ee', 'content');
const bundlePath = join(contentDir, 'frameworks-regulated.sql');
const seedPath = join(repoRoot, 'scripts', 'database', 'seed.sql');

// Matches a framework code as a SQL string literal, so the prose comment left
// behind in seed.sql ("SOC 2 Type 2 ... are Enterprise content") does not trip
// the check while an actual INSERT does.
const sqlLiteral = (code) => `'${code}'`;

if (existsSync(seedPath)) {
  const seed = readFileSync(seedPath, 'utf8');
  for (const code of REGULATED_FRAMEWORKS) {
    if (seed.includes(sqlLiteral(code))) {
      violations.push({
        file: 'scripts/database/seed.sql',
        reason:
          `seeds regulated framework '${code}' — it is Enterprise content and belongs only in ` +
          'services/compliance-engine/ee/content/frameworks-regulated.sql',
      });
    }
  }
  for (const code of FREE_FRAMEWORKS) {
    if (!seed.includes(sqlLiteral(code))) {
      violations.push({
        file: 'scripts/database/seed.sql',
        reason: `no longer seeds free framework '${code}' — Core must ship all six free frameworks`,
      });
    }
  }
}

if (existsSync(bundlePath)) {
  const bundle = readFileSync(bundlePath, 'utf8');
  const rel = relative(repoRoot, bundlePath);

  for (const code of REGULATED_FRAMEWORKS) {
    if (!bundle.includes(sqlLiteral(code))) {
      violations.push({ file: rel, reason: `does not seed regulated framework '${code}'` });
    }
  }
  for (const code of FREE_FRAMEWORKS) {
    if (bundle.includes(sqlLiteral(code))) {
      violations.push({
        file: rel,
        reason: `seeds free framework '${code}' — it belongs in scripts/database/seed.sql, not the paid bundle`,
      });
    }
  }

  // The two checks above compare seed.sql against the bundle, which is the
  // obvious place for a regulated framework to drift back into Core. It is not
  // the only place. scripts/build-soc2-framework.sh sat in the public tree
  // carrying SOC 2 controls and measurements as SQL inserts — content sold in
  // the Enterprise bundle, shipped free, and invisible to a check that only
  // ever opened seed.sql.
  //
  // So: anything under scripts/ that seeds a regulated framework is a boundary
  // violation wherever it lives. Only the bundle itself may.
  const scriptsDir = join(repoRoot, 'scripts');
  const scriptFiles = [];
  const collect = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules') continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) collect(full);
      else if (/\.(sh|sql|mjs|js|ts)$/.test(e.name)) scriptFiles.push(full);
    }
  };
  if (existsSync(scriptsDir)) collect(scriptsDir);

  for (const file of scriptFiles) {
    const relFile = relative(repoRoot, file);
    // seed.sql is checked above, on its own terms.
    if (relFile === join('scripts', 'database', 'seed.sql')) continue;
    // A checker necessarily contains the thing it checks for: this file holds
    // every regulated framework code AND the literal 'INSERT INTO
    // platform_frameworks' in the regex just above, so it flags itself. Same
    // shape as a leak gate matching its own pattern list. Skip the checkers.
    if (/audit-edition-boundary\.mjs$|^scripts[\\/]test-/.test(relFile)) continue;
    let body;
    try {
      body = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    // "Authoring" a framework means creating one, by either route: SQL rows, or
    // POSTing to the frameworks API. build-soc2-framework.sh used the second —
    // it is a curl script, not a .sql file — which is exactly why a check
    // written only against INSERT statements would have missed it a second time.
    const writesSql = /INSERT INTO\s+platform_frameworks/i.test(body);
    const writesApi = /POST["'\s]+[^\n]*\/frameworks\b/i.test(body);
    if (!writesSql && !writesApi) continue;

    // Match on the framework's identity: the code as a SQL literal, or the
    // human name as it appears in an API payload. A script merely mentioning
    // "pci-dss" in a comment does not create anything and is not a violation.
    const NAMES = {
      soc2: /"SOC ?2\b/i,
      'pci-dss': /"PCI[ -]?DSS\b/i,
      iso27001: /"ISO ?27001\b/i,
      'nist-csf': /"NIST ?CSF\b/i,
      'iec-62351-3': /"IEC ?62351\b/i,
    };
    for (const code of REGULATED_FRAMEWORKS) {
      const named = body.includes(sqlLiteral(code)) || (NAMES[code] && NAMES[code].test(body));
      if (named) {
        violations.push({
          file: relFile,
          reason:
            `authors regulated framework '${code}' outside the signed content bundle — ` +
            `that content ships with Enterprise, so carrying it here gives it away`,
        });
      }
    }
  }

  // The bundle is applied under ON_ERROR_STOP=1 on every helm upgrade, so a
  // non-idempotent statement breaks upgrades for every Enterprise customer.
  const frameworkInserts = (bundle.match(/INSERT INTO platform_frameworks/g) || []).length;
  const frameworkUpserts = (bundle.match(/ON CONFLICT \(code, version\) DO UPDATE/g) || []).length;
  if (frameworkInserts !== frameworkUpserts) {
    violations.push({
      file: rel,
      reason:
        `${frameworkInserts} platform_frameworks INSERT(s) but ${frameworkUpserts} ` +
        '`ON CONFLICT (code, version) DO UPDATE` clause(s) — the seed Job re-applies this file ' +
        'on every helm upgrade, so each insert must upsert',
    });
  }
  const measurementInserts = (bundle.match(/INSERT INTO control_measurements/g) || []).length;
  const measurementGuards = (bundle.match(/NOT EXISTS \(SELECT 1 FROM control_measurements/g) || [])
    .length;
  if (measurementGuards < measurementInserts) {
    violations.push({
      file: rel,
      reason:
        `${measurementInserts} control_measurements INSERT(s) but only ${measurementGuards} ` +
        'NOT EXISTS guard(s) — control_measurements has no unique key, so ON CONFLICT is ' +
        'unavailable and every insert must be guarded or re-seeding duplicates rules',
    });
  }

  // The chart verifies the bundle against a copy of the entitlement public key.
  // If the copy drifts, verification fails in a customer's cluster.
  const keyGoPath = join(servicesDir, 'admin-service', 'ee', 'edition', 'key.go');
  const verifyKeyPath = join(contentDir, 'verify-key.pem');
  if (existsSync(keyGoPath) && existsSync(verifyKeyPath)) {
    const normalize = (s) => (s.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/) || [''])[0]
      .split(/\s+/)
      .join('\n');
    if (normalize(readFileSync(verifyKeyPath, 'utf8')) !== normalize(readFileSync(keyGoPath, 'utf8'))) {
      violations.push({
        file: relative(repoRoot, verifyKeyPath),
        reason:
          'does not match edition.ProductionKeyPEM in services/admin-service/ee/edition/key.go — ' +
          'the chart would verify the content bundle against the wrong key',
      });
    }
  }

  // The repo has a blanket `*.pem` ignore (correct — private keys must never be
  // committable). verify-key.pem is a PUBLIC key that has to ship, so it needs a
  // negation. Without it the file silently stays untracked, the release stages
  // nothing, and the failure surfaces as a release-time abort at best.
  for (const f of ['verify-key.pem', 'frameworks-regulated.sql', 'frameworks-regulated.sql.sig']) {
    const p = join(contentDir, f);
    if (!existsSync(p)) continue; // the .sig legitimately does not exist until signed
    try {
      // Exit 0 means "this path IS ignored"; exit 1 means it is not.
      execFileSync('git', ['check-ignore', '-q', p], { cwd: repoRoot, stdio: 'ignore' });
      violations.push({
        file: relative(repoRoot, p),
        reason:
          'is gitignored, so it cannot be committed and the release would package a chart without ' +
          'it — add a `!` negation in .gitignore (the blanket *.pem / secret rules catch it)',
      });
    } catch {
      /* not ignored — correct */
    }
  }

  // charts/ is NOT deleted by the repo cut (the globs are services/*/ee/ and
  // services/*/cmd/edition_ee.go), so a committed staged copy under the chart
  // would publish the licensed content. It must be gitignored.
  const gitignorePath = join(repoRoot, '.gitignore');
  const stagedDir = 'charts/vistaplatform/files/ee/';
  if (existsSync(gitignorePath) && !readFileSync(gitignorePath, 'utf8').includes(stagedDir)) {
    violations.push({
      file: '.gitignore',
      reason:
        `does not ignore ${stagedDir} — the staged content bundle would be committable, and ` +
        'charts/ survives the open-source repo cut, so it would leak licensed content',
    });
  }

  // The gate must default OFF: a Core install has to render unchanged.
  const chartValues = join(repoRoot, 'charts', 'vistaplatform', 'values.yaml');
  if (existsSync(chartValues)) {
    const values = readFileSync(chartValues, 'utf8');
    if (!/contentBundle:\s*\n\s*enabled:\s*false/.test(values)) {
      violations.push({
        file: 'charts/vistaplatform/values.yaml',
        reason:
          'enterprise.contentBundle.enabled is not defaulted to false — a Core install must not ' +
          'reference the Enterprise content bundle at all',
      });
    }
  }

  // And the seed Job must both gate on the flag and verify before applying.
  const seedJob = join(repoRoot, 'charts', 'vistaplatform', 'templates', 'jobs', 'seed-data.yaml');
  if (existsSync(seedJob)) {
    const job = readFileSync(seedJob, 'utf8');
    if (!job.includes('.Values.enterprise.contentBundle.enabled')) {
      violations.push({
        file: 'charts/vistaplatform/templates/jobs/seed-data.yaml',
        reason: 'does not gate the content bundle on .Values.enterprise.contentBundle.enabled',
      });
    }
    if (!job.includes('openssl dgst -sha256 -verify')) {
      violations.push({
        file: 'charts/vistaplatform/templates/jobs/seed-data.yaml',
        reason:
          'applies the content bundle without verifying its detached signature — an unverified ' +
          'bundle is arbitrary SQL executed as the database owner',
      });
    }
  }
}

const label = strict ? 'ERROR' : 'WARN';
if (violations.length) {
  console.error(`\n[31m✗ edition-boundary audit: ${violations.length} violation(s)[0m`);
  for (const v of violations) console.error(`  ${label}  ${v.file}\n        ${v.reason}`);
  if (strict) process.exit(1);
} else {
  const services = new Set(guarded.map((f) => f.split('/')[1]));
  const bundleState = existsSync(bundlePath)
    ? 'content bundle: 5 regulated frameworks carved out of the Core seed'
    : 'content bundle: absent (Core checkout)';
  console.log(
    `[32m✓ edition-boundary ok[0m (${guarded.length} guarded wiring file(s) across ` +
      `${services.size} service(s); Core builds without ee/; ${bundleState})`,
  );
}
