#!/usr/bin/env node
/**
 * Chart schema mirror audit.
 *
 * The Helm chart's schema-migration Job runs charts/vistaplatform/files/schema/
 * schema.sql — NOT scripts/database/schema.sql. The chart copy is supposed to
 * be a byte-identical mirror of the scripts/ original, refreshed whenever the
 * schema changes. There is no build step keeping them in sync; humans (and
 * agents) do, and forget.
 *
 * That already burned us once: the cbom_artifacts inline_content jsonb→text
 * migration landed in scripts/ but never reached the chart copy, so no
 * helm-deployed cluster ever ran it and the CBOM verify-hash bug stayed live in
 * production while the repo said it was fixed. ~56 lines of drift, invisible to
 * every existing check.
 *
 * The rule this enforces: the two schema.sql files are byte-identical. Fix
 * drift by editing scripts/database/schema.sql (the manually maintained
 * source) and copying it over:
 *
 *   cp scripts/database/schema.sql charts/vistaplatform/files/schema/schema.sql
 *
 * seed.sql is deliberately NOT checked: the chart copy of seed.sql is not
 * committed — release-customer.yml copies it from scripts/database/ at package
 * time, and a dev may legitimately copy it in locally for a worktree install.
 *
 *   node scripts/audit-schema-mirror.mjs [--strict]
 *
 * Mutation-test it: append a line to the chart copy and check it fails; also
 * delete the chart copy and check it fails (a missing mirror is drift too).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

const SOURCE = path.join(ROOT, 'scripts/database/schema.sql');
const MIRROR = path.join(ROOT, 'charts/vistaplatform/files/schema/schema.sql');

const problems = [];

if (!fs.existsSync(SOURCE)) {
  problems.push(`source missing: ${path.relative(ROOT, SOURCE)}`);
} else if (!fs.existsSync(MIRROR)) {
  problems.push(`chart mirror missing: ${path.relative(ROOT, MIRROR)}`);
} else {
  const source = fs.readFileSync(SOURCE);
  const mirror = fs.readFileSync(MIRROR);
  if (!source.equals(mirror)) {
    // Point at the first diverging line so the failure is diagnosable without
    // re-running diff by hand.
    const srcLines = source.toString('utf8').split('\n');
    const mirLines = mirror.toString('utf8').split('\n');
    let line = 0;
    while (line < srcLines.length && line < mirLines.length && srcLines[line] === mirLines[line]) line++;
    problems.push(
      `chart schema mirror has drifted from scripts/database/schema.sql ` +
        `(first difference at line ${line + 1}; ` +
        `${srcLines.length} vs ${mirLines.length} lines). ` +
        `The schema-migration Job runs the CHART copy, so drift here means ` +
        `deployed clusters never see the missing statements.`
    );
  }
}

if (problems.length === 0) {
  console.log('✅ schema mirror: chart copy is byte-identical to scripts/database/schema.sql');
  process.exit(0);
}

for (const p of problems) {
  console.error(`${STRICT ? '❌' : '⚠️'} schema mirror: ${p}`);
}
console.error(
  '\nFix: edit scripts/database/schema.sql (the source), then\n' +
    '  cp scripts/database/schema.sql charts/vistaplatform/files/schema/schema.sql'
);
process.exit(STRICT ? 1 : 0);
