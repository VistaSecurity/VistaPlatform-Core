#!/usr/bin/env node
/**
 * Schema grant-order audit.
 *
 * `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO
 * crypto_app, crypto_bypass` is NOT a standing rule. Postgres expands `ON ALL
 * TABLES` once, at execution time, over the tables that exist at that instant.
 * Any table created later in the same file gets no privileges at all.
 *
 * That bug shipped: the blanket GRANT sat in the middle of
 * scripts/database/schema.sql, and nine tables defined below it (alerts,
 * alert_events, alert_framework_score_snapshots, legal_acceptances,
 * legal_documents, notification_digest_queue, platform_in_app_notifications,
 * platform_maintenance_windows, tenant_alert_settings) had zero privileges for
 * crypto_app after a FRESH SINGLE APPLY. serviceRls defaults to ON, so services
 * connect as the NOBYPASSRLS crypto_app role, and the chart's schema-migration
 * Job applies the file exactly ONCE on install — so a brand-new install
 * answered `permission denied for table alerts` across Remediation → Alerts,
 * the notification digest queue, the platform operator inbox, and the
 * ToS/Privacy acceptance write on the signup path.
 *
 * It survived for so long precisely because applying the schema TWICE hides it:
 * on the second pass the tables already exist when the GRANT runs. Neither the
 * double-apply pre-flight nor `ALTER DEFAULT PRIVILEGES FOR ROLE crypto_user`
 * (which only covers objects that role creates, and only after it runs) can
 * catch it.
 *
 * The rule this enforces: the blanket grants are the LAST thing in the file, so
 * a newly appended CREATE TABLE is above them by construction. Concretely — no
 * table-creating statement may appear after the ROLE GRANTS marker.
 *
 *   node scripts/audit-schema-grant-order.mjs [--strict]
 *
 * Mutation-test it (both polarities, per CLAUDE.md):
 *   1. Append `CREATE TABLE IF NOT EXISTS public.zzz_probe (id int);` to
 *      scripts/database/schema.sql -> must FAIL.
 *   2. Delete the blanket GRANT lines entirely -> must FAIL (missing grants).
 *   3. Restore -> must PASS.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

// Both copies are checked: the chart mirror is what deployed clusters actually
// run. audit-schema-mirror.mjs already pins them byte-identical, but if that
// check is ever relaxed this one must not go blind.
const FILES = [
  'scripts/database/schema.sql',
  'charts/vistaplatform/files/schema/schema.sql',
];

// The blanket grants whose position is the whole point.
const BLANKET_GRANT = /^\s*GRANT\b.*\bON\s+ALL\s+(TABLES|SEQUENCES)\s+IN\s+SCHEMA\s+(public|audit)\b/i;

// Statements that bring a new relation into existence and therefore need to be
// covered by the blanket grant. Views and matviews count: the grant covers them
// too, and a view created after it is just as unreachable.
const CREATES_RELATION =
  /^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?(?:MATERIALIZED\s+VIEW|TABLE|VIEW|SEQUENCE)\b/i;

const problems = [];

for (const rel of FILES) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) {
    problems.push(`${rel}: missing`);
    continue;
  }
  const lines = fs.readFileSync(abs, 'utf8').split('\n');

  // Strip whole-line comments so a CREATE TABLE quoted inside an explanatory
  // comment (there are several) does not trip the check. Statements inside
  // DO $$ ... $$ blocks are string-quoted DDL executed via EXECUTE format(...)
  // and are not matched by the anchored regexes either.
  const isComment = (l) => /^\s*--/.test(l);

  const grantLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (isComment(lines[i])) continue;
    if (BLANKET_GRANT.test(lines[i])) grantLines.push(i);
  }

  if (grantLines.length === 0) {
    problems.push(
      `${rel}: no blanket "GRANT ... ON ALL TABLES/SEQUENCES IN SCHEMA ..." found at all. ` +
        `Without it crypto_app has no privileges on anything and every service query fails.`
    );
    continue;
  }

  // Expect all four (tables+sequences × public+audit). A partial set means
  // someone deleted one and the corresponding objects are unreachable.
  const seen = new Set(
    grantLines.map((i) => {
      const m = lines[i].match(BLANKET_GRANT);
      return `${m[1].toUpperCase()}:${m[2].toLowerCase()}`;
    })
  );
  for (const want of ['TABLES:public', 'TABLES:audit', 'SEQUENCES:public', 'SEQUENCES:audit']) {
    if (!seen.has(want)) {
      problems.push(`${rel}: missing blanket GRANT ON ALL ${want.split(':')[0]} IN SCHEMA ${want.split(':')[1]}`);
    }
  }

  const firstGrant = grantLines[0];
  const offenders = [];
  for (let i = firstGrant + 1; i < lines.length; i++) {
    if (isComment(lines[i])) continue;
    if (CREATES_RELATION.test(lines[i])) {
      offenders.push(`${rel}:${i + 1}: ${lines[i].trim().slice(0, 100)}`);
    }
  }

  if (offenders.length > 0) {
    problems.push(
      `${rel}: ${offenders.length} relation-creating statement(s) appear AFTER the blanket ` +
        `GRANT on line ${firstGrant + 1}. "ON ALL TABLES" is expanded once, so these get NO ` +
        `privileges for crypto_app on a fresh single apply (the chart applies this file once ` +
        `on install). Move them above the ROLE GRANTS block at the end of the file:\n` +
        offenders.map((o) => `    ${o}`).join('\n')
    );
  }
}

if (problems.length === 0) {
  console.log('✅ schema grant order: blanket role grants come after every relation-creating statement');
  process.exit(0);
}

for (const p of problems) {
  console.error(`${STRICT ? '❌' : '⚠️'} schema grant order: ${p}`);
}
console.error(
  '\nFix: keep the "ROLE GRANTS" block the LAST thing in scripts/database/schema.sql,\n' +
    'then mirror it: cp scripts/database/schema.sql charts/vistaplatform/files/schema/schema.sql'
);
process.exit(STRICT ? 1 : 0);
