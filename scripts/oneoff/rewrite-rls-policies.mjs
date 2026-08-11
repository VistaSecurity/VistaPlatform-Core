#!/usr/bin/env node
/**
 * One-shot rewriter for Core-audit item W2-2: make every tenant-isolation RLS
 * policy predicate INDEXABLE.
 *
 * The old shape casts the COLUMN to text:
 *
 *     USING ((tenant_id)::text = current_setting('app.tenant_id', true))
 *
 * `(tenant_id)::text` is a function of the column, so no btree index on
 * tenant_id (or on any composite leading with it) can ever be used, and every
 * candidate row pays a uuid_out() call plus a current_setting() lookup. The
 * planner is forced into a seq scan on every policy-guarded table.
 *
 * The new shape casts the SETTING instead, so the comparison is
 * `uuid = uuid` against an indexable column reference:
 *
 *     USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 *
 * NULLIF is what makes the cast safe: `current_setting(..., true)` returns NULL
 * when the GUC was never set but '' when it was SET and then reset to empty,
 * and ''::uuid raises 22P02. NULLIF collapses both to NULL, and `tenant_id =
 * NULL` is NULL → the row is not visible. That "invisible, not an error"
 * behaviour is exactly what the old ::text form gave, which is why it was
 * chosen; NULLIF preserves it while staying indexable.
 *
 * Rewrites are applied ONLY inside CREATE POLICY statements. Everything else in
 * the file is untouched. Run from the repo root:
 *
 *     node scripts/oneoff/rewrite-rls-policies.mjs
 *
 * The script is idempotent: re-running it over an already-rewritten schema is a
 * no-op (it reports 0 rewrites).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = 'scripts/database/schema.sql';
const MIRROR = 'charts/vistaplatform/files/schema/schema.sql';

const NEW_PRED = (prefix) =>
  `${prefix}tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`;

// (a) the unindexable column-cast form, both the pg_dump rendering
//     (current_setting('app.tenant_id'::text, true)) and the hand-written one.
//     Optional table alias prefix covers the parent-join EXISTS policies
//     (e.g. `(s.tenant_id)::text = ...`).
const RE_COLUMN_CAST =
  /\((?<prefix>[a-z_]+\.)?tenant_id\)::text = current_setting\('app\.tenant_id'(?:::text)?, true\)/g;

// (b) the already-indexable-but-unguarded form (6 notification-family policies
//     in the pg_dump body). Indexable already; the rewrite only adds the NULLIF
//     guard so an empty GUC cannot raise 22P02. Same target text as (a), so the
//     file ends up spelling the predicate exactly one way.
const RE_UNGUARDED_UUID =
  /(?<prefix>[a-z_]+\.)?tenant_id = \(current_setting\('app\.tenant_id'(?:::text)?, true\)\)::uuid/g;

/** Extract [start,end) spans of every CREATE POLICY statement. */
export function policySpans(sql) {
  const re = /^[ \t]*CREATE POLICY[\s\S]*?;\s*$/gm;
  const spans = [];
  let m;
  while ((m = re.exec(sql))) spans.push([m.index, m.index + m[0].length]);
  return spans;
}

export function rewrite(sql) {
  const spans = policySpans(sql);
  let out = '';
  let cursor = 0;
  let counts = { columnCast: 0, unguardedUuid: 0, policies: 0 };

  for (const [start, end] of spans) {
    out += sql.slice(cursor, start);
    let stmt = sql.slice(start, end);
    const before = stmt;
    stmt = stmt.replace(RE_COLUMN_CAST, (_, prefix) => {
      counts.columnCast++;
      return NEW_PRED(prefix ?? '');
    });
    stmt = stmt.replace(RE_UNGUARDED_UUID, (_, prefix) => {
      counts.unguardedUuid++;
      return NEW_PRED(prefix ?? '');
    });
    if (stmt !== before) counts.policies++;
    out += stmt;
    cursor = end;
  }
  out += sql.slice(cursor);
  return { sql: out, counts, totalPolicies: spans.length };
}

/**
 * Policies that reach an EXISTING database only through the pg_dump body's
 * `DO $$ ... EXCEPTION WHEN duplicate_object THEN NULL` wrapper, or through the
 * same wrapper in POST-MIGRATIONS, and are NOT re-created by a
 * `DROP POLICY IF EXISTS ... ; CREATE POLICY ...` pair later in the file.
 *
 * For those, editing the CREATE text is inert on an existing deployment — the
 * CREATE raises duplicate_object and the exception handler swallows it, leaving
 * the OLD policy in place. They need an explicit ALTER POLICY.
 *
 * Computed rather than hand-listed so the set cannot silently go stale.
 */
export function policiesNeedingAlter(sql) {
  const created = [];
  const re = /^[ \t]*CREATE POLICY[\s\S]*?;\s*$/gm;
  let m;
  while ((m = re.exec(sql))) {
    const nm = m[0].match(/CREATE POLICY (\S+) ON (\S+)/);
    // Skip the dynamic `format('CREATE POLICY %I ON %s ...')` loop: it issues
    // its own DROP POLICY IF EXISTS per table, so it already converges.
    if (!nm || nm[1].includes('%') || nm[2].includes('%')) continue;
    created.push({ name: nm[1], table: nm[2], stmt: m[0] });
  }
  const dropped = new Set();
  for (const d of sql.matchAll(/DROP POLICY IF EXISTS (\S+) ON (\S+);/g)) {
    dropped.add(`${d[1]}|${d[2]}`);
  }
  return created.filter(
    (c) =>
      !dropped.has(`${c.name}|${c.table}`) &&
      /NULLIF\(current_setting\('app\.tenant_id', true\), ''\)::uuid/.test(c.stmt),
  );
}

/** Pull the USING / WITH CHECK expressions back out of a CREATE POLICY. */
export function splitClauses(stmt) {
  const grab = (kw) => {
    const i = stmt.indexOf(kw);
    if (i === -1) return null;
    let j = stmt.indexOf('(', i);
    if (j === -1) return null;
    let depth = 0;
    for (let k = j; k < stmt.length; k++) {
      if (stmt[k] === '(') depth++;
      else if (stmt[k] === ')') {
        depth--;
        if (depth === 0) return stmt.slice(j, k + 1).replace(/\s+/g, ' ');
      }
    }
    return null;
  };
  // "WITH CHECK" must be located before "USING" is searched naively, because
  // USING appears first in every policy we generate.
  return { using: grab('USING '), check: grab('WITH CHECK ') };
}

export function buildAlterBlock(alters) {
  const lines = [];
  lines.push('');
  lines.push('-- ============================================================================');
  lines.push('-- W2-2 CONVERGENCE: ALTER the tenant-isolation policies that the DO/EXCEPTION');
  lines.push('-- wrapper would otherwise leave on the OLD, unindexable predicate.');
  lines.push('--');
  lines.push('-- Most tenant-isolation policies are re-issued by the RLS HARDENING block above');
  lines.push('-- as `DROP POLICY IF EXISTS` + `CREATE POLICY`, which DOES converge an existing');
  lines.push('-- database. The handful below are created only inside');
  lines.push('-- `DO $$ ... EXCEPTION WHEN duplicate_object THEN NULL $$` wrappers: on a');
  lines.push('-- database that already has the policy, the CREATE raises duplicate_object, the');
  lines.push('-- handler swallows it, and the pre-existing (old-shape) policy survives. Editing');
  lines.push('-- the CREATE text alone therefore only fixes FRESH installs.');
  lines.push('--');
  lines.push('-- ALTER POLICY replaces the expression outright, so re-running it is a no-op in');
  lines.push('-- effect. Guarded on to_regclass + pg_policy so a partial schema cannot error.');
  lines.push('--');
  lines.push('-- DEPLOY NOTE: ALTER POLICY takes a brief ACCESS EXCLUSIVE lock on the table.');
  lines.push('-- It is a catalog-only change (no rewrite, no scan) and completes in');
  lines.push('-- milliseconds, but it will queue behind a long-running transaction on the same');
  lines.push('-- table and block new queries while it waits.');
  lines.push('-- ============================================================================');
  for (const a of alters) {
    const { using, check } = splitClauses(a.stmt);
    lines.push('DO $$');
    lines.push('BEGIN');
    lines.push(`    IF to_regclass('${a.table}') IS NOT NULL`);
    lines.push('       AND EXISTS (SELECT 1 FROM pg_policy');
    lines.push(`                    WHERE polname = '${a.name}'`);
    lines.push(`                      AND polrelid = to_regclass('${a.table}')) THEN`);
    lines.push(`        ALTER POLICY ${a.name} ON ${a.table}`);
    lines.push(`            USING ${using}${check ? '' : ';'}`);
    if (check) lines.push(`            WITH CHECK ${check};`);
    lines.push('    END IF;');
    lines.push('END $$;');
  }
  return lines.join('\n') + '\n';
}

export const VERIFY_BLOCK = `
-- ============================================================================
-- W2-2 SELF-CHECK: no tenant-isolation policy may survive on the old,
-- unindexable \`(tenant_id)::text = current_setting(...)\` predicate.
--
-- This is deliberately a WARNING and not an exception: a stray old-shape policy
-- is a performance regression, not a correctness or isolation failure, and
-- failing the schema-migration Job over one would take a customer's upgrade
-- down for a reason that does not warrant it. The message names every offender
-- so it is actionable from the Job log.
--
-- Mutation-tested: reverting a single policy to the old predicate makes this
-- block emit the WARNING naming exactly that policy.
-- ============================================================================
DO $$
DECLARE
    stale text;
BEGIN
    SELECT string_agg(format('%s ON %s', p.polname, c.oid::regclass), ', ' ORDER BY p.polname)
      INTO stale
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
     WHERE pg_get_expr(p.polqual, p.polrelid) LIKE '%tenant_id)::text = current_setting%'
        OR pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%tenant_id)::text = current_setting%';

    IF stale IS NOT NULL THEN
        RAISE WARNING 'W2-2: % RLS policies still use the unindexable (tenant_id)::text predicate: %',
            array_length(string_to_array(stale, ', '), 1), stale;
    END IF;
END $$;
`;

const hasConvergenceBlock = (sql) => sql.includes('-- W2-2 CONVERGENCE:');
const hasSelfCheckBlock = (sql) => sql.includes('-- W2-2 SELF-CHECK:');

export function rewriteSchema(sql) {
  const { sql: rewritten, counts, totalPolicies } = rewrite(sql);

  const alters = policiesNeedingAlter(rewritten);
  let final = rewritten;
  if (!final.endsWith('\n')) final += '\n';
  if (!hasConvergenceBlock(final)) final += buildAlterBlock(alters);
  if (!hasSelfCheckBlock(final)) final += VERIFY_BLOCK;

  return { sql: final, counts, totalPolicies, alters };
}

export function rewriteFiles({ schemaPath = SCHEMA, mirrorPath = MIRROR } = {}) {
  const original = fs.readFileSync(schemaPath, 'utf8');
  const result = rewriteSchema(original);

  fs.writeFileSync(schemaPath, result.sql);
  fs.writeFileSync(mirrorPath, result.sql);

  return result;
}

function main() {
  const { counts, totalPolicies, alters } = rewriteFiles();

  console.log(`CREATE POLICY statements scanned : ${totalPolicies}`);
  console.log(`  policies rewritten             : ${counts.policies}`);
  console.log(`  (a) column-cast predicates     : ${counts.columnCast}`);
  console.log(`  (b) unguarded ::uuid predicates: ${counts.unguardedUuid}`);
  console.log(`ALTER POLICY convergence stmts   : ${alters.length}`);
  for (const a of alters) console.log(`    ${a.name} ON ${a.table}`);
  console.log(`wrote ${SCHEMA} and ${MIRROR}`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  main();
}
