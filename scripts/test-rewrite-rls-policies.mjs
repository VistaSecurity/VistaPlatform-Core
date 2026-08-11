#!/usr/bin/env node
// Regression tests for the RLS policy predicate rewriter added during the
// Core audit W2-2 performance hardening.

import assert from 'node:assert/strict';

import {
  buildAlterBlock,
  policiesNeedingAlter,
  rewrite,
  rewriteSchema,
  splitClauses,
} from './oneoff/rewrite-rls-policies.mjs';

const oldPredicate = "(tenant_id)::text = current_setting('app.tenant_id', true)";
const sampleSql = `
-- Outside CREATE POLICY, the old predicate text is documentation and must stay:
-- ${oldPredicate}
SELECT '${oldPredicate}' AS example_text;

DO $$ BEGIN
  CREATE POLICY tenant_visible ON public.assets
    USING ((tenant_id)::text = current_setting('app.tenant_id'::text, true))
    WITH CHECK ((tenant_id)::text = current_setting('app.tenant_id', true));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE POLICY parent_visible ON public.child_assets
    USING (EXISTS (
      SELECT 1 FROM public.scopes s
       WHERE (s.tenant_id)::text = current_setting('app.tenant_id', true)
    ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE POLICY unguarded_uuid ON public.notification_rules
    USING (tenant_id = (current_setting('app.tenant_id'::text, true))::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE POLICY recreated_policy ON public.recreated
    USING ((tenant_id)::text = current_setting('app.tenant_id', true));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DROP POLICY IF EXISTS recreated_policy ON public.recreated;
CREATE POLICY recreated_policy ON public.recreated
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

EXECUTE format('CREATE POLICY %I ON %s USING ((tenant_id)::text = current_setting(''app.tenant_id'', true))', policy_name, table_name);
`;

function assertIncludes(haystack, needle, message) {
  assert.ok(haystack.includes(needle), message);
}

function count(value, needle) {
  return value.split(needle).length - 1;
}

const { sql: rewritten, counts, totalPolicies } = rewrite(sampleSql);

assert.equal(totalPolicies, 5, 'only real line-start CREATE POLICY statements are scanned');
assert.deepEqual(
  counts,
  { columnCast: 4, unguardedUuid: 1, policies: 4 },
  'column-cast and unguarded uuid predicates are counted separately',
);
assertIncludes(
  rewritten,
  "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid",
  'tenant_id comparisons cast the GUC, not the indexed column',
);
assertIncludes(
  rewritten,
  "s.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid",
  'aliased parent-join predicates preserve the table alias',
);
assert.equal(
  count(rewritten, oldPredicate),
  2,
  'documentation and string literals outside real CREATE POLICY statements are left untouched',
);
assertIncludes(
  rewritten,
  "CREATE POLICY %I ON %s USING ((tenant_id)::text = current_setting(''app.tenant_id'', true))",
  'dynamic SQL outside real CREATE POLICY statements is left untouched',
);

const alters = policiesNeedingAlter(rewritten);
assert.deepEqual(
  alters.map((a) => `${a.name} ON ${a.table}`),
  [
    'tenant_visible ON public.assets',
    'parent_visible ON public.child_assets',
    'unguarded_uuid ON public.notification_rules',
  ],
  'existing-database ALTER POLICY convergence skips policies already dropped and recreated',
);

const tenantClauses = splitClauses(alters[0].stmt);
assert.equal(
  tenantClauses.using,
  "(tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)",
  'USING clause extraction preserves the rewritten predicate',
);
assert.equal(
  tenantClauses.check,
  "(tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)",
  'WITH CHECK clause extraction preserves the rewritten predicate',
);

const alterBlock = buildAlterBlock([alters[0]]);
assertIncludes(alterBlock, 'ALTER POLICY tenant_visible ON public.assets', 'ALTER block targets the policy');
assertIncludes(
  alterBlock,
  "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)",
  'ALTER block carries the USING clause',
);
assertIncludes(
  alterBlock,
  "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);",
  'ALTER block carries the WITH CHECK clause',
);

const firstPass = rewriteSchema(sampleSql);
const secondPass = rewriteSchema(firstPass.sql);
assert.equal(secondPass.sql, firstPass.sql, 'full schema rewrite is idempotent');
assert.deepEqual(
  secondPass.counts,
  { columnCast: 0, unguardedUuid: 0, policies: 0 },
  'second pass reports no additional predicate rewrites',
);
assert.equal(count(firstPass.sql, '-- W2-2 CONVERGENCE:'), 1, 'convergence block is appended once');
assert.equal(count(firstPass.sql, '-- W2-2 SELF-CHECK:'), 1, 'self-check block is appended once');

console.log('ok - RLS policy rewrite guards column-cast regressions and remains idempotent');
