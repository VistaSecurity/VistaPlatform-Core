// Guard for BUILD_PLAN row 0.6: the DCIM-programme permissions exist in every
// generated mirror and are granted to exactly the roles ADR-0010 D10 names.
// Run: node --test scripts/audit-dcim-permissions.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ROLE_GRANTS } from './lib/role-grants.gen.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

const FAMILIES = ['dcim', 'ipam', 'circuits', 'virtualization', 'vpn', 'wireless'];
const ALL = [
  ...FAMILIES.flatMap((f) => [`${f}.read`, `${f}.manage`]),
  'business_units.manage',
  'custom_fields.manage',
];
const row = (name) => {
  const [resource, action] = name.split('.');
  return { name, resource, action };
};
const holds = (role, name) =>
  ROLE_GRANTS.find((r) => r.role === role).grants(row(name));

test('every DCIM permission is in the seed catalogue and the TS constants', () => {
  const seed = read('scripts/database/seed.sql');
  const ts = read('packages/primitives/src/rbac/constants.ts');
  for (const n of ALL) {
    assert.ok(seed.includes(`'${n}'`), `${n} missing from seed.sql`);
    assert.ok(ts.includes(`'${n}'`), `${n} missing from constants.ts`);
  }
});

test('grant matrix: tenant_admin and security_admin hold read+manage, viewer holds read only', () => {
  for (const f of FAMILIES) {
    for (const role of ['tenant_admin', 'security_admin']) {
      assert.ok(holds(role, `${f}.read`), `${role} lacks ${f}.read`);
      assert.ok(holds(role, `${f}.manage`), `${role} lacks ${f}.manage`);
    }
    assert.ok(holds('viewer', `${f}.read`), `viewer lacks ${f}.read`);
    assert.ok(!holds('viewer', `${f}.manage`), `viewer must not hold ${f}.manage`);
    assert.ok(!holds('billing_admin', `${f}.read`), `billing_admin must not hold ${f}.read`);
  }
});

test('business_units.manage and custom_fields.manage are tenant_admin only', () => {
  for (const n of ['business_units.manage', 'custom_fields.manage']) {
    assert.ok(holds('tenant_admin', n), `tenant_admin lacks ${n}`);
    for (const role of ['security_admin', 'viewer', 'billing_admin', 'api_user']) {
      assert.ok(!holds(role, n), `${role} must not hold ${n}`);
    }
  }
});
