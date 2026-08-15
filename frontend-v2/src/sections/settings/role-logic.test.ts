import { describe, it, expect } from 'vitest';
import {
  permissionLock, isLocked, lockReason, groupByResource, grantedIds,
  permissionIdsToSubmit, isDirty, roleErrorCode, roleErrorMessage, roleErrorUserCount,
  roleErrorMissingPermissions, nextDeleteStep, reassignTargets, slugifyRoleName, isValidRoleName,
  RoleApiError, type MatrixRow, type TenantRole,
} from './role-logic';

// Two independent locks govern the Roles & Permissions matrix, and every test
// below exists because conflating them produces a specific user-visible bug:
//   * role-level `editable` false → built-in role, whole matrix read-only. The
//     seed re-applies its grants on every helm upgrade, so an accepted edit
//     would be silently reverted; the server answers 403 system_role_immutable.
//   * per-permission `grantable` false → the CALLING user doesn't hold it, so
//     they may neither add nor drop it. `granted && !grantable` is legitimate.

const row = (over: Partial<MatrixRow> & { id: string; name: string }): MatrixRow => ({
  description: '', resource: over.name.split('.')[0], action: over.name.split('.')[1] ?? 'read',
  granted: false, grantable: true, ...over,
});

const role = (over: Partial<TenantRole> & { id: string }): TenantRole => ({
  name: 'custom', display_name: 'Custom', description: '', is_system_role: false,
  permission_count: 0, user_count: 0, permissions: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', ...over,
});

describe('permissionLock — the system-role lock', () => {
  it('locks EVERY row of a built-in role, whatever grantable says', () => {
    // The whole matrix is read-only, not just the rows the caller can't grant.
    expect(permissionLock({ grantable: true }, false)).toBe('system');
    expect(permissionLock({ grantable: false }, false)).toBe('system');
  });

  it('leaves a custom role editable where the caller holds the permission', () => {
    expect(permissionLock({ grantable: true }, true)).toBe('editable');
  });

  it('is the ONLY lock that survives a grantable row on a built-in role', () => {
    // Mutation guard: if `editable` were dropped from the check, this row would
    // read 'editable' and the drawer would offer a doomed checkbox.
    expect(isLocked(permissionLock({ grantable: true }, false))).toBe(true);
  });
});

describe('permissionLock — the grantable lock', () => {
  it('locks a permission the caller does not hold, granted or not', () => {
    expect(permissionLock({ grantable: false }, true)).toBe('not-held');
  });

  it('distinguishes the checked-but-locked state from the disabled-empty one', () => {
    // Same lock, different copy — one is "you may keep it", the other "you may
    // not add it". Both must be explained rather than silently disabled.
    expect(lockReason('not-held', true)).toMatch(/keeps it/);
    expect(lockReason('not-held', false)).toMatch(/don't hold/);
  });

  it('explains the built-in lock in terms of the platform reverting the edit', () => {
    expect(lockReason('system', true)).toMatch(/re-applies/);
  });

  it('gives an editable row no lock explanation', () => {
    expect(lockReason('editable', true)).toBeUndefined();
    expect(lockReason('editable', false)).toBeUndefined();
  });
});

describe('permissionIdsToSubmit — locked grants survive a REPLACE', () => {
  const rows = [
    row({ id: 'a', name: 'assets.read', granted: true, grantable: true }),
    row({ id: 'b', name: 'billing.update', granted: true, grantable: false }), // keepable, not addable
    row({ id: 'c', name: 'users.manage', granted: false, grantable: false }),  // disabled + empty
    row({ id: 'd', name: 'assets.update', granted: false, grantable: true }),
  ];

  it('carries a locked-but-granted permission through unchanged', () => {
    // PUT replaces the set. Dropping `b` because the checkbox is disabled would
    // silently strip a permission the caller was never allowed to touch.
    expect(permissionIdsToSubmit(rows, new Set(['a']), true)).toEqual(['a', 'b']);
  });

  it('never smuggles in a permission the caller does not hold', () => {
    // Even if `selected` somehow contains `c`, it isn't grantable — the server
    // would 403 permission_not_held, so the UI must not send it.
    expect(permissionIdsToSubmit(rows, new Set(['a', 'c']), true)).toEqual(['a', 'b']);
  });

  it('adds a newly-checked grantable permission', () => {
    expect(permissionIdsToSubmit(rows, new Set(['a', 'd']), true)).toEqual(['a', 'b', 'd']);
  });

  it('allows clearing every unlocked grant', () => {
    expect(permissionIdsToSubmit(rows, new Set(), true)).toEqual(['b']);
  });

  it('reproduces the current set exactly for a built-in role', () => {
    // Nothing is editable, so whatever the selection state, the submitted set is
    // the role's own — the drawer has no Save button here anyway.
    expect(permissionIdsToSubmit(rows, new Set(['d']), false)).toEqual(['a', 'b']);
  });
});

describe('isDirty', () => {
  const rows = [
    row({ id: 'a', name: 'assets.read', granted: true }),
    row({ id: 'b', name: 'assets.update', granted: false }),
  ];

  it('is clean at the granted set', () => {
    expect(isDirty(rows, grantedIds(rows), true)).toBe(false);
  });

  it('sees an addition', () => {
    expect(isDirty(rows, new Set(['a', 'b']), true)).toBe(true);
  });

  it('sees a removal', () => {
    expect(isDirty(rows, new Set(), true)).toBe(true);
  });

  it('sees a swap of equal size', () => {
    expect(isDirty(rows, new Set(['b']), true)).toBe(true);
  });

  it('can never be dirty on a built-in role', () => {
    expect(isDirty(rows, new Set(['b']), false)).toBe(false);
  });
});

describe('groupByResource', () => {
  it('groups without re-sorting — the API already orders by resource then action', () => {
    const rows = [
      row({ id: '1', name: 'assets.read' }), row({ id: '2', name: 'assets.update' }),
      row({ id: '3', name: 'billing.read' }),
    ];
    expect(groupByResource(rows).map((g) => [g.resource, g.rows.length])).toEqual([['assets', 2], ['billing', 1]]);
  });

  it('buckets a resource-less row rather than dropping it', () => {
    expect(groupByResource([row({ id: '1', name: 'weird', resource: '' })])[0].resource).toBe('other');
  });
});

describe('role error codes — branch on code, never the message', () => {
  it('reads the stable discriminator', () => {
    expect(roleErrorCode({ error: 'anything at all', code: 'role_in_use' })).toBe('role_in_use');
  });

  it('returns undefined for a body without one', () => {
    expect(roleErrorCode({ error: 'boom' })).toBeUndefined();
    expect(roleErrorCode(undefined)).toBeUndefined();
    expect(roleErrorCode(new Error('network'))).toBeUndefined();
  });

  it('prefers the server message, then an Error, then the fallback', () => {
    expect(roleErrorMessage({ error: 'from server' }, 'fb')).toBe('from server');
    expect(roleErrorMessage(new Error('thrown'), 'fb')).toBe('thrown');
    expect(roleErrorMessage(null, 'fb')).toBe('fb');
  });

  it('reads the holder count off role_in_use and the missing set off permission_not_held', () => {
    expect(roleErrorUserCount({ code: 'role_in_use', user_count: 3 })).toBe(3);
    expect(roleErrorUserCount({ code: 'role_in_use', user_count: 0 })).toBe(0); // 0 is an answer, not absence
    expect(roleErrorUserCount({ code: 'role_not_found' })).toBeUndefined();
    expect(roleErrorMissingPermissions({ code: 'permission_not_held', missing_permissions: ['billing.update'] }))
      .toEqual(['billing.update']);
    expect(roleErrorMissingPermissions({ code: 'role_in_use' })).toEqual([]);
  });

  it('unwraps RoleApiError bodies thrown by role mutations', () => {
    const err = new RoleApiError(
      { error: 'Move 3 users before deleting this role.', code: 'role_in_use', user_count: 3 },
      'Could not delete role',
    );

    expect(err.name).toBe('RoleApiError');
    expect(err.message).toBe('Move 3 users before deleting this role.');
    expect(roleErrorCode(err)).toBe('role_in_use');
    expect(roleErrorMessage(err, 'fb')).toBe('Move 3 users before deleting this role.');
    expect(roleErrorUserCount(err)).toBe(3);
  });

  it('preserves permission_not_held details through RoleApiError', () => {
    const err = new RoleApiError(
      { error: 'You do not hold every requested permission.', code: 'permission_not_held', missing_permissions: ['billing.update', 42, 'users.manage'] },
      'Could not save role',
    );

    expect(roleErrorCode(err)).toBe('permission_not_held');
    expect(roleErrorMissingPermissions(err)).toEqual(['billing.update', 'users.manage']);
  });
});

describe('delete flow', () => {
  it('offers reassignment only for role_in_use', () => {
    expect(nextDeleteStep('role_in_use')).toBe('reassign');
  });

  it('is terminal on role_referenced_by_sso — no retry from this dialog helps', () => {
    // Moving holders doesn't clear a group-to-role mapping, so retrying with
    // ?reassign_to= would fail identically. Send the user to Security & SSO.
    expect(nextDeleteStep('role_referenced_by_sso')).toBe('sso-blocked');
  });

  it('stays on the bare confirm for everything else, including no code at all', () => {
    expect(nextDeleteStep('system_role_immutable')).toBe('confirm');
    expect(nextDeleteStep('role_not_found')).toBe('confirm');
    expect(nextDeleteStep(undefined)).toBe('confirm');
  });

  it('never offers the doomed role as its own reassignment target', () => {
    const roles = [role({ id: 'x', name: 'doomed' }), role({ id: 'y', name: 'viewer' }), role({ id: 'z', name: 'admin', is_system_role: true })];
    // Built-in roles ARE valid targets — the seed's own analyst→viewer migration
    // moved holders onto one. Only the role being deleted is excluded.
    expect(reassignTargets(roles, 'x').map((r) => r.id)).toEqual(['y', 'z']);
  });
});

describe('role name slug', () => {
  it('derives the server-side shape from a display name', () => {
    expect(slugifyRoleName('Compliance Reviewer')).toBe('compliance_reviewer');
    expect(slugifyRoleName('  SOC 2 Auditor! ')).toBe('soc_2_auditor');
  });

  it('accepts what the server accepts and rejects what it rejects', () => {
    expect(isValidRoleName('compliance_reviewer')).toBe(true);
    expect(isValidRoleName('a1')).toBe(true);
    expect(isValidRoleName('a')).toBe(false);        // needs 2+ chars
    expect(isValidRoleName('1abc')).toBe(false);     // must start with a letter
    expect(isValidRoleName('Has_Caps')).toBe(false);
    expect(isValidRoleName('')).toBe(false);
    expect(isValidRoleName('a'.repeat(51))).toBe(false);
  });
});
