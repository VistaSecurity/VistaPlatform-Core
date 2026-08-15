// The role dropdown must never invent a role.
//
// `GET /tenant/{id}/roles` requires `users.manage`. Inviting requires only
// `users.create`. Until custom roles shipped no permission combination
// could hold one without the other, so the gap was unreachable and the modal's
// `roles.length ? … : ['viewer']` fallback never fired in practice.
//
// Custom roles make it reachable: a tenant can now build a role with
// `users.create` and no `users.manage`. The old fallback then offered exactly
// one option — viewer — with no error, so an invitation sent as the wrong role
// was indistinguishable from a correct one. These cases pin the honest
// behaviour: say what is missing, and block the send.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const src = readFileSync(
  fileURLToPath(new URL('./people-modals.tsx', import.meta.url)),
  'utf8',
);

describe('invite/change-role dropdowns', () => {
  it('does not fall back to a hardcoded role list', () => {
    // The exact shape of the old bug. Any resurrection of a literal role name
    // as a fallback option should fail here.
    expect(src).not.toContain(`: ['viewer']`);
    expect(src).not.toMatch(/roles\.length\s*\?[^:]*:\s*\[/);
  });

  it('disables Send invitation when no role could be loaded', () => {
    // Without this the dialog posts whatever `role` state holds, which is
    // seeded to 'viewer' before the query resolves.
    expect(src).toContain('roles.length === 0');
  });

  it('explains the missing permission rather than failing silently', () => {
    expect(src).toContain('roleFieldHint(rolesQ.isLoading, rolesQ.isError)');
    expect(src).toMatch(/Manage users permission/);
  });

  it('disables both selects on error', () => {
    const disabledOnError = src.match(/disabled=\{[^}]*rolesQ\.isError[^}]*\}/g) ?? [];
    expect(
      disabledOnError.length,
      'both the invite and change-role selects should disable when roles fail to load',
    ).toBe(2);
  });
});
