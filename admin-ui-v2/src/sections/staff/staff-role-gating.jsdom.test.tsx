// @vitest-environment jsdom
//
// Staff ▸ role gating, MOUNTED (security-staff-1).
//
// The admin-service now refuses any write of a platform user's role unless the
// caller holds platform_roles.assign, the role is within the caller's own
// permissions, and the user is not the caller. This pins what the Staff page
// does with that:
//
//   - without platform_roles.assign the Role select is disabled, Create/Invite
//     (which always set a role) are disabled, and an Edit does not send role_id;
//   - your own row's Role select is locked unless you are a super_admin;
//   - an Edit that keeps the role sends no role_id (it is not a role change);
//   - the server's 403 message is shown inline in the form.
//
// Mounts the real StaffListPage with only the data hooks and the auth context
// stubbed, jsdom + React's own `act`, no testing-library (same pattern as
// frontend-v2's *.jsdom.test.tsx).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// vi.mock factories are hoisted above plain consts, so the ids live in vi.hoisted.
const { ME_ID, OTHER_ID, ROLELESS_ID, ROLE_PA, ROLE_SUPPORT } = vi.hoisted(() => ({
  ME_ID: '00000000-0000-4000-8000-0000000000e1',
  OTHER_ID: '00000000-0000-4000-8000-0000000000e2',
  ROLELESS_ID: '00000000-0000-4000-8000-0000000000e3',
  ROLE_PA: '00000000-0000-4000-8000-00000000a001',
  ROLE_SUPPORT: '00000000-0000-4000-8000-00000000a002',
}));

type MutateOpts = { onSuccess?: (data?: unknown) => void; onError: (e: unknown) => void };
type Body = Record<string, unknown>;

const state = vi.hoisted(() => ({
  perms: new Set<string>(),
  me: { id: '', role: 'platform_admin' },
  updateMutate: vi.fn<(vars: { id: string; body: Body }, opts: MutateOpts) => void>(),
  createMutate: vi.fn<(vars: Body, opts: MutateOpts) => void>(),
  inviteMutate: vi.fn<(vars: Body, opts: MutateOpts) => void>(),
}));

vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePlatformAuth: () => ({ user: state.me }),
    usePlatformPermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }),
  };
});

vi.mock('./queries', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./queries')>();
  const user = (id: string, first: string, roleId: string | null, roleName: string | null) => ({
    id, email: `${first.toLowerCase()}@example.test`, first_name: first, last_name: 'Staff',
    role_id: roleId, is_active: true, email_verified: true, force_password_change: false,
    last_login_at: null, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    role: roleId ? { id: roleId, name: roleName, display_name: roleName } : null,
  });
  const staff = [
    user(ME_ID, 'Me', ROLE_PA, 'platform_admin'),
    user(OTHER_ID, 'Other', ROLE_SUPPORT, 'support_agent'),
    // What the API returns for a row without a role: `role_id: null` (the
    // admin-service maps a NULL role_id to null, never the zero UUID — see
    // PlatformUser.role_id in admin-service.openapi.yaml). The schema declares
    // the column NOT NULL, so such a row only exists if written outside it;
    // the page must still let it be edited rather than wedge.
    user(ROLELESS_ID, 'Roleless', null, null),
  ];
  const roles = [
    { id: ROLE_PA, name: 'platform_admin', display_name: 'Platform Admin' },
    { id: ROLE_SUPPORT, name: 'support_agent', display_name: 'Support Agent' },
  ];
  const mutation = (fn: unknown) => ({ mutate: fn, isPending: false });
  return {
    ...actual,
    useStaff: () => ({ data: staff, isLoading: false, isError: false, refetch: vi.fn() }),
    useRoles: () => ({ data: roles }),
    useCreateUser: () => mutation(state.createMutate),
    useInviteUser: () => mutation(state.inviteMutate),
    useUpdateUser: () => mutation(state.updateMutate),
    useDeleteUser: () => mutation(vi.fn()),
    useSetPassword: () => mutation(vi.fn()),
    useSendPasswordReset: () => mutation(vi.fn()),
  };
});

import { StaffListPage, UserFormModal } from './staff-list-page';

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  state.perms = new Set(['platform_users.read', 'platform_users.manage']);
  state.me = { id: ME_ID, role: 'platform_admin' };
  state.updateMutate.mockReset();
  state.createMutate.mockReset();
  state.inviteMutate.mockReset();
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function mount() {
  act(() => root.render(<StaffListPage />));
}

function buttonByText(text: string, scope: ParentNode = container): HTMLButtonElement {
  const b = Array.from(scope.querySelectorAll('button')).find((el) => el.textContent?.trim() === text);
  if (!b) throw new Error(`no button "${text}"`);
  return b;
}

function click(el: Element) {
  act(() => { (el as HTMLElement).click(); });
}

// Opens the row ⋯ menu for the user whose name cell starts with `first`, then Edit.
function openEdit(first: string) {
  const row = Array.from(container.querySelectorAll('tbody tr')).find((tr) => tr.textContent?.includes(`${first} Staff`));
  if (!row) throw new Error(`no row for ${first}`);
  const menuButtons = row.querySelectorAll('button.op-btn.icon');
  click(menuButtons[menuButtons.length - 1]); // the ⋯ menu is the last icon button
  click(buttonByText('Edit', row));
}

function roleSelect(): HTMLSelectElement {
  const s = container.querySelector('select[aria-label="Role"]');
  if (!s) throw new Error('no Role select');
  return s as HTMLSelectElement;
}

function chooseRole(roleId: string) {
  const s = roleSelect();
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')!.set!;
    setter.call(s, roleId);
    s.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

describe('Staff role gating', () => {
  it('without platform_roles.assign: Role select disabled, Create/Invite disabled, Edit sends no role_id', () => {
    mount();
    expect(buttonByText('Invite').disabled).toBe(true);
    expect(buttonByText('Create').disabled).toBe(true);

    openEdit('Other');
    expect(roleSelect().disabled).toBe(true);
    expect(container.textContent).toContain('requires the platform_roles.assign permission');

    click(buttonByText('Save changes'));
    expect(state.updateMutate).toHaveBeenCalledTimes(1);
    const { body } = state.updateMutate.mock.calls[0][0];
    expect(body).not.toHaveProperty('role_id');
    expect(body.first_name).toBe('Other');
  });

  it('with platform_roles.assign: Role select enabled and a changed role is sent', () => {
    state.perms.add('platform_roles.assign');
    mount();
    expect(buttonByText('Invite').disabled).toBe(false);
    expect(buttonByText('Create').disabled).toBe(false);

    openEdit('Other');
    expect(roleSelect().disabled).toBe(false);
    chooseRole(ROLE_PA);
    click(buttonByText('Save changes'));
    expect(state.updateMutate.mock.calls[0][0].body.role_id).toBe(ROLE_PA);
  });

  it('an Edit that keeps the role sends no role_id', () => {
    state.perms.add('platform_roles.assign');
    mount();
    openEdit('Other');
    click(buttonByText('Save changes'));
    expect(state.updateMutate.mock.calls[0][0].body).not.toHaveProperty('role_id');
  });

  it('locks your own role unless you are a super_admin', () => {
    state.perms.add('platform_roles.assign');
    mount();
    openEdit('Me');
    expect(roleSelect().disabled).toBe(true);
    expect(container.textContent).toContain("You can't change your own role");
  });

  it('a super_admin may open their own role', () => {
    state.perms.add('platform_roles.assign');
    state.me = { id: ME_ID, role: 'super_admin' };
    mount();
    openEdit('Me');
    expect(roleSelect().disabled).toBe(false);
  });

  it("shows the server's 403 message inline", () => {
    state.perms.add('platform_roles.assign');
    const refusal = 'The selected role grants permissions you do not hold';
    state.updateMutate.mockImplementation((_vars, opts) => {
      opts.onError({ error: refusal, missing_permissions: ['platform_roles.manage'] });
    });
    mount();
    openEdit('Other');
    chooseRole(ROLE_PA);
    click(buttonByText('Save changes'));
    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toBe(refusal);
  });

  // A user with no role, edited by a viewer who cannot assign one: the locked
  // Role select must not block saving their name/status.
  it('without platform_roles.assign: a roleless user can still be edited', () => {
    mount();
    openEdit('Roleless');
    expect(roleSelect().disabled).toBe(true);
    click(buttonByText('Save changes'));
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(state.updateMutate).toHaveBeenCalledTimes(1);
    const { id, body } = state.updateMutate.mock.calls[0][0];
    expect(id).toBe(ROLELESS_ID);
    expect(body).not.toHaveProperty('role_id');
    expect(body.first_name).toBe('Roleless');
  });

  it('with platform_roles.assign: a roleless user saves without a role, or with a chosen one', () => {
    state.perms.add('platform_roles.assign');
    mount();
    openEdit('Roleless');
    click(buttonByText('Save changes'));
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(state.updateMutate.mock.calls[0][0].body).not.toHaveProperty('role_id');

    chooseRole(ROLE_PA);
    click(buttonByText('Save changes'));
    expect(state.updateMutate.mock.calls[1][0].body.role_id).toBe(ROLE_PA);
  });

  // The modal itself, not only the page's doEdit, must not emit an empty
  // role_id for a roleless user (UserFormModal is exported and reusable).
  it('UserFormModal emits no role_id for an unchanged empty role', () => {
    const onSubmit = vi.fn();
    const roleless = {
      id: ROLELESS_ID, email: 'r@example.test', first_name: 'Roleless', last_name: 'Staff', role_id: null,
      is_active: true, email_verified: true, force_password_change: false, last_login_at: null,
      created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', role: null,
      // `satisfies`, not a cast: the generated PlatformUser type must itself
      // allow `role_id: null`, which is what the API returns for such a row.
    } satisfies Parameters<typeof UserFormModal>[0]['user'];
    act(() => root.render(
      <UserFormModal mode="edit" roles={[]} user={roleless} onClose={() => {}} onSubmit={onSubmit} loading={false} />,
    ));
    click(buttonByText('Save changes', document.body));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty('role_id');
  });

  // The other polarity: an existing role cannot be cleared by picking the
  // placeholder — that would silently keep the old role.
  it('with platform_roles.assign: clearing an existing role is refused', () => {
    state.perms.add('platform_roles.assign');
    mount();
    openEdit('Other');
    chooseRole('');
    click(buttonByText('Save changes'));
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('Role is required');
    expect(state.updateMutate).not.toHaveBeenCalled();
  });

  it('create sends the chosen role when the viewer can assign', () => {
    state.perms.add('platform_roles.assign');
    const refusal = 'Assigning a platform role requires the platform_roles.assign permission';
    state.createMutate.mockImplementation((_vars, opts) => {
      opts.onError({ error: refusal });
    });
    mount();
    click(buttonByText('Create'));
    const inputs = container.querySelectorAll('input');
    const set = (el: HTMLInputElement, v: string) => act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    });
    // First name, last name, email, password — in form order after the search box.
    const form = Array.from(inputs).filter((i) => i.getAttribute('placeholder') !== 'Search staff…' && i.type !== 'checkbox');
    set(form[0], 'New'); set(form[1], 'Person'); set(form[2], 'new@example.test'); set(form[3], 'Str0ng!Passw0rd');
    chooseRole(ROLE_SUPPORT);
    click(buttonByText('Create user'));
    expect(state.createMutate.mock.calls[0][0].role_id).toBe(ROLE_SUPPORT);
    expect(container.querySelector('[role="alert"]')?.textContent).toBe(refusal);
  });
});
