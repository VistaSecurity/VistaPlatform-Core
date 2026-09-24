// @vitest-environment jsdom
//
// Staff ▸ the "Email verified" column, MOUNTED (security-staff-20, decision 15).
//
// The roster used to head this column "2FA", but the cell has only ever shown
// PlatformUser.email_verified: the platform has no MFA for staff. A column
// headed "2FA" with a green shield told an operator their staff had a second
// factor that does not exist. This pins that the column says what it shows,
// that each cell names its state for assistive technology, and that no "2FA"
// wording is left on the page.
//
// Mounts the real StaffListPage with only the data hooks and the auth context
// stubbed (same pattern as staff-role-gating.jsdom.test.tsx).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePlatformAuth: () => ({ user: { id: 'someone-else', role: 'platform_admin' } }),
    usePlatformPermissions: () => ({ hasPermission: () => false }),
  };
});

vi.mock('./queries', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./queries')>();
  const user = (id: string, first: string, verified: boolean) => ({
    id, email: `${first.toLowerCase()}@example.test`, first_name: first, last_name: 'Staff',
    role_id: null, is_active: true, email_verified: verified, force_password_change: false,
    last_login_at: null, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    role: null,
  });
  const staff = [
    user('00000000-0000-4000-8000-0000000000f1', 'Verified', true),
    user('00000000-0000-4000-8000-0000000000f2', 'Unverified', false),
  ];
  const mutation = () => ({ mutate: vi.fn(), isPending: false });
  return {
    ...actual,
    useStaff: () => ({ data: staff, isLoading: false, isError: false, refetch: vi.fn() }),
    useRoles: () => ({ data: [] }),
    useCreateUser: () => mutation(),
    useInviteUser: () => mutation(),
    useUpdateUser: () => mutation(),
    useDeleteUser: () => mutation(),
    useSetPassword: () => mutation(),
    useSendPasswordReset: () => mutation(),
  };
});

import { StaffListPage } from './staff-list-page';

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => root.render(<StaffListPage />));
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function headers(): string[] {
  return Array.from(container.querySelectorAll('thead th')).map((th) => th.textContent?.trim() ?? '');
}

function rowFor(first: string): HTMLTableRowElement {
  const row = Array.from(container.querySelectorAll('tbody tr')).find((tr) => tr.textContent?.includes(`${first} Staff`));
  if (!row) throw new Error(`no row for ${first}`);
  return row as HTMLTableRowElement;
}

// The cell under the "Email verified" header, located by the header's index so
// the assertion follows the column rather than a hard-coded position.
function verifiedCell(first: string): HTMLTableCellElement {
  const idx = headers().indexOf('Email verified');
  if (idx < 0) throw new Error('no "Email verified" header');
  return rowFor(first).querySelectorAll('td')[idx];
}

describe('Staff roster email-verified column', () => {
  it('heads the column "Email verified", not "2FA"', () => {
    expect(headers()).toContain('Email verified');
    expect(headers()).not.toContain('2FA');
  });

  it('names the verified and unverified states in the cell', () => {
    expect(verifiedCell('Verified').querySelector('[role="img"]')?.getAttribute('aria-label')).toBe('Email verified');
    expect(verifiedCell('Unverified').querySelector('[role="img"]')?.getAttribute('aria-label')).toBe('Email not verified');
  });

  it('claims no second factor anywhere on the page', () => {
    const text = container.textContent ?? '';
    expect(text).not.toMatch(/\b2FA\b/);
    expect(text).not.toMatch(/MFA status/);
    // The footnote says plainly that this is not MFA.
    expect(text).toContain('It is not multi-factor authentication');
  });
});
