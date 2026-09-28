// @vitest-environment jsdom
//
// Security ▸ Policy saves the whole form, and the registration_enabled it loads
// can be an edition DEFAULT rather than a stored choice: on a fresh
// Core install it reads false while sign-up is open for the first organization.
// Writing it back would record "closed" and shut that first-run window as a side
// effect of an unrelated edit. So the page sends registration_enabled only when
// the operator changed it. Remove that and the first test goes red.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The settings object must be STABLE across renders, as react-query's is: the
// page derives its baseline with useMemo([settings]) and resets the form in an
// effect, so a fresh object per render loops until the worker dies.
const state = vi.hoisted(() => ({
  saved: [] as Record<string, unknown>[],
  settings: {
    password_min_length: 8,
    session_timeout_minutes: 1440,
    max_login_attempts: 5,
    lockout_duration_minutes: 30,
    registration_enabled: false, // Core's default, not a stored choice
    email_verification_required: true,
    admin_email_verification_required: false,
  },
}));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: () => true }) };
});
vi.mock('./queries', () => ({
  errMsg: (_e: unknown, fallback: string) => fallback,
  usePlatformSettings: () => ({
    data: state.settings,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
  useUpdateSecuritySettings: () => ({
    isPending: false,
    mutateAsync: async (patch: Record<string, unknown>) => {
      state.saved.push(patch);
    },
  }),
}));

import { SecurityPolicyPage } from './policy-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;

beforeEach(() => {
  state.saved = [];
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => root!.render(<SecurityPolicyPage />));
});

afterEach(() => {
  act(() => root?.unmount());
  host.remove();
  root = null;
});

function setNumber(index: number, value: string) {
  const input = host.querySelectorAll<HTMLInputElement>('input[type="number"]')[index];
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

function toggleRegistration() {
  // TOGGLE_FIELDS order: registration_enabled is first.
  const box = host.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')[0];
  act(() => box.click());
}

async function save() {
  const button = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Save changes'));
  expect(button).toBeTruthy();
  await act(async () => {
    button!.click();
  });
}

describe('Security policy save', () => {
  it('does not write registration_enabled when the operator did not change it', async () => {
    setNumber(0, '12'); // minimum password length
    await save();
    expect(state.saved).toHaveLength(1);
    expect(state.saved[0].password_min_length).toBe(12);
    expect(state.saved[0]).not.toHaveProperty('registration_enabled');
  });

  it('writes registration_enabled when the operator changed it', async () => {
    toggleRegistration();
    await save();
    expect(state.saved).toHaveLength(1);
    expect(state.saved[0].registration_enabled).toBe(true);
  });
});
