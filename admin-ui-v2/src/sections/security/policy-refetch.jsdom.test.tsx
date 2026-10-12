// @vitest-environment jsdom
//
// Security ▸ Policy: a settings refetch that lands while the operator is
// editing must not re-seed the form and discard their unsaved change; an
// unedited form still follows the server.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const base = {
  password_min_length: 8,
  session_timeout_minutes: 1440,
  max_login_attempts: 5,
  lockout_duration_minutes: 30,
  registration_enabled: false,
  email_verification_required: true,
  admin_email_verification_required: false,
};
const state = vi.hoisted(() => ({ settings: null as Record<string, unknown> | null }));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: () => true }) };
});
vi.mock('./queries', () => ({
  errMsg: (_e: unknown, f: string) => f,
  usePlatformSettings: () => ({ data: state.settings, isLoading: false, isError: false, refetch: vi.fn() }),
  useUpdateSecuritySettings: () => ({ isPending: false, mutateAsync: async () => {} }),
}));

import { SecurityPolicyPage } from './policy-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
const render = () => act(() => root!.render(<SecurityPolicyPage />));
const num = (i: number) => host.querySelectorAll<HTMLInputElement>('input[type="number"]')[i];

beforeEach(() => {
  state.settings = { ...base };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  render();
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
  root = null;
});

describe('policy form re-seeding', () => {
  it('keeps unsaved edits across a refetch with new server data', () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
    act(() => { setter.call(num(0), '16'); num(0).dispatchEvent(new Event('input', { bubbles: true })); });
    expect(num(0).value).toBe('16');
    state.settings = { ...base, session_timeout_minutes: 60 }; // refetch, changed elsewhere
    render();
    expect(num(0).value).toBe('16');
  });

  it('follows the server while the form is unedited', () => {
    state.settings = { ...base, password_min_length: 10 };
    render();
    expect(num(0).value).toBe('10');
  });
});
