// Settings ▸ Identity Providers and Settings ▸ Email: the write controls follow
// platform.security.manage, the permission admin-service enforces on those
// writes. A stock Platform Admin (platform.settings only) sees both pages
// read-only, with a notice that names the permission — not a Save button the
// server will answer with 403.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const state = vi.hoisted(() => ({
  granted: new Set<string>(),
  asked: [] as string[],
  queryData: undefined as unknown,
}));

vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { platform: { securityManage: 'platform.security.manage', settings: 'platform.settings' } },
  usePlatformPermissions: () => ({
    hasPermission: (p: string) => {
      state.asked.push(p);
      return state.granted.has(p);
    },
  }),
}));

vi.mock('@tanstack/react-query', () => ({
  useQuery: () => ({ data: state.queryData, isLoading: false, isError: false }),
  useMutation: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('../../lib/clients', () => ({ clients: { admin: {} } }));

import { SettingsIdentityProvidersPage } from './settings-identity-providers-page';
import { SettingsEmailPage } from './settings-email-page';

const provider = {
  id: '11111111-1111-4111-8111-111111111111',
  provider_type: 'google',
  provider_name: 'Google',
  purpose: 'admin_login',
  client_id: 'client-id',
  has_secret: true,
  auth_url: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_url: 'https://oauth2.googleapis.com/token',
  userinfo_url: 'https://openidconnect.googleapis.com/v1/userinfo',
  scopes: 'openid email profile',
  is_enabled: true,
};

beforeEach(() => {
  state.granted = new Set(['platform.settings']);
  state.asked = [];
  state.queryData = undefined;
});

describe('Identity Providers page', () => {
  it('is read-only without platform.security.manage and says which permission is needed', () => {
    state.queryData = [provider];
    const html = renderToStaticMarkup(createElement(SettingsIdentityProvidersPage));
    expect(state.asked).toContain('platform.security.manage');
    expect(html).not.toContain('Add provider');
    expect(html).not.toContain('title="Edit"');
    expect(html).toContain('Read-only');
    expect(html).toContain('platform.security.manage');
    expect(html).toContain('role="note"');
    // The row itself is still visible — reads stay on platform.settings.
    expect(html).toContain('client-id');
  });

  it('offers add and edit with platform.security.manage, and no notice', () => {
    state.granted.add('platform.security.manage');
    state.queryData = [provider];
    const html = renderToStaticMarkup(createElement(SettingsIdentityProvidersPage));
    expect(html).toContain('Add provider');
    expect(html).toContain('title="Edit"');
    expect(html).not.toContain('role="note"');
    expect(html).not.toContain('Read-only');
  });
});

describe('Email delivery page', () => {
  const stored = { smtp_host: 'smtp.example.test', smtp_port: '587', smtp_username: 'u', smtp_password: '', smtp_password_set: true, from_email: 'noreply@example.test', from_name: 'Vista' };

  it('disables the relay fields and hides Save without platform.security.manage', () => {
    state.queryData = stored;
    const html = renderToStaticMarkup(createElement(SettingsEmailPage));
    expect(html).not.toContain('Save settings');
    expect(html).toContain('platform.security.manage');
    expect(html).toContain('role="note"');
    const inputs = html.match(/<input[^>]*>/g) ?? [];
    const relayInputs = inputs.filter((i) => !i.includes('Send test to'));
    expect(relayInputs.length).toBe(6);
    for (const i of relayInputs) expect(i).toContain('disabled');
    // "Send test" uses the stored relay and stays available on platform.settings.
    expect(html).toContain('Send test to');
  });

  it('keeps the form editable with platform.security.manage', () => {
    state.granted.add('platform.security.manage');
    state.queryData = stored;
    const html = renderToStaticMarkup(createElement(SettingsEmailPage));
    expect(html).toContain('Save settings');
    expect(html).not.toContain('role="note"');
    const inputs = html.match(/<input[^>]*>/g) ?? [];
    for (const i of inputs) expect(i).not.toContain('disabled');
  });
});
