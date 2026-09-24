// Settings ▸ Identity Providers: the "Sign-up" purpose is not offered on Core
// (settings-8, admin-ui review decision 11). Social sign-up is served only by
// the Enterprise build, so a sign-up provider on Core would save, read
// "Enabled", and do nothing; admin-service now refuses it with 402, and the
// form stops offering it. Admin login (staff sign-in) is Core and always
// offered.
//
// Two halves: the pure rules in identity-provider-purpose.ts, and the real
// IdpModal / page rendered with the licence read-out stubbed.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { LicenseState } from '../../lib/edition';

const state = vi.hoisted((): { license: string; queryData: unknown } => ({
  license: 'core',
  queryData: undefined,
}));

vi.mock('../../lib/edition', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformEdition: () => ({ license: state.license }) };
});

vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { platform: { securityManage: 'platform.security.manage', settings: 'platform.settings' } },
  usePlatformPermissions: () => ({ hasPermission: () => true }),
}));

vi.mock('@tanstack/react-query', () => ({
  useQuery: () => ({ data: state.queryData, isLoading: false, isError: false }),
  useMutation: () => ({ mutate: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('../../lib/clients', () => ({ clients: { admin: {} } }));

import { defaultPurpose, purposeOptions, signupPurposeOffered } from './identity-provider-purpose';
import { IdpModal, SettingsIdentityProvidersPage } from './settings-identity-providers-page';

const signupRow = {
  id: '33333333-3333-4333-8333-333333333333',
  provider_type: 'google',
  provider_name: 'Google',
  purpose: 'signup',
  client_id: 'signup-client',
  has_secret: true,
  auth_url: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_url: 'https://oauth2.googleapis.com/token',
  userinfo_url: 'https://openidconnect.googleapis.com/v1/userinfo',
  scopes: 'openid email profile',
  is_enabled: true,
  allowed_email_domains: [] as string[],
};

describe('signupPurposeOffered', () => {
  const cases: Array<[LicenseState, boolean]> = [
    ['core', false],
    ['pending', false],
    ['enterprise', true],
    ['msp', true],
    ['unknown', true],
  ];
  for (const [license, want] of cases) {
    it(`${license} → ${want ? 'offered' : 'hidden'}`, () => {
      expect(signupPurposeOffered(license)).toBe(want);
    });
  }
});

describe('purposeOptions / defaultPurpose', () => {
  it('lists Admin login only on Core, and a new provider starts on it', () => {
    expect(purposeOptions('core')).toEqual(['admin_login']);
    expect(defaultPurpose('core')).toBe('admin_login');
  });

  it('lists both on a paid licence, starting on Sign-up', () => {
    expect(purposeOptions('enterprise')).toEqual(['signup', 'admin_login']);
    expect(defaultPurpose('msp')).toBe('signup');
  });

  it("keeps an existing sign-up row's own purpose on Core", () => {
    expect(purposeOptions('core', 'signup')).toEqual(['signup', 'admin_login']);
    expect(purposeOptions('core', 'admin_login')).toEqual(['admin_login']);
  });
});

function usedForOptions(html: string): string[] {
  const select = html.match(/<select aria-label="Used for"[^>]*>([\s\S]*?)<\/select>/);
  if (!select) throw new Error('no "Used for" select');
  return Array.from(select[1].matchAll(/<option value="([^"]+)"/g), (m) => m[1]);
}

describe('Add identity provider form', () => {
  beforeEach(() => {
    vi.stubGlobal('window', { location: { origin: 'https://admin.example.test' } });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('offers only Admin login on Core, selected, and says why', () => {
    state.license = 'core';
    const html = renderToStaticMarkup(createElement(IdpModal, { provider: null, onClose: () => {} }));
    expect(usedForOptions(html)).toEqual(['admin_login']);
    expect(html).not.toContain('Sign-up (tenant founders)');
    expect(html).toContain('Sign-up providers need an Enterprise or MSP licence');
    // The redirect URI shown is the staff (admin host) callback, not sign-up's.
    expect(html).toContain('/api/v1/admin-service/admin/sso/google/callback');
  });

  it('offers Sign-up on an Enterprise licence, selected by default', () => {
    state.license = 'enterprise';
    const html = renderToStaticMarkup(createElement(IdpModal, { provider: null, onClose: () => {} }));
    expect(usedForOptions(html)).toEqual(['signup', 'admin_login']);
    expect(html).toMatch(/<option value="signup" selected="">/);
    expect(html).not.toContain('need an Enterprise or MSP licence');
  });

  it('still shows an existing sign-up row on Core so it can be switched off or deleted', () => {
    state.license = 'core';
    const html = renderToStaticMarkup(createElement(IdpModal, { provider: signupRow as never, onClose: () => {} }));
    expect(usedForOptions(html)).toEqual(['signup', 'admin_login']);
    expect(html).toMatch(/<option value="signup" selected="">/);
    expect(html).toContain('Delete provider');
  });
});

describe('Identity Providers page copy', () => {
  it('does not promise social sign-up on Core', () => {
    state.license = 'core';
    state.queryData = [];
    const html = renderToStaticMarkup(createElement(SettingsIdentityProvidersPage));
    expect(html).not.toContain('enable social sign-up');
    expect(html).toContain('needs an Enterprise or MSP licence');
  });

  it('describes social sign-up on a paid licence', () => {
    state.license = 'msp';
    state.queryData = [];
    const html = renderToStaticMarkup(createElement(SettingsIdentityProvidersPage));
    expect(html).toContain('enable social sign-up');
  });
});
