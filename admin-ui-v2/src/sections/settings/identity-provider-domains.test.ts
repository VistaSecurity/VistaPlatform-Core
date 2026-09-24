import { describe, expect, it } from 'vitest';
import { allowedDomainsApply, isSingleTenantEntraUrl, parseAllowedDomains } from './identity-provider-domains';

describe('identity-provider allowed-domain helpers', () => {
  it('applies only to Microsoft admin-login providers', () => {
    expect(allowedDomainsApply('microsoft', 'admin_login')).toBe(true);
    expect(allowedDomainsApply('google', 'admin_login')).toBe(false);
    expect(allowedDomainsApply('microsoft', 'signup')).toBe(false);
  });

  it('splits on newlines, commas and spaces and drops blanks', () => {
    expect(parseAllowedDomains(' a.example\n\nb.example, c.example  ')).toEqual(['a.example', 'b.example', 'c.example']);
    expect(parseAllowedDomains('')).toEqual([]);
  });

  it('recognises a single-directory Entra endpoint', () => {
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f/oauth2/v2.0/token')).toBe(true);
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize')).toBe(true);
    for (const a of ['common', 'Organizations', 'consumers']) {
      expect(isSingleTenantEntraUrl(`https://login.microsoftonline.com/${a}/oauth2/v2.0/token`)).toBe(false);
    }
    // The personal-account directory GUID acts as "consumers".
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token')).toBe(false);
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/9188040D-6C67-4C5B-B112-36A304B66DAD/oauth2/v2.0/token')).toBe(false);
    // Decoded like the server's url.Path, so an escaped authority is still recognised.
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/%63ommon/oauth2/v2.0/token')).toBe(false);
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/%E0/oauth2/v2.0/token')).toBe(false);
    expect(isSingleTenantEntraUrl('https://login.microsoftonline.com/')).toBe(false);
    expect(isSingleTenantEntraUrl('not a url')).toBe(false);
  });
});
