// The form-side mirror of ssoclaims.EntraAuthorityIsSingleTenant. The
// cases are the Go test's: a dot segment, an empty segment or percent-encoding
// must not hide a multi-tenant authority, and the personal-account directory's
// GUID is multi-tenant even though it is a GUID.
import { describe, expect, it } from 'vitest';
import { entraDomainsNeedDirectory, isSingleTenantEntraUrl } from './entra-authority';

const DIR = '11111111-2222-4333-8444-555555555555';

describe('isSingleTenantEntraUrl', () => {
  it.each([
    `https://login.microsoftonline.com/${DIR}/oauth2/v2.0/authorize`,
    `https://login.microsoftonline.com/${DIR.toUpperCase()}/oauth2/v2.0/token`,
    'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token',
    `https://login.microsoftonline.com/./${DIR}/oauth2/v2.0/token`,
    // An encoded slash survives the URL parser and becomes a real "." segment
    // once decoded, as it does in Go's url.Path.
    `https://login.microsoftonline.com/.%2F${DIR}/oauth2/v2.0/token`,
  ])('accepts a directory-pinned endpoint: %s', (url) => {
    expect(isSingleTenantEntraUrl(url)).toBe(true);
  });

  it.each([
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://login.microsoftonline.com/Organizations/oauth2/v2.0/token',
    'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
    'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token',
    'https://login.microsoftonline.com/./common/oauth2/v2.0/token',
    'https://login.microsoftonline.com//common/oauth2/v2.0/token',
    'https://login.microsoftonline.com/%2e/common/oauth2/v2.0/token',
    'https://login.microsoftonline.com/%63ommon/oauth2/v2.0/token',
    'https://login.microsoftonline.com/x/../common/oauth2/v2.0/token',
    // Encoded slashes are not normalised by the URL parser, so the cleaning
    // has to happen after decoding: this is "common" to Go's path.Clean.
    'https://login.microsoftonline.com/contoso.com%2F..%2Fcommon/oauth2/v2.0/token',
    'https://login.microsoftonline.com/common;x/oauth2/v2.0/token',
    'https://login.microsoftonline.com/common%20/oauth2/v2.0/token',
    'https://login.microsoftonline.com/',
    'https://login.microsoftonline.com',
    'not a url',
    '',
  ])('refuses a multi-tenant, junk or unparsable endpoint: %s', (url) => {
    expect(isSingleTenantEntraUrl(url)).toBe(false);
  });
});

describe('entraDomainsNeedDirectory', () => {
  const common = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
  const pinned = `https://login.microsoftonline.com/${DIR}/oauth2/v2.0/authorize`;

  it('flags Microsoft and Azure with domains on a multi-tenant endpoint', () => {
    expect(entraDomainsNeedDirectory('microsoft', ['example.com'], common, common)).toBe(true);
    expect(entraDomainsNeedDirectory('azure', ['example.com'], pinned, common)).toBe(true);
  });

  it('allows a pinned directory, no domains, or a non-Entra provider', () => {
    expect(entraDomainsNeedDirectory('microsoft', ['example.com'], pinned, pinned)).toBe(false);
    expect(entraDomainsNeedDirectory('microsoft', [], common, common)).toBe(false);
    expect(entraDomainsNeedDirectory('google', ['example.com'], common, common)).toBe(false);
  });
});
