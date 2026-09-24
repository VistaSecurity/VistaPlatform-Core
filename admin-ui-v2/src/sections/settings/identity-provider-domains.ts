// Allowed-email-domain helpers for Settings ▸ Identity Providers. The server
// (admin-service identity_providers.go, shared ssoclaims) is the authority on
// every rule here; these only shape the form so the operator sees the same
// rule before saving.

// Allowed email domains apply to Microsoft admin-login providers only (Google
// asserts email_verified itself; sign-up providers never use a list).
export function allowedDomainsApply(type: string, purpose: string) {
  return type === 'microsoft' && purpose === 'admin_login';
}

// One domain per line or comma-separated; blanks dropped. The server trims,
// lower-cases, de-duplicates and validates — this only splits.
export function parseAllowedDomains(text: string): string[] {
  return text.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
}

// Multi-tenant Microsoft authorities, mirroring ssoclaims.entraMultiTenantAuthorities.
// The GUID is the personal-account (MSA) directory, which acts as "consumers".
const ENTRA_MULTI_TENANT_AUTHORITIES = ['common', 'organizations', 'consumers', '9188040d-6c67-4c5b-b112-36a304b66dad'];

// Mirrors ssoclaims.EntraAuthorityIsSingleTenant: the first path segment names
// one directory rather than a multi-tenant authority. The path is
// percent-decoded first, as Go's url.Path is: "/%63ommon/" is "/common/".
export function isSingleTenantEntraUrl(raw: string): boolean {
  try {
    const u = new URL(raw.trim());
    if (!u.host) return false;
    const seg = decodeURIComponent(u.pathname).replace(/^\//, '').split('/')[0]?.toLowerCase();
    return !!seg && !ENTRA_MULTI_TENANT_AUTHORITIES.includes(seg);
  } catch {
    return false;
  }
}
