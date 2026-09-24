// Microsoft Entra single-directory check for the tenant SSO provider form
//. The server (auth-service ee/sso tenant_sso_entra.go, shared
// ssoclaims.EntraAuthorityIsSingleTenant) is the authority; this only lets the
// form say so before saving instead of after a 400.
//
// Entra does not verify the `email` claim, so a Microsoft/Azure provider's
// allowed email domains are only accepted while both OAuth endpoints name the
// organisation's own directory — never a multi-tenant authority.

// Multi-tenant Microsoft authorities, mirroring ssoclaims.entraMultiTenantAuthorities.
// The GUID is the personal-account (MSA) directory, which acts as "consumers".
const ENTRA_MULTI_TENANT_AUTHORITIES = new Set(['common', 'organizations', 'consumers', '9188040d-6c67-4c5b-b112-36a304b66dad']);

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// Provider types whose allowed domains stand in for Entra's missing
// email_verified claim (ssoclaims.EmailEffectivelyVerified).
export function isEntraProviderType(type: string): boolean {
  return type === 'microsoft' || type === 'azure';
}

function isDomainShape(seg: string): boolean {
  if (seg.length > 253) return false;
  const labels = seg.split('.');
  return labels.length >= 2 && labels.every((l) => DOMAIN_LABEL.test(l));
}

// Mirrors ssoclaims.EntraAuthorityIsSingleTenant: the authority is the first
// segment of the percent-decoded, CLEANED path ("/./common/", "//common/" and
// "/%2e/common/" all name "common"), and it must look like a directory id Entra
// issues — a GUID or a dotted domain — rather than junk or a multi-tenant name.
export function isSingleTenantEntraUrl(raw: string): boolean {
  let pathname: string;
  try {
    const u = new URL(raw.trim());
    if (!u.host) return false;
    pathname = decodeURIComponent(u.pathname);
  } catch {
    return false;
  }
  const segs: string[] = [];
  for (const s of pathname.split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') {
      segs.pop();
      continue;
    }
    segs.push(s);
  }
  const seg = (segs[0] ?? '').toLowerCase();
  if (!seg || ENTRA_MULTI_TENANT_AUTHORITIES.has(seg)) return false;
  return GUID.test(seg) || isDomainShape(seg);
}

// True when a Microsoft/Azure provider carries allowed domains but either
// endpoint is not pinned to one directory — the combination the server refuses.
export function entraDomainsNeedDirectory(type: string, domains: string[], authUrl: string, tokenUrl: string): boolean {
  return isEntraProviderType(type) && domains.length > 0 && !(isSingleTenantEntraUrl(authUrl) && isSingleTenantEntraUrl(tokenUrl));
}
