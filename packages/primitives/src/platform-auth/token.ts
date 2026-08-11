// Platform-admin cookie/CSRF token manager. Mirrors the tenant tokenManager but
// for the platform_* cookie family the admin-service sets:
//   platform_access_token  (httpOnly) — the real credential
//   platform_refresh_token (httpOnly) — rotation
//   platform_csrf_token    (JS-readable) — the "is-authenticated" signal +
//                                          the X-CSRF-Token double-submit value
// Distinct from the tenant `csrf_token` so a tenant and a platform session can
// coexist in one browser without clobbering each other.

function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const escaped = name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1');
  const m = document.cookie.match(new RegExp('(?:^|; )' + escaped + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function deleteCookie(name: string): void {
  if (typeof document === 'undefined') return;
  document.cookie = `${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

export const PLATFORM_CSRF_COOKIE = 'platform_csrf_token';

export const platformTokenManager = {
  /** The platform CSRF token, echoed as X-CSRF-Token by the platform auth client. */
  getCsrf: (): string | null => getCookie(PLATFORM_CSRF_COOKIE),
  /** Presence of platform_csrf_token = a platform session exists (real auth is the httpOnly cookie). */
  hasToken: (): boolean => getCookie(PLATFORM_CSRF_COOKIE) !== null,
  /** Clears the JS-visible signal. The httpOnly cookies are cleared server-side on logout. */
  clearTokens: (): void => deleteCookie(PLATFORM_CSRF_COOKIE),
};
