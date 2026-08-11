// Cookie/CSRF token manager. Access + refresh tokens are httpOnly cookies the
// server sets; the JS-readable `csrf_token` cookie is the "is-authenticated"
// signal (it is NOT a JWT — its presence just means a session exists).
// Ported behavior from web-ui's proven tokenManager (cookies-only invariant).

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

export const tokenManager = {
  /** The CSRF token, echoed as X-CSRF-Token by the api-contract client. */
  getCsrf: (): string | null => getCookie('csrf_token'),
  /** Presence of csrf_token = a session exists (real auth is the httpOnly cookie). */
  hasToken: (): boolean => getCookie('csrf_token') !== null,
  /** Clears the JS-visible signal. The httpOnly cookies are cleared server-side on logout. */
  clearTokens: (): void => deleteCookie('csrf_token'),
};
