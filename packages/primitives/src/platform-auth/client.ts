// Platform-admin auth client built on the typed admin-service contract — the
// session spine for the admin console (login / logout / refresh / me / change).
// Clean re-implementation of admin-ui's proven flow, NOT a copy of its axios
// god-file. One transport: the api-contract admin client.
//
// CSRF note: the shared api-contract client echoes the *tenant* `csrf_token`
// cookie. The platform surface uses `platform_csrf_token`, so we layer a second
// middleware that overrides X-CSRF-Token with the platform value (and clears it
// when absent). openapi-fetch runs onRequest middlewares in registration order,
// so this one — added last — wins.
import { createAdminServiceClient, type adminServiceComponents } from '@vistasecurity/api-contract';
import { PLATFORM_CSRF_COOKIE, platformTokenManager } from './token';

export type PlatformLoginResponse = adminServiceComponents['schemas']['PlatformLoginResponse'];
export type PlatformUser = adminServiceComponents['schemas']['PlatformUser'];
export type CurrentPlatformUser = adminServiceComponents['schemas']['CurrentPlatformUser'];

/** Pull the human message out of the bare `{ error: string }` legacy error shape. */
function messageFromError(error: unknown, fallback = 'Request failed'): string {
  if (error && typeof error === 'object' && 'error' in error) {
    const e = (error as { error: unknown }).error;
    if (typeof e === 'string') return e;
    if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  }
  return fallback;
}

export interface PlatformAuthClient {
  login(email: string, password: string): Promise<PlatformLoginResponse>;
  logout(): Promise<void>;
  refresh(): Promise<PlatformLoginResponse>;
  me(): Promise<CurrentPlatformUser>;
  changePassword(currentPassword: string, newPassword: string, confirmPassword: string): Promise<void>;
}

export function createPlatformAuthClient(baseUrl?: string): PlatformAuthClient {
  const c = createAdminServiceClient(baseUrl ? { baseUrl } : {});
  // Override the CSRF header with the platform cookie (see file header).
  c.use({
    onRequest({ request }) {
      const token = platformTokenManager.getCsrf();
      if (token) request.headers.set('X-CSRF-Token', token);
      else request.headers.delete('X-CSRF-Token');
      return request;
    },
  });

  return {
    async login(email, password) {
      const { data, error } = await c.POST('/auth/login', { body: { email, password } });
      if (error || !data) throw new Error(messageFromError(error, 'Sign-in failed'));
      return data;
    },
    async logout() {
      // Best-effort: even if the server call fails we clear locally upstream.
      await c.POST('/admin/auth/logout', {});
    },
    async refresh() {
      const { data, error } = await c.POST('/auth/refresh', { body: {} });
      if (error || !data) throw new Error(messageFromError(error, 'Session refresh failed'));
      return data;
    },
    async me() {
      const { data, error } = await c.GET('/admin/auth/me', {});
      if (error || !data) throw new Error(messageFromError(error, 'Failed to load session'));
      return data.user;
    },
    async changePassword(currentPassword, newPassword, confirmPassword) {
      const { error } = await c.POST('/admin/auth/change-password', {
        body: { current_password: currentPassword, new_password: newPassword, confirm_password: confirmPassword },
      });
      if (error) throw new Error(messageFromError(error, 'Could not change password'));
    },
  };
}

export { PLATFORM_CSRF_COOKIE };
