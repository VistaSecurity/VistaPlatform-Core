// Clean auth client built on the typed API contract (one transport for the new
// UI). Covers the session spine: login / logout / refresh / me. Behavior is a
// clean re-implementation of web-ui's proven flow — NOT a copy of its axios
// god-file.
import { createAuthServiceClient, type authServiceComponents } from '@vistasecurity/api-contract';

export type AuthResponse = authServiceComponents['schemas']['AuthResponse'];
export type MeResponse = authServiceComponents['schemas']['MeResponse'];
export type AuthUser = authServiceComponents['schemas']['User'];
export type AuthTenant = authServiceComponents['schemas']['Tenant'];

/** Pull the human message out of the bare `{ error: string }` legacy error shape. */
function messageFromError(error: unknown, fallback = 'Request failed'): string {
  if (error && typeof error === 'object' && 'error' in error) {
    const e = (error as { error: unknown }).error;
    if (typeof e === 'string') return e;
    if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  }
  return fallback;
}

export interface AuthClient {
  login(email: string, password: string): Promise<AuthResponse>;
  logout(): Promise<void>;
  refresh(): Promise<AuthResponse>;
  me(): Promise<MeResponse>;
}

export function createAuthClient(baseUrl?: string): AuthClient {
  const c = createAuthServiceClient(baseUrl ? { baseUrl } : {});
  return {
    async login(email, password) {
      const { data, error } = await c.POST('/auth/login', { body: { email, password } });
      if (error || !data) throw new Error(messageFromError(error, 'Sign-in failed'));
      return data;
    },
    async logout() {
      // Best-effort: even if the server call fails we clear locally upstream.
      await c.POST('/auth/logout', {});
    },
    async refresh() {
      const { data, error } = await c.POST('/auth/refresh', { body: {} });
      if (error || !data) throw new Error(messageFromError(error, 'Session refresh failed'));
      return data;
    },
    async me() {
      const { data, error } = await c.GET('/auth/me', {});
      if (error || !data) throw new Error(messageFromError(error, 'Failed to load session'));
      return data;
    },
  };
}
