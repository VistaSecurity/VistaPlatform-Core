// Settings · Security & SSO — query factories, kept out of the component so the
// entitlement gate is unit testable (see sso-queries.test.ts).
//
// `/tenant/sso/**` lives in auth-service/ee/sso. A Core build never mounts it,
// so calling it does not 403 — it 404s. Unlike CMDB sync and SIEM export, this
// capability HAS a registered entitlement key (`sso_saml`, present in
// auth-service `knownFeatures`, the OpenAPI `FeatureFlags` closed shape, and the
// `FeatureName` union), so the correct gate is the flag: the request is skipped
// entirely rather than fired and recovered from.
import { clients } from '../../lib/clients';
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';

export type SSOProviderRow = AuthC['schemas']['SSOProvider'];

export const SSO_PROVIDERS_KEY = ['settings', 'sso-providers'] as const;
export const AUTH_POLICY_KEY = ['settings', 'auth-policy'] as const;

/**
 * The tenant's configured identity providers. `entitled` is the resolved
 * `sso_saml` flag — false ⇒ `enabled: false` ⇒ react-query never invokes the
 * query function, so no doomed request is emitted.
 */
export function ssoProvidersQuery(entitled: boolean) {
  return {
    queryKey: SSO_PROVIDERS_KEY,
    enabled: entitled,
    queryFn: async (): Promise<SSOProviderRow[]> => {
      const { data, error } = await clients.auth.GET('/tenant/sso/providers', {});
      if (error || !data) throw new Error('Failed to load SSO providers');
      return data.providers;
    },
  };
}

/** The org-wide authentication policy (password_only / prefer_sso / …). */
export function authPolicyQuery(entitled: boolean) {
  return {
    queryKey: AUTH_POLICY_KEY,
    enabled: entitled,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/sso/authentication-policy', {});
      if (error || !data) throw new Error('Failed to load authentication policy');
      return data;
    },
  };
}
