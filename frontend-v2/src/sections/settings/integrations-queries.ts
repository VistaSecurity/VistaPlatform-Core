// Settings · Integrations — query factories for the Enterprise-only half of the
// page, kept out of the component so the edition behaviour is unit testable
// (see integrations-queries.test.ts).
//
// WHY THIS IS BOTH FLAG-GATED AND PROBED
//
// CMDB/ITSM sync (`inventory-service/ee/cmdbsync`) was carved into the
// Enterprise tree, so a Core build does not mount its routes and the call 404s.
//
// It HAS a registered entitlement key (`cmdb_sync` in auth-service's
// `knownFeatures`, the OpenAPI `FeatureFlags` closed shape and the
// `FeatureName` union), so the flag is authoritative and the request never
// fires when it is off — that is the primary gate, and it is the one to reach
// for whenever a key exists.
//
// The response probe stays as the backstop for the two cases a tenant flag
// cannot cover: a Core build (route absent, 404) and a stale/unentitled call
// that still reaches the route (402). Either status becomes an
// EditionUnavailableError, which is never retried and renders an edition notice
// instead of a red failure.
import { assertEditionPresent, editionAwareRetry, isEditionUnavailable } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type CmdbProfileRow = inventoryComponents['schemas']['CMDBSyncProfile'];

export const CMDB_PROFILES_KEY = ['settings', 'cmdb-profiles'] as const;

/**
 * CMDB/ITSM sync profiles. Enterprise-only route; absent (404) on Core.
 * Exported as options rather than a hook so a test can drive it through a real
 * QueryClient and assert the request count.
 */
export function cmdbProfilesQuery(enabled = true) {
  return {
    queryKey: CMDB_PROFILES_KEY,
    // With cmdb_sync now a registered entitlement key, the flag is authoritative
    // and the request never fires when it is off. The probe below stays as the
    // backstop for the two cases a tenant flag cannot cover: a Core build (route
    // absent, 404) and a surface with no tenant feature map at all.
    enabled,
    retry: editionAwareRetry(),
    queryFn: async (): Promise<CmdbProfileRow[]> => {
      const { data, response } = await clients.inventory.GET('/cmdb/profiles', {});
      assertEditionPresent('CMDB / ITSM sync', response);
      if (!response.ok) throw new Error('Failed to load CMDB profiles');
      return data?.profiles ?? [];
    },
  };
}

// siemIntegrationsQuery was removed with the H2 security fix (v1.0.0 audit):
// GET /siem/integrations now requires a PLATFORM identity, because SIEM
// integrations are platform-global config that fans every tenant's audit events
// out to every enabled receiver. No tenant surface may call it, so the query
// factory is gone rather than left to 403. admin-ui-v2 -> Security -> SIEM
// Export owns that read.

/**
 * What an edition-probed section should render.
 *
 *  - `loading`     — first fetch in flight
 *  - `unavailable` — the running build does not ship the capability ⇒ upgrade card
 *  - `error`       — a real failure ⇒ error card (retry is meaningful)
 *  - `ready`       — data is usable
 *
 * `unavailable` deliberately outranks `error`: an absent route is not a fault,
 * and showing "couldn't load" for it is exactly the broken-page UX being fixed.
 */
export type EditionSectionState = 'loading' | 'unavailable' | 'error' | 'ready';

export function editionSectionState(q: {
  isLoading: boolean;
  isError: boolean;
  error: unknown;
}): EditionSectionState {
  if (isEditionUnavailable(q.error)) return 'unavailable';
  if (q.isError) return 'error';
  if (q.isLoading) return 'loading';
  return 'ready';
}
