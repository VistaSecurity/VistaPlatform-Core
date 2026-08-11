// Platform edition awareness for the operator console.
//
// THE BUG THIS EXISTS TO FIX. admin-service is carved into Core and
// Enterprise/MSP builds. A Core build does not 403 the Enterprise routes — it
// never mounts them, so they 404. Until now the console rendered its whole
// navigation unconditionally, so an operator on a Core deployment clicked
// "Tenants" and got "couldn't load tenants". The 404 was correct; offering the
// tab was the bug.
//
// WHY NOT `useFeature`. The tenant console gates on
// GET /api/v1/auth-service/tenant/features, which resolves a TENANT's
// entitlements. Platform admins live in `platform_users` and have no tenant
// context, so there is no feature map to consult. Edition is also a different
// question from entitlement: entitlement asks "may this customer use it",
// edition asks "is the code even in the binary". This module answers the
// second, from GET /api/v1/admin-service/admin/platform/edition — a Core route,
// answerable by a build with no ee/ tree.
//
// SCOPE. admin-service can only speak for its own routes. Enterprise surfaces
// carved out of OTHER binaries — SIEM export (audit-service/ee/siemexport) —
// keep their own response probes from @vistasecurity/primitives/features. Do
// not extend this map with capabilities this service cannot observe; that would
// be a guess dressed up as a fact.
import { useQuery } from '@tanstack/react-query';
import { clients } from './clients';

/** Optional admin-service surfaces, named as the API reports them. */
export type EditionCapability = 'msp' | 'billing';

export type EditionCapabilities = Record<EditionCapability, boolean>;

export interface PlatformEdition {
  /** Coarse build edition. Informational — gate on `capabilities`. */
  edition: 'core' | 'enterprise';
  capabilities: EditionCapabilities;
}

/**
 * What we assume before the read-out lands.
 *
 * HIDDEN while loading, on purpose. Either default causes one re-render, so the
 * choice is between the nav growing and the nav shrinking. Growing is the safe
 * direction: an operator can never click an entry that is about to vanish.
 */
export const CAPABILITIES_PENDING: EditionCapabilities = { msp: false, billing: false };

/**
 * What we assume when the read-out cannot be obtained at all.
 *
 * FAIL OPEN, on purpose, and it is the one place in this file worth arguing
 * about. The failure that matters is an admin-service too old to serve the
 * route (it 404s) or briefly unreachable. Failing closed there would blank half
 * of a paying MSP deployment's console over a transient error — a new, worse
 * outage. Failing open degrades to exactly the pre-fix behaviour: the tab is
 * offered and, if this really is Core, the section's own load fails. Bad, but
 * it is the status quo rather than a regression.
 */
export const CAPABILITIES_UNKNOWN: EditionCapabilities = { msp: true, billing: true };

export const platformEditionKey = ['platform', 'edition'] as const;

/**
 * Query options for the edition read-out. Exported separately from the hook so
 * tests can drive it through a real QueryClient.
 *
 * Cached forever: hooks are wired at process start, so the answer cannot change
 * while the console is open. One request per session.
 */
export function platformEditionQuery() {
  return {
    queryKey: platformEditionKey,
    queryFn: async (): Promise<PlatformEdition> => {
      const { data, error } = await clients.admin.GET('/admin/platform/edition', {});
      if (error || !data) throw new Error('Failed to resolve platform edition');
      return data as PlatformEdition;
    },
    staleTime: Infinity,
    gcTime: Infinity,
    // An absent route is a settled fact; one retry covers a transient blip
    // without multiplying 404s in the console.
    retry: 1,
  };
}

export interface PlatformEditionState {
  /** Resolved capabilities, already collapsed through the pending/unknown rules. */
  capabilities: EditionCapabilities;
  /** True once the read-out has settled either way. */
  resolved: boolean;
  /** The reported edition, or null until it settles. */
  edition: PlatformEdition['edition'] | null;
  /** Convenience predicate for nav filters and route guards. */
  has: (capability: EditionCapability) => boolean;
}

/**
 * Resolve which optional admin-service surfaces this deployment actually has.
 *
 * Safe to call from many components — react-query dedupes to a single request
 * and the result never goes stale.
 */
export function usePlatformEdition(): PlatformEditionState {
  const { data, isError } = useQuery(platformEditionQuery());
  return resolveEditionState(data, isError);
}

/**
 * The pure core of `usePlatformEdition`, so the pending / failed / resolved
 * rules can be tested without mounting React.
 */
export function resolveEditionState(
  data: PlatformEdition | undefined,
  isError: boolean,
): PlatformEditionState {
  const capabilities = data?.capabilities ?? (isError ? CAPABILITIES_UNKNOWN : CAPABILITIES_PENDING);
  return {
    capabilities,
    resolved: Boolean(data) || isError,
    edition: data?.edition ?? null,
    has: (capability) => capabilities[capability] !== false,
  };
}

/** Human label for the edition badge in the shell. */
export function editionLabel(edition: PlatformEdition['edition'] | null): string | null {
  if (edition === 'core') return 'Core';
  if (edition === 'enterprise') return 'Enterprise';
  return null;
}
