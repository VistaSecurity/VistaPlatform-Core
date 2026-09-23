// The MSP soft cap on tenants — GET /api/v1/admin-service/admin/license/cap
// (edition-licensing spec §3, PR 3).
//
// A Core route every build mounts: Core and Enterprise answer
// `state: "uncapped"`, and only an MSP licence carrying `max_tenants` caps
// anything. The shell's banner (app/license-cap-banner.tsx) and the tenant
// drawer's operator-tenant control both read it through this one query.
//
// The route needs platform.settings, so the query is only issued for an
// operator who holds it; everyone else simply never sees the banner.
import { useQuery } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { clients } from './clients';

export type LicenseCap = adminServiceComponents['schemas']['LicenseCapResponse'];

export const licenseCapKey = ['platform', 'license-cap'] as const;

/**
 * Query options for the licensed-tenant read. Exported apart from the hook so
 * a test can run them through a real QueryClient (same shape as
 * platformEditionQuery in ./edition).
 */
export function licenseCapQuery() {
  return {
    queryKey: licenseCapKey,
    // The grace clock moves in days; a signup elsewhere can start it at any
    // time, so poll gently rather than only on navigation.
    staleTime: 60 * 1000,
    refetchInterval: 5 * 60 * 1000,
    retry: 1,
    queryFn: async (): Promise<LicenseCap> => {
      const { data, error } = await clients.admin.GET('/admin/license/cap', {});
      if (error || !data) throw new Error('Could not read the licensed tenant limit');
      return data;
    },
  };
}

export function useLicenseCap() {
  const { hasPermission } = usePlatformPermissions();
  return useQuery({
    ...licenseCapQuery(),
    enabled: hasPermission(PLATFORM_PERMISSIONS.platform.settings),
  });
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Whole days of grace left, rounded up, never negative. */
export function graceDaysLeft(graceEndsAt: string | null | undefined, now: Date = new Date()): number {
  if (!graceEndsAt) return 0;
  const ms = new Date(graceEndsAt).getTime() - now.getTime();
  return ms <= 0 ? 0 : Math.ceil(ms / DAY_MS);
}

export type CapBanner = { tone: 'warn' | 'danger'; title: string; detail: string };

/**
 * What the shell banner says, or null when it should not render. Only the two
 * over-the-licence states are shown: under the licence, uncapped, or unknown
 * (no data yet, an error, no permission) all render nothing.
 */
export function capBanner(cap: LicenseCap | undefined, now: Date = new Date()): CapBanner | null {
  if (!cap || cap.licensed == null) return null;
  const counts = `${cap.current} of ${cap.licensed} licensed tenants`;
  if (cap.state === 'grace') {
    const days = graceDaysLeft(cap.grace_ends_at, now);
    return {
      tone: 'warn',
      title: `${counts} — ${days} ${days === 1 ? 'day' : 'days'} of grace left`,
      detail: 'Existing tenants are unaffected. When the grace period ends, new tenants will be refused until the licence is extended or tenants are removed.',
    };
  }
  if (cap.state === 'blocked') {
    return {
      tone: 'danger',
      title: `${counts} — grace period ended, new tenants are blocked`,
      detail: 'Existing tenants keep working. Contact Vista Security to extend your licence, or remove tenants to get back under it.',
    };
  }
  return null;
}
