// A tier's entitlement composition as the Plans & Pricing pages hold it: the
// rows AND the version the server computed for them. The version is what makes
// a multi-item save safe — the server refuses (409) a save computed from a
// composition that has changed since it was read — so it travels with the rows
// in one cache entry rather than beside them.
//
// Deliberately NOT the ['platform', 'tier-entitlements', id] key the Tenants
// drawer uses: that entry holds a bare row array, and sharing a key between two
// shapes is how one page's cache becomes another page's crash. Writes here
// invalidate both.
import type { QueryClient } from '@tanstack/react-query';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type TierEntitlement = adminServiceComponents['schemas']['TierEntitlement'];
export type TierComposition = { entitlements: TierEntitlement[]; version: string };

export const tierCompositionKey = (tierId: string) => ['platform', 'tier-composition', tierId] as const;

export async function fetchTierComposition(tierId: string): Promise<TierComposition> {
  const { data, error } = await clients.admin.GET('/admin/tiers/{id}/entitlements', { params: { path: { id: tierId } } });
  if (error || !data) throw new Error('Failed to load tier entitlements');
  // A composition without a version cannot be saved safely; treat it as a
  // failed load rather than let a later save go out unversioned.
  if (!data.version) throw new Error('Tier entitlements came back without a version');
  return { entitlements: data.entitlements ?? [], version: data.version };
}

/** After a composition write: pin what the server returned, refresh everyone else's view. */
export function storeTierComposition(qc: QueryClient, tierId: string, data: { entitlements?: TierEntitlement[] | null; version?: string }) {
  if (data.version) qc.setQueryData<TierComposition>(tierCompositionKey(tierId), { entitlements: data.entitlements ?? [], version: data.version });
  else void qc.invalidateQueries({ queryKey: tierCompositionKey(tierId) });
  void qc.invalidateQueries({ queryKey: ['platform', 'tier-entitlements', tierId] });
}

/** The server's 400/409 carries a `detail` naming the bad item or the conflict; prefer it to a generic message. */
export function apiDetail(err: unknown, fallback: string): string {
  const d = (err as { detail?: unknown } | null)?.detail;
  return typeof d === 'string' && d ? d : fallback;
}
