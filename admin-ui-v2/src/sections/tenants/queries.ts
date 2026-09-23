// Tenants data layer — TanStack Query over the typed admin-service client.
// This is the ONLY way the section reaches the backend (no hand-rolled calls).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { adminServiceComponents, tenantHealthServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { usePlatformEdition } from '../../lib/edition';
import { licenseCapKey } from '../../lib/license-cap';

export type Tenant = adminServiceComponents['schemas']['Tenant'];
export type TenantHealthSummary = tenantHealthServiceComponents['schemas']['TenantHealthSummary'];
export type TenantStats = adminServiceComponents['schemas']['TenantStats'];
export type TenantCost = adminServiceComponents['schemas']['TenantCost'];
export type TierEntitlement = adminServiceComponents['schemas']['TierEntitlement'];
export type TenantPlan = adminServiceComponents['schemas']['TenantPlan'];
export type TenantFeatures = adminServiceComponents['schemas']['TenantFeatures'];
export type TenantFeature = adminServiceComponents['schemas']['TenantFeature'];

/**
 * The name to show for a tenant's plan: the resolved plan block
 * (edition-licensing spec §3). "Vista Platform Enterprise" on Enterprise,
 * "Vista Platform Core" on Core, the MSP's own plan on MSP. Never a tier name
 * on Enterprise — the backend omits `subscription_tier` there — and never the
 * old "Trial" fallback, which labelled every tier-less tenant a trial.
 */
export function planLabel(t: Pick<Tenant, 'plan' | 'subscription_tier'>): string {
  return t.plan?.display_name ?? t.subscription_tier ?? '—';
}

/** The nil UUID a tenant with no tier used to serialise as (RC-10). */
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

/** The tenant's tier id, or null when it has none. */
export function tierIdOf(t: Pick<Tenant, 'subscription_tier_id'>): string | null {
  return t.subscription_tier_id && t.subscription_tier_id !== NIL_UUID ? t.subscription_tier_id : null;
}
export type CouponRedemption = adminServiceComponents['schemas']['CouponRedemption'];

/** Edit form payload — partial; `subscription_tier` is intentionally omitted (PUT ignores it). */
export type UpdateTenantInput = adminServiceComponents['schemas']['UpdateTenantRequest'];

/** Design status keys (ops-primitives STATUS) the table/filters use. */
export type TenantDisplayStatus = 'active' | 'trial' | 'past_due' | 'onboarding' | 'suspended' | 'canceled';

/** Map the backend payment_status (+ is_active) onto a design status key. */
export function tenantStatus(t: Tenant): TenantDisplayStatus {
  if (!t.is_active) return 'suspended';
  switch (t.payment_status) {
    case 'active': return 'active';
    case 'trial': return 'trial';
    case 'past_due': return 'past_due';
    case 'canceled': return 'canceled';
    default: return (t.payment_status as TenantDisplayStatus) || 'active';
  }
}

const tenantsKey = ['platform', 'tenants'] as const;

/** Tenant directory (page_size capped at 100 server-side; fine for the admin set).
 *  When an operator scope is set, narrow to that tenant server-side so the
 *  directory ships only the in-scope row. */
export function useTenants(scopeId: string | null = null) {
  // The tenant directory lives in admin-service/ee/msp: a Core build never
  // mounts /admin/tenants, so the call 404s. This hook has four callers — the
  // Tenants section, Mission Control, the topbar tenant switcher and the ⌘K
  // palette — and the last two render on EVERY page, so leaving it ungated
  // meant a Core operator collected a 404 on every navigation. Gating here
  // rather than at each call site means no caller can forget.
  const { has, resolved } = usePlatformEdition();
  return useQuery({
    queryKey: [...tenantsKey, scopeId],
    enabled: resolved && has('msp'),
    queryFn: async (): Promise<Tenant[]> => {
      const { data, error } = await clients.admin.GET('/admin/tenants', {
        params: { query: { page_size: 100, ...(scopeId ? { tenant_id: scopeId } : {}) } },
      });
      if (error || !data) throw new Error('Failed to load tenants');
      return data.tenants ?? [];
    },
    staleTime: 60 * 1000,
  });
}

/**
 * Cross-tenant health, keyed by tenant id, for enriching the list/drawer.
 * Independent of the tenant list query — if tenant-health is unavailable the
 * list still renders (the Health column just falls back to "—").
 */
export function useTenantHealthMap() {
  return useQuery({
    queryKey: ['platform', 'tenant-health'],
    queryFn: async (): Promise<Map<string, TenantHealthSummary>> => {
      const { data, error } = await clients.tenantHealth.GET('/tenants', { params: { query: { limit: 200 } } });
      if (error || !data) throw new Error('Failed to load tenant health');
      const m = new Map<string, TenantHealthSummary>();
      for (const s of data.tenants ?? []) m.set(s.tenant_id, s);
      return m;
    },
    staleTime: 60 * 1000,
    retry: 0, // enrichment is best-effort; don't hammer if the service is down
  });
}

/**
 * Per-tenant drawer enrichment. Each is best-effort (retry: 0, enabled only when
 * a tenant is open) so a slow/down source degrades to an empty-state in its tab
 * rather than blocking the drawer.
 */

/** Usage stats (users / assets / sensors / storage) — admin `/admin/tenants/{id}/stats`. */
export function useTenantStats(id: string | null) {
  return useQuery({
    queryKey: ['platform', 'tenant-stats', id],
    enabled: !!id,
    retry: 0,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<TenantStats> => {
      const { data, error } = await clients.admin.GET('/admin/tenants/{id}/stats', { params: { path: { id: id! } } });
      if (error || !data) throw new Error('Failed to load tenant stats');
      return data.stats;
    },
  });
}

/** Cost / usage for the current period — admin `/admin/costs/tenants/{id}` (returns TenantCost directly). */
export function useTenantCost(id: string | null) {
  return useQuery({
    queryKey: ['platform', 'tenant-cost', id],
    enabled: !!id,
    retry: 0,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<TenantCost> => {
      const { data, error } = await clients.admin.GET('/admin/costs/tenants/{id}', { params: { path: { id: id! } } });
      if (error || !data) throw new Error('Failed to load tenant cost');
      return data;
    },
  });
}

/** Applied coupon redemptions — admin `/admin/billing/coupons/tenants/{tenant_id}`. */
export function useTenantCoupons(id: string | null) {
  return useQuery({
    queryKey: ['platform', 'tenant-coupons', id],
    enabled: !!id,
    retry: 0,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<CouponRedemption[]> => {
      const { data, error } = await clients.admin.GET('/admin/billing/coupons/tenants/{tenant_id}', { params: { path: { tenant_id: id! } } });
      if (error || !data) throw new Error('Failed to load coupons');
      return data.redemptions ?? [];
    },
  });
}

/**
 * The entitlements granted by the tenant's subscription tier — admin
 * `/admin/tiers/{id}/entitlements`, keyed by the tenant's `subscription_tier_id`.
 * Read-only here; per-tenant *override* editing (tenant_limit_overrides) is a
 * separate surface not yet spec'd for admin.
 */
export function useTierEntitlements(tierId: string | null) {
  return useQuery({
    queryKey: ['platform', 'tier-entitlements', tierId],
    enabled: !!tierId,
    retry: 0,
    staleTime: 5 * 60 * 1000,
    queryFn: async (): Promise<TierEntitlement[]> => {
      const { data, error } = await clients.admin.GET('/admin/tiers/{id}/entitlements', { params: { path: { id: tierId! } } });
      if (error || !data) throw new Error('Failed to load entitlements');
      return data.entitlements ?? [];
    },
  });
}

/** Suspend / reactivate a tenant, then refresh the list. */
export function useTenantStatusMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, action }: { id: string; action: 'suspend' | 'activate' }) => {
      const path = action === 'suspend' ? '/admin/tenants/{id}/suspend' : '/admin/tenants/{id}/activate';
      const { error } = await clients.admin.POST(path, { params: { path: { id } } });
      if (error) throw new Error(`Failed to ${action} tenant`);
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: tenantsKey }); },
  });
}

/** Update a tenant (PUT /admin/tenants/{id}), then refresh the list + that tenant. */
export function useUpdateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: string; body: UpdateTenantInput }) => {
      const { error } = await clients.admin.PUT('/admin/tenants/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Failed to update tenant');
    },
    onSuccess: (_d, { id }) => {
      qc.invalidateQueries({ queryKey: tenantsKey });
      qc.invalidateQueries({ queryKey: ['platform', 'tenant-stats', id] });
    },
  });
}

/**
 * Mark (or unmark) a tenant as the MSP's own — PUT /admin/tenants/{id}/operator.
 * The MSP's own tenants never count against the licence's tenant limit, so the
 * change refreshes the licensed-tenant banner too. MSP licences only: the
 * server answers 409 otherwise, and its message is surfaced as-is.
 */
export function useSetTenantOperator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, isOperator }: { id: string; isOperator: boolean }) => {
      const { data, error } = await clients.admin.PUT('/admin/tenants/{id}/operator', {
        params: { path: { id } },
        body: { is_operator: isOperator },
      });
      if (error || !data) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Failed to update the tenant');
      }
      return data;
    },
    onSuccess: (data) => {
      // Patch every cached directory (one per operator scope) with the saved
      // value first, so the drawer — which reads its tenant from this cache —
      // shows it immediately instead of after the refetch lands.
      qc.setQueriesData<Tenant[]>({ queryKey: tenantsKey }, (rows) =>
        rows?.map((t) => (t.id === data.id ? { ...t, is_operator: data.is_operator } : t)),
      );
      void qc.invalidateQueries({ queryKey: tenantsKey });
      if (data.cap) qc.setQueryData(licenseCapKey, data.cap);
      else void qc.invalidateQueries({ queryKey: licenseCapKey });
    },
  });
}

/** Soft-delete a tenant (DELETE /admin/tenants/{id} — sets deleted_at), then refresh. */
export function useDeleteTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id }: { id: string }) => {
      const { error } = await clients.admin.DELETE('/admin/tenants/{id}', { params: { path: { id } } });
      if (error) throw new Error('Failed to delete tenant');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: tenantsKey });
      // A deleted tenant can take an MSP install back under its licence.
      void qc.invalidateQueries({ queryKey: licenseCapKey });
    },
  });
}

/** Active tier catalog for the support plan-change picker. */
export function useAdminTiers(enabled = true) {
  return useQuery({
    queryKey: ['platform', 'tiers'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/tiers', {});
      if (error || !data) throw new Error('Failed to load tiers');
      return data.tiers ?? [];
    },
  });
}

/** Support-granted plan change — POST /admin/tenants/{id}/billing/change-plan.
 *  The downgrade path tenants cannot self-serve: Stripe price change with NO
 *  proration (nothing refunded; next invoice bills the new rate). */
export function useAdminChangePlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, tierId, reason }: { id: string; tierId: string; reason: string }) => {
      const { data, error } = await clients.admin.POST('/admin/tenants/{id}/billing/change-plan', {
        params: { path: { id } },
        body: { tier_id: tierId, reason },
      });
      if (error || !data) throw new Error('Failed to change the tenant plan');
      return data;
    },
    onSuccess: (_d, { id }) => {
      qc.invalidateQueries({ queryKey: tenantsKey });
      qc.invalidateQueries({ queryKey: ['platform', 'tenant-stats', id] });
      qc.invalidateQueries({ queryKey: ['platform', 'tenant-cost', id] });
    },
  });
}

// ADR-0015: platform-admin manual re-evaluation of a tenant's inventory against all
// frameworks. Enqueues a bounded async reconcile in compliance-engine (202).
export function useTenantReevaluateMutation() {
  return useMutation({
    mutationFn: async ({ id }: { id: string }) => {
      const { error } = await clients.compliance.POST('/admin/tenants/{tenantId}/reevaluate', {
        params: { path: { tenantId: id } },
      });
      if (error) throw new Error('Failed to enqueue re-evaluation');
    },
  });
}

// ---- Per-tenant overrides (Tenants ▸ a tenant ▸ Settings) -------------------
//
// GET/PUT /admin/tenants/{id}/settings — an ee/msp surface, so it inherits the
// Tenants section's `edition: 'msp'` gate; a Core build never renders the tab.
//
// These two hooks are the first callers this endpoint has ever had. It shipped
// wired but unreachable: the v1 admin-ui drove it from the tenant modal's
// Security tab, and the v1→v2 rebuild dropped that surface without
// dropping the backend. It was also non-functional the whole time — an
// un-castable `$4` in its optimistic-locking WHERE clause made every real call
// fail at Postgres parse time — which is why nobody noticed the UI was gone.

/** A tenant's platform-admin overrides. Every field is tri-state: `undefined`
 *  means "no override, follow the platform default". */
export type TenantSettings = adminServiceComponents['schemas']['TenantSettings'];

/** The settings document plus its optimistic-locking version. */
export type TenantSettingsSnapshot = { settings: TenantSettings; version: number };

const tenantSettingsKey = (id: string | null) => ['platform', 'tenant-settings', id] as const;

/** One tenant's overrides. Unlike the drawer's best-effort enrichment reads,
 *  this is the tab's primary content, so it keeps the default retry behaviour —
 *  a transient failure should recover rather than render a permanent empty. */
export function useTenantSettings(id: string | null) {
  return useQuery({
    queryKey: tenantSettingsKey(id),
    enabled: !!id,
    staleTime: 30 * 1000,
    queryFn: async (): Promise<TenantSettingsSnapshot> => {
      const { data, error } = await clients.admin.GET('/admin/tenants/{id}/settings', {
        params: { path: { id: id! } },
      });
      if (error || !data) throw new Error('Failed to load tenant settings');
      // A tenant with no settings row yet answers `{settings: {}, version: 0}`;
      // that is a valid starting state, not an error.
      return { settings: data.settings ?? {}, version: data.version ?? 0 };
    },
  });
}

/**
 * Save a tenant's overrides.
 *
 * `settings` carries ONLY the keys this form owns, and a key whose control is
 * on "Platform default" is omitted entirely rather than sent as null — absent
 * is what the backend's jsonb merge reads as "leave this alone", so sending the
 * whole form with nulls would clobber. `version` comes from the last GET and
 * makes a concurrent edit fail with 409 instead of silently winning.
 */
export function useUpdateTenantSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, settings, version }: { id: string; settings: TenantSettings; version?: number }) => {
      const { data, error } = await clients.admin.PUT('/admin/tenants/{id}/settings', {
        params: { path: { id } },
        body: { settings, ...(version !== undefined ? { version } : {}) },
      });
      if (error || !data) {
        throw new Error(
          (error as { error?: string } | undefined)?.error === 'Version conflict'
            ? 'These settings were changed by someone else. Reload and try again.'
            : 'Failed to save tenant settings',
        );
      }
      return data;
    },
    onSuccess: (_d, { id }) => {
      void qc.invalidateQueries({ queryKey: tenantSettingsKey(id) });
    },
  });
}

// ---- Per-tenant feature switches (Tenants ▸ a tenant ▸ Entitlements) --------
//
// GET /admin/tenants/{id}/features lists every paid capability the licence
// covers, as the tenant resolves it; PUT .../features/{key} switches one off
// (reason required) or back on. Enterprise only — the backend answers 409 on
// any other licence, and `switchable` says so up front.

const tenantFeaturesKey = (id: string | null) => ['platform', 'tenant-features', id] as const;

export function useTenantFeatures(id: string | null) {
  return useQuery({
    queryKey: tenantFeaturesKey(id),
    enabled: !!id,
    staleTime: 30 * 1000,
    queryFn: async (): Promise<TenantFeatures> => {
      const { data, error } = await clients.admin.GET('/admin/tenants/{id}/features', { params: { path: { id: id! } } });
      if (error || !data) throw new Error('Failed to load features');
      return data;
    },
  });
}

export function useSetTenantFeature() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, key, enabled, reason }: { id: string; key: string; enabled: boolean; reason?: string }) => {
      const { data, error } = await clients.admin.PUT('/admin/tenants/{id}/features/{key}', {
        params: { path: { id, key } },
        body: enabled ? { enabled } : { enabled, reason: reason ?? '' },
      });
      if (error || !data) {
        const msg = (error as { error?: string } | undefined)?.error;
        throw new Error(msg ?? 'Failed to update the feature');
      }
      return data;
    },
    onSuccess: (data, { id }) => {
      qc.setQueryData(tenantFeaturesKey(id), data);
    },
  });
}
