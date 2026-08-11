// Settings · Account → Billing — query factories for the tenant-facing
// self-service billing surface, kept out of the component so the edition
// behaviour is unit testable (see edition-gating.test.ts).
//
// WHY THIS IS GATED AT ALL
//
// `/my-billing/**` is served by `services/admin-service/ee/billingapi`, which
// the Core export strips. A Core build never mounts these routes, so every call
// 404s and the page renders "Couldn't load the subscription" / "Couldn't load
// invoices" — which reads as broken software rather than "this is a paid
// feature". `billing.read` cannot separate the two: a Core tenant admin holds
// that permission perfectly legitimately.
//
// The gate is the registered `billing_portal` entitlement key, so the flag is
// known BEFORE any request and the doomed calls are never fired. The response
// probe below is the backstop for a stale feature map (402) or a client talking
// to an older/Core service it did not expect (404) — either way an upgrade card,
// never a red failure and never a retry storm.
//
// Deliberately NOT gated: Settings → Usage & Limits, which reads auth-service
// `/billing/usage/current`. That route is Core and consumption-against-plan-
// limits is meaningful on a Core install, so it stays unconditional.
import { assertEditionPresent, editionAwareRetry } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';

export const MY_SUBSCRIPTION_KEY = ['settings', 'my-subscription'] as const;
export const MY_INVOICES_KEY = ['settings', 'my-invoices'] as const;

/** The tenant's own subscription + tier. Enterprise-only route; absent (404) on Core. */
export function mySubscriptionQuery(enabled = true) {
  return {
    queryKey: MY_SUBSCRIPTION_KEY,
    enabled,
    retry: editionAwareRetry(),
    queryFn: async () => {
      const { data, response } = await clients.admin.GET('/my-billing/subscription', {});
      assertEditionPresent('Self-service billing', response);
      if (!response.ok || !data) throw new Error('Failed to load the subscription');
      return data;
    },
  };
}

/** The tenant's own invoices. Enterprise-only route; absent (404) on Core. */
export function myInvoicesQuery(enabled = true) {
  return {
    queryKey: MY_INVOICES_KEY,
    enabled,
    retry: editionAwareRetry(),
    queryFn: async () => {
      const { data, response } = await clients.admin.GET('/my-billing/invoices', {});
      assertEditionPresent('Self-service billing', response);
      if (!response.ok || !data) throw new Error('Failed to load invoices');
      return data;
    },
  };
}
