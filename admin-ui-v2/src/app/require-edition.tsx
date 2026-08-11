import type { ReactNode } from 'react';
import { Package } from 'lucide-react';
import { usePlatformEdition, type EditionCapability } from '../lib/edition';

// Route-level EDITION guard, the deep-link backstop for the nav filter in
// nav.ts (`visibleSections`).
//
// Distinct from RequirePlatformPermission, and neither substitutes for the
// other. Permission asks "may THIS OPERATOR see it" and the answer is a 403.
// Edition asks "did this BUILD ship it" and the answer is a 404 — a Core
// operator holds `tenants.read` perfectly legitimately, so RBAC alone still
// walks them into a Tenants tab whose backend does not exist.
//
// PRODUCT DECISION — hidden in the rail, explained on arrival.
// The nav entry is removed entirely rather than shown greyed-out with an
// "upgrade" affordance. Four permanently-dead entries on every page load of a
// single-organization console are noise, and the tenant console already set
// this precedent (frontend-v2/src/sections/settings/nav.ts `visibleSettingsNav`
// removes gated items and the route renders a lock card). Discoverability is
// preserved in the two places it belongs: the CORE/ENTERPRISE badge in the
// sidebar lockup, so an operator always knows which edition they are running,
// and this card, which explains what the section would have been if they arrive
// by deep link or bookmark. What must never happen is landing on a tab that
// 404s, and that is what this closes.

const COPY: Record<EditionCapability, { title: string; body: string }> = {
  msp: {
    title: 'Part of the multi-tenant management plane',
    body:
      'This deployment runs the Core edition of admin-service, which manages a single organization. ' +
      'The tenant directory, cross-tenant dashboards, customer announcements and maintenance windows ' +
      'belong to the MSP edition — the management plane you need when you operate other organizations. ' +
      'Everything else in this console works exactly as it does on a paid edition.',
  },
  billing: {
    title: 'Part of the Enterprise billing edition',
    body:
      'This deployment runs the Core edition of admin-service, which ships no monetization code — ' +
      'no Stripe, invoices, coupons, trials or revenue analytics. Plans & Pricing still works: the tier ' +
      'and entitlement catalog, and assigning a tier, are Core, so entitlements resolve normally.',
  },
};

export function RequirePlatformEdition({
  capability,
  children,
}: {
  /** Omit to pass through — sections with no edition requirement are Core. */
  capability?: EditionCapability;
  children: ReactNode;
}) {
  const { has, resolved } = usePlatformEdition();

  if (!capability) return <>{children}</>;

  // Hold the render until the read-out settles rather than flashing a section
  // that is about to be replaced by a notice (or vice versa).
  if (!resolved) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 13 }}>
        Checking edition…
      </div>
    );
  }

  if (!has(capability)) return <EditionNotice capability={capability} />;
  return <>{children}</>;
}

/**
 * "Not in this edition" panel. Deliberately NOT an error state: nothing failed,
 * the capability was never built into this deployment. Exported so page-level
 * partial gates (Mission Control's revenue hero, the legal acceptance ledger)
 * render the same thing instead of inventing their own.
 */
export function EditionNotice({
  capability,
  compact = false,
}: {
  capability: EditionCapability;
  compact?: boolean;
}) {
  const { title, body } = COPY[capability];
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: compact ? 'flex-start' : 'center', justifyContent: 'center', padding: compact ? 0 : 40 }}>
      <div style={{ maxWidth: 520, display: 'flex', gap: 14, padding: '22px 24px', borderRadius: 'var(--r-lg)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }}>
        <Package size={20} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 2 }} />
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)' }}>{title}</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4, lineHeight: 1.55 }}>{body}</div>
        </div>
      </div>
    </div>
  );
}
