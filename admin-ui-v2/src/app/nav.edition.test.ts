// Edition-gating regression guard for the operator navigation.
//
// The bug: admin-service is carved into Core and Enterprise/MSP builds, and a
// Core build does not 403 the Enterprise routes — it never mounts them, so they
// 404. The console rendered the whole nav regardless, so a Core operator clicked
// "Tenants" and got "couldn't load tenants".
//
// These tests pin BOTH directions of the filter. A gate asserted in one
// direction only is the classic failure here: hard-coding "hide everything"
// would pass a Core-only check while silently blanking a paying MSP console.
//
// Pure functions over the REAL SECTIONS registry — not a fixture — so marking a
// new section is covered automatically, and un-marking one fails a test.
import { describe, it, expect } from 'vitest';
import { SECTIONS, editionAllows, visibleSections, type NavItem } from './nav';
import { CAPABILITIES_PENDING, CAPABILITIES_UNKNOWN, type EditionCapabilities } from '../lib/edition';

const CORE: EditionCapabilities = { msp: false, billing: false };
const MSP: EditionCapabilities = { msp: true, billing: true };
/** Every operator permission granted — isolates the edition gate from RBAC. */
const superUser = () => true;

const ids = (sections: NavItem[]) => sections.map((s) => s.id);
const childIds = (sections: NavItem[], id: string) =>
  (sections.find((s) => s.id === id)?.children ?? []).map((c) => c.id);

describe('the sections a Core build must not offer', () => {
  const core = visibleSections(superUser, CORE);

  // Each of these was verified against the live Core deployment: the routes
  // behind them answer 404 unauthenticated, while Core routes answer 401.
  it.each([
    ['tenants', 'ee/msp — the whole /admin/tenants surface'],
    ['comms', 'ee/msp — announcements + maintenance windows'],
    ['billing', 'ee/billingapi — Stripe, invoices, coupons, trials, analytics'],
  ])('hides %s (%s)', (id) => {
    expect(ids(core)).not.toContain(id);
  });
});

describe('the sections a Core build must still offer', () => {
  const core = visibleSections(superUser, CORE);

  // The other half of the contract. Over-hiding is as much a bug as
  // under-hiding — these are all fully Core and must survive the filter.
  it.each(['overview', 'support', 'fleet', 'jobs', 'plans', 'system', 'catalog', 'settings', 'staff', 'security'])(
    'keeps %s',
    (id) => {
      expect(ids(core)).toContain(id);
    },
  );

  it('keeps every Core sub-view of Catalog and Settings', () => {
    expect(childIds(core, 'catalog')).toEqual(['ratings', 'frameworks']);
    expect(childIds(core, 'settings')).toContain('legal'); // authoring is Core
  });
});

describe('an MSP/Enterprise build loses nothing', () => {
  const msp = visibleSections(superUser, MSP);

  it('offers every section the registry defines', () => {
    expect(ids(msp)).toEqual(SECTIONS.map((s) => s.id));
  });

  it('offers every child and grandchild', () => {
    for (const section of SECTIONS) {
      expect(childIds(msp, section.id)).toEqual((section.children ?? []).map((c) => c.id));
    }
  });

  it('keeps FinOps under Billing & Revenue', () => {
    expect(childIds(msp, 'billing')).toContain('finops');
  });
});

describe('the two gates are independent', () => {
  it('RBAC alone does NOT hide Tenants on Core — which is why edition gating exists', () => {
    // A Core platform admin legitimately holds tenants.read. If permission were
    // sufficient, this fix would be unnecessary; asserting it keeps the reason
    // for the second gate from being refactored away.
    const permissionOnly = SECTIONS.filter((s) => !s.permission || superUser());
    expect(permissionOnly.map((s) => s.id)).toContain('tenants');
  });

  it('edition alone does NOT bypass RBAC on an MSP build', () => {
    const noTenantRead = (p: string) => !p.startsWith('tenants.');
    expect(ids(visibleSections(noTenantRead, MSP))).not.toContain('tenants');
  });
});

describe('capability defaults', () => {
  it('treats unmarked entries as Core, so a new section is never hidden by accident', () => {
    expect(editionAllows({}, CORE)).toBe(true);
  });

  it('hides gated entries while the read-out is still pending', () => {
    // Growing the nav is safer than shrinking it: an operator can never click
    // an entry that is about to disappear.
    expect(ids(visibleSections(superUser, CAPABILITIES_PENDING))).not.toContain('tenants');
  });

  it('shows gated entries when the read-out could not be obtained', () => {
    // Fail OPEN on an unreachable/too-old admin-service: blanking a paying
    // console over a transient error would be a worse failure than the bug.
    expect(ids(visibleSections(superUser, CAPABILITIES_UNKNOWN))).toContain('tenants');
  });
});
