// Reachability for workstream 2.8 (FEATURE_IMPLEMENTATION_FRAMEWORK).
//
// "A feature is done only when it is reachable by a user and gated correctly,
// and no layer ships without its consumer." Three layers landed here — the
// endpoints, the tab, and the Approvals row kind — and each can be orphaned in
// a way nothing else catches:
//
//   - the tab is registered but still a phase placeholder, so the page it
//     advertises renders "arrives in phase 2" over a live API;
//   - the tab is live but the asset page never dispatches to the component, so
//     the tab silently falls through to Overview;
//   - the proposal row exists but Approvals never renders it, so the queue the
//     endpoint feeds has no reader.
//
// A typecheck sees none of those: every file compiles perfectly with the wiring
// line deleted. So this reads the sources. `routing.contract.test.tsx` already
// walks ASSET_TABS for deep links; this covers the half that is about whether
// the tab does anything when you get there.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ASSET_TABS, assetTabPath, findAssetTab, isTabLive } from './asset-tabs';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const assetPage = read('./asset-page.tsx');
const approvalsPage = read('../discovery/approvals-page.tsx');
const inventoryPage = read('./inventory-page.tsx');

describe('the Relationships tab is reachable', () => {
  it('is in the tab registry', () => {
    expect(ASSET_TABS.map((t) => t.key)).toContain('relationships');
  });

  it('is LIVE, not a phase placeholder', () => {
    // It shipped in 2.8. A tab left marked "arrives in phase 2" would render
    // the placeholder card over a working endpoint, which is worse than either
    // shipping it or not.
    const tab = findAssetTab('relationships');
    expect(tab.placeholder).toBeUndefined();
    expect(isTabLive(tab)).toBe(true);
  });

  it('has a deep-linkable URL', () => {
    expect(assetTabPath('a1b2c3', 'relationships')).toBe('/inventory/assets/a1b2c3/relationships');
  });

  it('is DISPATCHED by the asset page to its component', () => {
    // The wiring line, not the component. Delete
    // `tab.key === 'relationships' ? <RelationshipsTab …>` and the tab falls
    // through to Overview under a Relationships label — with everything still
    // compiling and every other test still green.
    expect(assetPage).toContain("import { RelationshipsTab }");
    expect(assetPage).toMatch(/tab\.key === 'relationships'\s*\?\s*<RelationshipsTab/);
  });
});

describe('relationship proposals are reachable in Approvals', () => {
  it('the page imports the row component', () => {
    expect(approvalsPage).toContain("import { RelationshipProposalRow }");
  });

  it('the page actually RENDERS it', () => {
    // An imported-but-unrendered component is the orphan this check exists for.
    expect(approvalsPage).toMatch(/<RelationshipProposalRow/);
  });

  it('the page reads the proposals and can decide them', () => {
    expect(approvalsPage).toContain('useRelationshipProposals');
    expect(approvalsPage).toContain('useDecideRelationshipProposal');
    // Both decisions are wired, not just the happy one. A queue that can only
    // accept is a queue that grows.
    expect(approvalsPage).toContain("action: 'accept'");
    expect(approvalsPage).toContain("action: 'reject'");
  });

  it('a failed relationship read has its own visible error state', () => {
    // Rendering a failed read as an empty section tells a reviewer there is
    // nothing to do. The merge read had exactly this bug.
    expect(approvalsPage).toContain('relationship-proposals-error');
  });

  it('the empty-state guard covers the relationship read', () => {
    // `queryNote([q, proposalsQ])` with a third read in the page is how
    // "Nothing awaiting review" comes to be printed over work that exists.
    //
    // Matched by MEMBERSHIP rather than by the exact argument list: the queue
    // has since grown a fourth row kind (class proposals, workstream 2.10b) and
    // will grow more, and a pattern pinned to "exactly these three" fails on
    // every addition while proving nothing about the one this file is for.
    expect(approvalsPage).toMatch(/queryNote\(\[[^\]]*\brelProposalsQ\b[^\]]*\]/);
  });

  it('the source facet counts the new row kind', () => {
    expect(approvalsPage).toMatch(/countBySource\([^)]*\ballRelProposals\b[^)]*\)/);
  });
});

describe('the pending banner counts relationship proposals', () => {
  it('reads the third total', () => {
    // The banner on Inventory claims to count what is "awaiting review" and
    // links to the queue. Leaving a kind out makes the number smaller than the
    // page it points at — the same defect the merge total had before it was
    // read off `total`.
    expect(inventoryPage).toContain('useRelationshipProposals');
    expect(inventoryPage).toMatch(/relProposalsQ\.data\?\.total/);
  });
});
