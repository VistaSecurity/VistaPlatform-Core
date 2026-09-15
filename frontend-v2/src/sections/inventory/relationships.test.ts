// The Relationships tab's view model (ADR-0003, workstream 2.8).
//
// Everything pinned here is a way the tab can look correct and say something
// false: an edge labelled from the wrong end, a peer rendered as a uuid nobody
// can decide on, an Accept button offered where the server will refuse it, and
// an impact count presented as a total when it is a floor.
import { describe, expect, it } from 'vitest';
import {
  REVERSE_LABEL, RELATIONSHIP_TYPES, TYPE_LABEL,
  declarationPreview, depthSummary, directionOf, edgeLabel, groupByDirection,
  impactHeadline, isDecidable, peerName, peerOf,
  type Relationship, type RelationshipPeer, type RelationshipType,
} from './relationships';
import {
  RELATIONSHIPS_PAGE_SIZE, RELATIONSHIP_PROPOSALS_PAGE_SIZE,
  readRelationshipPage, readRelationshipProposalPage,
} from './relationship-queries';

const A = 'aaaaaaaa-0000-0000-0000-000000000001';
const B = 'bbbbbbbb-0000-0000-0000-000000000002';

function peer(over: Partial<RelationshipPeer> = {}): RelationshipPeer {
  return { asset_id: B, deleted: false, asset_status: 'monitoring', ...over };
}

/** An edge with the contract's required fields filled in, so a test states only
 *  the part it is about. */
function edge(over: Partial<Relationship> = {}): Relationship {
  return {
    id: 'e1', tenant_id: 't1', from_asset_id: A, to_asset_id: B,
    type: 'runs_on', source_kind: 'measured', confidence: 1, status: 'active',
    first_seen_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-10T00:00:00Z',
    observation_count: 1,
    ...over,
  };
}

describe('the vocabulary', () => {
  it('carries all ten types with a label and a reverse label', () => {
    // The registry is duplicated across the Go and TypeScript sides by
    // necessity — the server sends a label, the picker needs one before an edge
    // exists. A type missing from either map renders as `undefined`.
    expect(RELATIONSHIP_TYPES).toHaveLength(10);
    for (const t of RELATIONSHIP_TYPES) {
      expect(TYPE_LABEL[t], `TYPE_LABEL is missing ${t}`).toBeTruthy();
      expect(REVERSE_LABEL[t], `REVERSE_LABEL is missing ${t}`).toBeTruthy();
    }
  });

  it('never uses the same word for both directions', () => {
    // `runs_on` / `runs` reading the same on both ends would make the two pages
    // showing the same stored row say the same thing about opposite facts.
    for (const t of RELATIONSHIP_TYPES) {
      expect(TYPE_LABEL[t]).not.toBe(REVERSE_LABEL[t]);
    }
  });
});

describe('edgeLabel', () => {
  it('prefers the label the server computed for the asset asked about', () => {
    expect(edgeLabel(edge({ label: 'runs' }), B)).toBe(REVERSE_LABEL.runs_on);
  });

  it('reads forwards from the from end and backwards from the to end', () => {
    // One stored row, two pages, two correct readings. This is the whole point
    // of not storing both directions (ADR-0003 D1).
    const e = edge({ type: 'runs_on' });
    expect(edgeLabel(e, A)).toBe(TYPE_LABEL.runs_on);
    expect(edgeLabel(e, B)).toBe(REVERSE_LABEL.runs_on);
  });

  it('falls back to the forward label when no asset is named', () => {
    // The neighbourhood's edges carry no `direction`, because no end of a graph
    // edge is privileged.
    expect(edgeLabel(edge({ type: 'depends_on' }))).toBe(TYPE_LABEL.depends_on);
  });
});

describe('directionOf', () => {
  it('trusts the server when it says', () => {
    expect(directionOf(edge({ direction: 'in' }), A)).toBe('in');
  });

  it('works it out from the ends when the server does not', () => {
    expect(directionOf(edge(), A)).toBe('out');
    expect(directionOf(edge(), B)).toBe('in');
  });
});

describe('peerOf', () => {
  it('uses the list endpoint`s `peer` when present', () => {
    const p = peer({ asset_id: 'z' });
    expect(peerOf(edge({ peer: p }), A)).toBe(p);
  });

  it('picks the OTHER end from the proposal queue`s from/to pair', () => {
    // The proposal queue decorates both ends; the same row component renders
    // either shape, so it has to pick the right one relative to the asset.
    const from = peer({ asset_id: A });
    const to = peer({ asset_id: B });
    const e = edge({ from, to });
    expect(peerOf(e, A)).toBe(to);
    expect(peerOf(e, B)).toBe(from);
  });
});

describe('peerName', () => {
  it('prefers the display name', () => {
    expect(peerName(peer({ display_name: 'web-01' }))).toBe('web-01');
  });

  it('falls back to the strongest identifier, which is what a person recognises', () => {
    // Most freshly discovered assets have no display name at all.
    expect(peerName(peer({ primary_identifier: 'mac:aa:bb:cc:00:11:22' }))).toBe('mac:aa:bb:cc:00:11:22');
  });

  it('never renders a bare full uuid', () => {
    const name = peerName(peer({ asset_id: B }));
    expect(name).not.toBe(B);
    expect(name).toContain('…');
  });

  it('says so rather than crashing when there is no peer at all', () => {
    expect(peerName(undefined)).toBe('Unknown asset');
  });

  it('treats a blank display name as absent', () => {
    // `||` and not `??`: an empty string is not a name, and rendering one leaves
    // the row's most important cell blank.
    expect(peerName(peer({ display_name: '   ', primary_identifier: 'fqdn:a.test' }))).toBe('fqdn:a.test');
  });
});

describe('groupByDirection', () => {
  it('splits on which end the asset is', () => {
    const out = edge({ id: 'o', from_asset_id: A, to_asset_id: B });
    const inn = edge({ id: 'i', from_asset_id: B, to_asset_id: A });
    const g = groupByDirection([out, inn], A);
    expect(g.outbound.map((e) => e.id)).toEqual(['o']);
    expect(g.inbound.map((e) => e.id)).toEqual(['i']);
  });

  it('orders each side by the ADR vocabulary, not alphabetically', () => {
    // ADR-0003 D2's table order, which is the order a person learns them in.
    const types: RelationshipType[] = ['impacts', 'runs_on', 'depends_on'];
    const edges = types.map((t, i) => edge({ id: `e${i}`, type: t }));
    const g = groupByDirection(edges, A);
    expect(g.outbound.map((e) => e.type)).toEqual(['runs_on', 'depends_on', 'impacts']);
  });

  it('does not mutate its input', () => {
    const edges = [edge({ id: 'b', type: 'impacts' }), edge({ id: 'a', type: 'runs_on' })];
    groupByDirection(edges, A);
    expect(edges.map((e) => e.id)).toEqual(['b', 'a']);
  });
});

describe('isDecidable — where Accept/Reject may be offered', () => {
  it('is true for a pending edge whose ends are both monitored', () => {
    // The same predicate the server's proposal queue applies. Offering the
    // buttons anywhere else would put a control on the page the API refuses.
    expect(isDecidable(edge({ status: 'pending', peer: peer({ asset_status: 'monitoring' }) }), 'monitoring')).toBe(true);
  });

  it('is false for an active edge', () => {
    expect(isDecidable(edge({ status: 'active', peer: peer() }), 'monitoring')).toBe(false);
  });

  it('is false when the peer is still awaiting its OWN approval', () => {
    // That edge resolves when the asset is accepted (ADR-0003 D3). Offering a
    // second decision here would let a reviewer answer one question two ways.
    expect(isDecidable(edge({ status: 'pending', peer: peer({ asset_status: 'pending_approval' }) }), 'monitoring')).toBe(false);
  });

  it('is false when the peer has been deleted or merged away', () => {
    expect(isDecidable(edge({ status: 'pending', peer: peer({ deleted: true }) }), 'monitoring')).toBe(false);
  });

  it('is false when no end is decorated, rather than guessing', () => {
    // Without the peer's status there is no way to know whether the server will
    // accept the decision, and a button that might 409 is worse than none.
    expect(isDecidable(edge({ status: 'pending' }), 'monitoring')).toBe(false);
  });

  it('is false when THIS asset is the one still awaiting approval', () => {
    // The half the `peer` shape cannot see. On a pending asset's own page the
    // only decorated end is the monitored peer, so the edge read as decidable
    // from one side of a question with two — and Accept there produced an
    // `active` relationship to an asset nobody had admitted, which ADR-0003 D1
    // forbids and which the impact closure then walks.
    const e = edge({ status: 'pending', peer: peer({ asset_status: 'monitoring' }) });
    expect(isDecidable(e, 'pending_approval')).toBe(false);
    expect(isDecidable(e, 'archived')).toBe(false);
  });

  it('is false when the subject`s status was not supplied at all', () => {
    // Absent is not "monitoring". A caller that cannot say must not get the
    // benefit of the doubt on this question.
    expect(isDecidable(edge({ status: 'pending', peer: peer({ asset_status: 'monitoring' }) }))).toBe(false);
  });

  it('needs BOTH ends monitored on a proposal-queue row', () => {
    const both = edge({ status: 'pending', from: peer({ asset_id: A }), to: peer({ asset_id: B }) });
    expect(isDecidable(both)).toBe(true);
    const half = edge({
      status: 'pending',
      from: peer({ asset_id: A }),
      to: peer({ asset_id: B, asset_status: 'pending_approval' }),
    });
    expect(isDecidable(half)).toBe(false);
  });
});

describe('impactHeadline', () => {
  it('states a plain total when the closure is complete', () => {
    expect(impactHeadline({ total: 4, truncated: false, direction: 'downstream' }))
      .toBe('4 assets depend on this');
  });

  it('says "at least" when the closure was capped', () => {
    // A capped count presented as a total is a number somebody plans a
    // maintenance window around.
    expect(impactHeadline({ total: 500, truncated: true, direction: 'downstream' }))
      .toContain('At least 500');
  });

  it('reads the other way round for upstream', () => {
    expect(impactHeadline({ total: 2, truncated: false, direction: 'upstream' }))
      .toBe('2 assets this depends on');
  });

  it('distinguishes "nothing recorded" from an assertion of safety', () => {
    // Zero means no impact-bearing edges are RECORDED. "Nothing depends on
    // this" as a bare claim would be a much stronger statement than the data
    // supports.
    expect(impactHeadline({ total: 0, truncated: false, direction: 'downstream' }))
      .toBe('Nothing recorded depends on this');
    expect(impactHeadline({ total: 0, truncated: false, direction: 'upstream' }))
      .toBe('No recorded dependencies');
  });

  it('uses the singular for one', () => {
    expect(impactHeadline({ total: 1, truncated: false, direction: 'downstream' }))
      .toBe('1 asset depend on this');
  });
});

describe('depthSummary', () => {
  it('reads as hops', () => {
    expect(depthSummary({ counts_by_depth: [{ depth: 1, count: 4 }, { depth: 2, count: 2 }] }))
      .toBe('4 at 1 hop · 2 at 2 hops');
  });

  it('is empty rather than broken when there is nothing', () => {
    expect(depthSummary({ counts_by_depth: [] })).toBe('');
  });
});

describe('declarationPreview', () => {
  it('reads the sentence forwards for an outbound declaration', () => {
    expect(declarationPreview('runs_on', 'out', 'app-01', 'server-01'))
      .toBe('app-01 runs on server-01');
  });

  it('SWAPS the subject and object for an inbound one', () => {
    // Direction is the most confusable part of declaring an edge: "runs on"
    // pointing the wrong way is a plausible row that inverts every impact
    // answer built on it. The preview is what makes it checkable before it is
    // created.
    expect(declarationPreview('runs_on', 'in', 'server-01', 'app-01'))
      .toBe('app-01 runs on server-01');
  });
});

describe('readRelationshipPage / readRelationshipProposalPage', () => {
  it('reports the server total, not the page length', () => {
    const rows = Array.from({ length: 100 }, (_, i) => edge({ id: `e${i}` }));
    expect(readRelationshipPage({ relationships: rows, total: 412, limit: 100, offset: 0 }).total).toBe(412);
    expect(readRelationshipProposalPage({ relationship_proposals: rows, total: 77, limit: 50, offset: 0 }).total).toBe(77);
  });

  it('does not mistake a real zero for a missing total', () => {
    expect(readRelationshipPage({ relationships: [], total: 0 }).total).toBe(0);
    expect(readRelationshipProposalPage({ relationship_proposals: [], total: 0 }).total).toBe(0);
  });

  it('copes with no envelope at all', () => {
    expect(readRelationshipPage(undefined)).toEqual({
      relationships: [], total: 0, limit: RELATIONSHIPS_PAGE_SIZE, offset: 0,
    });
    expect(readRelationshipProposalPage(undefined)).toEqual({
      proposals: [], total: 0, limit: RELATIONSHIP_PROPOSALS_PAGE_SIZE, offset: 0,
    });
  });
});
