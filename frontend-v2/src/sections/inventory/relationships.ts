// The relationship vocabulary and the Relationships tab's view model
// (ADR-0003).
//
// Pure, so the parts that are easy to get quietly wrong are unit-tested rather
// than eyeballed in a browser: which direction an edge reads as, how a peer
// with no display name is labelled, and which edges a person can actually act
// on. The tab renders this; it does not compute it.

import type { inventoryComponents } from '@vistasecurity/api-contract';

export type Relationship = inventoryComponents['schemas']['Relationship'];
export type RelationshipPeer = inventoryComponents['schemas']['RelationshipPeer'];
export type Neighbourhood = inventoryComponents['schemas']['Neighbourhood'];
export type Impact = inventoryComponents['schemas']['Impact'];
export type GraphNode = inventoryComponents['schemas']['GraphNode'];
export type RelationshipType = Relationship['type'];
export type SourceKind = Relationship['source_kind'];

/**
 * The ten types in ADR-0003 D2 table order — the order of the ADR, not
 * alphabetical, because that is the order a person learns them in and the
 * picker shows the common ones first.
 */
export const RELATIONSHIP_TYPES: readonly RelationshipType[] = [
  'runs_on', 'hosted_on', 'virtualized_by', 'depends_on', 'connects_to',
  'member_of', 'contains', 'manages', 'sends_data_to', 'impacts',
] as const;

/** How each type reads left-to-right, from the FROM asset's side. */
export const TYPE_LABEL: Readonly<Record<RelationshipType, string>> = {
  runs_on: 'runs on',
  hosted_on: 'hosted on',
  virtualized_by: 'virtualized by',
  depends_on: 'depends on',
  connects_to: 'connects to',
  member_of: 'member of',
  contains: 'contains',
  manages: 'manages',
  sends_data_to: 'sends data to',
  impacts: 'impacts',
};

/**
 * How each type reads from the TO asset's side.
 *
 * This mirrors the Go registry's `reverseLabels`, and it has to: an edge is
 * stored once in the canonical direction (ADR-0003 D1), so the same row is
 * rendered on two different asset pages and must read correctly on both. The
 * server sends `label`; this is the fallback and the source of the picker's
 * preview sentence.
 */
export const REVERSE_LABEL: Readonly<Record<RelationshipType, string>> = {
  runs_on: 'runs',
  hosted_on: 'hosts',
  virtualized_by: 'virtualizes',
  depends_on: 'used by',
  connects_to: 'connected from',
  member_of: 'members',
  contains: 'contained by',
  manages: 'managed by',
  sends_data_to: 'receives data from',
  impacts: 'impacted by',
};

/** One line of help per type, for the picker. A vocabulary nobody can tell
 *  apart gets used as a coin flip. */
export const TYPE_HELP: Readonly<Record<RelationshipType, string>> = {
  runs_on: 'An application or container on the machine that runs it.',
  hosted_on: 'A virtual machine on its hypervisor, or a cloud resource in its account or region.',
  virtualized_by: 'A virtual machine on the hypervisor or cluster that virtualizes it.',
  depends_on: 'This needs that to work — an application and its database.',
  connects_to: 'An observed network connection. Not a dependency.',
  member_of: 'A node in a cluster, an access point on its controller, an asset in a group.',
  contains: 'A virtual network and its subnets, a cluster and its nodes.',
  manages: 'A controller and the things it manages.',
  sends_data_to: 'A declared data flow between applications.',
  impacts: 'This affects a business service.',
};

/** The four provenances, and what each one is worth. */
export const SOURCE_KIND_LABEL: Readonly<Record<SourceKind, string>> = {
  measured: 'Measured',
  declared: 'Declared',
  imported: 'Imported',
  inferred: 'Inferred',
};

export const SOURCE_KIND_HELP: Readonly<Record<SourceKind, string>> = {
  measured: 'A collector observed this.',
  declared: 'Someone here asserted it.',
  imported: 'It came from a CMDB or a spreadsheet.',
  inferred: 'The platform guessed it. Nothing has confirmed it.',
};

/**
 * How an edge reads from the asset whose page you are on.
 *
 * Prefers the server's `label` — it is computed from the same registry and is
 * already correct for the asset that was asked about — and falls back to the
 * local vocabulary only when the field is absent, which is the case on the
 * neighbourhood's edges, where no end is privileged.
 */
export function edgeLabel(edge: Relationship, assetId?: string): string {
  if (edge.label) return humanizeLabel(edge.label);
  const inbound = assetId !== undefined && edge.to_asset_id === assetId;
  return inbound ? REVERSE_LABEL[edge.type] : TYPE_LABEL[edge.type];
}

/** `runs_on` and `connected_from` both arrive as snake_case; the vocabulary
 *  maps the canonical ten, and anything else is de-underscored rather than
 *  shown raw. */
function humanizeLabel(label: string): string {
  const known = TYPE_LABEL[label as RelationshipType];
  if (known) return known;
  const reversed = Object.values(REVERSE_LABEL).find((v) => v.replace(/ /g, '_') === label);
  return reversed ?? label.replace(/_/g, ' ');
}

/**
 * The other end of an edge, relative to the asset in question.
 *
 * The list endpoint sends `peer`; the proposal queue sends `from` and `to`
 * instead, because a reviewer there has no asset page around them for context.
 * Both shapes are handled so one row component can render either.
 */
export function peerOf(edge: Relationship, assetId?: string): RelationshipPeer | undefined {
  if (edge.peer) return edge.peer;
  if (assetId !== undefined && edge.from_asset_id === assetId) return edge.to;
  if (assetId !== undefined && edge.to_asset_id === assetId) return edge.from;
  return edge.to ?? edge.from;
}

/** Which way the edge points, from this asset's side. */
export function directionOf(edge: Relationship, assetId?: string): 'out' | 'in' {
  if (edge.direction) return edge.direction;
  return assetId !== undefined && edge.to_asset_id === assetId ? 'in' : 'out';
}

/**
 * What to call a peer.
 *
 * Display name, then its strongest identifier, then a shortened id. Never the
 * bare uuid in full: a row a person cannot read is a row they cannot decide
 * anything about, and most freshly discovered assets have no display name at
 * all.
 */
export function peerName(peer: RelationshipPeer | undefined): string {
  if (!peer) return 'Unknown asset';
  if (peer.display_name?.trim()) return peer.display_name;
  if (peer.primary_identifier?.trim()) return peer.primary_identifier;
  return `${peer.asset_id.slice(0, 8)}…`;
}

/** Edges grouped by direction, each side sorted by type then peer name, so a
 *  tab with thirty edges reads as two lists rather than one shuffle. */
export interface GroupedRelationships {
  outbound: Relationship[];
  inbound: Relationship[];
}

export function groupByDirection(edges: Relationship[], assetId: string): GroupedRelationships {
  const outbound: Relationship[] = [];
  const inbound: Relationship[] = [];
  for (const e of edges) {
    (directionOf(e, assetId) === 'out' ? outbound : inbound).push(e);
  }
  const order = (a: Relationship, b: Relationship) => {
    const byType = RELATIONSHIP_TYPES.indexOf(a.type) - RELATIONSHIP_TYPES.indexOf(b.type);
    if (byType !== 0) return byType;
    return peerName(peerOf(a, assetId)).localeCompare(peerName(peerOf(b, assetId)));
  };
  return { outbound: [...outbound].sort(order), inbound: [...inbound].sort(order) };
}

/**
 * Whether this edge is a proposal a person can decide on THIS page.
 *
 * Pending alone is not enough. An edge waiting on an endpoint's own approval
 * resolves when that asset is accepted (ADR-0003 D3), and offering
 * Accept/Reject for it here would let a reviewer answer the same question two
 * ways. The server's proposal queue applies the same rule — "pending, and both
 * ends monitored" — and this is the client-side half so the buttons only appear
 * where they will work.
 *
 * BOTH ends have to be checked, and on the asset page only ONE of them is in
 * the payload. The list endpoint decorates the `peer` — the other end — so an
 * edge read from a pending asset's own page looks decidable from the peer
 * alone, and Accept there confirmed a relationship to an asset nobody had
 * admitted yet. `selfStatus` is the missing half: the status of the asset whose
 * page this is. The server refuses the same case (`ErrRelationshipEndPending`);
 * this keeps the button from being offered in the first place.
 */
export function isDecidable(edge: Relationship, selfStatus?: string): boolean {
  if (edge.status !== 'pending') return false;
  const ends = [edge.peer, edge.from, edge.to].filter(Boolean) as RelationshipPeer[];
  if (ends.length === 0) return false;
  // Undecorated (the `peer` shape) means the subject's own status was not in
  // the payload. Absent is not "monitoring": a caller that cannot say must not
  // get the benefit of the doubt on a question whose wrong answer confirms a
  // relationship to an unapproved asset.
  if (!edge.from || !edge.to) {
    if (selfStatus !== 'monitoring') return false;
  }
  return ends.every((p) => p.asset_status === 'monitoring' && !p.deleted);
}

/** Impact counts by depth, as a sentence fragment: "4 at 1 hop · 2 at 2 hops". */
export function depthSummary(impact: Pick<Impact, 'counts_by_depth'>): string {
  return (impact.counts_by_depth ?? [])
    .map((d) => `${d.count} at ${d.depth} hop${d.depth === 1 ? '' : 's'}`)
    .join(' · ');
}

/**
 * What the impact panel's headline says.
 *
 * A truncated closure reports a FLOOR, and says so. "500 assets affected" when
 * the real number is larger and unknown is the kind of number somebody plans a
 * maintenance window around.
 */
export function impactHeadline(impact: Pick<Impact, 'total' | 'truncated' | 'direction'>): string {
  const noun = impact.total === 1 ? 'asset' : 'assets';
  const verb = impact.direction === 'upstream' ? 'this depends on' : 'depend on this';
  if (impact.total === 0) {
    return impact.direction === 'upstream'
      ? 'No recorded dependencies'
      : 'Nothing recorded depends on this';
  }
  return impact.truncated
    ? `At least ${impact.total} ${noun} ${verb}`
    : `${impact.total} ${noun} ${verb}`;
}

/**
 * The picker's preview sentence, so a user can read the edge before creating it.
 *
 * Direction is the single most confusable part of declaring an edge — "runs on"
 * pointing the wrong way is a plausible-looking row that inverts every impact
 * answer downstream of it — so the modal shows the whole sentence with both
 * names in it rather than a dropdown and a hope.
 */
export function declarationPreview(
  type: RelationshipType, direction: 'out' | 'in', thisName: string, peerName_: string,
): string {
  return direction === 'out'
    ? `${thisName} ${TYPE_LABEL[type]} ${peerName_}`
    : `${peerName_} ${TYPE_LABEL[type]} ${thisName}`;
}
