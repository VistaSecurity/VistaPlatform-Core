// The Approvals source facet (ADR-0006 D6).
//
// "Approvals becomes the single proposal queue. No second queue anywhere. Every
// AI or rule proposal is a row here."
//
// The facet answers "where did this come from", which is the first thing a
// reviewer wants to know and the thing that decides how much scrutiny a row
// deserves: a serial read off a device is not the same claim as a classifier's
// guess. Pure so the mapping is unit-tested rather than eyeballed.

/** The seven sources a queue row can have. */
export const APPROVAL_SOURCES = [
  'discovered', 'imported', 'sbom', 'cmdb', 'matcher', 'classifier', 'assistant',
] as const;
export type ApprovalSource = (typeof APPROVAL_SOURCES)[number];

export const SOURCE_LABEL: Readonly<Record<ApprovalSource, string>> = {
  discovered: 'Discovered',
  imported: 'Imported',
  sbom: 'Declared from SBOM upload',
  cmdb: 'Pulled from CMDB',
  matcher: 'Proposed by matcher',
  classifier: 'Proposed by classifier',
  assistant: 'Proposed by assistant',
};

export const SOURCE_ICON: Readonly<Record<ApprovalSource, string>> = {
  discovered: 'radar',
  imported: 'file-up',
  sbom: 'package',
  cmdb: 'database',
  matcher: 'git-merge',
  classifier: 'shapes',
  assistant: 'sparkles',
};

export const SOURCE_HELP: Readonly<Record<ApprovalSource, string>> = {
  discovered: 'A sensor or scan observed this on the network.',
  imported: 'Came in through the spreadsheet import.',
  sbom: 'An uploaded bill of materials said what it was about, and this application was created from it. Nothing measured it, and an upload is a file arriving at an endpoint — so it waits here for a person.',
  cmdb: 'Pulled from a connected CMDB.',
  matcher: 'The identification engine thinks two records are one thing.',
  classifier: 'A classifier proposed this class; nothing measured it.',
  assistant: 'The AI assistant proposed this. Nothing here is applied without a person accepting it.',
};

/** What the queue row is: an asset waiting to be admitted, a proposal that two
 *  existing assets are one thing, a proposal about how two assets are
 *  connected, or a proposal about what one of them IS. */
export type QueueRowKind = 'asset' | 'merge' | 'relationship' | 'class';

/**
 * Which source a pending ASSET came from.
 *
 * `class_source_kind` records how the class was decided, and `class_source_ref`
 * names the producer that decided it (`classifier:<model>`, `cmdb:<profile>`,
 * `user:<id>`). Together they are enough to place a row without a seventh
 * column on the API: `inferred` + a `classifier:` ref is a classifier proposal,
 * `inferred` + an `assistant:` ref is the assistant's.
 *
 * Anything that does not match falls to `discovered`, which is the truthful
 * default — the queue existed for network discoveries before anything else
 * could write to it.
 */
export function sourceOfAsset(a: {
  class_source_kind?: string | null;
  class_source_ref?: string | null;
  discovery_method?: string | null;
}): ApprovalSource {
  const ref = (a.class_source_ref ?? '').toLowerCase();
  if (ref.startsWith('assistant')) return 'assistant';
  if (ref.startsWith('classifier')) return 'classifier';
  if (ref.startsWith('cmdb')) return 'cmdb';
  // `sbom:<upload id>` — the producer prefix identity.Source.Producer() reads.
  // It is checked BEFORE the source_kind branches below because an SBOM-created
  // asset is `declared`, which would otherwise fall through to `discovered` and
  // tell a reviewer a sensor saw it on the network.
  if (ref.startsWith('sbom')) return 'sbom';
  const kind = (a.class_source_kind ?? '').toLowerCase();
  if (kind === 'imported') {
    // An import that came through a CMDB connector is a CMDB pull; one that came
    // through the spreadsheet wizard is an import. The ref is what tells them
    // apart, and it was already checked above.
    return (a.discovery_method ?? '').toLowerCase().includes('cmdb') ? 'cmdb' : 'imported';
  }
  if (kind === 'inferred') return 'classifier';
  return 'discovered';
}

/**
 * A merge proposal is the matcher's unless its producer says otherwise.
 *
 * `source` names the producer that raised it (`matcher`, `assistant:<model>`,
 * …) and `source_kind` is how the observation itself was made. The producer is
 * what the facet groups by — "who is asking me this", not "how was the thing
 * seen".
 */
export function sourceOfProposal(p: { source?: string | null; source_kind?: string | null }): ApprovalSource {
  const by = (p.source ?? '').toLowerCase();
  if (by.startsWith('assistant')) return 'assistant';
  if (by.startsWith('classifier')) return 'classifier';
  return 'matcher';
}

/**
 * Which source a RELATIONSHIP proposal came from (ADR-0003 D3).
 *
 * `source_ref` names the producer that drew the edge — `matcher`, `assistant`,
 * `cmdb:<profile>`, `sensor:<id>`, `user:<id>` — and is what the facet groups
 * by, the same "who is asking me this" rule the merge proposals follow.
 *
 * The fallback is `matcher` rather than `discovered`, and the difference
 * matters: a relationship proposal is by construction something nothing will
 * promote on its own, so it was drawn by an inference engine rather than
 * observed and waiting. Calling an unattributed one "discovered" would tell a
 * reviewer a sensor saw it.
 */
export function sourceOfRelationshipProposal(
  p: { source_ref?: string | null; source_kind?: string | null },
): ApprovalSource {
  const ref = (p.source_ref ?? '').toLowerCase();
  if (ref.startsWith('assistant')) return 'assistant';
  if (ref.startsWith('classifier')) return 'classifier';
  if (ref.startsWith('cmdb')) return 'cmdb';
  if (ref.startsWith('sensor') || ref.startsWith('interrogation') || ref.startsWith('cloud')) return 'discovered';
  const kind = (p.source_kind ?? '').toLowerCase();
  if (kind === 'imported') return 'imported';
  if (kind === 'measured') return 'discovered';
  return 'matcher';
}

/**
 * A CLASS proposal is the classifier's, always.
 *
 * There is one producer of them — the curated rule engine, which writes
 * `classifier:rules` — and the facet's job is "who is asking me this". A second
 * producer (workstream 4.2's learned classifier, the assistant) would write its
 * own ref and is read here rather than assumed, so the chip moves with the
 * producer instead of with this function.
 *
 * The fallback is `classifier` and not `discovered`: a class proposal is by
 * construction something a RULE argued, never something a sensor observed, and
 * calling an unattributed one "discovered" would tell a reviewer the network
 * said so.
 */
export function sourceOfClassProposal(p: { source?: string | null }): ApprovalSource {
  const by = (p.source ?? '').toLowerCase();
  if (by.startsWith('assistant')) return 'assistant';
  return 'classifier';
}

/**
 * Counts per source over every row kind, seeded with every source at zero.
 *
 * Seeding matters: a facet that hides the sources with no rows teaches nothing
 * about what the queue can contain, and it makes the list jump as rows arrive.
 * A zero is a real answer here.
 */
export function countBySource(
  assets: { class_source_kind?: string | null; class_source_ref?: string | null; discovery_method?: string | null }[],
  proposals: { source?: string | null; source_kind?: string | null }[],
  relationshipProposals: { source_ref?: string | null; source_kind?: string | null }[] = [],
  classProposals: { source?: string | null }[] = [],
): Record<ApprovalSource, number> {
  const out = Object.fromEntries(APPROVAL_SOURCES.map((s) => [s, 0])) as Record<ApprovalSource, number>;
  for (const a of assets) out[sourceOfAsset(a)] += 1;
  for (const p of proposals) out[sourceOfProposal(p)] += 1;
  // Every row kind is counted. The chips claim to describe the queue, and a row
  // kind missing from them makes the numbers under-report the work waiting —
  // which is the same lie the merge total told before it was read off `total`.
  for (const r of relationshipProposals) out[sourceOfRelationshipProposal(r)] += 1;
  for (const c of classProposals) out[sourceOfClassProposal(c)] += 1;
  return out;
}

/** Keeps the rows whose source is selected. An EMPTY selection means "all" —
 *  not "none", which would render an empty queue as if the work were done. */
export function matchesSourceFilter(source: ApprovalSource, selected: ApprovalSource[]): boolean {
  return selected.length === 0 || selected.includes(source);
}
