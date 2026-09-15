// Headless review logic for ADR-0008's Author seam: drafting compliance
// controls from a pasted standard.
//
// Nothing here renders anything. Both authoring UIs — admin-ui-v2 Catalog →
// Frameworks and frontend-v2 Settings → Policies → Custom Policies — share the
// same modal states, the same accept/discard bookkeeping and the same citation
// highlighting, and share nothing else: their design systems have no component
// in common. Two copies of a state machine is how two surfaces of one feature
// drift apart, so the state machine lives here and each app brings its own
// chrome and its own endpoints.
//
// The wire types come from the generated client, not from hand-written copies:
// the spec is the source of truth (ADR-0001) and a second declaration of the
// same shape is a second thing to keep in step.
import type { complianceEngineComponents } from '@vistasecurity/api-contract';

export type ControlDraft = complianceEngineComponents['schemas']['ControlDraft'];
export type MeasurementDraft = complianceEngineComponents['schemas']['MeasurementDraft'];
export type DraftCitation = complianceEngineComponents['schemas']['DraftCitation'];
export type DraftDrop = complianceEngineComponents['schemas']['DraftDrop'];
export type DraftControlsResponse = complianceEngineComponents['schemas']['DraftControlsResponse'];
export type AuthorAvailability = complianceEngineComponents['schemas']['AuthorAvailability'];

/** What has happened to one draft in the review list. */
export type DraftStatus = 'pending' | 'accepting' | 'accepted' | 'discarded' | 'failed';

export interface DraftItem {
  /** Stable key for React. Index-based: the list never reorders. */
  key: string;
  draft: ControlDraft;
  status: DraftStatus;
  /** Why accepting it failed, when status is 'failed'. */
  error?: string;
}

/**
 * Every state the modal can be in, as a discriminated union.
 *
 * `review` deliberately keeps `text` — the pasted standard — because the cited
 * passages are byte spans into it and the review panel highlights them. Losing
 * the paste on success would leave the citations unresolvable, which is the
 * whole point of having them.
 */
export type ReviewState =
  | { phase: 'idle'; text: string }
  | { phase: 'running'; text: string }
  | { phase: 'error'; text: string; message: string }
  | {
      phase: 'review';
      text: string;
      modelId: string;
      items: DraftItem[];
      dropped: DraftDrop[];
      notes: string[];
      truncated: boolean;
    };

export type ReviewAction =
  | { type: 'edit'; text: string }
  | { type: 'run' }
  | { type: 'succeeded'; response: DraftControlsResponse }
  | { type: 'failed'; message: string }
  | { type: 'accepting'; key: string }
  | { type: 'accepted'; key: string }
  | { type: 'acceptFailed'; key: string; message: string }
  | { type: 'discarded'; key: string }
  | { type: 'reset' };

export const initialReviewState: ReviewState = { phase: 'idle', text: '' };

/**
 * The review state machine.
 *
 * Two rules it enforces that a component would otherwise get wrong:
 *
 * - A draft that has been accepted or discarded cannot go back to pending. The
 *   accept call created a row; offering the button again would create a second.
 * - A failed accept returns to `failed`, NOT to `pending`. "Retry" is a
 *   deliberate act on a draft the user can see failed, and silently re-arming
 *   it would make a double-create one stray click away.
 */
export function reviewReducer(state: ReviewState, action: ReviewAction): ReviewState {
  switch (action.type) {
    case 'edit':
      // Editing the paste after a run abandons the drafts on purpose: they cite
      // byte offsets into the OLD text, so keeping them beside new text would
      // highlight the wrong passages — evidence pointing at something it did
      // not come from is worse than no evidence.
      return { phase: 'idle', text: action.text };
    case 'run':
      return { phase: 'running', text: state.text };
    case 'failed':
      return { phase: 'error', text: state.text, message: action.message };
    case 'succeeded':
      return {
        phase: 'review',
        text: state.text,
        modelId: action.response.model_id,
        items: (action.response.drafts ?? []).map((draft, i) => ({
          key: `draft-${i}`,
          draft,
          status: 'pending' as DraftStatus,
        })),
        dropped: action.response.dropped?.reasons ?? [],
        notes: action.response.notes ?? [],
        truncated: action.response.truncated ?? false,
      };
    case 'accepting':
      return withStatus(state, action.key, 'accepting');
    case 'accepted':
      return withStatus(state, action.key, 'accepted');
    case 'acceptFailed':
      return withStatus(state, action.key, 'failed', action.message);
    case 'discarded':
      return withStatus(state, action.key, 'discarded');
    case 'reset':
      return { phase: 'idle', text: '' };
    default:
      return state;
  }
}

function withStatus(state: ReviewState, key: string, status: DraftStatus, error?: string): ReviewState {
  if (state.phase !== 'review') return state;
  return {
    ...state,
    items: state.items.map((item) => {
      if (item.key !== key) return item;
      // Terminal states stay terminal. The row exists; a second accept would
      // create a second one.
      if (item.status === 'accepted' || item.status === 'discarded') return item;
      return { ...item, status, error };
    }),
  };
}

/** How many drafts still need a decision. Drives the "3 left to review" line. */
export function pendingCount(state: ReviewState): number {
  if (state.phase !== 'review') return 0;
  return state.items.filter((i) => i.status === 'pending' || i.status === 'failed').length;
}

export function acceptedCount(state: ReviewState): number {
  if (state.phase !== 'review') return 0;
  return state.items.filter((i) => i.status === 'accepted').length;
}

/** A segment of the pasted text, flagged as cited or not. */
export interface TextSegment {
  text: string;
  cited: boolean;
}

/**
 * Parse a `"<start>-<end>"` citation ref. Returns null for anything else, so a
 * malformed ref renders as no highlight rather than as a highlight of the wrong
 * thing.
 */
export function parseCitationRef(ref: string): { start: number; end: number } | null {
  const m = /^(\d+)-(\d+)$/.exec(ref.trim());
  if (!m) return null;
  const start = Number(m[1]);
  const end = Number(m[2]);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) return null;
  return { start, end };
}

/**
 * Split `text` into cited and uncited segments, for highlighting a draft's
 * source passages inside the pasted standard.
 *
 * Offsets are BYTE offsets into the UTF-8 text the server redacted and sent —
 * JavaScript strings are UTF-16, so slicing by these numbers directly would cut
 * in the wrong place on any non-ASCII document. The text is encoded, sliced,
 * and decoded, which is the only way to land where the server did.
 *
 * Overlapping and out-of-order citations are merged and sorted, and anything
 * outside the text is dropped: a highlight is a claim about where a draft came
 * from, and a wrong one is worse than none.
 */
export function citedSegments(text: string, citations: DraftCitation[] | undefined): TextSegment[] {
  const bytes = new TextEncoder().encode(text);
  const ranges = (citations ?? [])
    .map((c) => parseCitationRef(c.ref ?? ''))
    .filter((r): r is { start: number; end: number } => r !== null && r.end <= bytes.length)
    .sort((a, b) => a.start - b.start);

  if (ranges.length === 0) return text ? [{ text, cited: false }] : [];

  const merged: { start: number; end: number }[] = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
    else merged.push({ ...r });
  }

  const decoder = new TextDecoder();
  const out: TextSegment[] = [];
  let cursor = 0;
  for (const r of merged) {
    if (r.start > cursor) out.push({ text: decoder.decode(bytes.slice(cursor, r.start)), cited: false });
    out.push({ text: decoder.decode(bytes.slice(r.start, r.end)), cited: true });
    cursor = r.end;
  }
  if (cursor < bytes.length) out.push({ text: decoder.decode(bytes.slice(cursor)), cited: false });
  return out.filter((s) => s.text !== '');
}

/**
 * Plain-language wording for a drop reason.
 *
 * The drop report is the honest half of this feature — it says what the model
 * produced that was thrown away and why — so it has to read as a sentence a
 * compliance author can act on, not as an enum value. An unrecognised reason
 * falls back to the raw code rather than to "unknown", so a new server-side
 * reason is visible rather than swallowed.
 */
export function dropReasonLabel(reason: string): string {
  switch (reason) {
    case 'no_citation':
      return 'Discarded: it cited no passage of your text, so there is nothing to check it against.';
    case 'unresolvable_citation':
      return 'Discarded: the passage it cited is not in your text.';
    case 'missing_title':
      return 'Discarded: it had no title.';
    case 'unknown_measurement_type':
      return 'Rule dropped: this platform has no measurement with that code. The control was kept without it.';
    case 'invalid_predicate':
      return 'Rule dropped: the condition was not valid for that measurement. The control was kept without it.';
    case 'over_limit':
      return 'Discarded: past the per-run limit.';
    default:
      return reason;
  }
}

/** A one-line summary of a drafted rule, for the review list. */
export function measurementSummary(m: MeasurementDraft): string {
  const p = (m.predicate ?? {}) as Record<string, unknown>;
  switch (m.rule_type) {
    case 'threshold':
      return `${m.measurement_type_code} ${String(p.operator ?? '?')} ${String(p.value ?? '?')}`;
    case 'presence':
      return `${m.measurement_type_code} ${p.required === false || p.exists === false ? 'absent' : 'present'}`;
    case 'pattern':
      return `${m.measurement_type_code} matches /${String(p.pattern ?? '')}/${String(p.flags ?? '')}`;
    case 'range':
      return `${m.measurement_type_code} in [${p.min ?? '−∞'}, ${p.max ?? '∞'}]`;
    default:
      return m.measurement_type_code;
  }
}

/**
 * The `source_ref` an accepted draft is stored under, mirroring the Go
 * SourceRefFor. Empty model id falls back to the seam name rather than storing
 * `author:`, which would read as a model called nothing.
 */
export function sourceRefFor(modelId: string): string {
  return modelId ? `author:${modelId}` : 'author:model';
}

/**
 * Whether the drafting action should be offered at all.
 *
 * `undefined` — the availability query has not answered yet, or failed — is
 * false. A capability offered before it is known to exist is one a user clicks
 * and gets an error from.
 */
export function draftingOffered(availability: AuthorAvailability | undefined): boolean {
  return availability?.available === true;
}
