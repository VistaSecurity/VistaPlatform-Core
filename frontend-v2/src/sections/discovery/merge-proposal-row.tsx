// A merge proposal in the Approvals queue (ADR-0006 D6).
//
// "Merge proposals as a row kind: two or more asset cards side by side, the
// identifiers that matched, the confidence, accept or keep separate."
//
// The shape the server sends is an OBSERVATION — a new sighting whose
// identifiers resolved to more than one existing asset — beside the CANDIDATES
// it could be, each carrying the identifiers that matched it and the matcher's
// score. So the row reads left to right: this is what we just saw, and here is
// what it might already be.
//
// Cards side by side is the point. A reviewer is being asked whether two records
// are the same physical thing, and that cannot be answered from a summary line:
// they need to see both, and they need to see WHICH identifiers matched, because
// that is the whole of the evidence. A proposal showing only a confidence number
// is asking for a coin flip.
import { Fragment, useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, MiniBar } from '../../components/ui';
import { classLabel, identifierKindLabel, sourceKindLabel } from '../inventory/asset-shape';
import { SOURCE_LABEL, sourceOfProposal } from './approval-sources';
import type { MergeCandidate, MergeProposal, MergeScoreFactor } from '../inventory/asset-queries';

/** One entry of a candidate's `matched_identifiers`, which the contract leaves
 *  as an open object. Narrowed here to the fields the row reads. */
export interface MatchedIdentifier { kind?: string; value?: string; scope?: string }

export function readIdentifier(raw: unknown): MatchedIdentifier {
  if (!raw || typeof raw !== 'object') return {};
  const r = raw as Record<string, unknown>;
  return {
    kind: typeof r.kind === 'string' ? r.kind : undefined,
    value: typeof r.value === 'string' ? r.value : undefined,
    scope: typeof r.scope === 'string' ? r.scope : undefined,
  };
}

/** The matcher's score as a percentage. ZERO means UNSCORED, not "certainly
 *  wrong" — so it is shown as an absence rather than as a 0% bar that reads as
 *  a confident rejection. */
export function scoreLabel(score: number): string | null {
  if (!Number.isFinite(score) || score <= 0) return null;
  return `${Math.round(score <= 1 ? score * 100 : score)}%`;
}

/** The best human label for a candidate. */
export function candidateName(c: MergeCandidate): string {
  return c.display_name ?? c.hostname ?? c.asset_id.slice(0, 8);
}

/** How many of the matcher's reasons a card shows. */
export const TOP_REASONS_SHOWN = 3;

/**
 * The reasons worth showing, strongest first.
 *
 * The server already orders the explanation by absolute contribution, so this
 * takes the front of the list rather than re-sorting — a UI that re-derived the
 * order would be a second opinion about which signal mattered most, and the
 * model's own ordering is the only one that is actually true of the score.
 *
 * Reasons that count AGAINST the match are kept, not filtered out. A merge
 * proposal is a question, and hiding the evidence against would turn the panel
 * into a case for the merge rather than a summary of it.
 */
export function topReasons(c: MergeCandidate): MergeScoreFactor[] {
  return (c.explanation ?? []).slice(0, TOP_REASONS_SHOWN);
}

/** A factor's contribution as a sign, for the caret and the colour. */
export function factorDirection(f: MergeScoreFactor): 'for' | 'against' {
  return f.contribution >= 0 ? 'for' : 'against';
}

/** The model's reasons, as a short list under the score bar. */
function ScoreReasons({ candidate }: { candidate: MergeCandidate }) {
  const reasons = topReasons(candidate);
  if (reasons.length === 0) return null;
  return (
    <ul
      data-testid="merge-score-reasons"
      style={{ listStyle: 'none', margin: '6px 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 2 }}
    >
      {reasons.map((f) => {
        const against = factorDirection(f) === 'against';
        return (
          <li
            key={f.feature}
            data-testid="merge-score-reason"
            data-direction={against ? 'against' : 'for'}
            style={{ display: 'flex', alignItems: 'flex-start', gap: 5, fontSize: 10.5, lineHeight: 1.4, color: 'var(--app-t3)' }}
          >
            <Icon
              name={against ? 'arrow-down' : 'arrow-up'}
              size={10}
              style={{ color: against ? 'var(--warn-strong)' : 'var(--ok)', flex: 'none', marginTop: 2 }}
            />
            <span>{f.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

function CandidateCard({ candidate, selected, onSelect, selectable }: {
  candidate: MergeCandidate;
  selected: boolean;
  onSelect: () => void;
  selectable: boolean;
}) {
  const idents = (candidate.matched_identifiers ?? []).map(readIdentifier);
  const pct = scoreLabel(candidate.score);
  // A candidate that can no longer be merged into is SHOWN, not dropped: "a
  // proposal that silently loses a candidate reads as if it only ever had one".
  const dead = candidate.deleted;
  return (
    <div
      data-testid="merge-candidate"
      data-selected={selected ? 'true' : 'false'}
      style={{
        flex: 1, minWidth: 220, padding: '11px 13px', borderRadius: 11,
        border: `1px solid ${selected ? 'var(--accent)' : 'var(--app-border2)'}`,
        background: selected ? 'color-mix(in srgb, var(--accent) 9%, transparent)' : 'var(--app-panel2)',
        opacity: dead ? 0.6 : 1,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 7, minWidth: 0 }}>
        {selectable && (
          <input
            type="radio"
            checked={selected}
            disabled={dead}
            onChange={onSelect}
            aria-label={`Keep ${candidateName(candidate)} as the surviving asset`}
            style={{ accentColor: 'var(--accent)', marginTop: 2, flex: 'none' }}
          />
        )}
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {candidateName(candidate)}
          </div>
          <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
            {[candidate.class_label ?? classLabel(candidate.class_key), candidate.asset_status].filter(Boolean).join(' · ') || 'unclassified'}
          </div>
        </div>
        <Link
          to={`/inventory/assets/${candidate.asset_id}`}
          title="Open this asset's page"
          className="ui-btn sm ghost"
          style={{ flex: 'none', padding: '0 6px', textDecoration: 'none' }}
        >
          <Icon name="external-link" size={12} />
        </Link>
      </div>

      {dead && (
        <div style={{ fontSize: 10.5, color: 'var(--warn-strong)', marginTop: 6 }}>
          No longer available — deleted, or merged away by an earlier decision.
        </div>
      )}

      {pct && (
        <div style={{ marginTop: 7 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{ width: 44 }}><MiniBar pct={Math.round(candidate.score <= 1 ? candidate.score * 100 : candidate.score)} color={candidate.score >= 0.8 ? 'var(--ok)' : 'var(--warn)'} /></div>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }} title="How likely the matcher thinks it is that these are the same thing. 50% means as likely as not.">{pct}</span>
          </div>
          {/* The score's working. A number on its own can only be agreed with;
              the reviewer is being asked to decide whether two records are one
              physical thing, and these are what the model actually weighed. */}
          <ScoreReasons candidate={candidate} />
        </div>
      )}

      {/* The MATCHED identifiers are the evidence — the reason this candidate is
          on the card at all — so they are what the card is mostly made of. */}
      <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {idents.length === 0 && <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>No matching identifiers listed.</div>}
        {idents.map((i, n) => (
          <div
            key={`${i.kind ?? ''}-${i.value ?? ''}-${n}`}
            data-testid="matched-identifier"
            style={{
              display: 'flex', alignItems: 'center', gap: 7, padding: '2px 6px', borderRadius: 6,
              background: 'color-mix(in srgb, var(--accent) 14%, transparent)',
              border: '1px solid color-mix(in srgb, var(--accent) 40%, transparent)',
            }}
          >
            <Icon name="link" size={10} style={{ color: 'var(--accent)', flex: 'none' }} />
            <span style={{ fontSize: 10.5, color: 'var(--app-t3)', flex: 'none', minWidth: 92 }}>{identifierKindLabel(i.kind ?? '')}</span>
            <span className="mono" title={i.value} style={{ fontSize: 11, color: 'var(--app-t1)', fontWeight: 600, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.value ?? '—'}</span>
          </div>
        ))}
      </div>

      {candidate.reason && (
        <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 7, lineHeight: 1.45 }}>{candidate.reason}</div>
      )}
    </div>
  );
}

/** The observation card — what was just seen. Not selectable: the survivor is
 *  one of the EXISTING assets, and the observation is archived into it. */
function ObservationCard({ observation }: { observation: MergeCandidate }) {
  const idents = (observation.matched_identifiers ?? []).map(readIdentifier);
  return (
    <div style={{ flex: 1, minWidth: 220, padding: '11px 13px', borderRadius: 11, border: '1px dashed var(--app-border2)', background: 'var(--app-panel2)' }}>
      <div className="eyebrow-app" style={{ marginBottom: 3 }}>Just discovered</div>
      <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {candidateName(observation)}
      </div>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
        {observation.class_label ?? classLabel(observation.class_key) ?? 'unclassified'}
      </div>
      <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {idents.map((i, n) => (
          <div key={`${i.kind ?? ''}-${i.value ?? ''}-${n}`} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span style={{ fontSize: 10.5, color: 'var(--app-t3)', flex: 'none', minWidth: 92 }}>{identifierKindLabel(i.kind ?? '')}</span>
            <span className="mono" title={i.value} style={{ fontSize: 11, color: 'var(--app-t2)', minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.value ?? '—'}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/** The candidate a fresh row should have selected: the highest-scoring one that
 *  is still available, or the first available one when nothing is scored. */
export function defaultSurvivor(candidates: MergeCandidate[]): string | undefined {
  const alive = candidates.filter((c) => !c.deleted);
  if (alive.length === 0) return undefined;
  const best = alive.reduce((a, b) => (b.score > a.score ? b : a), alive[0]);
  return best.asset_id;
}

export function MergeProposalRow({ proposal, onAccept, onKeepSeparate, busy }: {
  proposal: MergeProposal;
  onAccept: (survivorAssetId: string) => void;
  onKeepSeparate: () => void;
  busy?: boolean;
}) {
  const [survivor, setSurvivor] = useState<string | undefined>(() => defaultSurvivor(proposal.candidates));
  const source = sourceOfProposal(proposal);
  const alive = proposal.candidates.filter((c) => !c.deleted);
  // Merging is destructive, so the server refuses to pick a survivor and neither
  // does this row: with more than one candidate still available the reviewer
  // chooses, and with none available there is nothing to merge into.
  const mustChoose = alive.length > 1;
  const canMerge = !!survivor && alive.some((c) => c.asset_id === survivor);

  return (
    <div
      data-testid="merge-proposal-row"
      style={{ padding: '13px 15px', borderRadius: 13, border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)', background: 'color-mix(in srgb, var(--accent) 5%, transparent)', marginBottom: 11 }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 11, flexWrap: 'wrap' }}>
        <Icon name="git-merge" size={15} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)' }}>
          {proposal.candidates.length === 1
            ? 'This looks like something you already have'
            : `This matches ${proposal.candidates.length} assets you already have`}
        </span>
        <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{SOURCE_LABEL[source]}</span>
        {proposal.auto_accepted && (
          <span
            title="A matcher scored the top candidate above your threshold and wrote the sighting into it. The remaining candidates are still your decision."
            style={{ fontSize: 10.5, fontWeight: 600, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn) 13%, transparent)', borderRadius: 40, padding: '2px 8px' }}
          >
            Auto-accepted into one
          </span>
        )}
        <div style={{ flex: 1 }} />
        <PermissionGate
          permission={TENANT_PERMISSIONS.assets.update}
          fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>Read-only</span>}
        >
          <button
            className="ui-btn sm accent"
            disabled={busy || !canMerge}
            title={canMerge
              ? 'Merge into the selected asset. Its History records what was merged in.'
              : 'No candidate is available to merge into.'}
            onClick={() => { if (survivor) onAccept(survivor); }}
            style={{ opacity: canMerge ? 1 : 0.5 }}
          >
            <Icon name="git-merge" size={12} />Merge
          </button>
          <button
            className="ui-btn sm"
            disabled={busy}
            title="These are different things. The matcher will not propose this again; the discovery still waits for ordinary approval."
            onClick={onKeepSeparate}
          >
            <Icon name="split" size={12} />Keep separate
          </button>
        </PermissionGate>
      </div>

      {proposal.reason && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginBottom: 9 }}>{proposal.reason}</div>
      )}

      {mustChoose && (
        // Which record SURVIVES is a real decision, not a formality: the other
        // one's id becomes a tombstone pointing at it.
        <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginBottom: 9 }}>
          Pick which asset survives the merge — the discovery is folded into it, and everything on the others moves across.
        </div>
      )}

      <div style={{ display: 'flex', gap: 11, alignItems: 'stretch', flexWrap: 'wrap' }}>
        {proposal.observation && <ObservationCard observation={proposal.observation} />}
        {proposal.candidates.map((c) => (
          <Fragment key={c.asset_id}>
            <div style={{ display: 'flex', alignItems: 'center', color: 'var(--app-t3)', flex: 'none' }}>
              <Icon name="equal" size={14} />
            </div>
            <CandidateCard
              candidate={c}
              selected={survivor === c.asset_id}
              selectable={proposal.candidates.length > 1}
              onSelect={() => setSurvivor(c.asset_id)}
            />
          </Fragment>
        ))}
      </div>

      {proposal.source_kind && (
        <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 9 }}>
          Observed as {sourceKindLabel(proposal.source_kind)} · proposed {new Date(proposal.proposed_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}
