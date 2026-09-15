// Discovery → Approvals — "Auto-merged by the matcher (last 30 days)".
//
// A tenant who sets Settings → Identification rules → auto-accept above zero
// has told the platform it may merge two of their assets without asking. That
// is the only act in the identification path with no human in it, so it has to
// be VISIBLE to a human afterwards, on the page where identity decisions are
// already reviewed, with the score and the model's reasons beside each one.
//
// It is deliberately NOT a queue. Nothing here needs deciding and everything
// here already happened — there are no buttons, and the section does not render
// at all when it is empty, which is every tenant on the default threshold of
// zero. A section that appeared and said "nothing" would imply the capability
// was on.
import { Link } from 'react-router';
import { Icon, MiniBar } from '../../components/ui';
import { classLabel } from '../inventory/asset-shape';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { candidateName, scoreLabel, topReasons } from './merge-proposal-row';

/**
 * The caption under the heading.
 *
 * It says three things and the third is the one that matters: these already
 * happened, your threshold allowed them, and **there is no undo**. The settings
 * card warns before you turn the capability on; this warns while you are
 * reading what it did, which is when the question actually occurs to someone.
 */
export const AUTO_MERGED_CAPTION =
  'already done — your auto-accept threshold allowed these without asking, and there is no way to reverse one from here';

/** The candidate the matcher merged into, when the envelope names one. */
export function acceptedCandidate(p: MergeProposal): MergeCandidate | undefined {
  if (!p.accepted_asset_id) return undefined;
  return p.candidates.find((c) => c.asset_id === p.accepted_asset_id);
}

/**
 * The other candidates — the ones the matcher did NOT merge into.
 *
 * They still matter, and are shown: an auto-accept settles where the SIGHTING
 * went, not whether the remaining candidates are the same thing, and those are
 * still a person's decision. A row that showed only the winner would read as if
 * the whole question had been answered.
 */
export function remainingCandidates(p: MergeProposal): MergeCandidate[] {
  return p.candidates.filter((c) => c.asset_id !== p.accepted_asset_id);
}

/** "reviewed" once a person has decided the leftovers; otherwise not. */
export function isReviewed(p: MergeProposal): boolean {
  return p.status !== 'pending';
}

function AutoMergedRow({ proposal }: { proposal: MergeProposal }) {
  const winner = acceptedCandidate(proposal);
  const others = remainingCandidates(proposal);
  const pct = scoreLabel(proposal.accepted_score ?? 0);
  const reasons = winner ? topReasons(winner) : [];

  return (
    <div
      data-testid="auto-merged-row"
      style={{
        padding: '11px 13px', borderRadius: 11, marginBottom: 9,
        border: '1px solid var(--app-border2)', background: 'var(--app-panel2)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexWrap: 'wrap' }}>
        <Icon name="git-merge" size={14} style={{ color: 'var(--app-t3)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>
          {winner ? `Merged into ${candidateName(winner)}` : 'Merged into an asset that no longer exists'}
        </span>
        {winner && (
          <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
            {winner.class_label ?? classLabel(winner.class_key)}
          </span>
        )}
        {winner && (
          <Link
            to={`/inventory/assets/${winner.asset_id}`}
            title="Open the asset it was merged into"
            className="ui-btn sm ghost"
            style={{ padding: '0 6px', textDecoration: 'none' }}
          >
            <Icon name="external-link" size={12} />
          </Link>
        )}
        <div style={{ flex: 1 }} />
        {pct && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{ width: 44 }}>
              <MiniBar
                pct={Math.round((proposal.accepted_score ?? 0) * 100)}
                color={(proposal.accepted_score ?? 0) >= 0.8 ? 'var(--ok)' : 'var(--warn)'}
              />
            </div>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{pct}</span>
          </div>
        )}
        <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
          {new Date(proposal.proposed_at).toLocaleString()}
        </span>
      </div>

      {reasons.length > 0 && (
        <ul
          data-testid="auto-merged-reasons"
          style={{ listStyle: 'none', margin: '7px 0 0', padding: 0, display: 'flex', flexWrap: 'wrap', gap: '3px 12px' }}
        >
          {reasons.map((f) => (
            <li key={f.feature} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, color: 'var(--app-t3)' }}>
              <Icon
                name={f.contribution >= 0 ? 'arrow-up' : 'arrow-down'}
                size={10}
                style={{ color: f.contribution >= 0 ? 'var(--ok)' : 'var(--warn-strong)', flex: 'none' }}
              />
              {f.label}
            </li>
          ))}
        </ul>
      )}

      {others.length > 0 && (
        <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 7, lineHeight: 1.5 }}>
          {isReviewed(proposal)
            ? `${others.length} other candidate${others.length === 1 ? '' : 's'} — reviewed.`
            : `${others.length} other candidate${others.length === 1 ? '' : 's'} still waiting for a person: ${others.map(candidateName).join(', ')}.`}
        </div>
      )}

      {proposal.accepted_model_id && (
        <div className="mono" style={{ fontSize: 10, color: 'var(--app-t3)', marginTop: 6 }}>
          decided by {proposal.accepted_model_id}
        </div>
      )}
    </div>
  );
}

export function AutoMergedSection({ merges, windowDays }: { merges: MergeProposal[]; windowDays: number }) {
  // Empty means the capability is off, or on and quiet. Either way there is
  // nothing to say and a heading over an empty list would say something.
  if (merges.length === 0) return null;
  return (
    <div data-testid="auto-merged-section" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
        <div className="eyebrow-app">
          Auto-merged by the matcher (last {windowDays} days) ({merges.length})
        </div>
        {/* The irreversibility is stated HERE as well as on the settings card.
            A tenant reading this list is looking at merges that already
            happened, and the one question the list invites — "can I put that
            back?" — has to be answered where it is asked, not only on the page
            that turned the capability on months ago. */}
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
          {AUTO_MERGED_CAPTION}
        </span>
        <Link
          to="/settings/identification-rules"
          style={{ fontSize: 11.5, color: 'var(--accent)', textDecoration: 'none' }}
        >
          Change the threshold
        </Link>
      </div>
      {merges.map((m) => <AutoMergedRow key={m.id} proposal={m} />)}
    </div>
  );
}
