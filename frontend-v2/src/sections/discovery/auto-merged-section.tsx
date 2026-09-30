// Discovery → Approvals — "Merged automatically (last 30 days)".
//
// Two things merge two of a tenant's assets without a person deciding, and this
// is where both are listed: the learned matcher, when the tenant has set an
// auto-accept threshold above zero, and the same-device RULE, which is on by
// default ( Phase 4, owner decision D1). That is the only act in the
// identification path with no human in it, so it has to be VISIBLE to a human
// afterwards, on the page where identity decisions are already reviewed, with
// the reasons beside each one — the matcher's score and working, or the rule's
// evidence.
//
// It is deliberately NOT a queue. Nothing here needs deciding and everything
// here already happened — there are no buttons.
//
// It always renders, and an empty list says so. It used to vanish when empty,
// because the only capability behind it was off by default and a section that
// said "nothing" would have implied it was on. The rule merge IS on by default,
// so "nothing has been merged" is now a real and useful answer — and the
// section hiding itself is the one state that could not distinguish "the rule
// ran and found nothing" from "this page does not report on the rule".
import { Link } from 'react-router';
import { Icon, MiniBar, matcherConfidencePercent, percentLabel } from '../../components/ui';
import { classLabel } from '../inventory/asset-shape';
import type { MergeCandidate, MergeProposal } from '../inventory/asset-queries';
import { candidateName, topReasons } from './merge-proposal-row';

/**
 * The caption under the heading.
 *
 * It says three things and the third is the one that matters: these already
 * happened, your threshold allowed them, and **there is no undo**. The settings
 * card warns before you turn the capability on; this warns while you are
 * reading what it did, which is when the question actually occurs to someone.
 */
export const AUTO_MERGED_CAPTION =
  'already done — your identification settings allowed these without asking, and there is no way to reverse one from here';

/** The two row labels. Who decided is the first thing a reviewer wants to know. */
export const DECIDED_BY_MATCHER_LABEL = 'Auto-accepted by the matcher';
export const DECIDED_BY_RULE_LABEL = 'Merged by rule';

/** The empty state, verbatim from the spec's state table. */
export function autoMergedEmptyText(windowDays: number): string {
  return `Nothing has been merged automatically in the last ${windowDays} days.`;
}

/** A merge the same-device rule made. Anything else on this list is the matcher's. */
export function isRuleMerge(p: MergeProposal): boolean {
  return p.decided_by === 'rule';
}

/**
 * The survivor of a rule merge: the record the others were folded into.
 *
 * The rule row names it (`merged_into`) rather than `accepted_asset_id`, which
 * is the matcher's field — the two answer different questions. It is looked up
 * among the row's own records so the name comes decorated; when it is not there
 * the id stands in, rather than the row claiming nothing was merged.
 */
export function ruleSurvivor(p: MergeProposal): { id: string; name: string; candidate?: MergeCandidate } | undefined {
  if (!p.merged_into) return undefined;
  const candidate = p.candidates.find((c) => c.asset_id === p.merged_into)
    ?? (p.observation?.asset_id === p.merged_into ? p.observation : undefined);
  return { id: p.merged_into, name: candidate ? candidateName(candidate) : p.merged_into, candidate };
}

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

/** The chip saying who decided. Colour-neutral: neither kind is better or worse. */
function DecidedByChip({ label }: { label: string }) {
  return (
    <span
      data-testid="decided-by"
      style={{
        fontSize: 10.5, fontWeight: 600, padding: '1px 8px', borderRadius: 40, color: 'var(--app-t2)',
        border: '1px solid var(--app-border2)', background: 'var(--app-panel)',
      }}
    >
      {label}
    </span>
  );
}

/**
 * A rule merge: the survivor, the evidence the rule relied on, and when.
 *
 * No score and no model — a rule has neither, and rendering an empty bar would
 * read as "scored zero". The evidence is the reason, one line per fact, in the
 * order the rule established them.
 */
function RuleMergedRow({ proposal }: { proposal: MergeProposal }) {
  const survivor = ruleSurvivor(proposal);
  const evidence = proposal.rule_evidence ?? [];
  const when = proposal.resolved_at ?? proposal.proposed_at;
  return (
    <div
      data-testid="auto-merged-row"
      data-decided-by="rule"
      style={{
        padding: '11px 13px', borderRadius: 11, marginBottom: 9,
        border: '1px solid var(--app-border2)', background: 'var(--app-panel2)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexWrap: 'wrap' }}>
        <Icon name="git-merge" size={14} style={{ color: 'var(--app-t3)' }} />
        <DecidedByChip label={DECIDED_BY_RULE_LABEL} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>
          {survivor ? `Merged into ${survivor.name}` : 'Merged into an asset that no longer exists'}
        </span>
        {survivor?.candidate && (
          <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
            {survivor.candidate.class_label ?? classLabel(survivor.candidate.class_key)}
          </span>
        )}
        {survivor && (
          <Link
            to={`/inventory/assets/${survivor.id}`}
            data-testid="survivor-link"
            title="Open the asset it was merged into — its History shows what was merged in"
            className="ui-btn sm ghost"
            style={{ padding: '0 6px', textDecoration: 'none' }}
          >
            <Icon name="external-link" size={12} />
          </Link>
        )}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{new Date(when).toLocaleString()}</span>
      </div>
      {evidence.length > 0 && (
        <ul
          data-testid="rule-evidence"
          style={{ listStyle: 'none', margin: '7px 0 0', padding: 0, display: 'flex', flexWrap: 'wrap', gap: '3px 12px' }}
        >
          {evidence.map((line) => (
            <li key={line} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, color: 'var(--app-t3)' }}>
              <Icon name="check" size={10} style={{ color: 'var(--ok)', flex: 'none' }} />
              {line}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AutoMergedRow({ proposal }: { proposal: MergeProposal }) {
  if (isRuleMerge(proposal)) return <RuleMergedRow proposal={proposal} />;
  const winner = acceptedCandidate(proposal);
  const others = remainingCandidates(proposal);
  const confidence = matcherConfidencePercent(proposal.accepted_score);
  const pct = confidence === null ? null : percentLabel(confidence);
  const reasons = winner ? topReasons(winner) : [];

  return (
    <div
      data-testid="auto-merged-row"
      data-decided-by="matcher"
      style={{
        padding: '11px 13px', borderRadius: 11, marginBottom: 9,
        border: '1px solid var(--app-border2)', background: 'var(--app-panel2)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexWrap: 'wrap' }}>
        <Icon name="git-merge" size={14} style={{ color: 'var(--app-t3)' }} />
        <DecidedByChip label={DECIDED_BY_MATCHER_LABEL} />
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
        {confidence !== null && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{ width: 44 }}>
              <MiniBar
                pct={confidence}
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

/** Placeholder rows while the read is in flight — shaped like the rows they stand in for. */
function AutoMergedSkeleton() {
  return (
    <div data-testid="auto-merged-skeleton" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          style={{
            height: 52, borderRadius: 11, marginBottom: 9, opacity: 0.6,
            border: '1px solid var(--app-border)', background: 'var(--app-panel2)',
          }}
        />
      ))}
    </div>
  );
}

/**
 * The section. `loading` shows placeholder rows; a FAILED read is not this
 * component's state at all — the page shows the retry banner and does not render
 * the section, because "Nothing has been merged" over a read that never
 * answered would be a false negative about the one act nobody approved.
 */
export function AutoMergedSection({ merges, windowDays, loading = false }: {
  merges: MergeProposal[]; windowDays: number; loading?: boolean;
}) {
  return (
    <div data-testid="auto-merged-section" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
        <div className="eyebrow-app">
          Merged automatically (last {windowDays} days){merges.length > 0 ? ` (${merges.length})` : ''}
        </div>
        {/* The irreversibility is stated HERE as well as on the settings card.
            A tenant reading this list is looking at merges that already
            happened, and the one question the list invites — "can I put that
            back?" — has to be answered where it is asked, not only on the page
            that turned the capability on months ago. */}
        {merges.length > 0 && (
          <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            {AUTO_MERGED_CAPTION}
          </span>
        )}
        <Link
          to="/settings/identification-rules"
          style={{ fontSize: 11.5, color: 'var(--accent)', textDecoration: 'none' }}
        >
          Change these settings
        </Link>
      </div>
      {loading ? (
        <AutoMergedSkeleton />
      ) : merges.length === 0 ? (
        <div data-testid="auto-merged-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '4px 2px 8px' }}>
          {autoMergedEmptyText(windowDays)}
        </div>
      ) : (
        merges.map((m) => <AutoMergedRow key={m.id} proposal={m} />)
      )}
    </div>
  );
}
