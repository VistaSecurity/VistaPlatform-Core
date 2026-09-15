// A class proposal in the Approvals queue (ADR-0006 D6, ADR-0004 D6).
//
// The fourth row kind on the one queue, beside discovered assets, merge
// proposals and relationship proposals — "no second queue anywhere".
//
// What a reviewer is being asked is narrower than a merge and narrower than a
// relationship: not "are these two things one" and not "is this connection
// real", but "is this thing a printer". So the row reads as a COMPARISON — what
// it is now, what the rules say — with the argument beside it: which rules
// matched, what they assert, and where each mapping comes from.
//
// The citation is the part that makes this reviewable rather than a coin flip.
// A rule table whose rows a reviewer cannot check is one they can only
// rubber-stamp, which is the failure the whole "a wrong class is worse than no
// class" rule exists to avoid.
import { useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, MiniBar } from '../../components/ui';
import { relTime } from './kit';
import type {
  ClassModelReason, ClassOption, ClassificationRuleRef, ClassProposal,
} from './class-proposal-queries';

/** How a rule kind reads to somebody who has never opened the rule table. */
const KIND_LABEL: Readonly<Record<string, string>> = {
  oui: 'MAC prefix',
  sysobjectid: 'SNMP object ID',
  enip: 'EtherNet/IP vendor',
  cloud_type: 'Cloud resource type',
  banner: 'Service banner',
  port_profile: 'Open ports',
  model: 'Model prefix',
  platform: 'Management API',
  cdp_capabilities: 'CDP capabilities',
  lldp_capability: 'LLDP capabilities',
  mdns_service: 'Advertised service',
};

function ruleKindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind;
}

/** The first value that is actually there.
 *
 *  Not `a ?? b`: every one of these fields is `omitempty` on the wire, so it
 *  arrives either absent OR as an empty string, and `??` would render the empty
 *  one. Not `a || b` either, which says the same thing but reads as a lint
 *  warning at seven call sites. */
function firstNonEmpty(...values: (string | undefined)[]): string {
  for (const v of values) {
    if (v !== undefined && v !== '') return v;
  }
  return '';
}

/** The rule's assertion as a percentage, or null when it asserts nothing —
 *  which is what a CONFLICT looks like, and a 0% bar would read as a confident
 *  rejection rather than as an absent answer. */
function assertedPct(confidence: number | undefined): number | null {
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence <= 0) return null;
  return Math.round(confidence <= 1 ? confidence * 100 : confidence);
}

function ClassCard({ label, name, muted }: { label: string; name: string; muted?: boolean }) {
  return (
    <div
      style={{
        flex: 1, minWidth: 150, padding: '9px 12px', borderRadius: 10,
        border: `1px ${muted ? 'dashed' : 'solid'} var(--app-border2)`,
        background: muted ? 'transparent' : 'var(--app-panel2)',
      }}
    >
      <div className="eyebrow-app" style={{ marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 12.5, color: muted ? 'var(--app-t3)' : 'var(--app-t1)', fontWeight: muted ? 400 : 600 }}>
        {name}
      </div>
    </div>
  );
}

export function ClassProposalRow({ proposal, busy, onAccept, onReject }: {
  proposal: ClassProposal;
  busy: boolean;
  onAccept: (classKey?: string) => void;
  onReject: () => void;
}) {
  const conflicting = proposal.conflicting_classes ?? [];
  // A proposal with no single class is the rules DISAGREEING. There is nothing
  // to accept until the reviewer says which, and the server refuses to pick —
  // so the row asks, rather than offering a button that 400s.
  const isConflict = !proposal.proposed_class_key;
  // Whenever candidates were named the reviewer may pick among them, even when
  // something proposed one of them: the learned classifier settles a conflict
  // by choosing a tied class, and the person reviewing it must be able to take
  // the OTHER one without going back to the rules. The server allows exactly
  // that set and no more.
  const offersChoice = conflicting.length > 0;
  const [chosen, setChosen] = useState(proposal.proposed_class_key ?? '');
  // A model-derived proposal is a different KIND of claim from a rule-derived
  // one — nothing deterministic argued it and there is no source to cite — so
  // the row says which, rather than letting a percentage stand for both.
  const byModel = Boolean(proposal.model_id);
  const pct = assertedPct(byModel ? proposal.model_probability : proposal.confidence);
  const rules = proposal.matched_rules ?? [];
  const reasons = proposal.model_reasons ?? [];
  const assetName = firstNonEmpty(
    proposal.asset_display_name, proposal.asset_hostname,
    proposal.asset_primary_address, proposal.asset_id,
  );

  return (
    <div
      data-testid="class-proposal"
      data-proposal-id={proposal.id}
      style={{
        padding: '13px 15px', borderRadius: 12, border: '1px solid var(--app-border2)',
        background: 'var(--app-panel)', marginBottom: 10,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10, flexWrap: 'wrap' }}>
        <Icon name="shapes" size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)' }}>
          {isConflict ? 'Classification rules disagree' : 'Proposed class'}
        </span>
        <span
          data-testid="class-proposal-provenance"
          data-provenance={byModel ? 'model' : 'rule'}
          title={byModel
            ? 'Proposed by the learned classifier, which only speaks where the curated rules could not decide. It cannot cite a source and nothing measured it, so it waits for a person.'
            : 'Argued by the curated classification rules. Deterministic and citable — but nothing measured it, so it waits for a person.'}
          style={{
            fontSize: 10.5, fontWeight: 600, padding: '1px 7px', borderRadius: 40,
            border: '1px solid color-mix(in srgb, var(--warn) 45%, transparent)',
            color: 'var(--warn-text, var(--warn))',
            background: 'color-mix(in srgb, var(--warn) 9%, transparent)',
          }}
        >
          {byModel ? 'Model' : 'Rule'}
        </span>
        {byModel && pct !== null && (
          <span
            data-testid="class-proposal-model"
            title={proposal.model_id}
            className="mono"
            style={{ fontSize: 11, color: 'var(--app-t3)' }}
          >
            proposed by model (P={(pct / 100).toFixed(2)})
          </span>
        )}
        {pct !== null && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 36 }}>
              <MiniBar pct={pct} color={pct >= 70 ? 'var(--ok)' : 'var(--warn)'} />
            </span>
            <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{pct}%</span>
          </span>
        )}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 11, color: 'var(--app-t3)' }} title={proposal.proposed_at}>
          {relTime(proposal.proposed_at)}
        </span>
      </div>

      <div style={{ marginBottom: 10 }}>
        <Link
          to={`/inventory/assets/${proposal.asset_id}`}
          style={{ fontSize: 13, color: 'var(--accent)', textDecoration: 'none' }}
        >
          {assetName}
        </Link>
        {proposal.asset_primary_address && proposal.asset_display_name && (
          <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', marginLeft: 8 }}>
            {proposal.asset_primary_address}
          </span>
        )}
      </div>

      {/* Now, and what is proposed — read left to right. */}
      <div style={{ display: 'flex', alignItems: 'stretch', gap: 10, flexWrap: 'wrap' }}>
        <ClassCard
          label="Classed as"
          name={firstNonEmpty(proposal.current_class_label, proposal.current_class_key, 'Unclassified')}
          muted
        />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minWidth: 40 }}>
          <Icon name="arrow-right" size={14} style={{ color: 'var(--app-t3)' }} />
        </div>
        {offersChoice ? (
          <div
            data-testid="class-proposal-choice"
            style={{ flex: 1, minWidth: 180, padding: '9px 12px', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)' }}
          >
            <div className="eyebrow-app" style={{ marginBottom: 4 }}>
              {isConflict ? 'Candidates' : 'Candidates — the model picked one'}
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {conflicting.map((c: ClassOption) => (
                <button
                  key={c.key}
                  className="ui-btn sm"
                  aria-pressed={chosen === c.key}
                  onClick={() => setChosen(chosen === c.key ? '' : c.key)}
                  style={{
                    borderColor: chosen === c.key ? 'var(--accent)' : 'var(--app-border2)',
                    color: chosen === c.key ? 'var(--accent)' : 'var(--app-t2)',
                  }}
                >
                  {firstNonEmpty(c.label, c.key)}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <ClassCard
            label={byModel ? 'Model says' : 'Rules say'}
            name={firstNonEmpty(proposal.proposed_class_label, proposal.proposed_class_key)}
          />
        )}
      </div>

      {/* The model's argument. It cannot cite a URL the way a rule can, so the
          three feature contributions the score is literally made of are what
          makes the row reviewable rather than a number to rubber-stamp. */}
      {byModel && reasons.length > 0 && (
        <ul data-testid="class-proposal-model-reasons" style={{ listStyle: 'none', margin: '11px 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {reasons.map((r: ClassModelReason, i: number) => (
            <li key={`${r.feature}:${i}`} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--app-t3)' }}>
              <Icon name={r.contribution >= 0 ? 'plus' : 'minus'} size={11} style={{ color: r.contribution >= 0 ? 'var(--ok)' : 'var(--warn)' }} />
              <span style={{ color: 'var(--app-t2)' }}>{r.label}</span>
            </li>
          ))}
        </ul>
      )}

      {/* The argument. Without it a reviewer can only rubber-stamp. */}
      {rules.length > 0 && (
        <ul data-testid="class-proposal-rules" style={{ listStyle: 'none', margin: '11px 0 0', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {rules.slice(0, 5).map((r: ClassificationRuleRef, i: number) => (
            <li key={`${r.kind}:${r.pattern}:${i}`} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--app-t3)', flexWrap: 'wrap' }}>
              <span style={{ color: 'var(--app-t2)' }}>{ruleKindLabel(r.kind)}</span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--app-t2)' }}>{r.pattern}</span>
              {r.class && <span>&rarr; {r.class}</span>}
              {r.source_url && (
                <a
                  href={r.source_url}
                  target="_blank"
                  rel="noreferrer noopener"
                  style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: 11 }}
                >
                  source
                </a>
              )}
            </li>
          ))}
          {rules.length > 5 && (
            <li style={{ fontSize: 11, color: 'var(--app-t3)' }}>and {rules.length - 5} more</li>
          )}
        </ul>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 11, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 1, minWidth: 240, lineHeight: 1.55 }}>
          {isConflict
            ? 'Two rules argued different classes at similar confidence, so nothing was applied. Pick the right one, or reject them both and fix the rules.'
            : byModel
              ? 'No rule could decide this, so the learned classifier proposed it. Accepting sets the class and records that a model proposed it. Rejecting records the decision so the same class is not proposed again.'
              : 'Accepting sets the class on this asset and records which rule decided it. Rejecting records the decision so the same class is not proposed again.'}
        </span>
        <PermissionGate
          permission={TENANT_PERMISSIONS.assets.update}
          fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>You don&rsquo;t have permission to decide this.</span>}
        >
          <span style={{ display: 'inline-flex', gap: 7 }}>
            <button
              className="ui-btn sm accent"
              disabled={busy || (isConflict && !chosen)}
              title={isConflict && !chosen ? 'Pick one of the candidate classes first' : undefined}
              onClick={() => onAccept(offersChoice ? chosen : undefined)}
            >
              <Icon name="check" size={12} />Accept
            </button>
            <button className="ui-btn sm ghost" disabled={busy} onClick={onReject}>
              <Icon name="x" size={12} />Reject
            </button>
          </span>
        </PermissionGate>
      </div>
    </div>
  );
}
