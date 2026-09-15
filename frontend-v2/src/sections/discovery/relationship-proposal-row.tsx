// A relationship proposal in the Approvals queue (ADR-0006 D6, ADR-0003 D3).
//
// "Relationship proposals as a row kind." The third kind on the one queue,
// beside discovered assets and merge proposals — "no second queue anywhere".
//
// What a reviewer is being asked here is narrower than a merge: not "are these
// two records the same thing" but "is this claim about how they are connected
// true". So the row reads as a SENTENCE — subject, relationship, object — with
// both ends named and linked, and the evidence beside it: where the claim came
// from, how confident its producer was, and how often it has been seen.
//
// Both ends have to be named. A proposal rendered as "something depends on
// something" with a confidence number is a coin flip, which is the same failure
// the merge row was written to avoid.
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, MiniBar } from '../../components/ui';
import { classLabel } from '../inventory/asset-shape';
import {
  SOURCE_KIND_HELP, SOURCE_KIND_LABEL, TYPE_HELP, TYPE_LABEL, peerName,
  type Relationship, type RelationshipPeer,
} from '../inventory/relationships';
import { relTime } from './kit';

/** The producer's confidence as a percentage, or null when it is unscored.
 *
 *  Zero means UNSCORED, not "certainly wrong" — the same distinction the merge
 *  row makes, and the same reason: a 0% bar reads as a confident rejection. */
export function confidencePct(confidence: number | undefined): string | null {
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence <= 0) return null;
  return `${Math.round(confidence <= 1 ? confidence * 100 : confidence)}%`;
}

function EndCard({ peer, role }: { peer: RelationshipPeer | undefined; role: string }) {
  if (!peer) {
    return (
      <div style={{ flex: 1, minWidth: 160, padding: '9px 12px', borderRadius: 10, border: '1px dashed var(--app-border2)' }}>
        <div className="eyebrow-app" style={{ marginBottom: 2 }}>{role}</div>
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Unknown asset</div>
      </div>
    );
  }
  return (
    <div
      data-testid="relationship-end"
      style={{ flex: 1, minWidth: 160, padding: '9px 12px', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)' }}
    >
      <div className="eyebrow-app" style={{ marginBottom: 2 }}>{role}</div>
      <Link
        to={`/inventory/assets/${peer.asset_id}`}
        style={{ fontSize: 12.5, color: 'var(--accent)', textDecoration: 'none', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
      >
        {peerName(peer)}
      </Link>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>
        {classLabel(peer.class_key ?? '') || peer.class_key || '—'}
      </div>
      {peer.primary_identifier && peer.display_name && (
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {peer.primary_identifier}
        </div>
      )}
    </div>
  );
}

export function RelationshipProposalRow({ proposal, busy, onAccept, onReject }: {
  proposal: Relationship;
  busy: boolean;
  onAccept: () => void;
  onReject: () => void;
}) {
  const pct = confidencePct(proposal.confidence);
  const kind = proposal.source_kind;

  return (
    <div
      data-testid="relationship-proposal"
      data-edge-id={proposal.id}
      style={{
        padding: '13px 15px', borderRadius: 12, border: '1px solid var(--app-border2)',
        background: 'var(--app-panel)', marginBottom: 10,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10, flexWrap: 'wrap' }}>
        <Icon name="waypoints" size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--app-t1)' }}>
          Proposed relationship
        </span>
        <span
          data-testid="proposal-provenance"
          data-kind={kind}
          title={proposal.source_ref ? `${SOURCE_KIND_HELP[kind]} (${proposal.source_ref})` : SOURCE_KIND_HELP[kind]}
          style={{
            fontSize: 10.5, fontWeight: 600, padding: '1px 7px', borderRadius: 40,
            border: '1px solid color-mix(in srgb, var(--warn) 45%, transparent)',
            color: 'var(--warn-text, var(--warn))',
            background: 'color-mix(in srgb, var(--warn) 9%, transparent)',
          }}
        >
          {SOURCE_KIND_LABEL[kind]}
        </span>
        {pct && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 36 }}>
              <MiniBar
                pct={Math.round(proposal.confidence <= 1 ? proposal.confidence * 100 : proposal.confidence)}
                color={proposal.confidence >= 0.7 ? 'var(--ok)' : 'var(--warn)'}
              />
            </span>
            <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{pct}</span>
          </span>
        )}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 11, color: 'var(--app-t3)' }} title={proposal.first_seen_at}>
          {relTime(proposal.first_seen_at)}
        </span>
      </div>

      {/* Subject, relationship, object — read left to right. */}
      <div style={{ display: 'flex', alignItems: 'stretch', gap: 10, flexWrap: 'wrap' }}>
        <EndCard peer={proposal.from} role="This" />
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2, minWidth: 108, padding: '0 4px' }}>
          <span
            data-testid="proposal-type"
            title={TYPE_HELP[proposal.type]}
            style={{ fontSize: 12, fontWeight: 700, color: 'var(--app-t1)', textAlign: 'center' }}
          >
            {TYPE_LABEL[proposal.type]}
          </span>
          <Icon name="arrow-right" size={14} style={{ color: 'var(--app-t3)' }} />
        </div>
        <EndCard peer={proposal.to} role="That" />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 11, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 1, minWidth: 240, lineHeight: 1.55 }}>
          {/* What accepting actually does, and what rejecting does. Neither is
              obvious, and the consequence of accepting — it starts counting in
              impact — is the part a reviewer needs to weigh. */}
          Accepting makes this a confirmed relationship, and it starts counting in impact analysis.
          Rejecting records the decision so the same claim is not proposed again.
          {proposal.observation_count > 1 && ` Seen ${proposal.observation_count} times.`}
        </span>
        <PermissionGate
          permission={TENANT_PERMISSIONS.assets.update}
          fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>You don&rsquo;t have permission to decide this.</span>}
        >
          <span style={{ display: 'inline-flex', gap: 7 }}>
            <button className="ui-btn sm accent" disabled={busy} onClick={onAccept}>
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
