// Proposed cables in Discovery → Approvals (DCIM BUILD_PLAN row 3.3;
// asset-inventory ADR-0010 D6). An LLDP / CDP neighbour between two known
// interfaces is a measured, pending cable: it holds both ports but carries no
// cable path until a person approves it here. Approve → the cable is active and
// its paths are computed; Reject → it stays as rejected, so the same pairing is
// not proposed again.
//
// States: loading (a line), failing (a banner with Retry — an unknown number of
// proposals is not "none"), empty (nothing rendered; the page's empty state
// counts this read too), the list, and a decision in flight.
import { Link } from 'react-router';
import type { UseQueryResult } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { relTime } from './kit';
import { endText, proposedBy, useDecideCable, type Cable, type CableTerminationRef } from '../inventory/dcim/cable-queries';

function EndLink({ end }: { end: CableTerminationRef[] }) {
  const assetId = end[0]?.asset_id;
  const text = endText(end);
  return assetId
    ? <Link to={`/inventory/assets/${assetId}`} className="mono" style={{ color: 'var(--accent)' }}>{text}</Link>
    : <span className="mono">{text}</span>;
}

export function ProposedCablesSection({ query }: { query: UseQueryResult<{ rows: Cable[]; total: number }> }) {
  const decide = useDecideCable();
  if (query.isLoading) {
    return <div data-testid="proposed-cables-loading" style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 10 }}>Loading proposed cables…</div>;
  }
  if (query.isError) {
    return (
      <div
        data-testid="proposed-cables-error"
        style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 12, padding: '9px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--danger) 35%, transparent)', background: 'color-mix(in srgb, var(--danger) 8%, transparent)' }}
      >
        <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flexShrink: 0 }} />
        <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
          Couldn&rsquo;t load proposed cables — {query.error instanceof Error ? query.error.message : 'the request failed'}. Any cables awaiting review are not shown below.
        </span>
        <button className="ui-btn sm" onClick={() => { void query.refetch(); }}>Retry</button>
      </div>
    );
  }
  const rows = query.data?.rows ?? [];
  const total = query.data?.total ?? rows.length;
  if (rows.length === 0) return null;
  return (
    <div data-testid="proposed-cables-section" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <div className="eyebrow-app">Proposed cables ({total})</div>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
          links a device&rsquo;s neighbour table reports between two known ports — approving one makes it a cable of record
        </span>
      </div>
      {rows.map((c) => (
        <div
          key={c.id}
          data-testid="proposed-cable-row"
          style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px', marginBottom: 6, border: '1px solid var(--app-border)', borderRadius: 10 }}
        >
          <Icon name="cable" size={14} style={{ color: 'var(--app-t3)', flexShrink: 0 }} />
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 0, flexWrap: 'wrap', fontSize: 12.5 }}>
            <EndLink end={c.a_terminations} />
            <Icon name="arrow-left-right" size={12} style={{ color: 'var(--app-t3)' }} />
            <EndLink end={c.b_terminations} />
          </span>
          <span style={{ fontSize: 11.5, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>
            seen by {proposedBy(c)} · {c.observation_count} observation{c.observation_count === 1 ? '' : 's'} · {relTime(c.last_seen_at)}
          </span>
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage} fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}>
            <button
              className="ui-btn sm accent"
              aria-label={`Approve cable ${endText(c.a_terminations)} to ${endText(c.b_terminations)}`}
              disabled={decide.isPending}
              onClick={() => decide.mutate({ id: c.id, approve: true })}
            >
              <Icon name="check" />Approve
            </button>
            <button
              className="ui-btn sm ghost"
              aria-label={`Reject cable ${endText(c.a_terminations)} to ${endText(c.b_terminations)}`}
              title="Reject (the same pairing is not proposed again)"
              disabled={decide.isPending}
              onClick={() => decide.mutate({ id: c.id, approve: false })}
            >
              <Icon name="x" />
            </button>
          </PermissionGate>
        </div>
      ))}
      {total > rows.length && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Showing {rows.length} of {total}.</div>
      )}
    </div>
  );
}
