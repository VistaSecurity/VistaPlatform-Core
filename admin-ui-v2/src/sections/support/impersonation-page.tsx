// VISTA Operations — Support ▸ Impersonation. A READ-ONLY view of the support
// impersonation audit trail (GET /admin/impersonations/audit). No start/stop
// controls — this surface only shows who impersonated whom, when, and why.
// `event_data` arrives as a JSONB-serialized STRING; we parse it defensively and
// read its fields via Record access (actor_email / target_email / reason / …).
// All calls go through the typed clients.auth.
import { useMemo } from 'react';
import { UserCog, ArrowRight } from 'lucide-react';
import { Tag, relTime } from '../../components/ui/primitives';
import { useImpersonationEvents, type ImpersonationEvent } from './support-queries';

// event_type → a Start/Stop label + color. Start = active (blue), Stop = ended
// (muted). Anything unexpected falls back to the raw value.
const typeMeta = (t: string): { label: string; color: string } =>
  t === 'impersonation_start' ? { label: 'Start', color: 'var(--info)' }
  : t === 'impersonation_stop' ? { label: 'Stop', color: 'var(--neutral)' }
  : { label: t, color: 'var(--neutral)' };

/** event_data is a JSON string (or already-loose value). Parse to a flat map. */
function parseEventData(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object') return raw as Record<string, unknown>;
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') return parsed as Record<string, unknown>;
    } catch {
      /* not JSON — fall through to empty */
    }
  }
  return {};
}

const str = (v: unknown): string => (v == null ? '' : String(v));

interface Row {
  ev: ImpersonationEvent;
  actor: string;
  target: string;
  reason: string;
}

export function ImpersonationPage() {
  const { data, isLoading, isError, refetch } = useImpersonationEvents();

  const rows = useMemo<Row[]>(() => {
    return (data ?? []).map((ev) => {
      const d = parseEventData(ev.event_data);
      return {
        ev,
        actor: str(d.actor_email),
        target: str(d.target_email),
        reason: str(d.reason),
      };
    });
  }, [data]);

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
        <table className="op-table">
          <thead>
            <tr>
              <th>Actor</th>
              <th>Target</th>
              <th>Type</th>
              <th>Reason</th>
              <th>When</th>
              <th>Source IP</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.ev.occurred_at}-${i}`}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{r.actor || '—'}</td>
                <td>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--op-t1)', fontWeight: 500 }}>
                    <ArrowRight size={12} style={{ color: 'var(--op-t3)' }} />{r.target || '—'}
                  </span>
                </td>
                <td>{(() => { const m = typeMeta(r.ev.event_type); return <Tag color={m.color}>{m.label}</Tag>; })()}</td>
                <td className="t-muted" style={{ fontSize: 12, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.reason || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }} title={new Date(r.ev.occurred_at).toLocaleString()}>{relTime(r.ev.occurred_at)}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{r.ev.ip_address || '—'}</td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading impersonation history…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Couldn't load impersonation history. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 60, color: 'var(--op-t3)' }}>
                <UserCog size={26} style={{ color: 'var(--op-t3)', marginBottom: 8 }} />
                <div>No impersonation sessions recorded.</div>
                <div style={{ fontSize: 11.5, marginTop: 4 }}>Support impersonation start/stop events will appear here.</div>
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ flex: 'none', padding: '9px 24px', borderTop: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--op-t3)' }}>
        <UserCog size={13} />
        <span>{rows.length} events</span>
        <span>·</span>
        <span>Read-only audit trail of support impersonation sessions.</span>
      </div>
    </div>
  );
}
