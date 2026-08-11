// VISTA Operations — Jobs & Queues. Wired to device-interrogation /admin/jobs
// (cross-tenant discovery/interrogation runs) + /admin/queues (live NATS
// JetStream stream/consumer stats). Observe-only (no platform retry/cancel —
// act on a customer's job via impersonation). Honest: JetStream gives depth /
// in-flight / message counts but NOT throughput rate or p95 (no fabrication).
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Workflow, Layers } from 'lucide-react';
import { clients } from '../../lib/clients';
import { StatusTag, statusOf, num, relTime } from '../../components/ui/primitives';
import { useScope } from '../../app/scope';

function useAdminJobs(scopeId: string | null) {
  return useQuery({
    // scopeId is part of the key so switching the operator scope refetches the
    // narrowed page instead of reusing the full cross-tenant cache.
    queryKey: ['platform', 'jobs', scopeId],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/admin/jobs', {
        // Narrow server-side so other tenants' rows are never shipped to the client.
        params: { query: { page_size: 100, ...(scopeId ? { tenant_id: scopeId } : {}) } },
      });
      if (error || !data) throw new Error('Failed to load jobs');
      return data.jobs ?? [];
    },
    staleTime: 20 * 1000, refetchInterval: 30 * 1000,
  });
}
function useAdminQueues() {
  return useQuery({
    queryKey: ['platform', 'queues'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/admin/queues', {});
      if (error || !data) throw new Error('queues');
      return data.queues ?? [];
    },
    staleTime: 15 * 1000, refetchInterval: 20 * 1000, retry: 0,
  });
}

export function JobsPage() {
  const { scopeId } = useScope();
  const jobsQ = useAdminJobs(scopeId);
  const queuesQ = useAdminQueues();
  const [status, setStatus] = useState('all');

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => jobsQ.data ?? [], [jobsQ.data]);
  const statuses = useMemo(() => ['all', ...Array.from(new Set(all.map((j) => j.status).filter(Boolean)))], [all]);
  // Tenant scope is now applied server-side (tenant_id query param); only the
  // status facet is filtered client-side here.
  const rows = useMemo(
    () => all.filter((j) => status === 'all' || j.status === status),
    [all, status],
  );

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* queues */}
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7 }}><Layers size={13} />Queues · live JetStream</div>
        {queuesQ.isError ? (
          <div className="op-panel" style={{ padding: '16px 18px', fontSize: 12, color: 'var(--op-t3)' }}>NATS/JetStream not reachable (queue metrics unavailable in this environment).</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
            {(queuesQ.data ?? []).map((qd) => {
              const depth = (qd.consumers ?? []).reduce((s, c) => s + (c.depth ?? 0), 0);
              const inFlight = (qd.consumers ?? []).reduce((s, c) => s + (c.in_flight ?? 0), 0);
              return (
                <div key={qd.name} className="op-panel" style={{ padding: '14px 15px' }}>
                  <div className="mono" style={{ fontSize: 12.5, color: 'var(--op-t1)', fontWeight: 600 }}>{qd.name}</div>
                  <div style={{ display: 'flex', gap: 16, marginTop: 10 }}>
                    <div><div className="op-num" style={{ fontSize: 18, fontWeight: 700, color: depth ? 'var(--warn)' : 'var(--op-t1)' }}>{num(depth)}</div><div style={{ fontSize: 9.5, color: 'var(--op-t3)' }}>backlog</div></div>
                    <div><div className="op-num" style={{ fontSize: 18, fontWeight: 700, color: 'var(--op-t1)' }}>{num(inFlight)}</div><div style={{ fontSize: 9.5, color: 'var(--op-t3)' }}>in flight</div></div>
                    <div><div className="op-num" style={{ fontSize: 18, fontWeight: 700, color: 'var(--op-t1)' }}>{num(qd.messages ?? 0)}</div><div style={{ fontSize: 9.5, color: 'var(--op-t3)' }}>messages</div></div>
                  </div>
                </div>
              );
            })}
            {!queuesQ.isLoading && (queuesQ.data ?? []).length === 0 && <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No active streams.</div>}
          </div>
        )}
      </div>

      {/* jobs table */}
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}><Workflow size={16} style={{ color: 'var(--op-t3)' }} />Discovery jobs</span>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {statuses.map((s) => <button key={s} onClick={() => setStatus(s)} className={'op-chip' + (status === s ? ' active' : '')} style={{ textTransform: s === 'all' ? 'none' : 'capitalize' }}>{s === 'all' ? 'All' : statusOf(s).label}</button>)}
          </div>
        </div>
        <table className="op-table">
          <thead><tr><th>Job</th><th>Type</th><th>Tenant</th><th>Status</th><th>Device</th><th>Worker</th><th>Started</th><th className="num">Found</th></tr></thead>
          <tbody>
            {rows.map((j) => (
              <tr key={j.id}>
                <td className="mono" style={{ fontSize: 11 }}>{j.id.slice(0, 8)}</td>
                <td className="t-muted" style={{ fontSize: 12 }}>{j.job_type}</td>
                <td className="t-muted" style={{ fontSize: 12 }}>{j.tenant_name || j.tenant_slug || '—'}</td>
                <td><StatusTag status={j.status} />{j.status === 'failed' && j.error_message ? <div style={{ fontSize: 10.5, color: 'var(--danger-text)', marginTop: 3, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.error_message}</div> : null}</td>
                <td className="t-muted" style={{ fontSize: 12 }}>{j.device_name || '—'}</td>
                <td className="mono t-muted" style={{ fontSize: 10.5 }}>{j.worker ? j.worker.slice(0, 8) : '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(j.started_at ?? j.created_at)}</td>
                <td className="num">{num(j.assets_discovered ?? 0)}</td>
              </tr>
            ))}
            {jobsQ.isLoading && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 44, color: 'var(--op-t3)' }}>Loading jobs…</td></tr>}
            {jobsQ.isError && !jobsQ.isLoading && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 44, color: 'var(--op-t3)' }}>Couldn't load jobs. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => jobsQ.refetch()}>Retry</button></td></tr>}
            {!jobsQ.isLoading && !jobsQ.isError && rows.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 44, color: 'var(--op-t3)' }}>No jobs match.</td></tr>}
          </tbody>
        </table>
        <div style={{ padding: '9px 16px', borderTop: '1px solid var(--op-border)', fontSize: 11.5, color: 'var(--op-t3)' }}>
          {rows.length} of {all.length} jobs · observe-only (retry a customer's job via Impersonation) · queue rate/p95 need a metrics time-series (JetStream gives depth only).
        </div>
      </div>
    </div>
  );
}
