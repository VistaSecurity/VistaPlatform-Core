// VISTA Operations — System Health › Services (left-rail index/default).
// Reads monitoring /admin/status (typed getAdminSystemStatus, RequirePlatformAuth)
// — NOT /status/system, which 403s for platform-admin sessions (). The
// response is SystemStatusResponse: per-service ServiceStatus[] plus an aggregate
// `metrics` block we surface as honest tiles. No fabricated CPU/mem bars, no
// per-service uptime%, no Core/Platform/Infra grouping (the schema has none).
// The "No open incidents" card is honest: /status/incidents is an empty stub by
// design — do not build incident tracking here (NEEDS-BACKEND).
import { useQuery } from '@tanstack/react-query';
import { Activity, CheckCircle2, AlertTriangle, ArrowDownCircle, Timer } from 'lucide-react';
import { clients } from '../../lib/clients';
import { StatusDot, statusOf, StatTile } from '../../components/ui/primitives';
import { Panel, EmptyRow } from './parts';

export function ServicesPage() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['platform', 'system-status'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/admin/status', {});
      if (error || !data) throw new Error('Failed to load system status');
      return data;
    },
    staleTime: 30 * 1000,
    refetchInterval: 30 * 1000,
  });

  const services = data?.services ?? [];
  const overall = data?.overall_status ?? data?.status ?? 'unknown';
  const m = data?.metrics;
  // Prefer aggregate metrics when present; fall back to counting the array.
  const healthy = m?.healthy_services ?? services.filter((s) => s.status === 'healthy').length;
  const degraded = m?.degraded_services ?? services.filter((s) => s.status === 'degraded').length;
  const down = m?.down_services ?? services.filter((s) => s.status === 'down').length;
  const avgLatency = m?.average_response_time;
  const unhealthy = services.filter((s) => s.status !== 'healthy').length;
  const ok = overall === 'healthy' || unhealthy === 0;

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* overall-status hero */}
      <div className="op-panel" style={{ padding: '16px 18px', display: 'flex', alignItems: 'center', gap: 12, borderColor: ok ? 'color-mix(in srgb, var(--ok) 30%, transparent)' : 'color-mix(in srgb, var(--warn) 35%, transparent)', background: ok ? 'color-mix(in srgb, var(--ok) 6%, transparent)' : 'color-mix(in srgb, var(--warn) 6%, transparent)' }}>
        {ok ? <CheckCircle2 size={20} style={{ color: 'var(--ok)' }} /> : <AlertTriangle size={20} style={{ color: 'var(--warn)' }} />}
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--op-t1)' }}>
            {isLoading ? 'Checking platform status…' : ok ? 'All systems operational' : `${unhealthy} service${unhealthy === 1 ? '' : 's'} need attention`}
          </div>
          <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>{services.length} services monitored{data?.timestamp ? ` · updated ${new Date(data.timestamp).toLocaleTimeString()}` : ''}</div>
        </div>
      </div>

      {/* honest tiles off the aggregate metrics block */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        <StatTile label="Healthy" value={isLoading ? '—' : healthy} icon={CheckCircle2} accent={healthy ? 'var(--ok)' : undefined} />
        <StatTile label="Degraded" value={isLoading ? '—' : degraded} icon={AlertTriangle} accent={degraded ? 'var(--warn)' : undefined} />
        <StatTile label="Down" value={isLoading ? '—' : down} icon={ArrowDownCircle} accent={down ? 'var(--danger)' : undefined} />
        <StatTile label="Avg latency" value={isLoading || avgLatency == null ? '—' : `${Math.round(avgLatency)}ms`} icon={Timer} accent={avgLatency != null && avgLatency > 300 ? 'var(--warn)' : undefined} />
      </div>

      <Panel title="Services" icon={Activity}>
        <table className="op-table">
          <thead><tr><th>Service</th><th>Status</th><th>Message</th><th className="num">Latency</th></tr></thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.name}>
                <td><div style={{ display: 'flex', alignItems: 'center', gap: 9 }}><StatusDot status={s.status} size={7} /><span style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{s.name}</span></div></td>
                <td style={{ color: statusOf(s.status).c, fontWeight: 600, fontSize: 12 }}>{statusOf(s.status).label}</td>
                <td className="t-muted" style={{ fontSize: 12, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.error || s.message || '—'}</td>
                <td className="num t-muted" style={{ color: s.response_time_ms > 300 ? 'var(--warn)' : undefined }}>{s.response_time_ms}ms</td>
              </tr>
            ))}
            {(isLoading || isError || services.length === 0) && <EmptyRow cols={4} loading={isLoading} error={isError} onRetry={refetch} label="No services reported." />}
          </tbody>
        </table>
      </Panel>

      {/* honest incidents card — /status/incidents is an empty stub by design */}
      <div className="op-panel" style={{ padding: '26px', textAlign: 'center', color: 'var(--op-t3)', fontSize: 12.5 }}>
        <CheckCircle2 size={22} style={{ color: 'var(--ok)', marginBottom: 8 }} />
        <div style={{ color: 'var(--op-t1)', fontWeight: 600, fontSize: 13 }}>No open incidents</div>
        <div style={{ marginTop: 4 }}>Incident tracking, per-service uptime, and Core/Platform/Infra grouping need a monitoring API extension — tracked as NEEDS-BACKEND.</div>
      </div>
    </div>
  );
}
