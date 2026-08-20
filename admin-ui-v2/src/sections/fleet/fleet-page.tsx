// VISTA Operations — Fleet. The design wants a per-sensor/agent table across all
// tenants, but the only platform endpoint that exists server-side is
// device-interrogation /admin/metrics (aggregate counts). So this is the Fleet
// OVERVIEW (real aggregates); the per-agent table needs a new /admin/agents
// platform endpoint — see the decision list. No fabricated rows.
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Radar, Wifi, WifiOff, Workflow, Cable, Search } from 'lucide-react';
import { clients } from '../../lib/clients';
import { StatTile, MiniBar, StatusDot, StatusTag, Tag, num, relTime } from '../../components/ui/primitives';
import { useFleetSensors, useFleetAgents, type FleetRow } from './queries';
import { useScope } from '../../app/scope';

// /admin/metrics is explicitly cross-tenant and takes no tenant filter (unlike
// /admin/sensors and /admin/agents below it), so this query never varies with
// the tenant scope selector — no scopeId in the key. The headline tiles and
// breakdowns are labeled "platform-wide" in the JSX below so they don't read
// as a shrunken-but-wrong version of the scoped FleetTable beneath them.
function useFleetMetrics() {
  return useQuery({
    queryKey: ['platform', 'fleet-metrics'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/admin/metrics', {});
      if (error || !data) throw new Error('Failed to load fleet metrics');
      return data;
    },
    staleTime: 30 * 1000,
    refetchInterval: 60 * 1000,
  });
}

function Breakdown({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="op-panel" style={{ padding: '16px 18px' }}>
      <div className="op-eyebrow" style={{ marginBottom: 12 }}>{title}</div>
      {entries.length === 0 ? <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No data.</div> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
          {entries.map(([k, v]) => (
            <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12 }}>
              <span style={{ width: 130, color: 'var(--op-t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textTransform: 'capitalize' }}>{k.replace(/[_-]/g, ' ')}</span>
              <div style={{ flex: 1 }}><MiniBar pct={(v / max) * 100} color="var(--info)" h={6} /></div>
              <span className="op-num" style={{ color: 'var(--op-t1)', fontWeight: 600, width: 36, textAlign: 'right' }}>{num(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FleetTable() {
  const { scopeId } = useScope();
  const sensors = useFleetSensors(scopeId);
  const agents = useFleetAgents(scopeId);
  const [q, setQ] = useState('');
  const [kind, setKind] = useState<'all' | 'sensor' | 'agent'>('all');

  const rows = useMemo<FleetRow[]>(() => {
    // Tenant scope is applied server-side (tenant_id query param); only the kind
    // and text facets are filtered client-side here.
    const merged = [...(sensors.data ?? []), ...(agents.data ?? [])];
    const ql = q.trim().toLowerCase();
    return merged
      .filter((r) => (kind === 'all' || r.kind === kind) && (!ql || r.name.toLowerCase().includes(ql) || r.tenant.toLowerCase().includes(ql) || r.typeLabel.toLowerCase().includes(ql)))
      .sort((a, b) => a.tenant.localeCompare(b.tenant) || a.name.localeCompare(b.name));
  }, [sensors.data, agents.data, q, kind]);

  const loading = sensors.isLoading || agents.isLoading;
  const counts = { all: (sensors.data?.length ?? 0) + (agents.data?.length ?? 0), sensor: sensors.data?.length ?? 0, agent: agents.data?.length ?? 0 };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}><Radar size={16} style={{ color: 'var(--op-t3)' }} />Agent estate</span>
        <div style={{ display: 'flex', gap: 6 }}>
          {(['all', 'sensor', 'agent'] as const).map((k) => (
            <button key={k} onClick={() => setKind(k)} className={'op-chip' + (kind === k ? ' active' : '')} style={{ textTransform: 'capitalize' }}>{k === 'all' ? 'All' : k + 's'}<span style={{ opacity: 0.6 }}>{counts[k]}</span></button>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 30, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 200 }}>
          <Search size={14} style={{ color: 'var(--op-t3)' }} />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search agents, tenant…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }} />
        </div>
      </div>
      <table className="op-table">
        <thead><tr><th>Agent</th><th>Type</th><th>Tenant</th><th>Version</th><th>Status</th><th>Heartbeat</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.kind}:${r.id}`}>
              <td><div style={{ display: 'flex', alignItems: 'center', gap: 9 }}><StatusDot status={r.status} size={7} /><span style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{r.name}</span></div></td>
              <td><Tag color={r.kind === 'sensor' ? 'var(--info)' : 'var(--chart-1)'}>{r.typeLabel}</Tag></td>
              <td className="t-muted" style={{ fontSize: 12 }}>{r.tenant}</td>
              <td className="mono t-muted" style={{ fontSize: 11.5 }}>{r.version}</td>
              <td><StatusTag status={r.status} /></td>
              <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(r.heartbeat)}</td>
            </tr>
          ))}
          {loading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading agent estate…</td></tr>}
          {!loading && rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No agents match.</td></tr>}
        </tbody>
      </table>
      <div style={{ padding: '9px 16px', borderTop: '1px solid var(--op-border)', fontSize: 11.5, color: 'var(--op-t3)' }}>
        {rows.length} of {counts.all} agents · live throughput / CPU / mem per row need a join to sensor health metrics (follow-up). Observe-only — act on a customer's agent via Impersonation.
      </div>
    </div>
  );
}

export function FleetPage() {
  const { data: m, isLoading, isError, refetch } = useFleetMetrics();

  if (isError) {
    return <div className="op-fade" style={{ padding: '20px 24px' }}><div className="op-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--op-t3)' }}>Couldn't load fleet metrics. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></div></div>;
  }

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 10 }}>
          Platform-wide — all tenants, regardless of the tenant scope selector above
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
          <StatTile label="Connected" value={isLoading ? '…' : num(m?.connected_devices ?? 0)} sub={`${num(m?.total_devices ?? 0)} total · platform-wide`} icon={Wifi} accent="var(--ok)" />
          <StatTile label="Disconnected" value={isLoading ? '…' : num(m?.disconnected_devices ?? 0)} sub="devices · platform-wide" icon={WifiOff} accent={(m?.disconnected_devices ?? 0) > 0 ? 'var(--warn)' : undefined} />
          <StatTile label="Active integrations" value={isLoading ? '…' : num(m?.active_integrations ?? 0)} sub={`${num(m?.total_integrations ?? 0)} total · ${num(m?.error_integrations ?? 0)} error · platform-wide`} icon={Cable} />
          <StatTile label="Jobs · 24h" value={isLoading ? '…' : num(m?.jobs_last_24h ?? 0)} sub={`${(m?.success_rate ?? 0).toFixed(0)}% success · platform-wide`} icon={Workflow} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        <Breakdown title="Devices by type (platform-wide)" data={(m?.devices_by_type ?? {}) as Record<string, number>} />
        <Breakdown title="Integrations by provider (platform-wide)" data={(m?.integrations_by_provider ?? {}) as Record<string, number>} />
      </div>

      <FleetTable />
    </div>
  );
}
