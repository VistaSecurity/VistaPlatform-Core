// VISTA Operations — System Health › Gateway (left-rail sub-page). Folds the v1
// gateway pages over monitoring /gateway/* which proxies Traefik's API. Those
// payloads are typed `unknown` (GatewayPassthrough) in the contract, so we read
// them defensively with local interfaces — NOT a hand-rolled client. Overview
// counts come from /gateway/overview when present, falling back to array lengths.
// Gateway deep-dive Grafana charts are out of scope this wave.
import { useQuery } from '@tanstack/react-query';
import { Network } from 'lucide-react';
import { clients } from '../../lib/clients';
import { StatusTag } from '../../components/ui/primitives';
import { Panel, EmptyRow } from './parts';

// Traefik passthrough shapes (monitoring /gateway/* returns `unknown`).
interface GwRouter { name?: string; rule?: string; service?: string; status?: string; provider?: string }
interface GwService { name?: string; status?: string; provider?: string; type?: string }
// Traefik /api/overview is a nested { http: { routers: { total, ... }, services: {...} } } shape.
interface GwOverview { http?: { routers?: { total?: number; warnings?: number; errors?: number }; services?: { total?: number } } }

function readCount(o: GwOverview | undefined, path: 'routers' | 'services', key: 'total' | 'warnings' | 'errors'): number | undefined {
  const node = o?.http?.[path] as Record<string, number | undefined> | undefined;
  return node?.[key];
}

export function GatewayPage() {
  const overviewQ = useQuery({
    queryKey: ['platform', 'gateway', 'overview'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/gateway/overview', {});
      if (error) throw new Error('Failed to load gateway overview');
      return (data ?? {}) as GwOverview;
    },
    staleTime: 30 * 1000, retry: 0,
  });
  const routersQ = useQuery({
    queryKey: ['platform', 'gateway', 'routers'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/gateway/routers', {});
      if (error) throw new Error('Failed to load routers');
      return Array.isArray(data) ? (data as GwRouter[]) : [];
    },
    staleTime: 30 * 1000, retry: 0,
  });
  const servicesQ = useQuery({
    queryKey: ['platform', 'gateway', 'services'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/gateway/services', {});
      if (error) throw new Error('Failed to load gateway services');
      return Array.isArray(data) ? (data as GwService[]) : [];
    },
    staleTime: 30 * 1000, retry: 0,
  });

  const overview = overviewQ.data;
  const routers = routersQ.data ?? [];
  const services = servicesQ.data ?? [];

  const routerCount = readCount(overview, 'routers', 'total') ?? routers.length;
  const serviceCount = readCount(overview, 'services', 'total') ?? services.length;
  const routerWarnings = readCount(overview, 'routers', 'warnings');
  const routerErrors = readCount(overview, 'routers', 'errors');
  // Prefer Traefik's own warnings/errors, else derive degraded from the router rows.
  const routersDegraded = (routerWarnings ?? 0) + (routerErrors ?? 0) || routers.filter((r) => r.status && r.status !== 'enabled').length;
  const countsLoading = overviewQ.isLoading && routersQ.isLoading;

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
        <div className="op-panel" style={{ padding: '14px 16px' }}><div className="op-eyebrow">Routers</div><div className="op-num" style={{ fontSize: 22, fontWeight: 700, color: 'var(--op-t1)', marginTop: 4 }}>{countsLoading ? '…' : routerCount}</div></div>
        <div className="op-panel" style={{ padding: '14px 16px' }}><div className="op-eyebrow">Services</div><div className="op-num" style={{ fontSize: 22, fontWeight: 700, color: 'var(--op-t1)', marginTop: 4 }}>{countsLoading ? '…' : serviceCount}</div></div>
        <div className="op-panel" style={{ padding: '14px 16px' }}><div className="op-eyebrow">Routers degraded</div><div className="op-num" style={{ fontSize: 22, fontWeight: 700, color: routersDegraded ? 'var(--warn)' : 'var(--op-t1)', marginTop: 4 }}>{countsLoading ? '…' : routersDegraded}</div></div>
      </div>
      <Panel title="Routers" icon={Network}>
        <table className="op-table">
          <thead><tr><th>Name</th><th>Rule</th><th>Service</th><th>Provider</th><th>Status</th></tr></thead>
          <tbody>
            {routers.map((r, i) => (
              <tr key={r.name ?? i}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{(r.name ?? '—').replace(/@.*$/, '')}</td>
                <td className="mono t-muted" style={{ fontSize: 11, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.rule ?? '—'}</td>
                <td className="t-muted">{(r.service ?? '—').replace(/@.*$/, '')}</td>
                <td className="t-muted">{r.provider ?? '—'}</td>
                <td><StatusTag status={r.status === 'enabled' ? 'active' : (r.status ?? 'unknown')} /></td>
              </tr>
            ))}
            {(routersQ.isLoading || routersQ.isError || routers.length === 0) && <EmptyRow cols={5} loading={routersQ.isLoading} error={routersQ.isError} onRetry={routersQ.refetch} label="No routers reported." />}
          </tbody>
        </table>
      </Panel>
      <Panel title="Gateway services" icon={Network}>
        <table className="op-table">
          <thead><tr><th>Name</th><th>Type</th><th>Provider</th><th>Status</th></tr></thead>
          <tbody>
            {services.map((s, i) => (
              <tr key={s.name ?? i}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{(s.name ?? '—').replace(/@.*$/, '')}</td>
                <td className="t-muted">{s.type ?? '—'}</td>
                <td className="t-muted">{s.provider ?? '—'}</td>
                <td><StatusTag status={s.status === 'enabled' ? 'active' : (s.status ?? 'unknown')} /></td>
              </tr>
            ))}
            {(servicesQ.isLoading || servicesQ.isError || services.length === 0) && <EmptyRow cols={4} loading={servicesQ.isLoading} error={servicesQ.isError} onRetry={servicesQ.refetch} label="No gateway services reported." />}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
