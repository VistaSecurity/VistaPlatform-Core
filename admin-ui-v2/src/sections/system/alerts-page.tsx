// VISTA Operations — System Health › Alerts (left-rail sub-page). Read-only view
// of monitoring /alerting/{history,thresholds} (typed getAlertHistory /
// getAlertThresholds). Lifted verbatim from the old tabbed system-page; no
// mutation surface this wave.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { BellRing, CalendarClock, ShieldAlert, SlidersHorizontal, Trash2 } from 'lucide-react';
import { clients } from '../../lib/clients';
import { StatusTag, relTime } from '../../components/ui/primitives';
import { Panel, EmptyRow } from './parts';

export function AlertsPage() {
  const historyQ = useQuery({
    queryKey: ['platform', 'alerting', 'history'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/alerting/history', {});
      if (error || !data) throw new Error('Failed to load alert history');
      return data.alerts ?? [];
    },
    staleTime: 30 * 1000, retry: 0,
  });
  const thresholdsQ = useQuery({
    queryKey: ['platform', 'alerting', 'thresholds'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/alerting/thresholds', {});
      if (error || !data) throw new Error('Failed to load thresholds');
      return data.thresholds ?? [];
    },
    staleTime: 60 * 1000, retry: 0,
  });
  // Platform-track stateful alerts (service_down, tenant_health_degraded)
  // raised under the sentinel platform tenant, read via the platform-admin
  // route. Typed compliance-engine client (contract: GET /admin/alerts).
  const platformAlertsQ = useQuery({
    queryKey: ['platform', 'compliance', 'platform-alerts'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/admin/alerts', {
        params: { query: { status: 'active' } },
      });
      if (error || !data) throw new Error('Failed to load platform alerts');
      return data.alerts ?? [];
    },
    staleTime: 30 * 1000, retry: 0,
  });

  // Maintenance windows (storm control §10.3): during an active window,
  // notification delivery is suppressed. Typed notification-service client
  // (contract: /platform/maintenance-windows); CSRF is injected by the client.
  const qc = useQueryClient();
  const maintQ = useQuery({
    queryKey: ['platform', 'notif', 'maintenance-windows'],
    queryFn: async () => {
      const { data, error } = await clients.notifications.GET('/platform/maintenance-windows', {});
      if (error || !data) throw new Error('Failed to load maintenance windows');
      return data.windows ?? [];
    },
    staleTime: 30 * 1000, retry: 0,
  });
  const [mwStart, setMwStart] = useState('');
  const [mwEnd, setMwEnd] = useState('');
  const [mwReason, setMwReason] = useState('');
  const createMw = useMutation({
    mutationFn: async () => {
      const { error } = await clients.notifications.POST('/platform/maintenance-windows', {
        body: { starts_at: new Date(mwStart).toISOString(), ends_at: new Date(mwEnd).toISOString(), reason: mwReason },
      });
      if (error) throw new Error('create failed');
    },
    onSuccess: () => { setMwStart(''); setMwEnd(''); setMwReason(''); qc.invalidateQueries({ queryKey: ['platform', 'notif', 'maintenance-windows'] }); },
  });
  const deleteMw = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.notifications.DELETE('/platform/maintenance-windows/{id}', {
        params: { path: { id } },
      });
      if (error) throw new Error('delete failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'notif', 'maintenance-windows'] }),
  });

  const alerts = historyQ.data ?? [];
  const thresholds = thresholdsQ.data ?? [];
  const platformAlerts = platformAlertsQ.data ?? [];
  const maintenance = maintQ.data ?? [];

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <Panel title="Recent alerts" icon={BellRing}>
        <table className="op-table">
          <thead><tr><th>Alert</th><th>Service</th><th>Severity</th><th className="num">Value</th><th>Status</th><th>Triggered</th></tr></thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{a.threshold_name}</td>
                <td className="t-muted">{a.service_name ?? '—'}</td>
                <td><StatusTag status={a.severity} /></td>
                <td className="num t-muted">{a.actual_value} / {a.threshold_value}</td>
                <td><StatusTag status={a.status} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(a.triggered_at)}</td>
              </tr>
            ))}
            {(historyQ.isLoading || historyQ.isError || alerts.length === 0) && <EmptyRow cols={6} loading={historyQ.isLoading} error={historyQ.isError} onRetry={historyQ.refetch} label="No alerts triggered." />}
          </tbody>
        </table>
      </Panel>
      <Panel title="Platform alerts" icon={ShieldAlert}>
        <table className="op-table">
          <thead><tr><th>Alert</th><th>Type</th><th>Subject</th><th>Severity</th><th>Status</th><th>Last event</th></tr></thead>
          <tbody>
            {platformAlerts.map((a) => (
              <tr key={a.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{a.title}</td>
                <td className="t-muted">{a.alert_type}</td>
                <td className="t-muted">{a.subject_label ?? '—'}</td>
                <td><StatusTag status={a.severity} /></td>
                <td><StatusTag status={a.status} /></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(a.last_event_at)}</td>
              </tr>
            ))}
            {(platformAlertsQ.isLoading || platformAlertsQ.isError || platformAlerts.length === 0) && <EmptyRow cols={6} loading={platformAlertsQ.isLoading} error={platformAlertsQ.isError} onRetry={platformAlertsQ.refetch} label="No platform alerts." />}
          </tbody>
        </table>
      </Panel>
      <Panel title="Maintenance windows" icon={CalendarClock}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12, alignItems: 'flex-end' }}>
          <label style={{ fontSize: 12 }}>Start<br /><input type="datetime-local" value={mwStart} onChange={(e) => setMwStart(e.target.value)} /></label>
          <label style={{ fontSize: 12 }}>End<br /><input type="datetime-local" value={mwEnd} onChange={(e) => setMwEnd(e.target.value)} /></label>
          <label style={{ fontSize: 12, flex: 1, minWidth: 160 }}>Reason<br /><input type="text" value={mwReason} onChange={(e) => setMwReason(e.target.value)} placeholder="Planned maintenance" style={{ width: '100%' }} /></label>
          <button disabled={!mwStart || !mwEnd || createMw.isPending} onClick={() => createMw.mutate()}>Add window</button>
        </div>
        <table className="op-table">
          <thead><tr><th>Start</th><th>End</th><th>Reason</th><th /></tr></thead>
          <tbody>
            {maintenance.map((m) => (
              <tr key={m.id}>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(m.starts_at)}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(m.ends_at)}</td>
                <td className="t-muted">{m.reason || '—'}</td>
                <td><button title="Delete" onClick={() => deleteMw.mutate(m.id)}><Trash2 size={14} /></button></td>
              </tr>
            ))}
            {(maintQ.isLoading || maintQ.isError || maintenance.length === 0) && <EmptyRow cols={4} loading={maintQ.isLoading} error={maintQ.isError} onRetry={maintQ.refetch} label="No maintenance windows." />}
          </tbody>
        </table>
      </Panel>
      <Panel title="Alert thresholds" icon={SlidersHorizontal}>
        <table className="op-table">
          <thead><tr><th>Threshold</th><th>Metric</th><th>Service</th><th className="num">Warn</th><th className="num">Critical</th><th>Severity</th><th>Enabled</th></tr></thead>
          <tbody>
            {thresholds.map((t) => (
              <tr key={t.id}>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{t.threshold_name}</td>
                <td className="t-muted">{t.metric_type}</td>
                <td className="t-muted">{t.service_name ?? 'all'}</td>
                <td className="num t-muted">{t.warning_threshold ?? '—'}</td>
                <td className="num t-muted">{t.critical_threshold ?? '—'}</td>
                <td><StatusTag status={t.severity} /></td>
                <td><StatusTag status={t.enabled ? 'active' : 'canceled'} /></td>
              </tr>
            ))}
            {(thresholdsQ.isLoading || thresholdsQ.isError || thresholds.length === 0) && <EmptyRow cols={7} loading={thresholdsQ.isLoading} error={thresholdsQ.isError} onRetry={thresholdsQ.refetch} label="No thresholds configured." />}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
