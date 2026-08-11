import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Pill, riskColor } from '../../components/ui';
import { severityLevel, type AuditAlert } from './meta';

// Remediation → Triage. The mock's alert inbox (Remediation.jsx Triage) on the
// audit-service alerts API: separate signal from noise. Acknowledge dismisses
// an alert; Convert creates a remediation ticket from it (and acknowledges),
// feeding the Queue.

function ago(iso?: string | null): string {
  if (!iso) return '';
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 60) return `${m}m`;
  if (m < 1440) return `${Math.floor(m / 60)}h`;
  return `${Math.floor(m / 1440)}d`;
}

export function TriagePage() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const [show, setShow] = useState<'open' | 'acknowledged' | 'all'>('open');

  const alertsQ = useQuery({
    queryKey: ['remediation', 'alerts'],
    queryFn: async () => {
      const { data, error } = await clients.audit.GET('/alerts', {});
      if (error || !data) throw new Error('Failed to load alerts');
      return data.alerts ?? [];
    },
  });

  const ack = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.audit.POST('/alerts/{id}/acknowledge', { params: { path: { id } } });
      if (error) throw new Error('Failed to acknowledge');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation', 'alerts'] }),
  });

  const convert = useMutation({
    mutationFn: async (a: AuditAlert) => {
      const { error } = await clients.compliance.POST('/tickets', {
        body: {
          category: 'remediation',
          title: a.rule_name ? `${a.rule_name}: ${a.message}`.slice(0, 200) : a.message.slice(0, 200),
          description: `Converted from audit alert ${a.id} (rule: ${a.rule_name}, ${a.event_count} events, triggered ${a.triggered_at}).`,
          priority: (a.severity || 'medium').toLowerCase(),
          severity: (a.severity || 'medium').toLowerCase(),
          source: 'alert',
          tags: ['triage'],
        },
      });
      if (error) throw new Error('Failed to create ticket');
      await clients.audit.POST('/alerts/{id}/acknowledge', { params: { path: { id: a.id } } });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['remediation'] });
      nav('/remediation/queue');
    },
  });

  const all = alertsQ.data ?? [];
  const openCount = all.filter((a) => a.status === 'open').length;
  const rows = show === 'all' ? all : all.filter((a) => a.status === show);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '14px 26px', borderBottom: '1px solid var(--app-border)', flexWrap: 'wrap' }}>
        {([['open', `Open · ${openCount}`], ['acknowledged', 'Acknowledged'], ['all', 'All']] as const).map(([k, label]) => (
          <button key={k} onClick={() => setShow(k)} className="ui-btn sm" style={{ height: 29, fontSize: 12.5, background: show === k ? 'var(--accent-gradient)' : undefined, color: show === k ? 'var(--accent-fg)' : undefined, border: show === k ? 'none' : undefined, fontWeight: show === k ? 700 : 600 }}>
            {label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>separate signal from noise — convert real work into tickets</span>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '10px 26px 26px' }}>
        {alertsQ.isError ? (
          <Empty icon="alert-triangle" title="Couldn't load alerts" message={alertsQ.error instanceof Error ? alertsQ.error.message : 'Request failed'} />
        ) : alertsQ.isLoading ? (
          <Empty icon="loader" title="Loading…" message="Fetching the alert inbox." />
        ) : rows.length === 0 ? (
          <Empty icon="check" title="Inbox zero" message={show === 'open' ? 'Nothing to triage right now. Alerts fire from audit alert-rules as events arrive.' : 'No alerts in this view.'} />
        ) : (
          rows.map((a) => {
            const tone = riskColor(severityLevel(a.severity));
            return (
              <div key={a.id} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '12px 14px', borderBottom: '1px solid var(--app-border)' }}>
                <span style={{ width: 30, height: 30, borderRadius: 8, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${tone} 12%, transparent)`, color: tone }}>
                  <Icon name="bell" size={15} />
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, color: 'var(--app-t1)', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.message}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
                    <Pill color={tone} style={{ fontSize: 9.5, padding: '1px 6px' }}>{a.severity}</Pill>
                    <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{a.rule_name} · {a.event_count} events · {ago(a.triggered_at)} ago</span>
                    {a.status === 'acknowledged' && <span style={{ fontSize: 10, color: 'var(--app-t3)', fontWeight: 600 }}>ACK</span>}
                  </div>
                </div>
                {a.status === 'open' && (
                  <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
                    <button className="ui-btn sm accent" disabled={convert.isPending} onClick={() => convert.mutate(a)} style={{ opacity: convert.isPending ? 0.6 : 1 }}>
                      <Icon name="plus" size={13} />Convert to work
                    </button>
                    <button className="ui-btn sm ghost" disabled={ack.isPending} title="Acknowledge" onClick={() => ack.mutate(a.id)}>
                      <Icon name="x" size={14} />
                    </button>
                  </PermissionGate>
                )}
              </div>
            );
          })
        )}
        {(ack.isError || convert.isError) && (
          <div style={{ marginTop: 10, fontSize: 12, color: 'var(--danger-text)' }}>The last action failed — try again.</div>
        )}
      </div>
    </div>
  );
}

function Empty({ icon, title, message }: { icon: string; title: string; message: string }) {
  return (
    <div style={{ padding: '60px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ opacity: 0.6 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
