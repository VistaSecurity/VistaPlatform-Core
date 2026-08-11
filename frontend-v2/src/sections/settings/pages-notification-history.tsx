// Settings · Notifications & Alerts · Delivery History — the tenant-facing
// observability surface for the notification pipeline. Every event the platform
// tried to notify about lands here, including the ones that matched NO routing
// rule and were therefore silently dropped — those rows get a warning tint and
// an explicit "no rule matched" channels cell so silent drops are visible.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SCard, STable, STableRow, STag, StateNote, relTime, GREEN, AMBER, RED } from './kit';
import type { SettingsNavItem } from './nav';

const SEVERITY_TONE: Record<string, string> = {
  critical: RED, high: 'var(--warn-strong)', medium: AMBER, low: 'var(--info)', info: 'var(--app-t3)',
};
const STATUS_TONE: Record<string, string> = {
  sent: GREEN, failed: RED, pending: AMBER, partial: AMBER,
};

function useNotificationHistory() {
  return useQuery({
    queryKey: ['settings', 'notification-history'],
    queryFn: async () => {
      // Gate on response.ok — empty-body errors surface as falsy `error` in
      // openapi-fetch (same guard as the other settings pages).
      const { data, response } = await clients.notifications.GET('/tenant/history', {
        params: { query: { limit: 100 } },
      });
      if (!response.ok) throw new Error('Failed to load notification history');
      return data ?? [];
    },
  });
}

export function NotificationHistoryPage({ meta }: { meta: SettingsNavItem }) {
  const { data, isLoading, isError } = useNotificationHistory();
  const rows = data ?? [];

  const cols = [
    { label: 'Time', w: '80px' },
    { label: 'Source', w: '110px' },
    { label: 'Type', w: '150px' },
    { label: 'Severity', w: '90px' },
    { label: 'Message', w: '2fr' },
    { label: 'Channels', w: '1.1fr' },
    { label: 'Status', w: '80px', align: 'right' as const },
  ];

  return (
    <SPage eyebrow="Notifications & Alerts" title="Delivery History" job={meta.job} maxWidth={1100}>
      <div className="panel" style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '12px 16px', marginBottom: 14, border: `1px solid color-mix(in srgb, ${AMBER} 35%, transparent)` }}>
        <Icon name="info" size={15} style={{ color: AMBER, flex: 'none', marginTop: 1 }} />
        <p style={{ margin: 0, fontSize: 12, lineHeight: 1.55, color: 'var(--app-t2)' }}>
          Rows with an empty channels column matched <strong style={{ color: 'var(--app-t1)' }}>no routing rule</strong> — the event was recorded but not delivered anywhere.
          Add or widen a rule under <strong style={{ color: 'var(--app-t1)' }}>Routing Rules</strong> if those events should reach a channel.
        </p>
      </div>

      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load delivery history" message="The notification history failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading delivery history…" message="Fetching the tenant's recent notifications." /></SCard>
      ) : rows.length === 0 ? (
        <SCard><StateNote icon="mail" tone="var(--app-t3)" title="No notifications recorded yet." message="Once the platform starts raising alerts, every delivery attempt will be listed here." /></SCard>
      ) : (
        <STable cols={cols}>
          {rows.map((r, i) => {
            const sev = (r.severity || '').toLowerCase();
            const status = (r.status || '').toLowerCase();
            const undelivered = !r.channels_used || r.channels_used.length === 0;
            return (
              <STableRow
                key={r.id}
                first={i === 0}
                cols={cols}
                style={undelivered ? { background: `color-mix(in srgb, ${AMBER} 6%, transparent)` } : undefined}
                cells={[
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>{relTime(r.created_at)}</span>,
                  <span style={{ fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>{r.alert_source || '—'}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>{r.alert_type || r.notification_type || '—'}</span>,
                  <STag color={SEVERITY_TONE[sev] ?? 'var(--app-t3)'}>{r.severity || '—'}</STag>,
                  <span title={r.message} style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>{r.message}</span>,
                  undelivered ? (
                    <span style={{ fontSize: 11.5, color: AMBER, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>— (no rule matched)</span>
                  ) : (
                    <span style={{ fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>{(r.channels_used ?? []).join(', ')}</span>
                  ),
                  <STag color={STATUS_TONE[status] ?? 'var(--app-t3)'}>{r.status || '—'}</STag>,
                ]}
              />
            );
          })}
        </STable>
      )}
    </SPage>
  );
}
