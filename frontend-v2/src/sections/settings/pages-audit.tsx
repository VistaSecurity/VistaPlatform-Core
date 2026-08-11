// Settings · Audit Log — ported from the mock's settings/sectionF.jsx audit
// page, wired to audit-service GET /activity-logs. The search / actor / window
// filters run client-side over the loaded page (the list endpoint paginates
// but does not yet expose filter params in the contract slice).
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SCard, STable, STableRow, SSelect, StateNote, relTime } from './kit';
import type { SettingsNavItem } from './nav';

const WINDOWS: Record<string, number> = { '24h': 24 * 3600e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

export function AuditPage({ meta }: { meta: SettingsNavItem }) {
  const [search, setSearch] = useState('');
  const [actor, setActor] = useState('all');
  const [window_, setWindow] = useState('7d');

  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'audit-logs'],
    queryFn: async () => {
      const { data, error } = await clients.audit.GET('/activity-logs', {
        params: { query: { page: 1, page_size: 100 } },
      });
      if (error || !data) throw new Error('Failed to load the audit trail');
      return data;
    },
  });

  const logs = useMemo(() => data?.logs ?? [], [data]);
  const actors = useMemo(
    () => Array.from(new Set(logs.map((l) => l.user_email || 'System'))).sort(),
    [logs],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const cutoff = Date.now() - (WINDOWS[window_] ?? WINDOWS['7d']);
    return logs.filter((l) => {
      const who = l.user_email || 'System';
      if (actor !== 'all' && who !== actor) return false;
      if (new Date(l.occurred_at).getTime() < cutoff) return false;
      if (!q) return true;
      return [who, l.action, l.event_type, l.event_category, l.resource_type, l.resource_id]
        .filter(Boolean).join(' ').toLowerCase().includes(q);
    });
  }, [logs, search, actor, window_]);

  const cols = [
    { label: 'Actor', w: '170px' }, { label: 'Action', w: '1fr' },
    { label: 'Target', w: '1.4fr' }, { label: 'When', w: '100px', align: 'right' as const },
  ];

  return (
    <SPage eyebrow="Audit" title="Audit Log" job={meta.job} maxWidth={1000}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '0 0 240px' }}>
          <Icon name="search" size={14} style={{ position: 'absolute', left: 11, top: 10, color: 'var(--app-t3)' }} />
          <input
            placeholder="Search audit trail…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: '100%', height: 34, padding: '0 12px 0 33px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }}
          />
        </div>
        <SSelect key={actors.join('|')} value={actor} onChange={setActor} options={[['all', 'All actors'], ...actors.map((a): [string, string] => [a, a])]} width={190} />
        <SSelect value={window_} onChange={setWindow} options={[['24h', 'Last 24h'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']]} width={140} />
      </div>

      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the audit trail" message="The activity log failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading audit trail…" message="Fetching recent activity." /></SCard>
      ) : filtered.length === 0 ? (
        <SCard><StateNote icon="history" tone="var(--app-t3)" title="No matching activity" message={logs.length ? 'No events match the current filters.' : 'No activity has been recorded yet.'} /></SCard>
      ) : (
        <STable cols={cols}>
          {filtered.map((l, i) => (
            <STableRow
              key={l.id}
              first={i === 0}
              cols={cols}
              cells={[
                <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>
                  {l.user_email || 'System'}
                </span>,
                <span style={{ fontSize: 12.5, color: l.success ? 'var(--app-t2)' : 'var(--danger-text)' }}>
                  {l.action}{l.success ? '' : ' · failed'}
                </span>,
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>
                  {[l.resource_type, l.resource_id].filter(Boolean).join(' · ') || l.event_category}
                </span>,
                <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{relTime(l.occurred_at)}</span>,
              ]}
            />
          ))}
        </STable>
      )}
      {data?.pagination && data.pagination.total > logs.length && (
        <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 13 }}>
          Showing the {logs.length} most recent of {data.pagination.total} events.
        </p>
      )}
    </SPage>
  );
}
