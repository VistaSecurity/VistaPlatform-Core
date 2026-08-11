import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon, LevelDot, MiniBar } from '../../components/ui';
import { CATEGORY_ICON, SLA_META, dueDays, severityLevel, slaState, type SlaState, type Ticket } from './meta';
import { TicketDrawer } from './ticket-drawer';

// Remediation → Queue. The mock's SLA-driven work queue (Remediation.jsx Queue)
// on the unified tickets API: metric cards filter the list, rows open the
// ticket drawer. SLA states derive from due_date exactly like the backend's
// overdue / due-soon (3-day) checker.

const GRID = '10px 1.6fr 1fr 1fr 130px 90px';

export function QueuePage() {
  const [filter, setFilter] = useState<'all' | SlaState | 'resolved'>('all');
  const [sel, setSel] = useState<Ticket | null>(null);

  const ticketsQ = useQuery({
    queryKey: ['remediation', 'tickets'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets', { params: { query: {} } });
      if (error || !data) throw new Error('Failed to load tickets');
      return data.tickets ?? [];
    },
  });

  const all = ticketsQ.data ?? [];
  const open = all.filter((t) => t.status === 'open' || t.status === 'in_progress');
  const resolved = all.filter((t) => t.status === 'resolved' || t.status === 'closed');
  const overdue = open.filter((t) => slaState(t) === 'overdue');
  const dueSoon = open.filter((t) => slaState(t) === 'due_soon');
  const onTrackPct = open.length ? Math.round(((open.length - overdue.length - dueSoon.length) / open.length) * 100) : null;

  const rows =
    filter === 'all' ? open
    : filter === 'resolved' ? resolved
    : open.filter((t) => slaState(t) === filter);

  const metric = (label: string, val: number, color: string | null, key: typeof filter) => (
    <button key={key} onClick={() => setFilter(filter === key ? 'all' : key)} className="panel" style={{ padding: '13px 16px', flex: 1, minWidth: 120, cursor: 'pointer', textAlign: 'left', borderColor: filter === key ? 'var(--accent)' : 'var(--app-border)' }}>
      <div className="eyebrow-app">{label}</div>
      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--app-t1)', marginTop: 6 }}>{ticketsQ.isLoading ? '…' : val}</div>
    </button>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', gap: 12, padding: '16px 26px 8px', flexWrap: 'wrap' }}>
        {metric('Open work', open.length, null, 'all')}
        {metric('Overdue', overdue.length, 'var(--danger)', 'overdue')}
        {metric('Due soon', dueSoon.length, 'var(--warn-strong)', 'due_soon')}
        {metric('Resolved', resolved.length, 'var(--ok)', 'resolved')}
        <div className="panel" style={{ padding: '13px 16px', flex: 1, minWidth: 140 }}>
          <div className="eyebrow-app">Keeping pace</div>
          {onTrackPct == null ? (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 10 }}>no open work</div>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 6 }}>
                <span className="mono" style={{ fontSize: 24, fontWeight: 700, color: onTrackPct >= 70 ? 'var(--ok)' : 'var(--warn-strong)' }}>{onTrackPct}%</span>
                <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>on track</span>
              </div>
              <div style={{ marginTop: 6 }}><MiniBar pct={onTrackPct} color={onTrackPct >= 70 ? 'var(--ok)' : 'var(--warn-strong)'} /></div>
            </>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 26px 12px' }}>
        {filter !== 'all' && (
          <button onClick={() => setFilter('all')} className="ui-btn sm" style={{ height: 28, fontSize: 12 }}>
            {filter === 'resolved' ? 'Resolved' : SLA_META[filter as Exclude<SlaState, 'none'>]?.label}<Icon name="x" size={13} />
          </button>
        )}
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{rows.length} items</span>
      </div>

      <div className="panel" style={{ flex: 1, minHeight: 0, margin: '0 26px 22px', overflow: 'auto', borderRadius: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
          {['', 'Ticket', 'Category', 'External', 'SLA', 'Due'].map((h, i) => <span key={i} className="eyebrow-app" style={{ textAlign: i === 5 ? 'right' : 'left' }}>{h}</span>)}
        </div>
        {ticketsQ.isError ? (
          <Empty icon="alert-triangle" title="Couldn't load the queue" message={ticketsQ.error instanceof Error ? ticketsQ.error.message : 'Request failed'} />
        ) : ticketsQ.isLoading ? (
          <Empty icon="loader" title="Loading…" message="Fetching the work queue." />
        ) : rows.length === 0 ? (
          <Empty icon="check" title={filter === 'all' ? 'Queue clear' : 'No items match'} message={filter === 'all' ? 'No open remediation work. New tickets land here.' : 'Nothing in this slice — clear the filter to see all open work.'} />
        ) : (
          rows.map((t) => {
            const sla = slaState(t);
            const d = dueDays(t);
            return (
              <div key={t.id} onClick={() => setSel(t)} className="row-hover" style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
                <LevelDot level={severityLevel(t.severity || t.priority)} />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.title}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{t.status.replace('_', ' ')} · {t.priority}</div>
                </div>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t2)', textTransform: 'capitalize' }}>
                  <Icon name={CATEGORY_ICON[t.category] || 'wrench'} size={13} style={{ color: 'var(--app-t3)' }} />{t.category}
                </span>
                {t.external_ticket_id ? (
                  <span className="mono" style={{ fontSize: 10.5, color: 'var(--info)' }}>{t.external_ticket_system} · {t.external_ticket_id}</span>
                ) : <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}
                <div>
                  {sla === 'none' ? (
                    <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>—</span>
                  ) : (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 600, color: SLA_META[sla].color }}>
                      <span style={{ width: 6, height: 6, borderRadius: 50, background: SLA_META[sla].color }} />{SLA_META[sla].label}
                    </span>
                  )}
                </div>
                <div style={{ textAlign: 'right' }}>
                  {d == null ? <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>—</span>
                    : <span className="mono" style={{ fontSize: 12, color: sla === 'none' ? 'var(--app-t3)' : SLA_META[sla as Exclude<SlaState, 'none'>].color }}>{d < 0 ? `${-d}d late` : `${d}d`}</span>}
                </div>
              </div>
            );
          })
        )}
      </div>

      {sel && <TicketDrawer ticket={sel} onClose={() => setSel(null)} />}
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
