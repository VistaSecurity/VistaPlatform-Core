import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { LEGACY_TICKET_CATEGORIES, TICKET_CATEGORIES, ticketCategory } from '@vistasecurity/primitives/tickets';
import { clients } from '../../lib/clients';
import { Icon, LevelDot, MiniBar } from '../../components/ui';
import { SLA_META, dueDays, severityLevel, slaState, type Ticket } from './meta';
import { TicketDrawer } from './ticket-drawer';
import { CreateTicketModal } from './create-ticket-modal';
import { useTenantUsers } from '../findings/queries';

// Remediation → Queue. The SLA-driven work queue on the unified tickets API.
//
// Two things here are load-bearing and were both wrong before:
//
//   1. THE CARDS COME FROM /tickets/stats, not from the rows on screen.
//      GET /tickets is paginated and defaults to twenty rows; this page used to
//      request it with no parameters and treat the response as the whole
//      tenant. So "Open work", "Overdue", "Due soon" and "Keeping pace" all
//      described the newest twenty tickets while appearing to describe
//      everything, and the error grew silently with the backlog.
//   2. FILTERING IS SERVER-SIDE. Filtering a page of twenty locally answers a
//      different question from filtering the tenant, and gives fewer rows than
//      the card it sits under claims.

const GRID = '10px 1.6fr 1fr 1fr 130px 90px';
const PAGE_SIZE = 25;

// The retired category still appears in the FILTER — those rows exist and have
// to be findable — but never in the create form. See the primitives registry.
const FILTERABLE = [...TICKET_CATEGORIES.map((c) => c.key), ...LEGACY_TICKET_CATEGORIES];

const STATUSES = ['open', 'in_progress', 'resolved', 'closed'] as const;

type Slice = 'open' | 'overdue' | 'due_soon' | 'resolved';

export function QueuePage() {
  const { tenant } = useAuth();
  const [params, setParams] = useSearchParams();
  const [slice, setSlice] = useState<Slice>('open');
  // ?category= is how Progress drills into a specific backlog. Seeded from the
  // URL rather than read on every render: once here, the filter dropdown owns
  // it, and re-reading would fight the user's next change.
  const [category, setCategory] = useState(() => params.get('category') ?? '');
  const [status, setStatus] = useState('');
  const [assignee, setAssignee] = useState('');
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  // Page is keyed by the filter set rather than reset from an effect: any
  // filter change must return you to page 1, and doing that in an effect means
  // one render where page 4 is requested against the new filters. Staying on
  // page 4 of a narrower result set shows an empty table that reads as "no
  // matches".
  const filterKey = [slice, category, status, assignee, debounced].join('|');
  const [pageState, setPage] = useState({ key: filterKey, page: 1 });
  const page = pageState.key === filterKey ? pageState.page : 1;
  const goToPage = (next: number) => setPage({ key: filterKey, page: next });
  const [createOpen, setCreateOpen] = useState(false);
  const [sel, setSel] = useState<Ticket | null>(null);

  const members = useTenantUsers(tenant?.id);

  // Typing a search term should not fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 250);
    return () => clearTimeout(t);
  }, [search]);

  // The cards are tenant-wide and independent of the filters, which is the
  // point — they are the denominator the filtered list is a slice of.
  const statsQ = useQuery({
    queryKey: ['remediation', 'ticket-stats'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets/stats', {});
      if (error || !data) throw new Error('Failed to load ticket totals');
      return data.stats;
    },
  });

  const query = useMemo(() => {
    const q: Record<string, string | number | boolean> = { page, page_size: PAGE_SIZE };
    if (category) q.category = category;
    if (assignee) q.assigned_to = assignee;
    if (debounced) q.search = debounced;
    if (slice === 'overdue') q.overdue = true;
    // The status filter and the slice both constrain status, so an explicit
    // choice wins over the slice's implied one.
    if (status) q.status = status;
    else if (slice === 'resolved') q.status = 'resolved';
    else if (slice === 'open') q.status = 'open';
    return q;
  }, [page, category, assignee, debounced, slice, status]);

  const ticketsQ = useQuery({
    queryKey: ['remediation', 'tickets', query],
    // Without this the table blanks to the loading state on every page step,
    // which reads as the data vanishing.
    placeholderData: keepPreviousData,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets', { params: { query } });
      if (error || !data) throw new Error('Failed to load tickets');
      return data;
    },
  });

  const rowsRaw = ticketsQ.data?.tickets ?? [];
  // `due_soon` has no server-side filter — it is a window over due_date rather
  // than a column — so this one slice narrows the PAGE. The card above it still
  // reads the tenant-wide number, and the count beside the table says how many
  // of the fetched page matched, so the two are not presented as the same thing.
  const rows = slice === 'due_soon' ? rowsRaw.filter((t) => slaState(t) === 'due_soon') : rowsRaw;
  const total = ticketsQ.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const st = statsQ.data;
  const openCount = (st?.by_status?.open ?? 0) + (st?.by_status?.in_progress ?? 0);
  const resolvedCount = (st?.by_status?.resolved ?? 0) + (st?.by_status?.closed ?? 0);
  const overdue = st?.overdue ?? 0;
  const dueSoon = st?.due_soon ?? 0;
  const onTrackPct = openCount ? Math.round(((openCount - overdue - dueSoon) / openCount) * 100) : null;

  // ?ticket=<id> deep-links straight into the drawer, the way Alerts does with
  // ?alert=<id> — so a notification or a shared link opens the ticket itself.
  const deepLinked = params.get('ticket');
  const deepQ = useQuery({
    queryKey: ['remediation', 'ticket', deepLinked],
    enabled: !!deepLinked,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets/{id}', { params: { path: { id: deepLinked! } } });
      if (error || !data) throw new Error('Failed to load ticket');
      return data.ticket;
    },
  });
  // The drawer shows the deep-linked ticket until it is closed, then whatever
  // row is selected. Derived rather than copied into state by an effect, which
  // would re-open the drawer every time the query refetched.
  const [deepDismissed, setDeepDismissed] = useState(false);
  const shown: Ticket | null = sel ?? (deepDismissed ? null : (deepQ.data ?? null));

  const closeDrawer = () => {
    setSel(null);
    setDeepDismissed(true);
    if (params.get('ticket')) {
      const next = new URLSearchParams(params);
      next.delete('ticket');
      setParams(next, { replace: true });
    }
  };

  const metric = (label: string, val: number, color: string | null, key: Slice) => (
    <button
      key={key}
      onClick={() => setSlice(key)}
      className="panel"
      style={{ padding: '13px 16px', flex: 1, minWidth: 120, cursor: 'pointer', textAlign: 'left', borderColor: slice === key ? 'var(--accent)' : 'var(--app-border)' }}
    >
      <div className="eyebrow-app">{label}</div>
      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: statsQ.isError ? 'var(--danger-text)' : color ?? 'var(--app-t1)', marginTop: 6 }}>
        {statsQ.isError ? '—' : statsQ.isLoading ? '…' : val}
      </div>
    </button>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 26px 0' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>Queue</h2>
        <div style={{ flex: 1 }} />
        <button className="ui-btn sm accent" onClick={() => setCreateOpen(true)}>
          <Icon name="plus" size={14} />New ticket
        </button>
      </div>

      <div style={{ display: 'flex', gap: 12, padding: '12px 26px 8px', flexWrap: 'wrap' }}>
        {metric('Open work', openCount, null, 'open')}
        {metric('Overdue', overdue, 'var(--danger)', 'overdue')}
        {metric('Due soon', dueSoon, 'var(--warn-strong)', 'due_soon')}
        {metric('Resolved', resolvedCount, 'var(--ok)', 'resolved')}
        <div className="panel" style={{ padding: '13px 16px', flex: 1, minWidth: 140 }}>
          <div className="eyebrow-app">Keeping pace</div>
          {statsQ.isError ? (
            <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 10 }}>couldn't load totals</div>
          ) : onTrackPct == null ? (
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

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 26px 12px', flexWrap: 'wrap' }}>
        <Select value={category} onChange={setCategory} label="All categories" width={168}>
          {FILTERABLE.map((key) => (
            <option key={key} value={key}>{ticketCategory(key)?.label ?? key}</option>
          ))}
        </Select>
        <Select value={status} onChange={setStatus} label="Any status" width={140}>
          {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </Select>
        <Select value={assignee} onChange={setAssignee} label="Anyone" width={170} disabled={members.isError}>
          {(members.data ?? []).map((u) => (
            <option key={u.id} value={u.id}>{[u.first_name, u.last_name].filter(Boolean).join(' ') || u.email}</option>
          ))}
        </Select>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search titles…"
          style={{ height: 28, minWidth: 180, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none' }}
        />
        {(category || status || assignee || search) && (
          <button
            className="ui-btn sm"
            style={{ height: 28, fontSize: 12 }}
            onClick={() => { setCategory(''); setStatus(''); setAssignee(''); setSearch(''); }}
          >
            Clear<Icon name="x" size={13} />
          </button>
        )}
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>
          {ticketsQ.isLoading ? '…' : slice === 'due_soon' ? `${rows.length} on this page` : `${total} item${total === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="panel" style={{ flex: 1, minHeight: 0, margin: '0 26px 10px', overflow: 'auto', borderRadius: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
          {['', 'Ticket', 'Category', 'External', 'SLA', 'Due'].map((h, i) => <span key={i} className="eyebrow-app" style={{ textAlign: i === 5 ? 'right' : 'left' }}>{h}</span>)}
        </div>
        {ticketsQ.isError ? (
          <Empty icon="alert-triangle" title="Couldn't load the queue" message={ticketsQ.error instanceof Error ? ticketsQ.error.message : 'Request failed'} />
        ) : ticketsQ.isLoading ? (
          <Empty icon="loader" title="Loading…" message="Fetching the work queue." />
        ) : rows.length === 0 ? (
          <Empty
            icon="check"
            title={category || status || assignee || search ? 'No items match' : 'Queue clear'}
            message={category || status || assignee || search
              ? 'Nothing matches these filters — clear them to see all work.'
              : 'No open remediation work. New tickets land here.'}
          />
        ) : (
          rows.map((t) => {
            const sla = slaState(t);
            const d = dueDays(t);
            const cat = ticketCategory(t.category);
            return (
              <div key={t.id} onClick={() => setSel(t)} className="row-hover" style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
                {/* eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing --
                    `??` is WRONG here. severity is nullable and also clearable to
                    "" from the drawer, and an empty severity must fall through to
                    priority; `??` keeps the "" and grades the row Informational. */}
                <LevelDot level={severityLevel(t.severity || t.priority)} />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.title}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{t.status.replace('_', ' ')} · {t.priority}</div>
                </div>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t2)' }}>
                  <Icon name={cat?.icon ?? 'wrench'} size={13} style={{ color: 'var(--app-t3)' }} />{cat?.label ?? t.category}
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
                    : <span className="mono" style={{ fontSize: 12, color: sla === 'none' ? 'var(--app-t3)' : SLA_META[sla].color }}>{d < 0 ? `${-d}d late` : `${d}d`}</span>}
                </div>
              </div>
            );
          })
        )}
      </div>

      {pages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, padding: '0 26px 18px' }}>
          <button className="ui-btn sm" style={{ height: 28, fontSize: 12 }} disabled={page <= 1} onClick={() => goToPage(page - 1)}>
            <Icon name="chevron-left" size={13} />Previous
          </button>
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>page {page} of {pages}</span>
          <button className="ui-btn sm" style={{ height: 28, fontSize: 12 }} disabled={page >= pages} onClick={() => goToPage(page + 1)}>
            Next<Icon name="chevron-right" size={13} />
          </button>
        </div>
      )}

      {createOpen && (
        <CreateTicketModal
          open
          onClose={() => setCreateOpen(false)}
          onCreated={(id) => setParams({ ticket: id }, { replace: true })}
        />
      )}
      {shown && <TicketDrawer ticket={shown} onClose={closeDrawer} />}
    </div>
  );
}

function Select({ value, onChange, label, width, disabled, children }: {
  value: string; onChange: (v: string) => void; label: string; width: number; disabled?: boolean; children: React.ReactNode;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      style={{ height: 28, width, padding: '0 8px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: value ? 'var(--app-t1)' : 'var(--app-t3)', fontSize: 12, outline: 'none', cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.5 : 1 }}
    >
      <option value="">{label}</option>
      {children}
    </select>
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
