// VISTA Operations — Audit ▸ Activity (the index sub-view). The platform-wide
// activity trail. Folds the v1 admin-ui audit-logs page AND impersonation-log
// page (impersonation is a filter chip here, not a separate page). Filters +
// pagination run server-side via POST /activity-logs/query; clicking a row opens
// a detail modal (ported from v1 audit-logs-page). CSV/JSON export hits the
// server-side export endpoint. All calls go through the typed clients.audit.
import { useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Search, ScrollText, Download, UserCog, ChevronLeft, ChevronRight } from 'lucide-react';
import { Avatar, Tag, initialsFromName, relTime } from '../../components/ui/primitives';
import { Modal } from '../../components/ui/modal';
import { useScope } from '../../app/scope';
import { useActivityLogs, exportActivityLogs, type ActivityFilters, type ActivityLog } from './audit-queries';

const USER_TYPES = ['all', 'platform', 'tenant', 'system'] as const;
type UserTypeFilter = (typeof USER_TYPES)[number];

const PAGE_SIZE = 50;

const actorName = (email?: string, userType?: string) => (email ? email.split('@')[0] : userType || 'system');

/* ----------------------------- detail modal ----------------------------- */

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 12.5, padding: '4px 0' }}>
      <span style={{ color: 'var(--op-t3)', flex: 'none' }}>{label}</span>
      <span style={{ color: 'var(--op-t1)', textAlign: 'right', minWidth: 0, wordBreak: 'break-word' }}>{children}</span>
    </div>
  );
}

function ActivityDetailModal({ log, onClose }: { log: ActivityLog; onClose: () => void }) {
  const detailJson = JSON.stringify(log.metadata ?? log.new_values ?? {}, null, 2);
  return (
    <Modal open onClose={onClose} title="Audit log details" size="lg" secondaryLabel="Close">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        <div>
          <div className="op-eyebrow" style={{ marginBottom: 6 }}>Basic information</div>
          <DetailRow label="Timestamp">{new Date(log.occurred_at).toLocaleString()}</DetailRow>
          <DetailRow label="User">{log.user_email ?? log.user_type}</DetailRow>
          <DetailRow label="User type"><span style={{ textTransform: 'capitalize' }}>{log.user_type}</span></DetailRow>
          <DetailRow label="Action">{log.action}</DetailRow>
          <DetailRow label="Category"><span style={{ textTransform: 'capitalize' }}>{log.event_category}</span></DetailRow>
          <DetailRow label="Resource">{log.resource_type ? `${log.resource_type}${log.resource_id ? ` (${log.resource_id})` : ''}` : '—'}</DetailRow>
          <DetailRow label="Status">
            <span style={{ color: log.success ? 'var(--ok)' : 'var(--danger)', fontWeight: 600 }}>{log.success ? 'Success' : 'Failure'}</span>
          </DetailRow>
          {log.error_message && <DetailRow label="Error">{log.error_message}</DetailRow>}
          {log.compliance_tags && log.compliance_tags.length > 0 && (
            <DetailRow label="Compliance">
              <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {log.compliance_tags.map((t) => <Tag key={t} color="var(--info)">{t}</Tag>)}
              </span>
            </DetailRow>
          )}
        </div>
        <div>
          <div className="op-eyebrow" style={{ marginBottom: 6 }}>Technical details</div>
          <DetailRow label="IP address"><span className="mono">{log.ip_address || '—'}</span></DetailRow>
          <DetailRow label="Request ID"><span className="mono" style={{ fontSize: 11 }}>{log.request_id || '—'}</span></DetailRow>
          {log.session_id && <DetailRow label="Session ID"><span className="mono" style={{ fontSize: 11 }}>{log.session_id}</span></DetailRow>}
          {log.tenant_id && <DetailRow label="Tenant ID"><span className="mono" style={{ fontSize: 11 }}>{log.tenant_id}</span></DetailRow>}
          {log.user_agent && (
            <div style={{ marginTop: 8 }}>
              <div className="op-eyebrow" style={{ marginBottom: 4 }}>User agent</div>
              <div style={{ fontSize: 11, color: 'var(--op-t2)', background: 'var(--op-panel2)', borderRadius: 'var(--r-sm)', padding: 8, wordBreak: 'break-all' }}>{log.user_agent}</div>
            </div>
          )}
        </div>
      </div>
      <div>
        <div className="op-eyebrow" style={{ marginBottom: 4 }}>Action details</div>
        <pre style={{ fontSize: 11, color: 'var(--op-t2)', background: 'var(--op-panel2)', borderRadius: 'var(--r-sm)', padding: 10, margin: 0, maxHeight: 220, overflow: 'auto' }}>{detailJson}</pre>
      </div>
    </Modal>
  );
}

/* -------------------------------- page ---------------------------------- */

export function ActivityPage() {
  const { scopeId } = useScope();
  const [q, setQ] = useState('');
  const [cat, setCat] = useState('all');
  const [userType, setUserType] = useState<UserTypeFilter>('all');
  const [impOnly, setImpOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<ActivityLog | null>(null);

  // All filters run server-side via the typed query body, so pagination totals
  // reflect the filtered set. Tenant scope + impersonation are real server
  // filters now (no client-side refinement).
  const filters: ActivityFilters = useMemo(() => ({
    page,
    page_size: PAGE_SIZE,
    search: q.trim() || undefined,
    event_category: cat === 'all' ? undefined : [cat],
    user_type: userType === 'all' ? undefined : userType,
    tenant_id: scopeId || undefined,
    impersonation: impOnly || undefined,
  }), [page, q, cat, userType, scopeId, impOnly]);

  const { data, isLoading, isError, refetch } = useActivityLogs(filters);
  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const rows = useMemo(() => data?.logs ?? [], [data?.logs]);
  const pagination = data?.pagination;

  // Reset to page 1 whenever a result-set-changing filter toggles, so we never
  // land on an out-of-range page after the filtered count shrinks.
  useEffect(() => { setPage(1); }, [q, cat, userType, scopeId, impOnly]);

  // Category chips derived from the visible page (the server has no category-list
  // endpoint; chips reflect what's present).
  const categories = useMemo(
    () => ['all', ...Array.from(new Set(rows.map((l) => l.event_category).filter(Boolean)))],
    [rows],
  );

  const onExport = async (format: 'csv' | 'json') => {
    try { await exportActivityLogs(format); toast.success(`Exported ${format.toUpperCase()}`); }
    catch { toast.error('Export failed'); }
  };

  const resetPage = () => setPage(1);

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {/* filter bar */}
      <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 10, padding: '12px 24px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 32, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 220 }}>
          <Search size={14} style={{ color: 'var(--op-t3)' }} />
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); resetPage(); }}
            placeholder="Search actor, action, target…"
            style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }}
          />
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {categories.map((c) => (
            <button key={c} onClick={() => { setCat(c); resetPage(); }} className={'op-chip' + (cat === c ? ' active' : '')} style={{ textTransform: c === 'all' ? 'none' : 'capitalize' }}>{c === 'all' ? 'All' : c}</button>
          ))}
        </div>
        <div style={{ width: 1, height: 20, background: 'var(--op-border)' }} />
        <div style={{ display: 'flex', gap: 6 }}>
          {USER_TYPES.map((u) => (
            <button key={u} onClick={() => { setUserType(u); resetPage(); }} className={'op-chip' + (userType === u ? ' active' : '')} style={{ textTransform: 'capitalize' }}>{u}</button>
          ))}
        </div>
        {/* impersonation filter (folds the v1 impersonation-log page) */}
        <button onClick={() => setImpOnly((v) => !v)} className={'op-chip' + (impOnly ? ' active' : '')} title="Show only impersonation events"><UserCog size={13} style={{ marginRight: 4, verticalAlign: '-2px' }} />Impersonation</button>
        {/* export */}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          <button onClick={() => onExport('csv')} className="op-btn sm"><Download size={13} />CSV</button>
          <button onClick={() => onExport('json')} className="op-btn sm"><Download size={13} />JSON</button>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
        <table className="op-table">
          <thead><tr><th>Actor</th><th>Action</th><th>Target</th><th>Category</th><th>Time</th><th>Source IP</th></tr></thead>
          <tbody>
            {rows.map((l) => (
              <tr key={l.id} onClick={() => setSelected(l)} style={{ cursor: 'pointer' }}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <Avatar initials={initialsFromName(actorName(l.user_email, l.user_type)).slice(0, 2)} size={24} />
                    <span style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{l.user_email ?? l.user_type}</span>
                  </div>
                </td>
                <td className="t-muted" style={{ fontSize: 12 }}>{l.action}</td>
                <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{l.resource_type ? `${l.resource_type}${l.resource_id ? ` · ${l.resource_id.slice(0, 8)}` : ''}` : '—'}</td>
                <td><Tag color="var(--op-t2)" style={{ textTransform: 'capitalize' }}>{l.event_category}</Tag></td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(l.occurred_at)}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{l.ip_address || '—'}</td>
              </tr>
            ))}
            {isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading audit log…</td></tr>}
            {isError && !isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Couldn't load audit log. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
            {!isLoading && !isError && rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No matching audit entries.</td></tr>}
          </tbody>
        </table>
      </div>

      {/* footer + pagination */}
      <div style={{ flex: 'none', padding: '9px 24px', borderTop: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--op-t3)' }}>
        <ScrollText size={13} />
        <span>{pagination ? `${pagination.total.toLocaleString()} events` : `${rows.length} events`}</span>
        <span>·</span>
        <span>Platform-wide trail (folds Log Explorer + impersonation log). Export is the full server-side log.</span>
        <div style={{ flex: 1 }} />
        {pagination && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Page {pagination.page} / {Math.max(1, pagination.total_pages)}</span>
            <button className="op-btn icon sm" disabled={!pagination.has_prev} onClick={() => setPage((p) => Math.max(1, p - 1))}><ChevronLeft size={14} /></button>
            <button className="op-btn icon sm" disabled={!pagination.has_next} onClick={() => setPage((p) => p + 1)}><ChevronRight size={14} /></button>
          </div>
        )}
      </div>

      {selected && <ActivityDetailModal log={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
