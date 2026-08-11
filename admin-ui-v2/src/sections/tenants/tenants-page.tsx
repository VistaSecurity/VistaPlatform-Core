// VISTA Operations — Tenants list. Ported from the kit's Tenants screen, wired
// to the real admin-service tenant list. Search / status filter / plan filter /
// sort are real; the cross-service metric columns (Health, Assets, Sensors, MRR,
// CSM) render "—" until enriched from tenant-health / inventory / fleet / billing
// — no fabricated data. Row click opens the tenant drawer.
import { useMemo, useState } from 'react';
import { Search, ChevronRight } from 'lucide-react';
import { Avatar, MiniBar, PlanTag, StatusTag, healthColor, initialsFromName, relTime } from '../../components/ui/primitives';
import { useTenants, useTenantHealthMap, tenantStatus, type Tenant, type TenantDisplayStatus } from './queries';
import { TenantDrawer } from './tenant-drawer';
import { useScope } from '../../app/scope';

const STATUS_FILTERS: [TenantDisplayStatus | 'all', string][] = [
  ['all', 'All'], ['active', 'Active'], ['trial', 'Trial'], ['past_due', 'Past due'], ['suspended', 'Suspended'], ['canceled', 'Canceled'],
];

type Sort = 'name' | 'active' | 'created';

export function TenantsPage() {
  const { scopeId } = useScope();
  const { data: tenants, isLoading, isError, refetch } = useTenants(scopeId);
  const { data: healthMap } = useTenantHealthMap();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<TenantDisplayStatus | 'all'>('all');
  const [plan, setPlan] = useState('all');
  const [sort, setSort] = useState<Sort>('name');
  const [open, setOpen] = useState<Tenant | null>(null);

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const all = useMemo(() => tenants ?? [], [tenants]);
  const plans = useMemo(() => Array.from(new Set(all.map((t) => t.subscription_tier).filter(Boolean))) as string[], [all]);
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: all.length };
    for (const [k] of STATUS_FILTERS.slice(1)) c[k] = all.filter((t) => tenantStatus(t) === k).length;
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    // Tenant scope is applied server-side (tenant_id query param); the remaining
    // facets (status/plan/text) filter client-side here.
    const filtered = all.filter((t) =>
      (status === 'all' || tenantStatus(t) === status) &&
      (plan === 'all' || t.subscription_tier === plan) &&
      (!ql || t.name.toLowerCase().includes(ql) || t.slug.toLowerCase().includes(ql) || (t.domain ?? '').toLowerCase().includes(ql)),
    );
    return [...filtered].sort((a, b) =>
      sort === 'name' ? a.name.localeCompare(b.name)
        : sort === 'created' ? Date.parse(b.created_at) - Date.parse(a.created_at)
          : Date.parse(b.updated_at) - Date.parse(a.updated_at),
    );
  }, [all, q, status, plan, sort]);

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {/* filter bar */}
      <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 10, padding: '12px 24px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 32, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 240 }}>
          <Search size={14} style={{ color: 'var(--op-t3)' }} />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search tenants, slug, domain…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }} />
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {STATUS_FILTERS.map(([k, l]) => (
            <button key={k} onClick={() => setStatus(k)} className={'op-chip' + (status === k ? ' active' : '')}>
              {l}<span style={{ opacity: 0.6 }}>{counts[k] ?? 0}</span>
            </button>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        <select value={plan} onChange={(e) => setPlan(e.target.value)} className="op-chip" style={{ height: 32 }}>
          <option value="all">All plans</option>
          {plans.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <select value={sort} onChange={(e) => setSort(e.target.value as Sort)} className="op-chip" style={{ height: 32 }}>
          <option value="name">Sort: Name</option>
          <option value="active">Sort: Recently active</option>
          <option value="created">Sort: Newest</option>
        </select>
        {/* No "New tenant" action: tenants onboard exclusively via self-service signup. */}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
        <table className="op-table">
          <thead><tr>
            <th>Tenant</th><th>Plan</th><th>Status</th><th>Health</th><th className="num">Assets</th><th>Sensors</th><th className="num">MRR</th><th>CSM</th><th>Active</th><th />
          </tr></thead>
          <tbody>
            {rows.map((t) => {
              const plan = t.subscription_tier ?? 'Trial';
              const h = healthMap?.get(t.id);
              const score = h ? Math.round(h.overall_score) : null;
              return (
                <tr key={t.id} style={{ cursor: 'pointer' }} onClick={() => setOpen(t)}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <Avatar initials={initialsFromName(t.name)} size={26} brand={plan === 'Sovereign'} square />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{t.name}</div>
                        <div className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>{t.slug}{t.domain ? ` · ${t.domain}` : ''}</div>
                      </div>
                    </div>
                  </td>
                  <td><PlanTag plan={plan} /></td>
                  <td><StatusTag status={tenantStatus(t)} /></td>
                  <td>
                    {score === null ? <span className="t-muted">—</span> : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className="op-num" style={{ color: healthColor(score), fontWeight: 700, width: 20 }}>{score}</span>
                        <div style={{ width: 40 }}><MiniBar pct={score} color={healthColor(score)} h={5} /></div>
                      </div>
                    )}
                  </td>
                  <td className="num t-muted">—</td>
                  <td className="t-muted">—</td>
                  <td className="num t-muted">—</td>
                  <td className="t-muted">—</td>
                  <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(t.updated_at)}</td>
                  <td><ChevronRight size={15} style={{ color: 'var(--op-t3)' }} /></td>
                </tr>
              );
            })}
            {isLoading && <tr><td colSpan={10} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading tenants…</td></tr>}
            {isError && !isLoading && (
              <tr><td colSpan={10} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>
                Couldn't load tenants. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button>
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={10} style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>No tenants match these filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ flex: 'none', padding: '9px 24px', borderTop: '1px solid var(--op-border)', display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--op-t3)' }}>
        <span>{rows.length} of {all.length} tenants</span>
        <span>·</span>
        <span>Assets · Sensors · MRR enrich from inventory / fleet / billing — wiring next</span>
      </div>

      {open && <TenantDrawer tenant={open} health={healthMap?.get(open.id)} onClose={() => setOpen(null)} />}
    </div>
  );
}
