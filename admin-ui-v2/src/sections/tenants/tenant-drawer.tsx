// Tenant detail drawer (right-side slide-in) — ported from the kit's TenantDrawer
// and built up to a tabbed surface that folds the v1 tenant-detail / tenant-billing
// / tenant-entitlements / tenant-sso pages into one drawer (see admin-ui-v2
// BUILD_PLAN Phase 1). Every tab renders what its typed endpoint actually
// provides; cross-service gaps render an honest empty-state with a note — no
// fabricated numbers. Best-effort first pass; polish (per-tenant entitlement
// overrides, SSO config editing, platform-scoped activity) tracked in BUILD_PLAN.
import { useState } from 'react';
import toast from 'react-hot-toast';
import {
  X, LogIn, Filter, Pencil, Pause, Play, Trash2, MapPin, RefreshCw,
  Users, Boxes, Radar, HardDrive, KeyRound, ShieldCheck, ShieldOff, Ticket, ScrollText,
} from 'lucide-react';
import { Avatar, MiniBar, PlanTag, StatusTag, healthColor, initialsFromName, money, relTime } from '../../components/ui/primitives';
import {
  type Tenant, type TenantHealthSummary, tenantStatus, useTenantStatusMutation,
  useTenantReevaluateMutation, useTenantStats, useTenantCost, useTenantCoupons, useTierEntitlements,
  useDeleteTenant, useAdminTiers, useAdminChangePlan,
} from './queries';
import { TenantFormModal } from './tenant-form-modal';
import { PlanExceptionsPanel } from './plan-exceptions';

const TABS = ['Overview', 'Billing', 'Entitlements', 'SSO', 'Activity'] as const;
type DrawerTab = (typeof TABS)[number];

function DrawerSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: '16px 20px', borderTop: '1px solid var(--op-border)' }}>
      <div className="op-eyebrow" style={{ marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 12.5 }}>
      <span style={{ color: 'var(--op-t3)' }}>{label}</span>
      <span style={{ color: 'var(--op-t1)', fontWeight: 500, textAlign: 'right', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</span>
    </div>
  );
}

/** Honest empty/pending block — used where a tab's data source isn't wired yet. */
function Pending({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '12px 14px', fontSize: 12, color: 'var(--op-t3)', lineHeight: 1.55 }}>
      {children}
    </div>
  );
}

function StatCell({ icon: Icon, label, value }: { icon: typeof Users; label: string; value: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '11px 13px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--op-t3)', fontSize: 11 }}><Icon size={13} />{label}</div>
      <div className="op-num" style={{ fontSize: 19, fontWeight: 700, color: 'var(--op-t1)', marginTop: 5 }}>{value}</div>
    </div>
  );
}

// ---- Tabs ------------------------------------------------------------------

function OverviewTab({ t, health, onClose }: { t: Tenant; health?: TenantHealthSummary; onClose: () => void }) {
  const status = tenantStatus(t);
  const plan = t.subscription_tier ?? 'Trial';
  const score = health ? Math.round(health.overall_score) : null;
  const stats = useTenantStats(t.id);
  const statusMut = useTenantStatusMutation();
  const deleteMut = useDeleteTenant();

  const toggleStatus = () => {
    const action = status === 'suspended' ? 'activate' : 'suspend';
    if (!window.confirm(`${action === 'suspend' ? 'Suspend' : 'Reactivate'} ${t.name}? This is logged to audit.`)) return;
    statusMut.mutate(
      { id: t.id, action },
      {
        onSuccess: () => toast.success(`${t.name} ${action === 'suspend' ? 'suspended' : 'reactivated'}`),
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Action failed'),
      },
    );
  };
  const reevalMut = useTenantReevaluateMutation();
  const reevaluate = () => {
    if (!window.confirm(`Re-evaluate all of ${t.name}'s assets against every framework? This is an extraordinary action and is logged to audit.`)) return;
    reevalMut.mutate(
      { id: t.id },
      {
        onSuccess: () => toast.success(`Re-evaluation enqueued for ${t.name}`),
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Action failed'),
      },
    );
  };
  const remove = () => {
    if (!window.confirm(`Delete ${t.name}? This soft-deletes the tenant (recoverable) and is logged to audit.`)) return;
    deleteMut.mutate(
      { id: t.id },
      {
        onSuccess: () => { toast.success(`${t.name} deleted`); onClose(); },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Delete failed'),
      },
    );
  };

  return (
    <>
      {score !== null && health && (
        <DrawerSection title="Health">
          <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '12px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className="op-num" style={{ fontSize: 24, fontWeight: 700, color: healthColor(score), lineHeight: 1 }}>{score}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--op-t1)', fontWeight: 500, textTransform: 'capitalize' }}>{health.health_status}</div>
                <div style={{ marginTop: 6 }}><MiniBar pct={score} color={healthColor(score)} h={5} /></div>
              </div>
              {health.critical_alerts > 0 && <span style={{ fontSize: 11, color: 'var(--danger)', fontWeight: 600 }}>{health.critical_alerts} critical</span>}
            </div>
          </div>
        </DrawerSection>
      )}

      <DrawerSection title="Usage">
        {stats.isLoading ? (
          <Pending>Loading usage…</Pending>
        ) : stats.data ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <StatCell icon={Users} label="Users" value={stats.data.user_count.toLocaleString()} />
            <StatCell icon={Boxes} label="Assets" value={stats.data.asset_count.toLocaleString()} />
            <StatCell icon={Radar} label="Sensors" value={stats.data.sensor_count.toLocaleString()} />
            <StatCell icon={HardDrive} label="Storage" value={`${(stats.data.storage_used / 1e9).toFixed(1)} GB`} />
          </div>
        ) : (
          <Pending>Usage stats unavailable.</Pending>
        )}
      </DrawerSection>

      <DrawerSection title="Account">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
          <Row label="Plan" value={plan} />
          <Row label="Billing status" value={statusOfLabel(status)} />
          <Row label="Billing email" value={t.billing_email || '—'} />
          <Row label="SSO" value={t.sso_enabled ? 'Enabled' : 'Disabled'} />
          <Row label="Trial ends" value={t.trial_ends_at ? new Date(t.trial_ends_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'} />
          <Row label="Customer since" value={relTime(t.created_at)} />
          <Row label="Last updated" value={relTime(t.updated_at)} />
        </div>
      </DrawerSection>

      <DrawerSection title="Tenant controls">
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={toggleStatus} disabled={statusMut.isPending} className="op-btn sm" style={{ flex: 1, justifyContent: 'center' }}>
            {status === 'suspended' ? <><Play size={14} />Reactivate</> : <><Pause size={14} />Suspend</>}
          </button>
          <button onClick={remove} disabled={deleteMut.isPending} className="op-btn danger sm" style={{ flex: 1, justifyContent: 'center' }}><Trash2 size={14} />{deleteMut.isPending ? 'Deleting…' : 'Delete'}</button>
        </div>
        <button onClick={reevaluate} disabled={reevalMut.isPending} className="op-btn sm" style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}>
          <RefreshCw size={14} />{reevalMut.isPending ? 'Enqueuing…' : 'Re-evaluate compliance'}
        </button>
      </DrawerSection>
    </>
  );
}

// Support plan change: the only downgrade path — tenants can't
// self-serve one mid-agreement. Applied with NO proration: monthly tenants
// bill the new price from the next period; annual-prepaid tenants get no
// automatic refund and renew at the new rate.
function PlanChangePanel({ t }: { t: Tenant }) {
  const tiers = useAdminTiers();
  const change = useAdminChangePlan();
  const [tierId, setTierId] = useState('');
  const [reason, setReason] = useState('');

  const options = (tiers.data ?? []).filter((tier) => tier.is_active && !tier.deprecated_at);
  const apply = async () => {
    try {
      const res = await change.mutateAsync({ id: t.id, tierId, reason: reason.trim() });
      toast.success(res.message || 'Plan changed — next invoice bills the new rate.');
      setTierId(''); setReason('');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to change the tenant plan');
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 10px', borderRadius: 'var(--r-sm)', fontSize: 12.5,
    border: '1px solid var(--op-border)', background: 'var(--op-panel2)', color: 'var(--op-t1)', outline: 'none',
  };

  return (
    <DrawerSection title="Change plan (support)">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
          Current plan: <strong style={{ color: 'var(--op-t1)' }}>{t.subscription_tier ?? 'Trial'}</strong>.
          Applied with no proration — nothing is refunded; the next invoice bills the new plan's rate.
          Downgrades mid-agreement are granted here only (tenants can only upgrade themselves).
        </div>
        <select value={tierId} onChange={(e) => setTierId(e.target.value)} disabled={tiers.isLoading || change.isPending} style={inputStyle}>
          <option value="">{tiers.isLoading ? 'Loading plans…' : 'Select a plan…'}</option>
          {options.map((tier) => (
            <option key={tier.id} value={tier.id}>{tier.display_name || tier.name}</option>
          ))}
        </select>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          placeholder="Reason (required — recorded in the platform audit log)"
          disabled={change.isPending}
          style={{ ...inputStyle, resize: 'vertical' }}
        />
        <button
          className="op-btn sm"
          style={{ justifyContent: 'center' }}
          disabled={!tierId || !reason.trim() || change.isPending}
          onClick={apply}
        >
          {change.isPending ? 'Applying…' : 'Apply plan change'}
        </button>
      </div>
    </DrawerSection>
  );
}

function BillingTab({ t }: { t: Tenant }) {
  const cost = useTenantCost(t.id);
  const coupons = useTenantCoupons(t.id);
  const breakdown = cost.data?.cost_breakdown ? Object.entries(cost.data.cost_breakdown) : [];

  return (
    <>
      <PlanChangePanel t={t} />
      <DrawerSection title="Current period cost">
        {cost.isLoading ? (
          <Pending>Loading cost…</Pending>
        ) : cost.data ? (
          <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '12px 14px' }}>
            <div className="op-num" style={{ fontSize: 22, fontWeight: 700, color: 'var(--op-t1)' }}>{money(cost.data.total_cost_usd)}</div>
            <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>
              {new Date(cost.data.period_start).toLocaleDateString()} – {new Date(cost.data.period_end).toLocaleDateString()}
            </div>
            {breakdown.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7, marginTop: 12 }}>
                {breakdown.map(([k, v]) => <Row key={k} label={k} value={money(v)} />)}
              </div>
            )}
          </div>
        ) : (
          <Pending>No cost record for this tenant yet.</Pending>
        )}
      </DrawerSection>

      <DrawerSection title="Coupons">
        {coupons.isLoading ? (
          <Pending>Loading coupons…</Pending>
        ) : coupons.data && coupons.data.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {coupons.data.map((c) => (
              <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--op-t1)' }}>
                <Ticket size={13} style={{ color: 'var(--op-t3)' }} />
                <span style={{ flex: 1 }}>Redeemed {relTime(c.redeemed_at)}</span>
                <StatusTag status={c.is_active ? 'active' : 'canceled'} />
              </div>
            ))}
          </div>
        ) : (
          <Pending>No coupons applied.</Pending>
        )}
      </DrawerSection>

      <DrawerSection title="Invoices">
        <Pending>Full invoice history lives in <strong>Billing &amp; Revenue → Invoices</strong>, filterable by tenant. Per-tenant credit issuance wires next (BUILD_PLAN Phase 3).</Pending>
      </DrawerSection>
    </>
  );
}

function EntitlementsTab({ t }: { t: Tenant }) {
  const ents = useTierEntitlements(t.subscription_tier_id || null);
  return (
    <>
      <DrawerSection title={`Tier entitlements — ${t.subscription_tier ?? 'Trial'}`}>
        {ents.isLoading ? (
          <Pending>Loading entitlements…</Pending>
        ) : ents.data && ents.data.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            {ents.data.map((e) => <Row key={e.item_id} label={e.item_display_name} value={fmtEntitlement(e.included_value, e.item_unit)} />)}
          </div>
        ) : (
          <Pending>No entitlements resolved for this tier.</Pending>
        )}
      </DrawerSection>
      <DrawerSection title="Plan Exceptions">
        <PlanExceptionsPanel tenantId={t.id} />
      </DrawerSection>
    </>
  );
}

function SSOTab({ t }: { t: Tenant }) {
  return (
    <DrawerSection title="Single sign-on">
      <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '14px', display: 'flex', alignItems: 'center', gap: 12 }}>
        {t.sso_enabled ? <ShieldCheck size={22} style={{ color: 'var(--op-good)' }} /> : <ShieldOff size={22} style={{ color: 'var(--op-t3)' }} />}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--op-t1)' }}>{t.sso_enabled ? 'SSO enabled' : 'SSO disabled'}</div>
          <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>{t.sso_enabled ? 'This tenant signs in through an external identity provider.' : 'This tenant uses password / platform auth.'}</div>
        </div>
        <KeyRound size={15} style={{ color: 'var(--op-t3)' }} />
      </div>
      <div style={{ marginTop: 12 }}>
        <Pending>Provider configuration (SAML / OIDC metadata, certificate, attribute mapping) editing isn't on the admin contract yet — the v1 tenant-SSO page reads it from auth-service. Wiring the config view/editor is BUILD_PLAN Phase 1 polish.</Pending>
      </div>
    </DrawerSection>
  );
}

function ActivityTab() {
  return (
    <DrawerSection title="Activity">
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, padding: '28px 14px', textAlign: 'center' }}>
        <ScrollText size={26} style={{ color: 'var(--op-t3)' }} />
        <div style={{ fontSize: 12.5, color: 'var(--op-t3)', lineHeight: 1.55 }}>
          A per-tenant audit slice needs a platform-scoped audit endpoint — today
          <span className="mono"> /activity-logs</span> auto-scopes to the caller's own tenant,
          so it can't surface another tenant's trail. Tracked with the Audit platform-scope
          gap (BUILD_PLAN Phase 7). The full cross-tenant trail is in <strong>Audit</strong>.
        </div>
      </div>
    </DrawerSection>
  );
}

// ---- Drawer shell ----------------------------------------------------------

export function TenantDrawer({ tenant: t, health, onClose }: { tenant: Tenant; health?: TenantHealthSummary; onClose: () => void }) {
  const [tab, setTab] = useState<DrawerTab>('Overview');
  const [editing, setEditing] = useState(false);
  const status = tenantStatus(t);
  const plan = t.subscription_tier ?? 'Trial';
  const notWired = (what: string) => () => toast(`${what} — wired with the impersonation flow`, { icon: '🔒' });

  return (
    <>
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 80, background: 'var(--op-scrim)', display: 'flex', justifyContent: 'flex-end', animation: 'opScrim .15s ease both' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 480, maxWidth: '94vw', height: '100%', background: 'var(--op-panel)', borderLeft: '1px solid var(--op-border2)', boxShadow: 'var(--op-shadow)', display: 'flex', flexDirection: 'column', animation: 'opDrawer .28s cubic-bezier(.2,.8,.2,1) both' }}>
        {/* header */}
        <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid var(--op-border)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 13 }}>
            <Avatar initials={initialsFromName(t.name)} size={44} brand={plan === 'Sovereign'} square />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-head)', fontSize: 18, fontWeight: 700, color: 'var(--op-t1)', letterSpacing: '-.01em' }}>{t.name}</div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>{t.slug}{t.domain ? ` · ${t.domain}` : ''}</div>
            </div>
            <button onClick={onClose} className="op-btn icon sm"><X size={14} /></button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
            <PlanTag plan={plan} /><StatusTag status={status} />
            {t.domain && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--op-t2)' }}><MapPin size={12} style={{ color: 'var(--op-t3)' }} />{t.domain}</span>}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 15 }}>
            <button onClick={notWired('Open in Console')} className="op-btn accent sm" style={{ flex: 1, justifyContent: 'center' }}><LogIn size={14} />Open in Console</button>
            <button onClick={notWired('Scope to tenant')} className="op-btn sm" style={{ flex: 1, justifyContent: 'center' }}><Filter size={14} />Scope</button>
            <button onClick={() => setEditing(true)} className="op-btn icon sm" title="Edit tenant"><Pencil size={14} /></button>
          </div>
          {/* tab strip */}
          <div style={{ display: 'flex', gap: 6, marginTop: 14, flexWrap: 'wrap' }}>
            {TABS.map((tb) => (
              <button key={tb} className={'op-chip' + (tab === tb ? ' active' : '')} onClick={() => setTab(tb)}>{tb}</button>
            ))}
          </div>
        </div>

        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
          {tab === 'Overview' && <OverviewTab t={t} health={health} onClose={onClose} />}
          {tab === 'Billing' && <BillingTab t={t} />}
          {tab === 'Entitlements' && <EntitlementsTab t={t} />}
          {tab === 'SSO' && <SSOTab t={t} />}
          {tab === 'Activity' && <ActivityTab />}
          <div style={{ height: 16 }} />
        </div>
      </div>
    </div>
    {editing && <TenantFormModal tenant={t} onClose={() => setEditing(false)} />}
    </>
  );
}

function statusOfLabel(s: string): string {
  return ({ active: 'Active', trial: 'Trial', past_due: 'Past due', suspended: 'Suspended', canceled: 'Canceled', onboarding: 'Onboarding' } as Record<string, string>)[s] ?? s;
}

/** Entitlement `included_value` is an untyped JSON value (number / "unlimited" / bool). */
function fmtEntitlement(v: unknown, unit?: string): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'Included' : 'Not included';
  if (typeof v === 'number') return unit ? `${v.toLocaleString()} ${unit}` : v.toLocaleString();
  return String(v);
}
