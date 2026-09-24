// Plan builder (ADR-0004 /, Slice 3b). The single-plan create/edit view:
// EVERY lever from the Entitlements catalog (grouped, kind-aware), plus identity,
// pricing, a live customer-facing plan card, a margin signal, and Save. Opens from
// "+ New plan" (blank/defaults) or a tier header (pre-filled). Writes to
// tier_entitlements (the enforced layer): create posts every active lever inline;
// edit sends ONE PUT /admin/tiers/{id} carrying identity, price and only the
// levers the admin changed, plus the composition version it was opened on. The
// server applies all of it in one transaction or none of it — it used to be two
// PUTs, and a rejected composition left the new price saved. A 409 means someone
// changed the plan's entitlements meanwhile: the admin's own edits are kept, the
// rest reloads, and saving again applies them to the current composition.
//
// Edit mode cannot save until the composition has loaded. Before, a Save while it
// was still loading (or after it failed) sent every lever at its blank draft —
// blank reads as "unlimited" — and silently rewrote the plan.
//
// There is no backend "draft" state today — a saved plan is live — so this ships
// Save (+ Deprecate for existing) rather than a faked draft→publish lifecycle.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { X, ToggleRight, Gauge, Activity, ListChecks, Trash2, UserPlus, RefreshCw } from 'lucide-react';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { modalInputStyle } from '../../components/ui/modal';
import { money } from '../../components/ui/primitives';
import { AssignTierModal } from './assign-tier-modal';
import { apiDetail, fetchTierComposition, tierCompositionKey } from './composition';

type SubscriptionTier = adminServiceComponents['schemas']['SubscriptionTier'];
type BillableItem = adminServiceComponents['schemas']['BillableItem'];
type TierEntitlementInput = adminServiceComponents['schemas']['TierEntitlementInput'];

const GROUPS: { kind: string; label: string; icon: typeof ToggleRight; note?: string }[] = [
  { kind: 'boolean', label: 'Capability gates', icon: ToggleRight },
  { kind: 'numeric_cap', label: 'Capacity caps', icon: Gauge },
  { kind: 'numeric_metered', label: 'Metered meters', icon: Activity, note: 'Not billed yet (#813) — catalogued for when metered billing lands.' },
  { kind: 'enum_choice', label: 'Support / choice', icon: ListChecks },
];
type DV = { enabled?: boolean; quantity?: number | null; value?: string };
const slug = (s: string) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

/** Initial string-draft for a lever, from a value (tier override or item default). */
function draftFrom(kind: string, v: unknown): string {
  const dv = (v ?? {}) as DV;
  if (kind === 'boolean') return dv.enabled ? 'on' : 'off';
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return dv.quantity == null ? '' : String(dv.quantity);
  return dv.value ?? '';
}
function toValue(kind: string, draft: string): unknown {
  if (kind === 'boolean') return { enabled: draft === 'on' };
  if (kind === 'numeric_cap' || kind === 'numeric_metered') {
    const t = (draft ?? '').trim().toLowerCase();
    return { quantity: t === '' || t === '∞' || t === 'unlimited' ? null : Number(t) };
  }
  return { value: draft.trim() };
}
/**
 * Why a lever draft cannot be sent. Mirrors the server's entitlements.ValidateValue:
 * a quantity is a whole number ≥ 0 or blank/∞ for unlimited, an enum choice is a
 * non-empty string. Before the server rule existed, `Number("abc")` was NaN,
 * JSON.stringify turned NaN into null, and "abc" silently saved as unlimited.
 */
function leverDraftError(kind: string, draft: string): string | null {
  if (kind === 'numeric_cap' || kind === 'numeric_metered') {
    const t = (draft ?? '').trim().toLowerCase();
    if (t === '' || t === '∞' || t === 'unlimited') return null;
    if (!/^\d+$/.test(t)) return 'must be a whole number ≥ 0, or blank for unlimited';
    return null;
  }
  if (kind === 'enum_choice' && !(draft ?? '').trim()) return 'cannot be blank';
  return null;
}
function fmtCard(kind: string, draft: string): string {
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return draft.trim() === '' ? 'Unlimited' : Number(draft).toLocaleString();
  return draft;
}

const INFRA_PER_CUSTOMER = 28; // cost-model assumption (100-customer scale); see Vista Cost Model

export function PlanBuilder({ tier, items: allItems, onClose }: { tier?: SubscriptionTier; items: BillableItem[]; onClose: () => void }) {
  const isEdit = !!tier;
  const qc = useQueryClient();
  // Only active catalogue items can be composed — the server rejects the rest.
  const items = useMemo(() => allItems.filter((it) => it.is_active), [allItems]);

  // Edit mode: load the tier's current composition (and its version) to pre-fill.
  const entQ = useQuery({
    queryKey: tierCompositionKey(tier?.id ?? ''),
    enabled: isEdit,
    queryFn: () => fetchTierComposition(tier!.id),
    staleTime: 0,
    retry: 0,
  });

  const [assigning, setAssigning] = useState(false);
  const [displayName, setDisplayName] = useState(tier?.display_name ?? '');
  const [monthly, setMonthly] = useState(tier ? String((tier.price_cents ?? 0) / 100) : '');
  const [annual, setAnnual] = useState(tier?.annual_price_cents != null ? String(tier.annual_price_cents / 100) : '');
  const [billingMethod, setBillingMethod] = useState<'stripe' | 'invoice'>((tier?.billing_method as 'stripe' | 'invoice') ?? 'stripe');
  const [isCustom, setIsCustom] = useState(!!tier?.is_custom);

  // Levers: `initDrafts` is what the plan grants now (its composition, else the
  // catalogue default); `edits` holds only the levers the admin touched. Keeping
  // them apart is what lets a save send only real changes, and lets a reload
  // after a 409 refresh the untouched levers without losing the admin's work.
  const [edits, setEdits] = useState<Record<string, string>>({});
  const ready = !isEdit || entQ.isSuccess;
  const initDrafts = useMemo(() => {
    if (!ready) return null;
    const ents = entQ.data?.entitlements ?? [];
    const byKey = new Map(ents.map((e) => [e.item_key, e.included_value]));
    const d: Record<string, string> = {};
    for (const it of items) d[it.key] = draftFrom(it.kind, byKey.has(it.key) ? byKey.get(it.key) : it.default_value);
    return d;
  }, [ready, entQ.data, items]);
  const draft = useMemo(() => ({ ...(initDrafts ?? {}), ...edits }), [initDrafts, edits]);
  const setLever = (k: string, v: string) => setEdits((e) => ({ ...e, [k]: v }));

  const byKind = useMemo(() => {
    const m = new Map<string, BillableItem[]>();
    for (const it of items) { const a = m.get(it.kind) ?? []; a.push(it); m.set(it.kind, a); }
    for (const a of m.values()) a.sort((x, y) => x.sort_order - y.sort_order || x.display_name.localeCompare(y.display_name));
    return m;
  }, [items]);

  // Create: the whole composition. Edit: only the levers whose draft differs
  // from what the plan grants now — an untouched lever is never re-sent, so it
  // cannot overwrite a change someone else made to it.
  const entitlementsBody = (): TierEntitlementInput[] => items.map((it) => ({ item_key: it.key, included_value: toValue(it.kind, draft[it.key] ?? '') }));
  const changedLevers = (): TierEntitlementInput[] =>
    items
      .filter((it) => it.key in edits && edits[it.key] !== initDrafts?.[it.key])
      .map((it) => ({ item_key: it.key, included_value: toValue(it.kind, edits[it.key] ?? '') }));

  const save = useMutation({
    mutationFn: async () => {
      const price_cents = Math.round(Number(monthly || 0) * 100);
      const annual_price_cents = annual.trim() === '' ? undefined : Math.round(Number(annual) * 100);
      if (isEdit) {
        if (!entQ.isSuccess) throw new Error('The plan’s entitlements have not loaded — reload before saving');
        const changed = changedLevers();
        const res = await clients.admin.PUT('/admin/tiers/{id}', {
          params: { path: { id: tier!.id } },
          body: {
            display_name: displayName.trim(), price_cents, annual_price_cents, billing_method: billingMethod, is_custom: isCustom,
            ...(changed.length ? { entitlements: changed, entitlements_version: entQ.data.version } : {}),
          },
        });
        if (res.response.status === 409) {
          // Someone changed this plan's entitlements since it was opened.
          // Nothing was saved. Reload the composition: untouched levers pick
          // up the new values, the admin's edits stay, and the next Save goes
          // against the current version.
          void qc.invalidateQueries({ queryKey: tierCompositionKey(tier!.id) });
          throw new Error(apiDetail(res.error, 'This plan changed since you opened it. Nothing was saved — review and save again.'));
        }
        if (res.error) throw new Error(apiDetail(res.error, 'Failed to save plan — nothing was changed'));
      } else {
        const { error } = await clients.admin.POST('/admin/tiers', { body: { name: slug(displayName), display_name: displayName.trim(), billing_interval: 'month', billing_method: billingMethod, price_cents, annual_price_cents, is_custom: isCustom, entitlements: entitlementsBody() } });
        if (error) throw new Error(apiDetail(error, 'Failed to create plan'));
      }
    },
    onSuccess: () => {
      toast.success(isEdit ? `Saved ${displayName}` : `Created ${displayName}`);
      qc.invalidateQueries({ queryKey: ['platform', 'tiers'] });
      if (isEdit) {
        void qc.invalidateQueries({ queryKey: tierCompositionKey(tier!.id) });
        void qc.invalidateQueries({ queryKey: ['platform', 'tier-entitlements', tier!.id] });
      }
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  });

  const deprecate = useMutation({
    mutationFn: async () => {
      const { error } = await clients.admin.DELETE('/admin/tiers/{id}', { params: { path: { id: tier!.id } } });
      if (error) throw new Error('Failed to deprecate');
    },
    onSuccess: () => { toast.success(`Deprecated ${displayName}`); qc.invalidateQueries({ queryKey: ['platform', 'tiers'] }); onClose(); },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Deprecate failed'),
  });

  const leverError = useMemo(() => {
    for (const it of items) {
      const e = leverDraftError(it.kind, draft[it.key] ?? '');
      if (e) return `${it.display_name} ${e}`;
    }
    return null;
  }, [items, draft]);
  const error = !ready
    ? (entQ.isError ? 'The plan’s entitlements failed to load' : 'Loading the plan’s entitlements…')
    : !displayName.trim() ? 'Plan name is required' : leverError;
  const price = Number(monthly || 0);
  const stripeFee = billingMethod === 'stripe' && price > 0 ? price * 0.029 + 0.3 : 0;
  const marginAbs = price - INFRA_PER_CUSTOMER - stripeFee;
  const marginPct = price > 0 ? Math.round((marginAbs / price) * 100) : 0;

  // plan-card bullets: gates that are on, then numeric caps with a value
  const cardLines = items
    .filter((it) => (it.kind === 'boolean' ? (draft[it.key] === 'on') : it.kind !== 'numeric_metered'))
    .slice(0, 8)
    .map((it) => it.kind === 'boolean' ? it.display_name : `${fmtCard(it.kind, draft[it.key] ?? '')} ${it.unit || it.display_name.toLowerCase()}`);

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'var(--op-scrim)', backdropFilter: 'blur(3px)', display: 'flex', justifyContent: 'flex-end', animation: 'opScrim .15s ease both' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 'min(980px, 96vw)', height: '100%', background: 'var(--op-panel)', borderLeft: '1px solid var(--op-border2)', boxShadow: 'var(--op-shadow)', display: 'flex', animation: 'opDrawer .26s cubic-bezier(.2,.8,.2,1) both' }}>
        {/* LEFT — form */}
        <div style={{ flex: 1, minWidth: 0, overflowY: 'auto', padding: '18px 22px 40px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ fontFamily: 'var(--font-head)', fontSize: 19, fontWeight: 700, color: 'var(--op-t1)' }}>{isEdit ? `Edit plan — ${tier!.display_name || tier!.name}` : 'New plan'}</div>
            <div style={{ flex: 1 }} />
            <button onClick={onClose} className="op-btn icon sm"><X size={14} /></button>
          </div>

          <Eyebrow>Identity</Eyebrow>
          <Field label="Display name">
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Pro" style={modalInputStyle} autoFocus />
          </Field>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', marginTop: 8 }}>
            <input type="checkbox" checked={isCustom} onChange={(e) => setIsCustom(e.target.checked)} /> Custom — a bespoke plan scoped to one tenant
          </label>

          <Eyebrow>Pricing</Eyebrow>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
            <Field label="Monthly ($)">
              <input
                type="number"
                value={monthly}
                onChange={(e) => {
                  const v = e.target.value;
                  setMonthly(v);
                  // Contract-model convention: annual prepay = 10 months'
                  // price. Track the monthly field while annual is untouched or
                  // still following the convention; a hand-edited annual sticks.
                  const m = Number(v);
                  const followed = annual.trim() === '' || Number(annual) === Number(monthly) * 10;
                  if (Number.isFinite(m) && m > 0 && followed) setAnnual(String(m * 10));
                }}
                placeholder="0"
                style={modalInputStyle}
              />
            </Field>
            <Field label="Annual ($) — convention: 10× monthly">
              <input type="number" value={annual} onChange={(e) => setAnnual(e.target.value)} placeholder="—" style={modalInputStyle} />
            </Field>
            <Field label="Billing">
              <select value={billingMethod} onChange={(e) => setBillingMethod(e.target.value as 'stripe' | 'invoice')} style={modalInputStyle}>
                <option value="stripe">Stripe (card)</option>
                <option value="invoice">Invoice (offline)</option>
              </select>
            </Field>
          </div>
          {annual.trim() !== '' && Number(monthly) > 0 && (
            <div style={{ fontSize: 11.5, color: Number(annual) === Number(monthly) * 10 ? 'var(--op-t3)' : 'var(--warn)', marginTop: 4 }}>
              {Number(annual) === Number(monthly) * 10
                ? `Annual = 10× monthly (2 months free, ~${Math.round((1 - Number(annual) / (Number(monthly) * 12)) * 100)}% off) — the standard 12-month agreement pricing.`
                : `Annual is ${Number(annual) < Number(monthly) * 10 ? 'below' : 'above'} the 10× monthly convention (effective ${Math.round((1 - Number(annual) / (Number(monthly) * 12)) * 100)}% off vs. monthly ×12).`}
            </div>
          )}

          <Eyebrow>Entitlements · set every lever for this plan</Eyebrow>
          {entQ.isError ? (
            <div role="alert" style={{ padding: 24, color: 'var(--op-t3)', fontSize: 12.5 }}>
              Couldn&apos;t load this plan&apos;s entitlements, so it can&apos;t be saved yet.{' '}
              <button className="op-btn sm" onClick={() => { void entQ.refetch(); }}><RefreshCw size={13} />Retry</button>
            </div>
          ) : !ready ? (
            <div style={{ padding: 24, color: 'var(--op-t3)', fontSize: 12.5 }}>Loading composition…</div>
          ) : GROUPS.map((g) => {
            const rows = byKind.get(g.kind) ?? [];
            if (rows.length === 0) return null;
            const Icon = g.icon;
            return (
              <div key={g.kind} style={{ marginTop: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 6 }}>
                  <Icon size={13} style={{ color: 'var(--op-t3)' }} />
                  <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--op-t2)' }}>{g.label}</span>
                  {g.note && <span style={{ fontSize: 11, color: 'var(--op-t3)' }}>· {g.note}</span>}
                </div>
                {rows.map((it) => (
                  <div key={it.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ fontSize: 12.5, color: 'var(--op-t1)' }}>{it.display_name}</span>
                      {it.unit ? <span style={{ fontSize: 11, color: 'var(--op-t3)' }}> · {it.unit}</span> : null}
                    </div>
                    {it.kind === 'boolean' ? (
                      <button aria-label={it.display_name} onClick={() => setLever(it.key, draft[it.key] === 'on' ? 'off' : 'on')} className="op-chip" style={{ width: 64, justifyContent: 'center', color: draft[it.key] === 'on' ? 'var(--op-accent-text)' : 'var(--op-t3)', fontWeight: 600 }}>{draft[it.key] === 'on' ? 'On' : 'Off'}</button>
                    ) : (it.kind === 'numeric_cap' || it.kind === 'numeric_metered') ? (
                      <input aria-label={it.display_name} inputMode="numeric" value={draft[it.key] ?? ''} onChange={(e) => setLever(it.key, e.target.value)} placeholder="∞" aria-invalid={!!leverDraftError(it.kind, draft[it.key] ?? '')} title={leverDraftError(it.kind, draft[it.key] ?? '') ?? 'Whole number, or blank for unlimited'} style={{ ...modalInputStyle, width: 120, textAlign: 'right', borderColor: leverDraftError(it.kind, draft[it.key] ?? '') ? 'var(--op-danger, #d33)' : undefined }} />
                    ) : (
                      <input aria-label={it.display_name} value={draft[it.key] ?? ''} onChange={(e) => setLever(it.key, e.target.value)} placeholder="—" style={{ ...modalInputStyle, width: 160 }} />
                    )}
                  </div>
                ))}
              </div>
            );
          })}
        </div>

        {/* RIGHT — preview + margin + actions */}
        <div style={{ width: 320, flex: 'none', borderLeft: '1px solid var(--op-border)', padding: '18px 18px 16px', display: 'flex', flexDirection: 'column', gap: 16, background: 'var(--op-panel2)' }}>
          <div>
            <Eyebrow>Live plan card</Eyebrow>
            <div style={{ background: 'var(--op-panel)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-md)', padding: '14px 16px' }}>
              <div style={{ fontFamily: 'var(--font-head)', fontSize: 16, fontWeight: 700, color: 'var(--op-t1)' }}>{displayName || 'New plan'}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--op-accent-text)', marginTop: 2 }}>{price > 0 ? `${money(price)}/mo` : 'Free'}</div>
              <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 5 }}>
                {cardLines.length ? cardLines.map((l, i) => <div key={i} style={{ fontSize: 11.5, color: 'var(--op-t2)' }}>• {l}</div>) : <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>Set levers to populate…</div>}
              </div>
            </div>
          </div>

          <div>
            <Eyebrow>Margin</Eyebrow>
            <div style={{ fontSize: 12, color: 'var(--op-t2)' }}>{money(price)} − infra {money(INFRA_PER_CUSTOMER)} − Stripe {money(stripeFee)}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 6 }}>
              <span style={{ fontFamily: 'var(--font-head)', fontSize: 22, fontWeight: 700, color: marginPct >= 70 ? 'var(--ok)' : marginPct >= 40 ? 'var(--op-accent-text)' : 'var(--danger)' }}>{price > 0 ? `${marginPct}%` : '—'}</span>
              <div style={{ flex: 1, height: 8, borderRadius: 4, background: 'var(--op-border)', overflow: 'hidden' }}>
                <div style={{ width: `${Math.max(0, Math.min(100, marginPct))}%`, height: '100%', background: marginPct >= 70 ? 'var(--ok)' : marginPct >= 40 ? 'var(--warn)' : 'var(--danger)' }} />
              </div>
            </div>
            <div style={{ fontSize: 10.5, color: 'var(--op-t3)', marginTop: 5 }}>infra/customer is a cost-model assumption (~{money(INFRA_PER_CUSTOMER)} at 100-customer scale).</div>
          </div>

          <div style={{ flex: 1 }} />
          {isEdit && <div style={{ fontSize: 11, color: 'var(--op-t3)' }}>Deprecating keeps existing tenants on the plan (grandfathered) and hides it from new sign-ups.</div>}
          <div style={{ display: 'flex', gap: 8 }}>
            {isEdit && <button onClick={() => setAssigning(true)} className="op-btn sm"><UserPlus size={14} />Assign to tenant…</button>}
            {isEdit && <button onClick={() => { if (window.confirm(`Deprecate ${displayName}? Existing tenants are grandfathered.`)) deprecate.mutate(); }} disabled={deprecate.isPending} className="op-btn danger sm"><Trash2 size={14} />Deprecate</button>}
            <div style={{ flex: 1 }} />
            <button onClick={onClose} className="op-btn ghost sm">Cancel</button>
            <button onClick={() => { if (error) { toast.error(error); return; } save.mutate(); }} disabled={!!error || save.isPending} title={error ?? undefined} className="op-btn primary sm">{save.isPending ? 'Saving…' : isEdit ? 'Save plan' : 'Create plan'}</button>
          </div>
        </div>
      </div>
      {isEdit && assigning && <AssignTierModal tier={tier} onClose={() => setAssigning(false)} />}
    </div>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="op-eyebrow" style={{ margin: '18px 0 8px' }}>{children}</div>;
}
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, color: 'var(--op-t2)' }}>{label}{children}</label>;
}
