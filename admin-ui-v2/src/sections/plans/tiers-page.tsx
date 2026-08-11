// Tiers — the Entitlements × Tiers MATRIX (ADR-0004 /, Slice 3a).
// Rows = entitlements (billable_items) grouped by lever type; columns = tiers.
// Cells are inline-editable and persist to `tier_entitlements` (the authoritative,
// enforced layer) via the bulk-replace PUT. Numbers here are editable DATA, not
// code — punch in ballpark bands now, refine with the team later, no redeploy.
// The per-tier builder DRAWER (price, plan-card preview, margin, publish) is 3b.
import { useMemo, useState } from 'react';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Plus, ToggleRight, Gauge, Activity, ListChecks } from 'lucide-react';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { money, num } from '../../components/ui/primitives';
import { PlanBuilder } from './plan-builder';

type SubscriptionTier = adminServiceComponents['schemas']['SubscriptionTier'];
type BillableItem = adminServiceComponents['schemas']['BillableItem'];
type TierEntitlement = adminServiceComponents['schemas']['TierEntitlement'];
type TierEntitlementInput = adminServiceComponents['schemas']['TierEntitlementInput'];

const GROUPS: { kind: string; label: string; icon: typeof ToggleRight }[] = [
  { kind: 'boolean', label: 'Capability gates', icon: ToggleRight },
  { kind: 'numeric_cap', label: 'Capacity caps', icon: Gauge },
  { kind: 'numeric_metered', label: 'Metered meters', icon: Activity },
  { kind: 'enum_choice', label: 'Support / choice', icon: ListChecks },
];

type DV = { enabled?: boolean; quantity?: number | null; value?: string };
function fmtVal(kind: string, v: unknown): string {
  const dv = (v ?? {}) as DV;
  if (kind === 'boolean') return dv.enabled ? 'On' : 'Off';
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return dv.quantity == null ? '∞' : num(dv.quantity);
  if (kind === 'enum_choice') return dv.value ?? '—';
  return '—';
}
function toValue(kind: string, draft: string): unknown {
  if (kind === 'boolean') return { enabled: draft === 'on' || draft === 'true' };
  if (kind === 'numeric_cap' || kind === 'numeric_metered') {
    const t = draft.trim().toLowerCase();
    return { quantity: t === '' || t === '∞' || t === 'unlimited' ? null : Number(t) };
  }
  return { value: draft };
}
export function TiersPage() {
  const qc = useQueryClient();
  const tiersQ = useQuery({
    queryKey: ['platform', 'tiers'],
    queryFn: async (): Promise<SubscriptionTier[]> => {
      const { data, error } = await clients.admin.GET('/admin/tiers', {});
      if (error || !data) throw new Error('Failed to load tiers');
      return data.tiers ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
  const itemsQ = useQuery({
    queryKey: ['platform', 'billable-items'],
    queryFn: async (): Promise<BillableItem[]> => {
      const { data, error } = await clients.admin.GET('/admin/billable-items', {});
      if (error || !data) throw new Error('Failed to load entitlements');
      return data.items ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });

  const tiers = useMemo(
    () => (tiersQ.data ?? []).filter((t) => !t.deprecated_at).sort((a, b) => a.display_order - b.display_order || a.name.localeCompare(b.name)),
    [tiersQ.data],
  );
  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const items = useMemo(() => itemsQ.data ?? [], [itemsQ.data]);

  // One entitlements query per tier; entByTier keyed by tier id.
  const entQueries = useQueries({
    queries: tiers.map((t) => ({
      queryKey: ['platform', 'tier-entitlements', t.id],
      queryFn: async (): Promise<TierEntitlement[]> => {
        const { data, error } = await clients.admin.GET('/admin/tiers/{id}/entitlements', { params: { path: { id: t.id } } });
        if (error || !data) throw new Error('Failed to load tier entitlements');
        return data.entitlements ?? [];
      },
      staleTime: 5 * 60 * 1000,
      retry: 0,
    })),
  });
  const entByTier = useMemo(() => {
    const m = new Map<string, TierEntitlement[]>();
    tiers.forEach((t, i) => m.set(t.id, entQueries[i]?.data ?? []));
    return m;
  }, [tiers, entQueries]);

  const byKind = useMemo(() => {
    const m = new Map<string, BillableItem[]>();
    for (const it of items) { const a = m.get(it.kind) ?? []; a.push(it); m.set(it.kind, a); }
    for (const a of m.values()) a.sort((x, y) => x.sort_order - y.sort_order || x.display_name.localeCompare(y.display_name));
    return m;
  }, [items]);

  // bulk-replace one tier's composition with a single cell changed
  const setCell = useMutation({
    mutationFn: async ({ tierId, itemKey, included_value }: { tierId: string; itemKey: string; included_value: unknown }) => {
      const current = (qc.getQueryData<TierEntitlement[]>(['platform', 'tier-entitlements', tierId]) ?? []);
      const inputs: TierEntitlementInput[] = current.map((e) => ({
        item_key: e.item_key,
        included_value: e.item_key === itemKey ? included_value : e.included_value,
        overage_price_cents: e.overage_price_cents,
        overage_unit_size: e.overage_unit_size,
      }));
      if (!current.some((e) => e.item_key === itemKey)) inputs.push({ item_key: itemKey, included_value });
      const { error } = await clients.admin.PUT('/admin/tiers/{id}/entitlements', { params: { path: { id: tierId } }, body: { entitlements: inputs } });
      if (error) throw new Error('Failed to save');
    },
    onSuccess: (_d, v) => qc.invalidateQueries({ queryKey: ['platform', 'tier-entitlements', v.tierId] }),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  });

  // The full plan builder (create/edit one plan, all levers + price + margin).
  const [builder, setBuilder] = useState<{ tier?: SubscriptionTier } | null>(null);

  const [edit, setEdit] = useState<{ tierId: string; itemKey: string; draft: string } | null>(null);
  const commit = (tier: SubscriptionTier, item: BillableItem, draft: string) => {
    setCell.mutate({ tierId: tier.id, itemKey: item.key, included_value: toValue(item.kind, draft) });
    setEdit(null);
  };

  const loading = tiersQ.isLoading || itemsQ.isLoading;
  const colW = 132;

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 10, padding: '12px 24px', borderBottom: '1px solid var(--op-border)' }}>
        <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>Compose tiers by setting each entitlement across plans. Cells edit live and save to <span className="mono">tier_entitlements</span>. Pricing &amp; publish land in the per-tier builder (Slice 3b).</div>
        <div style={{ flex: 1 }} />
        <button onClick={() => setBuilder({})} className="op-btn primary sm" style={{ height: 32 }}><Plus size={14} />New plan</button>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '0 24px 40px' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading matrix…</div>
        ) : (
          <table className="op-table" style={{ minWidth: 320 + tiers.length * colW }}>
            <thead>
              <tr>
                <th style={{ position: 'sticky', left: 0, background: 'var(--op-panel)', minWidth: 240, zIndex: 1 }}>Entitlement</th>
                {tiers.map((t) => (
                  <th key={t.id} className="num" style={{ minWidth: colW, cursor: 'pointer' }} onClick={() => setBuilder({ tier: t })} title="Open the plan builder (price, all levers, margin)">
                    <div style={{ fontWeight: 700, color: 'var(--op-t1)' }}>{t.display_name || t.name}{t.is_custom ? ' ·🔒' : ''}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--op-t3)', fontWeight: 400 }}>{money(t.price_cents / 100)}/{t.billing_interval?.[0] ?? 'mo'} · edit</div>
                  </th>
                ))}
                {tiers.length === 0 && <th className="t-muted">No tiers yet — add one →</th>}
              </tr>
            </thead>
            <tbody>
              {GROUPS.map((g) => {
                const rows = byKind.get(g.kind) ?? [];
                if (rows.length === 0) return null;
                const Icon = g.icon;
                return [
                  <tr key={g.kind + '-h'}>
                    <td colSpan={tiers.length + 1} style={{ background: 'var(--op-panel2)' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 12.5, color: 'var(--op-t2)' }}>
                        <Icon size={13} style={{ color: 'var(--op-t3)' }} />{g.label}
                      </span>
                    </td>
                  </tr>,
                  ...rows.map((item) => (
                    <tr key={item.id}>
                      <td style={{ position: 'sticky', left: 0, background: 'var(--op-panel)', zIndex: 1 }}>
                        <div style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{item.display_name}</div>
                        <div className="mono" style={{ fontSize: 10, color: 'var(--op-t3)' }}>{item.key}{item.unit ? ` · ${item.unit}` : ''}</div>
                      </td>
                      {tiers.map((t) => {
                        const te = entByTier.get(t.id)?.find((e) => e.item_key === item.key);
                        const isDefault = !te;
                        const val = te ? te.included_value : item.default_value;
                        const editing = edit && edit.tierId === t.id && edit.itemKey === item.key;
                        const saving = setCell.isPending && setCell.variables?.tierId === t.id && setCell.variables?.itemKey === item.key;
                        return (
                          <td key={t.id} className="num" style={{ cursor: 'pointer', opacity: saving ? 0.5 : 1 }}>
                            {item.kind === 'boolean' ? (
                              <button
                                onClick={() => commit(t, item, ((val ?? {}) as DV).enabled ? 'off' : 'on')}
                                className="op-chip"
                                style={{ height: 22, padding: '0 9px', color: ((val ?? {}) as DV).enabled ? 'var(--op-accent-text)' : 'var(--op-t3)', fontWeight: 600 }}
                                title={isDefault ? 'Inherited default — click to set on this tier' : 'Click to toggle'}
                              >{fmtVal(item.kind, val)}</button>
                            ) : editing ? (
                              <input
                                autoFocus
                                defaultValue={edit!.draft}
                                onBlur={(e) => commit(t, item, e.target.value)}
                                onKeyDown={(e) => { if (e.key === 'Enter') commit(t, item, (e.target as HTMLInputElement).value); if (e.key === 'Escape') setEdit(null); }}
                                style={{ width: colW - 24, height: 24, textAlign: 'right', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-accent, var(--warn))', background: 'var(--op-panel2)', color: 'var(--op-t1)', padding: '0 7px', fontSize: 12.5, outline: 'none' }}
                              />
                            ) : (
                              <span
                                onClick={() => setEdit({ tierId: t.id, itemKey: item.key, draft: item.kind === 'enum_choice' ? (((val ?? {}) as DV).value ?? '') : (((val ?? {}) as DV).quantity == null ? '' : String(((val ?? {}) as DV).quantity)) })}
                                style={{ display: 'inline-block', minWidth: 30, color: isDefault ? 'var(--op-t3)' : 'var(--op-t1)', fontStyle: isDefault ? 'italic' : 'normal' }}
                                title={isDefault ? 'Inherited default — click to set on this tier' : 'Click to edit'}
                              >{fmtVal(item.kind, val)}</span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  )),
                ];
              })}
            </tbody>
          </table>
        )}
        <div style={{ marginTop: 14, fontSize: 11.5, color: 'var(--op-t3)', lineHeight: 1.55 }}>
          Two ways to compose: edit a cell inline here (greyed/italic = inherited default — click to set it on that tier; numeric takes a number or <span className="mono">∞</span>/blank for unlimited), or
          <strong> click a tier header</strong> (or <strong>+ New plan</strong>) to open the full <strong>plan builder</strong> — all levers, price, live plan card, margin, save. Custom (tenant-owned) tiers are marked 🔒.
        </div>
      </div>
      {builder && <PlanBuilder tier={builder.tier} items={items} onClose={() => setBuilder(null)} />}
    </div>
  );
}
