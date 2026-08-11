// Plan Exceptions (ADR-0004 /, Slice 4b). The slim per-tenant grant:
// a platform admin bumps ONE lever's value for ONE tenant to satisfy a sales /
// support need. Non-billing (no price) — it's a pure entitlement exception to the
// tenant's tier. Reason required; expiry optional; fully audited server-side.
// Lives in the tenant drawer → Entitlements tab.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Plus, Pencil, Trash2 } from 'lucide-react';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { StatusTag, num } from '../../components/ui/primitives';

type TenantEntitlement = adminServiceComponents['schemas']['TenantEntitlement'];
type TenantEntitlementInput = adminServiceComponents['schemas']['TenantEntitlementInput'];
type BillableItem = adminServiceComponents['schemas']['BillableItem'];

type DV = { enabled?: boolean; quantity?: number | null; value?: string };
function fmtVal(kind: string, v: unknown): string {
  const dv = (v ?? {}) as DV;
  if (kind === 'boolean') return dv.enabled ? 'On' : 'Off';
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return dv.quantity == null ? 'Unlimited' : num(dv.quantity);
  if (kind === 'enum_choice') return dv.value ?? '—';
  return '—';
}
function toValue(kind: string, draft: string): unknown {
  if (kind === 'boolean') return { enabled: draft === 'on' };
  if (kind === 'numeric_cap' || kind === 'numeric_metered') {
    const t = (draft ?? '').trim().toLowerCase();
    return { quantity: t === '' || t === '∞' || t === 'unlimited' ? null : Number(t) };
  }
  return { value: draft };
}
function draftFrom(kind: string, v: unknown): string {
  const dv = (v ?? {}) as DV;
  if (kind === 'boolean') return dv.enabled ? 'on' : 'off';
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return dv.quantity == null ? '' : String(dv.quantity);
  return dv.value ?? '';
}
function exStatus(e: TenantEntitlement): 'active' | 'scheduled' | 'expired' {
  const now = Date.now();
  if (e.effective_from && Date.parse(e.effective_from) > now) return 'scheduled';
  if (e.expires_at && Date.parse(e.expires_at) < now) return 'expired';
  return 'active';
}

const KEY = (id: string) => ['platform', 'tenant-entitlements', id] as const;

function useTenantEntitlements(tenantId: string) {
  return useQuery({
    queryKey: KEY(tenantId),
    retry: 0,
    staleTime: 60 * 1000,
    queryFn: async (): Promise<TenantEntitlement[]> => {
      const { data, error } = await clients.admin.GET('/admin/tenants/{id}/entitlements', { params: { path: { id: tenantId } } });
      if (error || !data) throw new Error('Failed to load plan exceptions');
      return data.entitlements ?? [];
    },
  });
}
function useBillableItems() {
  return useQuery({
    queryKey: ['platform', 'billable-items'],
    staleTime: 5 * 60 * 1000,
    queryFn: async (): Promise<BillableItem[]> => {
      const { data, error } = await clients.admin.GET('/admin/billable-items', {});
      if (error || !data) throw new Error('Failed to load levers');
      return (data.items ?? []).filter((i) => i.is_active);
    },
  });
}

export function PlanExceptionsPanel({ tenantId }: { tenantId: string }) {
  const exQ = useTenantEntitlements(tenantId);
  const itemsQ = useBillableItems();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<TenantEntitlement | null>(null);
  const [creating, setCreating] = useState(false);

  const items = itemsQ.data ?? [];
  const del = useMutation({
    mutationFn: async (overrideId: string) => {
      const { error } = await clients.admin.DELETE('/admin/tenants/{id}/entitlements/{overrideId}', { params: { path: { id: tenantId, overrideId } } });
      if (error) throw new Error('Failed to remove');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY(tenantId) }),
  });
  const remove = (e: TenantEntitlement) => {
    if (!window.confirm(`Remove the "${e.item_display_name}" exception for this tenant? This reverts them to their tier value.`)) return;
    del.mutate(e.id, { onSuccess: () => toast.success('Exception removed'), onError: (err) => toast.error(err instanceof Error ? err.message : 'Failed') });
  };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)', flex: 1, lineHeight: 1.5 }}>
          A bump of one lever for this tenant (sales/support). Non-billing; reason required, expiry optional, audited.
        </div>
        <button onClick={() => setCreating(true)} className="op-btn sm" style={{ flex: 'none' }}><Plus size={13} />Grant exception</button>
      </div>
      {exQ.isLoading ? (
        <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>Loading exceptions…</div>
      ) : exQ.data && exQ.data.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {exQ.data.map((e) => {
            const st = exStatus(e);
            return (
              <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '9px 11px' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, color: 'var(--op-t1)', fontWeight: 500 }}>{e.item_display_name} <span style={{ color: 'var(--op-accent-text)', fontWeight: 600 }}>→ {fmtVal(e.item_kind, e.override_value)}</span></div>
                  <div style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>
                    {e.reason ? `${e.reason} · ` : ''}{e.expires_at ? `until ${new Date(e.expires_at).toLocaleDateString()}` : 'no expiry'}
                  </div>
                </div>
                <StatusTag status={st === 'active' ? 'active' : st === 'scheduled' ? 'onboarding' : 'canceled'} />
                <button onClick={() => setEditing(e)} className="op-btn icon sm" title="Edit"><Pencil size={12} /></button>
                <button onClick={() => remove(e)} className="op-btn icon sm danger" title="Remove"><Trash2 size={12} /></button>
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>No exceptions — this tenant uses its tier values.</div>
      )}

      {(creating || editing) && (
        <ExceptionModal tenantId={tenantId} items={items} existing={editing} onClose={() => { setCreating(false); setEditing(null); }} />
      )}
    </>
  );
}

function ExceptionModal({ tenantId, items, existing, onClose }: { tenantId: string; items: BillableItem[]; existing: TenantEntitlement | null; onClose: () => void }) {
  const isEdit = !!existing;
  const qc = useQueryClient();
  const [itemKey, setItemKey] = useState(existing?.item_key ?? items[0]?.key ?? '');
  const item = useMemo(() => items.find((i) => i.key === itemKey), [items, itemKey]);
  const [draft, setDraft] = useState(() => existing ? draftFrom(existing.item_kind, existing.override_value) : draftFrom(item?.kind ?? 'boolean', item?.default_value));
  const [reason, setReason] = useState(existing?.reason ?? '');
  const [expires, setExpires] = useState(existing?.expires_at ? existing.expires_at.slice(0, 16) : '');

  const onPickItem = (k: string) => { setItemKey(k); const it = items.find((i) => i.key === k); setDraft(draftFrom(it?.kind ?? 'boolean', it?.default_value)); };
  const kind = (existing?.item_kind ?? item?.kind ?? 'boolean');
  const numeric = kind === 'numeric_cap' || kind === 'numeric_metered';
  const error = !reason.trim() ? 'Reason is required' : (!itemKey ? 'Pick a lever' : null);

  const save = useMutation({
    mutationFn: async () => {
      const body: TenantEntitlementInput = {
        item_key: itemKey,
        override_value: toValue(kind, draft),
        reason: reason.trim(),
        expires_at: expires ? new Date(expires).toISOString() : undefined,
      };
      if (isEdit) {
        const { error: err } = await clients.admin.PUT('/admin/tenants/{id}/entitlements/{overrideId}', { params: { path: { id: tenantId, overrideId: existing!.id } }, body });
        if (err) throw new Error('Failed to update exception');
      } else {
        const { error: err } = await clients.admin.POST('/admin/tenants/{id}/entitlements', { params: { path: { id: tenantId } }, body });
        if (err) throw new Error('Failed to grant exception');
      }
    },
    onSuccess: () => { toast.success(isEdit ? 'Exception updated' : 'Exception granted'); qc.invalidateQueries({ queryKey: KEY(tenantId) }); onClose(); },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  });

  return (
    <Modal
      open onClose={onClose}
      title={isEdit ? `Edit exception — ${existing!.item_display_name}` : 'Grant a plan exception'}
      description="A non-billing bump of one lever for this tenant. The lever is immutable on edit — remove + re-grant to change it."
      size="md"
      primaryLabel={isEdit ? 'Save' : 'Grant'}
      onPrimary={() => { if (error) { toast.error(error); return; } save.mutate(); }}
      primaryDisabled={!!error}
      primaryLoading={save.isPending}
      footerNote="Logged to audit."
    >
      <ModalField label="Lever">
        {isEdit ? (
          <input value={existing!.item_display_name} disabled style={{ ...modalInputStyle, opacity: 0.7 }} />
        ) : (
          <select value={itemKey} onChange={(e) => onPickItem(e.target.value)} style={modalInputStyle}>
            {items.map((i) => <option key={i.key} value={i.key}>{i.display_name} ({i.kind})</option>)}
          </select>
        )}
      </ModalField>

      <ModalField label="Value">
        {kind === 'boolean' ? (
          <select value={draft === 'on' ? 'on' : 'off'} onChange={(e) => setDraft(e.target.value)} style={modalInputStyle}>
            <option value="off">Off</option><option value="on">On</option>
          </select>
        ) : numeric ? (
          <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="number, or ∞ / blank for unlimited" style={modalInputStyle} />
        ) : (
          <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="value" style={modalInputStyle} />
        )}
      </ModalField>

      <ModalField label="Reason (required)">
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. comped +50 sensors for Q3 pilot" style={modalInputStyle} autoFocus />
      </ModalField>

      <ModalField label="Expires (optional)">
        <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} style={modalInputStyle} />
      </ModalField>
    </Modal>
  );
}
