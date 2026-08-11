// Entitlements — the unified lever catalog (ADR-0004 ·, Slice 1).
// CRUD over `billable_items`, grouped by lever type. Absorbs the retired Feature
// Flags page (boolean levers = capability gates) and the Billing → Billable Items
// tab. Typed admin client only. Metered levers are surfaced but flagged
// "not yet billable" (metered-vs-flat decision pending).
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Plus, Pencil, Trash2, ToggleRight, Gauge, Activity, ListChecks } from 'lucide-react';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { StatusTag, money, num } from '../../components/ui/primitives';

type BillableItem = adminServiceComponents['schemas']['BillableItem'];
type BillableItemInput = adminServiceComponents['schemas']['BillableItemInput'];

const KIND_OPTIONS = ['boolean', 'numeric_cap', 'numeric_metered', 'enum_choice'] as const;
const CATEGORY_OPTIONS = ['capability', 'capacity', 'meter', 'support', 'addon'] as const;
const KIND_CATEGORY: Record<string, string> = { boolean: 'capability', numeric_cap: 'capacity', numeric_metered: 'meter', enum_choice: 'support' };

/** Lever-type groups (by `kind`), in display order. */
const GROUPS: { kind: string; label: string; hint: string; icon: typeof ToggleRight; note?: string }[] = [
  { kind: 'boolean', label: 'Capability gates', hint: 'on / off', icon: ToggleRight },
  { kind: 'numeric_cap', label: 'Capacity caps', hint: 'up to N', icon: Gauge },
  { kind: 'numeric_metered', label: 'Metered meters', hint: 'per unit', icon: Activity, note: 'Metered billing is deferred (epic #813) — these are catalogued but not billed yet.' },
  { kind: 'enum_choice', label: 'Support / choice', hint: 'pick a level', icon: ListChecks },
];

// ---- data layer ------------------------------------------------------------
const KEY = ['platform', 'billable-items'] as const;

function useBillableItems() {
  return useQuery({
    queryKey: KEY,
    queryFn: async (): Promise<BillableItem[]> => {
      const { data, error } = await clients.admin.GET('/admin/billable-items', {});
      if (error || !data) throw new Error('Failed to load entitlements');
      return data.items ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
}
function useSaveBillableItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id?: string; body: BillableItemInput }) => {
      if (id) {
        const { error } = await clients.admin.PUT('/admin/billable-items/{id}', { params: { path: { id } }, body });
        if (error) throw new Error('Failed to update entitlement');
      } else {
        const { error } = await clients.admin.POST('/admin/billable-items', { body });
        if (error) throw new Error('Failed to create entitlement');
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
function useDeleteBillableItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.admin.DELETE('/admin/billable-items/{id}', { params: { path: { id } } });
      if (error) throw new Error('Delete failed — the entitlement may be in use by a tier or tenant');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

// ---- helpers ---------------------------------------------------------------
/** `default_value` is freeform JSON keyed by kind: {enabled} / {quantity} / {value}. */
function fmtDefault(kind: string, v: unknown): string {
  const dv = (v ?? {}) as { enabled?: boolean; quantity?: number | null; value?: string };
  if (kind === 'boolean') return dv.enabled ? 'On' : 'Off';
  if (kind === 'numeric_cap' || kind === 'numeric_metered') return dv.quantity == null ? 'Unlimited' : num(dv.quantity);
  if (kind === 'enum_choice') return dv.value ?? '—';
  return JSON.stringify(v);
}

// ---- page ------------------------------------------------------------------
export function EntitlementsPage() {
  const { data, isLoading, isError, refetch } = useBillableItems();
  const del = useDeleteBillableItem();
  const [editing, setEditing] = useState<BillableItem | null>(null);
  const [creating, setCreating] = useState(false);

  // Memoised so the fallback `[]` keeps a stable identity — otherwise every
  // render produces a fresh array and the useMemo blocks below never hit.
  const items = useMemo(() => data ?? [], [data]);
  const byKind = useMemo(() => {
    const m = new Map<string, BillableItem[]>();
    for (const it of items) {
      const arr = m.get(it.kind) ?? [];
      arr.push(it);
      m.set(it.kind, arr);
    }
    for (const arr of m.values()) arr.sort((a, b) => a.sort_order - b.sort_order || a.display_name.localeCompare(b.display_name));
    return m;
  }, [items]);
  const knownKinds = new Set(GROUPS.map((g) => g.kind));
  const otherItems = items.filter((it) => !knownKinds.has(it.kind));

  const remove = (it: BillableItem) => {
    if (!window.confirm(`Delete entitlement "${it.display_name}" (${it.key})? This is refused if a tier or tenant still references it.`)) return;
    del.mutate(it.id, {
      onSuccess: () => toast.success(`Deleted ${it.display_name}`),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Delete failed'),
    });
  };

  return (
    <div className="op-fade" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 10, padding: '12px 24px', borderBottom: '1px solid var(--op-border)' }}>
        <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>
          The master catalog of monetization <strong>levers</strong> — every gateable, cappable, or meterable thing a tier can grant.
        </div>
        <div style={{ flex: 1 }} />
        <button onClick={() => setCreating(true)} className="op-btn primary sm" style={{ height: 32 }}><Plus size={14} />New entitlement</button>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '8px 24px 32px' }}>
        {isError && (
          <div style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>
            Couldn't load entitlements. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button>
          </div>
        )}
        {isLoading && <div style={{ textAlign: 'center', padding: 50, color: 'var(--op-t3)' }}>Loading entitlements…</div>}

        {!isLoading && !isError && GROUPS.map((g) => (
          <Group key={g.kind} group={g} items={byKind.get(g.kind) ?? []} onEdit={setEditing} onDelete={remove} />
        ))}
        {otherItems.length > 0 && (
          <Group group={{ kind: 'other', label: 'Other', hint: '', icon: ListChecks }} items={otherItems} onEdit={setEditing} onDelete={remove} />
        )}
      </div>

      {(creating || editing) && (
        <BillableItemModal
          item={editing}
          onClose={() => { setCreating(false); setEditing(null); }}
        />
      )}
    </div>
  );
}

function Group({ group, items, onEdit, onDelete }: {
  group: { kind: string; label: string; hint: string; icon: typeof ToggleRight; note?: string };
  items: BillableItem[];
  onEdit: (it: BillableItem) => void;
  onDelete: (it: BillableItem) => void;
}) {
  const Icon = group.icon;
  return (
    <div style={{ marginTop: 22 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <Icon size={15} style={{ color: 'var(--op-accent-text)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>{group.label}</span>
        <span style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>· {group.hint}</span>
        <span style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>· {items.length}</span>
      </div>
      {group.note && (
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '7px 11px', marginBottom: 8 }}>{group.note}</div>
      )}
      <table className="op-table">
        <thead><tr><th>Key</th><th>Name</th><th>Default</th><th>Unit</th><th>Add-on</th><th>Status</th><th /></tr></thead>
        <tbody>
          {items.map((b) => (
            <tr key={b.id}>
              <td className="mono" style={{ fontSize: 11.5, color: 'var(--op-t1)' }}>{b.key}</td>
              <td style={{ fontWeight: 500 }}>{b.display_name}{b.description ? <div style={{ fontSize: 11, color: 'var(--op-t3)' }}>{b.description}</div> : null}</td>
              <td>{fmtDefault(b.kind, b.default_value)}</td>
              <td className="t-muted">{b.unit || '—'}</td>
              <td className="t-muted">{b.is_addon_eligible ? (b.default_addon_price_cents != null ? `${money(b.default_addon_price_cents / 100)}/mo` : 'yes') : '—'}</td>
              <td><StatusTag status={b.is_active ? 'active' : 'canceled'} /></td>
              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                <button onClick={() => onEdit(b)} className="op-btn icon sm" title="Edit"><Pencil size={13} /></button>
                <button onClick={() => onDelete(b)} className="op-btn icon sm danger" title="Delete" style={{ marginLeft: 4 }}><Trash2 size={13} /></button>
              </td>
            </tr>
          ))}
          {items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 22, color: 'var(--op-t3)' }}>No entitlements in this group yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ---- create / edit modal ---------------------------------------------------
function BillableItemModal({ item, onClose }: { item: BillableItem | null; onClose: () => void }) {
  const isEdit = !!item;
  const save = useSaveBillableItem();
  const dv = (item?.default_value ?? {}) as { enabled?: boolean; quantity?: number | null; value?: string };

  const [key, setKey] = useState(item?.key ?? '');
  const [displayName, setDisplayName] = useState(item?.display_name ?? '');
  const [description, setDescription] = useState(item?.description ?? '');
  const [kind, setKind] = useState(item?.kind ?? 'boolean');
  const [category, setCategory] = useState(item?.category ?? 'capability');
  const [unit, setUnit] = useState(item?.unit ?? '');
  const [dvBool, setDvBool] = useState(!!dv.enabled);
  const [dvUnlimited, setDvUnlimited] = useState(dv.quantity === null);
  const [dvQty, setDvQty] = useState(dv.quantity != null ? String(dv.quantity) : '0');
  const [dvEnum, setDvEnum] = useState(dv.value ?? '');
  const [isAddon, setIsAddon] = useState(!!item?.is_addon_eligible);
  const [addonPrice, setAddonPrice] = useState(item?.default_addon_price_cents != null ? String(item.default_addon_price_cents / 100) : '');
  const [isActive, setIsActive] = useState(item?.is_active ?? true);
  const [sortOrder, setSortOrder] = useState(String(item?.sort_order ?? 0));

  const onKindChange = (k: string) => { setKind(k); if (KIND_CATEGORY[k]) setCategory(KIND_CATEGORY[k]); };

  const slug = (s: string) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  const error = !displayName.trim() ? 'Name is required' : (!isEdit && !key.trim() ? 'Key is required' : null);

  const submit = () => {
    if (error) { toast.error(error); return; }
    let default_value: unknown;
    if (kind === 'boolean') default_value = { enabled: dvBool };
    else if (kind === 'numeric_cap' || kind === 'numeric_metered') default_value = { quantity: dvUnlimited ? null : Number(dvQty || 0) };
    else if (kind === 'enum_choice') default_value = { value: dvEnum };
    else default_value = {};

    const body: BillableItemInput = {
      display_name: displayName.trim(),
      description: description.trim() || undefined,
      category,
      kind,
      unit: unit.trim() || undefined,
      default_value,
      is_addon_eligible: isAddon,
      default_addon_price_cents: isAddon && addonPrice ? Math.round(Number(addonPrice) * 100) : undefined,
      is_active: isActive,
      sort_order: Number(sortOrder) || 0,
    };
    if (!isEdit) body.key = slug(key);

    save.mutate(
      { id: item?.id, body },
      {
        onSuccess: () => { toast.success(`${isEdit ? 'Updated' : 'Created'} ${displayName.trim()}`); onClose(); },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
      },
    );
  };

  const numeric = kind === 'numeric_cap' || kind === 'numeric_metered';
  return (
    <Modal
      open onClose={onClose}
      title={isEdit ? `Edit ${item!.display_name}` : 'New entitlement'}
      description={isEdit ? 'The key is immutable. Changing the default affects tenants that fall through to it.' : 'A lever a tier can grant. The key is the stable code id (immutable).'}
      size="md"
      primaryLabel={isEdit ? 'Save changes' : 'Create'}
      onPrimary={submit}
      primaryDisabled={!!error}
      primaryLoading={save.isPending}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {!isEdit && (
          <ModalField label="Key (immutable)">
            <input value={key} onChange={(e) => setKey(e.target.value)} placeholder="custom_policies" className="mono" style={modalInputStyle} />
          </ModalField>
        )}
        <ModalField label="Display name">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Custom policies" style={modalInputStyle} autoFocus />
        </ModalField>
        <ModalField label="Lever type">
          <select value={kind} onChange={(e) => onKindChange(e.target.value)} style={modalInputStyle}>
            {KIND_OPTIONS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </ModalField>
        <ModalField label="Category">
          <select value={category} onChange={(e) => setCategory(e.target.value)} style={modalInputStyle}>
            {CATEGORY_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </ModalField>
      </div>

      <ModalField label="Description (optional)">
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this lever unlocks" style={modalInputStyle} />
      </ModalField>

      {/* kind-aware default value */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Default value">
          {kind === 'boolean' ? (
            <select value={dvBool ? 'on' : 'off'} onChange={(e) => setDvBool(e.target.value === 'on')} style={modalInputStyle}>
              <option value="off">Off</option><option value="on">On</option>
            </select>
          ) : numeric ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input type="number" value={dvQty} disabled={dvUnlimited} onChange={(e) => setDvQty(e.target.value)} style={{ ...modalInputStyle, flex: 1, opacity: dvUnlimited ? 0.5 : 1 }} />
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--op-t2)', whiteSpace: 'nowrap' }}>
                <input type="checkbox" checked={dvUnlimited} onChange={(e) => setDvUnlimited(e.target.checked)} /> Unlimited
              </label>
            </div>
          ) : (
            <input value={dvEnum} onChange={(e) => setDvEnum(e.target.value)} placeholder="community" style={modalInputStyle} />
          )}
        </ModalField>
        <ModalField label="Unit (optional)">
          <input value={unit} onChange={(e) => setUnit(e.target.value)} placeholder={numeric ? 'sensors' : '—'} style={modalInputStyle} />
        </ModalField>
      </div>

      {/* add-on + status */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, alignItems: 'end' }}>
        <ModalField label="Add-on eligible">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, height: 34 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--op-t1)' }}>
              <input type="checkbox" checked={isAddon} onChange={(e) => setIsAddon(e.target.checked)} /> Sellable as add-on
            </label>
            {isAddon && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ fontSize: 12, color: 'var(--op-t3)' }}>$</span>
                <input type="number" value={addonPrice} onChange={(e) => setAddonPrice(e.target.value)} placeholder="49" style={{ ...modalInputStyle, width: 80 }} />
                <span style={{ fontSize: 12, color: 'var(--op-t3)' }}>/mo</span>
              </div>
            )}
          </div>
        </ModalField>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <ModalField label="Sort order">
            <input type="number" value={sortOrder} onChange={(e) => setSortOrder(e.target.value)} style={modalInputStyle} />
          </ModalField>
          <ModalField label="Active">
            <div style={{ display: 'flex', alignItems: 'center', height: 34 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--op-t1)' }}>
                <input type="checkbox" checked={isActive} onChange={(e) => setIsActive(e.target.checked)} /> Active
              </label>
            </div>
          </ModalField>
        </div>
      </div>
    </Modal>
  );
}
