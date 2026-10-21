// The "Inventory changes" condition of a routing rule (DCIM gap 5): which
// object kinds and actions the rule delivers, and whether changes made by
// discovery intake or a sync connection are included. Shown by RuleModal only
// when the rule's source is Inventory changes; stored as the rule's
// change_filter and evaluated by notification-service.
//
// Kinds are the inventory object nouns from standards/vocabulary.yaml (the
// generated OBJECT_KINDS), labelled as the product names them. No kind or no
// action selected means "all" — the hint says so rather than showing an empty
// selection as if it were a choice.
import { useMemo, useState } from 'react';
import { OBJECT_KINDS, OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';
import { ModalField, ModalInput } from '../../components/ui';

export type ChangeFilter = NC['schemas']['ChangeFilter'];
type ChangeAction = 'create' | 'update' | 'delete';

export const CHANGE_ACTIONS: { value: ChangeAction; label: string }[] = [
  { value: 'create', label: 'Created' },
  { value: 'update', label: 'Updated' },
  { value: 'delete', label: 'Deleted' },
];

export const EMPTY_CHANGE_FILTER: ChangeFilter = { object_kinds: [], actions: [], include_intake: false, include_sync: false };

const kindLabel = (k: ObjectKind) => OBJECT_KIND_LABELS[k]?.uiLabel ?? k;

/** Normalises a stored filter (lists may be omitted) for editing. */
export function editableChangeFilter(f: ChangeFilter | null | undefined): ChangeFilter {
  return {
    object_kinds: f?.object_kinds ?? [],
    actions: f?.actions ?? [],
    include_intake: f?.include_intake ?? false,
    include_sync: f?.include_sync ?? false,
  };
}

function Chip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className="chip"
      style={{ borderColor: active ? 'var(--accent)' : undefined, color: active ? 'var(--app-t1)' : undefined, background: active ? 'color-mix(in srgb, var(--accent) 10%, transparent)' : undefined }}
    >
      {label}
    </button>
  );
}

export function ChangeFilterFields({ value, onChange }: { value: ChangeFilter; onChange: (next: ChangeFilter) => void }) {
  const [search, setSearch] = useState('');
  const kinds = value.object_kinds ?? [];
  const actions = value.actions ?? [];
  const toggle = <T extends string>(arr: T[], v: T): T[] => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

  const sortedKinds = useMemo(() => [...OBJECT_KINDS].sort((a, b) => kindLabel(a).localeCompare(kindLabel(b))), []);
  const q = search.trim().toLowerCase();
  const shown = q ? sortedKinds.filter((k) => kindLabel(k).toLowerCase().includes(q) || k.includes(q)) : sortedKinds;

  return (
    <div data-testid="change-filter-fields">
      <ModalField
        label="Object kinds"
        hint={kinds.length === 0 ? 'None selected — changes to every kind of object are delivered.' : `${kinds.length} selected: ${kinds.map((k) => kindLabel(k as ObjectKind)).join(', ')}`}
      >
        <ModalInput value={search} placeholder="Filter kinds, e.g. cable, prefix" aria-label="Filter object kinds" onChange={(e) => setSearch(e.target.value)} />
        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginTop: 8, maxHeight: 150, overflowY: 'auto' }}>
          {shown.length === 0 ? (
            <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>No object kind matches “{search}”.</span>
          ) : (
            shown.map((k) => (
              <Chip key={k} label={kindLabel(k)} active={kinds.includes(k)} onClick={() => onChange({ ...value, object_kinds: toggle(kinds, k) })} />
            ))
          )}
        </div>
      </ModalField>
      <ModalField label="Actions" hint={actions.length === 0 ? 'None selected — creates, updates and deletes are all delivered.' : undefined}>
        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
          {CHANGE_ACTIONS.map((a) => (
            <Chip key={a.value} label={a.label} active={actions.includes(a.value)} onClick={() => onChange({ ...value, actions: toggle(actions, a.value) })} />
          ))}
        </div>
      </ModalField>
      <ModalField label="Automatic changes" hint="Discovery and sync write in bursts, so their changes are left out unless you include them.">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12.5, color: 'var(--app-t2)' }}>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input type="checkbox" checked={value.include_intake} onChange={(e) => onChange({ ...value, include_intake: e.target.checked })} />
            Include changes made by discovery (sensors, agents, imports)
          </label>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input type="checkbox" checked={value.include_sync} onChange={(e) => onChange({ ...value, include_sync: e.target.checked })} />
            Include changes made by a sync connection
          </label>
        </div>
      </ModalField>
    </div>
  );
}
