// Settings → Infrastructure → Custom Fields (DCIM BUILD_PLAN row 5.1;
// ADR-0010 D5): the tenant's custom field definitions and the choice sets a
// selection field draws from. Reading needs `dcim.read` (the nav entry; every
// DCIM detail renders the definitions); every write control sits behind
// `custom_fields.manage`. The values themselves are edited on each object's
// own page through <CustomFieldsPanel>.
import { useMemo, useState, type ReactNode } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { OBJECT_KINDS, OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import {
  CUSTOM_FIELD_TYPES, fieldLabel, useChoiceSetWrite, useChoiceSets, useCustomFieldWrite, useCustomFields,
  type CustomField, type CustomFieldChoiceSet, type CustomFieldInput, type CustomFieldType,
} from '../inventory/dcim/custom-field-queries';
import { valueOf } from '../inventory/dcim/custom-fields-panel';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const MANAGE = TENANT_PERMISSIONS.custom_fields.manage;
const ACTIONS: STableCol = { label: '', w: '80px', align: 'right' };
const NUMERIC: CustomFieldType[] = ['integer', 'decimal'];
const TEXTUAL: CustomFieldType[] = ['text', 'longtext', 'url'];
const typeLabel = (t: string) => CUSTOM_FIELD_TYPES.find((x) => x.value === t)?.label ?? t;
const kindLabel = (k: string) => (OBJECT_KIND_LABELS as Record<string, { label: string }>)[k]?.label ?? k;

function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" data-testid="custom-field-form-error" style={{ display: 'flex', gap: 8, padding: '9px 11px', marginBottom: 14, borderRadius: 9, border: '1px solid var(--danger)', fontSize: 12.5, color: 'var(--app-t1)' }}>
      <Icon name="alert-triangle" size={14} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />{message}
    </div>
  );
}

function DeleteModal({ what, note, pending, error, onConfirm, onClose }: {
  what: string; note: string; pending: boolean; error: string | null; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Modal
      open onClose={onClose} tone="danger" icon="trash-2" title={`Delete ${what}?`} description={note}
      primary={(
        <button type="button" className="ui-btn accent" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }} data-testid="custom-field-delete-confirm" disabled={pending} onClick={onConfirm}>
          {pending ? 'Deleting…' : 'Delete'}
        </button>
      )}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={error} />
    </Modal>
  );
}

/** The object-kinds multiselect: a filterable checklist of the vocabulary. */
function KindsPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [filter, setFilter] = useState('');
  const shown = OBJECT_KINDS.filter((k) => value.includes(k) || kindLabel(k).toLowerCase().includes(filter.toLowerCase()));
  return (
    <div>
      <ModalInput aria-label="Filter object kinds" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter: prefix, asset, circuit…" />
      <div role="group" aria-label="Object kinds" data-testid="custom-field-kinds" style={{ maxHeight: 150, overflowY: 'auto', marginTop: 6, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
        {shown.map((k) => (
          <label key={k} style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
            <input type="checkbox" checked={value.includes(k)} onChange={(e) => onChange(e.target.checked ? [...value, k] : value.filter((x) => x !== k))} />
            {kindLabel(k)}
          </label>
        ))}
      </div>
    </div>
  );
}

function FieldModal({ field, sets, onClose }: { field?: CustomField; sets: CustomFieldChoiceSet[]; onClose: () => void }) {
  const { create, update } = useCustomFieldWrite();
  const [v, setV] = useState({
    name: field?.name ?? '', label: field?.label ?? '', type: field?.type ?? 'text',
    kinds: field?.object_kinds ?? [], required: field?.required ?? false,
    def: field?.default === undefined || field?.default === null ? '' : typeof field.default === 'string' ? field.default : JSON.stringify(field.default),
    choiceSet: field?.choice_set_id ?? '', related: field?.related_object_kind ?? '',
    min: field?.validation_minimum?.toString() ?? '', max: field?.validation_maximum?.toString() ?? '', regex: field?.validation_regex ?? '',
    uiVisible: field?.ui_visible ?? 'always', uiEditable: field?.ui_editable ?? 'yes', weight: String(field?.weight ?? 100),
    group: field?.group_name ?? '', cloneable: field?.is_cloneable ?? false, description: field?.description ?? '',
  });
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const set = <K extends keyof typeof v>(k: K) => (x: (typeof v)[K]) => setV((c) => ({ ...c, [k]: x }));
  const usesChoices = v.type === 'select' || v.type === 'multiselect';
  const usesObjects = v.type === 'object' || v.type === 'multiobject';
  const missing = [v.name.trim() === '' && 'Name', v.kinds.length === 0 && 'Object kinds', usesChoices && !v.choiceSet && 'Choice set', usesObjects && !v.related && 'Related object kind'].filter(Boolean);

  const submit = async () => {
    setErr(null);
    let def: unknown = null;
    try {
      if (v.def.trim() !== '') {
        const shape = { name: v.name, label: v.label, type: v.type } as CustomField;
        def = v.type === 'multiselect' ? v.def.split('|').map((s) => s.trim()).filter(Boolean) : valueOf(shape, v.def);
      }
    } catch (e) {
      setErr(`Default: ${e instanceof Error ? e.message : 'invalid'}`);
      return;
    }
    const body: CustomFieldInput = {
      name: v.name.trim(), label: v.label.trim() || null, type: v.type, object_kinds: v.kinds, required: v.required,
      default: def, choice_set_id: usesChoices ? v.choiceSet : null, related_object_kind: usesObjects ? v.related : null,
      validation_minimum: NUMERIC.includes(v.type) && v.min.trim() ? Number(v.min) : null,
      validation_maximum: NUMERIC.includes(v.type) && v.max.trim() ? Number(v.max) : null,
      validation_regex: TEXTUAL.includes(v.type) && v.regex.trim() ? v.regex.trim() : null,
      ui_visible: v.uiVisible, ui_editable: v.uiEditable,
      weight: Number(v.weight) || 100, group_name: v.group.trim() || null, is_cloneable: v.cloneable, description: v.description.trim() || null,
    };
    try {
      if (field) await update.mutateAsync({ id: field.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="list-checks" title={field ? `Edit ${fieldLabel(field)}` : 'Add custom field'}
      description="A field every object of the chosen kinds carries. Values are checked on every save."
      primary={<button type="button" className="ui-btn accent" data-testid="custom-field-save" disabled={busy || missing.length > 0} onClick={() => { void submit(); }}>{busy ? 'Saving…' : field ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      footerNote={missing.length > 0 ? `Required: ${missing.join(', ')}` : undefined}
    >
      <FormError message={err} />
      <ModalField label="Name *" hint="Lowercase letters, digits and underscores; it is how a query names the field: cf.<name>.">
        <ModalInput aria-label="Name" className="mono" value={v.name} onChange={(e) => set('name')(e.target.value)} placeholder="owner_team" />
      </ModalField>
      <ModalField label="Label"><ModalInput aria-label="Label" value={v.label} onChange={(e) => set('label')(e.target.value)} placeholder="Owner team" /></ModalField>
      <ModalField label="Type *">
        <ModalSelect aria-label="Type" value={v.type} onChange={(e) => set('type')(e.target.value as CustomFieldType)}>
          {CUSTOM_FIELD_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Object kinds *" hint="The objects that carry this field."><KindsPicker value={v.kinds} onChange={set('kinds')} /></ModalField>
      {usesChoices && (
        <ModalField label="Choice set *">
          <ModalSelect aria-label="Choice set" value={v.choiceSet} onChange={(e) => set('choiceSet')(e.target.value)}>
            <option value="">Pick a choice set</option>
            {sets.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </ModalSelect>
        </ModalField>
      )}
      {usesObjects && (
        <ModalField label="Related object kind *">
          <ModalSelect aria-label="Related object kind" value={v.related} onChange={(e) => set('related')(e.target.value)}>
            <option value="">Pick a kind</option>
            {OBJECT_KINDS.map((k: ObjectKind) => <option key={k} value={k}>{kindLabel(k)}</option>)}
          </ModalSelect>
        </ModalField>
      )}
      <ModalField label="Required">
        <label style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
          <input type="checkbox" aria-label="Required" checked={v.required} onChange={(e) => set('required')(e.target.checked)} />
          A person saving an object must fill it in
        </label>
      </ModalField>
      <ModalField label="Default" hint={v.type === 'multiselect' ? 'Values separated by |.' : 'A new object starts with this value.'}>
        <ModalInput aria-label="Default" value={v.def} onChange={(e) => set('def')(e.target.value)} />
      </ModalField>
      {NUMERIC.includes(v.type) && (
        <div style={{ display: 'flex', gap: 10 }}>
          <ModalField label="Minimum"><ModalInput aria-label="Minimum" type="number" value={v.min} onChange={(e) => set('min')(e.target.value)} /></ModalField>
          <ModalField label="Maximum"><ModalInput aria-label="Maximum" type="number" value={v.max} onChange={(e) => set('max')(e.target.value)} /></ModalField>
        </div>
      )}
      {TEXTUAL.includes(v.type) && (
        <ModalField label="Validation regex" hint="A value must match it."><ModalInput aria-label="Validation regex" className="mono" value={v.regex} onChange={(e) => set('regex')(e.target.value)} placeholder="^[A-Z]{3}-\d+$" /></ModalField>
      )}
      <div style={{ display: 'flex', gap: 10 }}>
        <ModalField label="Shown">
          <ModalSelect aria-label="Shown" value={v.uiVisible} onChange={(e) => set('uiVisible')(e.target.value as CustomFieldInput['ui_visible'] & string)}>
            <option value="always">Always</option><option value="if-set">If set</option><option value="hidden">Hidden</option>
          </ModalSelect>
        </ModalField>
        <ModalField label="Editable">
          <ModalSelect aria-label="Editable" value={v.uiEditable} onChange={(e) => set('uiEditable')(e.target.value as CustomFieldInput['ui_editable'] & string)}>
            <option value="yes">Yes</option><option value="no">Read-only</option><option value="hidden">Not in the form</option>
          </ModalSelect>
        </ModalField>
      </div>
      <div style={{ display: 'flex', gap: 10 }}>
        <ModalField label="Group"><ModalInput aria-label="Group" value={v.group} onChange={(e) => set('group')(e.target.value)} placeholder="Ownership" /></ModalField>
        <ModalField label="Weight" hint="Lower first."><ModalInput aria-label="Weight" type="number" value={v.weight} onChange={(e) => set('weight')(e.target.value)} /></ModalField>
      </div>
      <ModalField label="Cloneable">
        <label style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
          <input type="checkbox" aria-label="Cloneable" checked={v.cloneable} onChange={(e) => set('cloneable')(e.target.checked)} />
          Copied when an object is cloned
        </label>
      </ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={v.description} onChange={(e) => set('description')(e.target.value)} /></ModalField>
    </Modal>
  );
}

/** `value|Label` per line ⇄ NetBox's [[value, label], …]. */
export function parseChoices(text: string): string[][] {
  return text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const [value, ...rest] = l.split('|');
    const label = rest.join('|').trim();
    return label ? [value.trim(), label] : [value.trim(), value.trim()];
  });
}

function SetModal({ set: existing, onClose }: { set?: CustomFieldChoiceSet; onClose: () => void }) {
  const { create, update } = useChoiceSetWrite();
  const [name, setName] = useState(existing?.name ?? '');
  const [choices, setChoices] = useState((existing?.choices ?? []).map((c) => (c[1] && c[1] !== c[0] ? `${c[0]}|${c[1]}` : c[0])).join('\n'));
  const [alpha, setAlpha] = useState(existing?.order_alphabetically ?? false);
  const [description, setDescription] = useState(existing?.description ?? '');
  const [err, setErr] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;
  const parsed = parseChoices(choices);
  const submit = async () => {
    setErr(null);
    const body = { name: name.trim(), choices: parsed, order_alphabetically: alpha, description: description.trim() || null };
    try {
      if (existing) await update.mutateAsync({ id: existing.id, body });
      else await create.mutateAsync(body);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'The request failed');
    }
  };
  return (
    <Modal
      open onClose={onClose} icon="list" title={existing ? `Edit ${existing.name}` : 'Add choice set'}
      primary={<button type="button" className="ui-btn accent" data-testid="choice-set-save" disabled={busy || name.trim() === '' || parsed.length === 0} onClick={() => { void submit(); }}>{busy ? 'Saving…' : existing ? 'Save' : 'Create'}</button>}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <FormError message={err} />
      <ModalField label="Name *"><ModalInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Service tiers" /></ModalField>
      <ModalField label="Choices *" hint="One per line: value, or value|Label.">
        <textarea aria-label="Choices" className="ui-input mono" rows={6} style={{ width: '100%' }} value={choices} onChange={(e) => setChoices(e.target.value)} placeholder={'gold|Gold\nsilver|Silver'} />
      </ModalField>
      <ModalField label="Order">
        <label style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
          <input type="checkbox" aria-label="Order alphabetically" checked={alpha} onChange={(e) => setAlpha(e.target.checked)} />
          Order alphabetically
        </label>
      </ModalField>
      <ModalField label="Description"><ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} /></ModalField>
    </Modal>
  );
}

function Rows({ q, empty, children }: { q: { isLoading: boolean; isError: boolean; error: unknown; refetch: () => unknown; data?: unknown[] }; empty: ReactNode; children: ReactNode }) {
  if (q.isLoading) return <PanelLoading label="Loading…" />;
  if (q.isError) return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  if (q.data && q.data.length === 0) return <>{empty}</>;
  return <>{children}</>;
}

function FieldsTab() {
  const q = useCustomFields();
  const sets = useChoiceSets();
  const { remove } = useCustomFieldWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CustomField | null>(null);
  const [deleting, setDeleting] = useState<CustomField | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const setName = useMemo(() => new Map((sets.data ?? []).map((s) => [s.id, s.name])), [sets.data]);
  const cols: STableCol[] = [{ label: 'Field', w: '1.4fr' }, { label: 'Type', w: '1fr' }, { label: 'Applies to', w: '1.6fr' }, { label: 'Group', w: '0.8fr' }, ACTIONS];
  return (
    <SSection title="Custom fields" desc="Fields you add to inventory objects. Each object's page shows and edits them." action={(
      <PermissionGate permission={MANAGE}>
        <button type="button" className="ui-btn sm accent" data-testid="add-custom-field" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add field</button>
      </PermissionGate>
    )}>
      <div data-testid="custom-fields-table">
        <Rows q={q} empty={<PanelEmpty icon="list-checks" title="No custom fields yet" message="Add a field — an owner team, a cost centre, a service tier — and every object of the kinds you choose carries it." />}>
          <STable cols={cols}>
            {rows.map((f, i) => (
              <STableRow key={f.id} first={i === 0} cols={cols} cells={[
                <span key="n"><b>{fieldLabel(f)}</b> <span className="mono" style={{ color: 'var(--app-t3)' }}>cf.{f.name}</span>{f.required ? <> <STag>Required</STag></> : null}</span>,
                <span key="t">{typeLabel(f.type)}{f.choice_set_id ? <span style={{ color: 'var(--app-t3)' }}> · {setName.get(f.choice_set_id) ?? 'choice set'}</span> : null}{f.related_object_kind ? <span style={{ color: 'var(--app-t3)' }}> · {kindLabel(f.related_object_kind)}</span> : null}</span>,
                f.object_kinds.map(kindLabel).join(', '),
                f.group_name ?? '—',
                <PermissionGate key="a" permission={MANAGE}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${f.name}`} onClick={() => setEditing(f)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${f.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(f); }}><Icon name="x" size={13} /></button>
                </PermissionGate>,
              ]} />
            ))}
          </STable>
        </Rows>
      </div>
      {adding && <FieldModal sets={sets.data ?? []} onClose={() => setAdding(false)} />}
      {editing && <FieldModal field={editing} sets={sets.data ?? []} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal what={fieldLabel(deleting)} note="Objects keep the stored value, but it is no longer shown, checked or queryable as a field. The deletion is recorded in the change log."
          pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SSection>
  );
}

function SetsTab() {
  const q = useChoiceSets();
  const { remove } = useChoiceSetWrite();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CustomFieldChoiceSet | null>(null);
  const [deleting, setDeleting] = useState<CustomFieldChoiceSet | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const rows = q.data ?? [];
  const cols: STableCol[] = [{ label: 'Name', w: '1fr' }, { label: 'Choices', w: '2fr' }, ACTIONS];
  return (
    <SSection title="Choice sets" desc="The values a selection field offers. A set a field uses cannot be deleted." action={(
      <PermissionGate permission={MANAGE}>
        <button type="button" className="ui-btn sm accent" data-testid="add-choice-set" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add choice set</button>
      </PermissionGate>
    )}>
      <div data-testid="choice-sets-table">
        <Rows q={q} empty={<PanelEmpty icon="list" title="No choice sets yet" message="Add one before you create a selection field." />}>
          <STable cols={cols}>
            {rows.map((s, i) => (
              <STableRow key={s.id} first={i === 0} cols={cols} cells={[
                <b key="n">{s.name}</b>,
                s.choices.map((c) => c[1] ?? c[0]).join(', '),
                <PermissionGate key="a" permission={MANAGE}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${s.name}`} onClick={() => setEditing(s)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${s.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => { setDelErr(null); setDeleting(s); }}><Icon name="x" size={13} /></button>
                </PermissionGate>,
              ]} />
            ))}
          </STable>
        </Rows>
      </div>
      {adding && <SetModal onClose={() => setAdding(false)} />}
      {editing && <SetModal set={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <DeleteModal what={deleting.name} note="The deletion is recorded in the change log." pending={remove.isPending} error={delErr} onClose={() => setDeleting(null)}
          onConfirm={() => { setDelErr(null); remove.mutateAsync(deleting.id).then(() => setDeleting(null), (e: unknown) => setDelErr(e instanceof Error ? e.message : 'The request failed')); }} />
      )}
    </SSection>
  );
}

export function CustomFieldsSettingsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const [tab, setTab] = useState<'fields' | 'sets'>('fields');
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job}>
      <div data-testid="custom-fields-settings">
        <div role="tablist" aria-label="Custom fields" style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
          {(['fields', 'sets'] as const).map((t) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} data-testid={`tab-${t}`} className={`ui-btn sm${tab === t ? ' accent' : ''}`} onClick={() => setTab(t)}>
              {t === 'fields' ? 'Fields' : 'Choice sets'}
            </button>
          ))}
        </div>
        {tab === 'fields' ? <FieldsTab /> : <SetsTab />}
      </div>
    </SPage>
  );
}
