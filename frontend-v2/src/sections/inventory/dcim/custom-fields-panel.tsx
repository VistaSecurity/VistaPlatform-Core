// <CustomFieldsPanel kind id values permission onChange /> — an object's
// custom field values (DCIM BUILD_PLAN row 5.1; ADR-0010 D5), rendered by
// type from the tenant's definitions for `kind`, with an inline editor for
// whoever holds that kind's manage permission.
//
// The panel does not write itself: the host page passes `onChange`, which
// sends `{custom_fields: patch}` through that object's own update route (PATCH
// a prefix, PUT an asset, …), so the server's validation is the one on that
// route and the change lands in that object's change log. The patch names only
// the fields that changed; the server keeps the rest (NetBox's PATCH).
import { useMemo, useState } from 'react';
import { PermissionGate } from '@vistasecurity/primitives/rbac';
import { OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import { PanelError, PanelLoading } from './substrate-states';
import { fieldLabel, isSet, useChoiceSets, useCustomFields, type CustomField, type CustomFieldChoiceSet } from './custom-field-queries';

type Values = Record<string, unknown>;

export interface CustomFieldsPanelProps {
  kind: ObjectKind;
  id: string;
  values: Values | null | undefined;
  /** The permission that may edit this object (its kind's manage permission). */
  permission: string;
  /** Saves a patch of the changed fields; rejects with the server's reason. */
  onChange: (patch: Values) => Promise<unknown>;
}

function choiceLabels(f: CustomField, sets: CustomFieldChoiceSet[] | undefined): Map<string, string> {
  const set = sets?.find((s) => s.id === f.choice_set_id);
  const out = new Map<string, string>();
  for (const c of set?.choices ?? []) out.set(c[0], c[1] ?? c[0]);
  return out;
}

/** A stored value as text to read. */
export function displayValue(f: CustomField, v: unknown, labels: Map<string, string>): string {
  if (!isSet(v)) return '—';
  switch (f.type) {
    case 'boolean': return v === true ? 'Yes' : v === false ? 'No' : String(v);
    case 'select': return labels.get(String(v)) ?? String(v);
    case 'multiselect': return (v as unknown[]).map((x) => labels.get(String(x)) ?? String(x)).join(', ');
    case 'multiobject': return (v as unknown[]).map(String).join(', ');
    case 'json': return JSON.stringify(v);
    default: return String(v);
  }
}

/** The editor's string form of a stored value. */
function draftOf(f: CustomField, v: unknown): string | string[] {
  if (!isSet(v)) return f.type === 'multiselect' ? [] : '';
  switch (f.type) {
    case 'multiselect': return (v as unknown[]).map(String);
    case 'multiobject': return (v as unknown[]).map(String).join(', ');
    case 'json': return JSON.stringify(v, null, 2);
    case 'datetime': return String(v).slice(0, 16);
    default: return String(v);
  }
}

/** The value to send for a draft; throws a person-readable reason. */
export function valueOf(f: CustomField, d: string | string[]): unknown {
  if (Array.isArray(d)) return d.length ? d : null;
  const s = d.trim();
  if (s === '') return null;
  switch (f.type) {
    case 'integer':
    case 'decimal': {
      const n = Number(s);
      if (Number.isNaN(n)) throw new Error(`${fieldLabel(f)} must be a number`);
      return n;
    }
    case 'boolean': return s === 'true';
    case 'datetime': {
      const t = new Date(s);
      if (Number.isNaN(t.getTime())) throw new Error(`${fieldLabel(f)} must be a date and time`);
      return t.toISOString().replace(/\.\d{3}Z$/, 'Z');
    }
    case 'json':
      try {
        return JSON.parse(s) as unknown;
      } catch {
        throw new Error(`${fieldLabel(f)} must be valid JSON`);
      }
    case 'multiobject': return s.split(',').map((x) => x.trim()).filter(Boolean);
    default: return s;
  }
}

function FieldControl({ f, draft, labels, onDraft }: {
  f: CustomField; draft: string | string[]; labels: Map<string, string>; onDraft: (d: string | string[]) => void;
}) {
  const label = fieldLabel(f);
  const common = { 'aria-label': label, className: 'ui-input', style: { width: '100%' } };
  const text = typeof draft === 'string' ? draft : '';
  switch (f.type) {
    case 'longtext':
    case 'json':
      return <textarea {...common} rows={f.type === 'json' ? 4 : 3} value={text} onChange={(e) => onDraft(e.target.value)} />;
    case 'integer':
    case 'decimal':
      return <input {...common} type="number" step={f.type === 'integer' ? 1 : 'any'} value={text} onChange={(e) => onDraft(e.target.value)} />;
    case 'boolean':
      return (
        <select {...common} value={text} onChange={(e) => onDraft(e.target.value)}>
          <option value="">—</option><option value="true">Yes</option><option value="false">No</option>
        </select>
      );
    case 'date':
      return <input {...common} type="date" value={text} onChange={(e) => onDraft(e.target.value)} />;
    case 'datetime':
      return <input {...common} type="datetime-local" value={text} onChange={(e) => onDraft(e.target.value)} />;
    case 'select':
      return (
        <select {...common} value={text} onChange={(e) => onDraft(e.target.value)}>
          <option value="">—</option>
          {[...labels].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      );
    case 'multiselect': {
      const picked = Array.isArray(draft) ? draft : [];
      return (
        <div role="group" aria-label={label} style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          {[...labels].map(([v, l]) => (
            <label key={v} style={{ display: 'inline-flex', gap: 5, alignItems: 'center', fontSize: 12.5 }}>
              <input type="checkbox" checked={picked.includes(v)}
                onChange={(e) => onDraft(e.target.checked ? [...picked, v] : picked.filter((x) => x !== v))} />
              {l}
            </label>
          ))}
        </div>
      );
    }
    default:
      return <input {...common} type={f.type === 'url' ? 'url' : 'text'} value={text}
        placeholder={f.type === 'object' || f.type === 'multiobject' ? `${f.related_object_kind ?? 'object'} id${f.type === 'multiobject' ? 's, comma separated' : ''}` : undefined}
        onChange={(e) => onDraft(e.target.value)} />;
  }
}

export function CustomFieldsPanel({ kind, id, values, permission, onChange }: CustomFieldsPanelProps) {
  const defs = useCustomFields(kind);
  const sets = useChoiceSets();
  const [editing, setEditing] = useState(false);
  const [drafts, setDrafts] = useState<Record<string, string | string[]>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const stored = useMemo(() => values ?? {}, [values]);

  const visible = useMemo(() => (defs.data ?? []).filter((f) => f.ui_visible !== 'hidden'), [defs.data]);

  if (defs.isLoading) return <div data-testid="custom-fields-panel"><PanelLoading label="Loading custom fields…" /></div>;
  if (defs.isError) {
    return (
      <div data-testid="custom-fields-panel">
        <PanelError message={defs.error instanceof Error ? defs.error.message : 'Request failed'} onRetry={() => { void defs.refetch(); }} />
      </div>
    );
  }
  if (visible.length === 0) {
    return (
      <div data-testid="custom-fields-panel">
        <div data-testid="custom-fields-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '4px 0' }}>
          No custom fields apply to {OBJECT_KIND_LABELS[kind].plural.toLowerCase()}. An administrator defines them in Settings → Custom Fields.
        </div>
      </div>
    );
  }

  const editable = visible.filter((f) => f.ui_editable === 'yes');
  const shown = editing ? visible.filter((f) => f.ui_editable !== 'hidden') : visible.filter((f) => f.ui_visible !== 'if-set' || isSet(stored[f.name]));

  const start = () => {
    const d: Record<string, string | string[]> = {};
    for (const f of editable) d[f.name] = draftOf(f, stored[f.name]);
    setDrafts(d);
    setError(null);
    setSaved(false);
    setEditing(true);
  };
  const save = async () => {
    setError(null);
    const patch: Values = {};
    try {
      for (const f of editable) {
        const next = valueOf(f, drafts[f.name] ?? '');
        if (JSON.stringify(next ?? null) !== JSON.stringify(isSet(stored[f.name]) ? stored[f.name] : null)) patch[f.name] = next;
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Invalid value');
      return;
    }
    if (Object.keys(patch).length === 0) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await onChange(patch);
      setEditing(false);
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The request failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div data-testid="custom-fields-panel" data-object-id={id}>
      {shown.map((f, i) => {
        const labels = choiceLabels(f, sets.data);
        const header = f.group_name && f.group_name !== shown[i - 1]?.group_name
          ? <div key={`g-${f.group_name}`} className="eyebrow-app" style={{ margin: '8px 0 4px' }}>{f.group_name}</div>
          : null;
        const canEdit = editing && f.ui_editable === 'yes';
        return (
          <div key={f.id}>
            {header}
            <div data-testid={`custom-field-${f.name}`} style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: 10, alignItems: 'center', padding: '4px 0', fontSize: 12.5 }}>
              <span style={{ color: 'var(--app-t3)' }} title={f.description ?? undefined}>{fieldLabel(f)}{f.required ? ' *' : ''}</span>
              {canEdit
                ? <FieldControl f={f} draft={drafts[f.name] ?? ''} labels={labels} onDraft={(d) => setDrafts((c) => ({ ...c, [f.name]: d }))} />
                : f.type === 'url' && isSet(stored[f.name])
                  ? <a href={String(stored[f.name])} target="_blank" rel="noreferrer noopener">{String(stored[f.name])}</a>
                  : <span className={f.type === 'object' || f.type === 'multiobject' || f.type === 'json' ? 'mono' : undefined}>{displayValue(f, stored[f.name], labels)}</span>}
            </div>
          </div>
        );
      })}
      {error && (
        <div role="alert" data-testid="custom-fields-error" style={{ marginTop: 8, fontSize: 12.5, color: 'var(--danger-text)' }}>{error}</div>
      )}
      {saved && !editing && (
        <div role="status" data-testid="custom-fields-saved" style={{ marginTop: 6, fontSize: 12, color: 'var(--app-t3)' }}>
          <Icon name="circle-check" size={12} /> Saved
        </div>
      )}
      {editable.length > 0 && (
        <PermissionGate permission={permission}>
          <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            {editing ? (
              <>
                <button type="button" className="ui-btn sm accent" data-testid="custom-fields-save" disabled={saving} onClick={() => { void save(); }}>{saving ? 'Saving…' : 'Save'}</button>
                <button type="button" className="ui-btn sm" disabled={saving} onClick={() => { setEditing(false); setError(null); }}>Cancel</button>
              </>
            ) : (
              <button type="button" className="ui-btn sm" data-testid="custom-fields-edit" onClick={start}><Icon name="sliders-horizontal" size={12} />Edit custom fields</button>
            )}
          </div>
        </PermissionGate>
      )}
    </div>
  );
}
