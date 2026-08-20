// Measurement rule builder (admin framework Phase 2b). Manages the measurement
// rules on a single control: list existing rules, add/edit via a per-rule-type
// predicate editor (threshold / presence / pattern / range), delete. The rule
// types + operators + enum values come from the measurement-types catalog.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Plus, Pencil, Trash2, ArrowLeft } from 'lucide-react';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { Tag } from '../../components/ui/primitives';

type MeasurementType = complianceEngineComponents['schemas']['MeasurementType'];
type ControlMeasurement = complianceEngineComponents['schemas']['ControlMeasurement'];
type MeasurementInput = complianceEngineComponents['schemas']['ControlMeasurementInput'];
type RuleType = 'threshold' | 'presence' | 'pattern' | 'range';

const ALL_RULE_TYPES: RuleType[] = ['threshold', 'presence', 'pattern', 'range'];
const DEFAULT_OPERATORS = ['<=', '>=', '<', '>', '==', '!='];

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : 'Action failed';
}

function allowedRuleTypes(t?: MeasurementType): RuleType[] {
  const declared = (t?.allowed_rule_types ?? []).filter((r): r is RuleType => (ALL_RULE_TYPES as string[]).includes(r));
  if (declared.length) return declared;
  switch (t?.data_type) {
    case 'integer':
    case 'date':
      return ['threshold', 'range', 'presence'];
    case 'enum':
    case 'string':
      return ['pattern', 'presence'];
    case 'boolean':
      return ['presence'];
    default:
      return ALL_RULE_TYPES;
  }
}

function validOperators(t?: MeasurementType): string[] {
  return t?.valid_operators?.length ? t.valid_operators : DEFAULT_OPERATORS;
}

function ruleSummary(m: ControlMeasurement, typeName: string): string {
  const p = (m.predicate ?? {}) as Record<string, unknown>;
  switch (m.rule_type) {
    case 'threshold':
      return `${typeName} ${String(p.operator ?? '?')} ${String(p.value ?? '?')}`;
    case 'presence':
      return `${typeName} ${p.required === false ? 'absent' : 'present'}`;
    case 'pattern':
      return `${typeName} matches /${String(p.pattern ?? '')}/${String(p.flags ?? '')}`;
    case 'range':
      return `${typeName} in [${p.min ?? '−∞'}, ${p.max ?? '∞'}]`;
    default:
      return typeName;
  }
}

interface FormState {
  editingId: string | null;
  mtId: string;
  ruleType: RuleType;
  operator: string;
  value: string;
  required: boolean;
  pattern: string;
  flags: string;
  min: string;
  max: string;
  weight: string;
  severity: '' | 'Low' | 'Med' | 'High' | 'Critical';
}

function blankForm(mtId: string, ruleType: RuleType): FormState {
  return { editingId: null, mtId, ruleType, operator: '>=', value: '', required: true, pattern: '', flags: 'i', min: '', max: '', weight: '1', severity: '' };
}

function formFromMeasurement(m: ControlMeasurement): FormState {
  const p = (m.predicate ?? {}) as Record<string, unknown>;
  return {
    editingId: m.id,
    mtId: m.measurement_type_id,
    ruleType: m.rule_type as RuleType,
    operator: String(p.operator ?? '>='),
    value: p.value != null ? String(p.value) : '',
    required: p.required !== false,
    pattern: String(p.pattern ?? ''),
    flags: String(p.flags ?? 'i'),
    min: p.min != null ? String(p.min) : '',
    max: p.max != null ? String(p.max) : '',
    weight: String(m.weight ?? 1),
    severity: (m.severity_override as FormState['severity']) || '',
  };
}

export function MeasurementRulesModal({ control, onClose }: { control: { id: string; control_id: string; title: string }; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<FormState | null>(null);

  const typesQ = useQuery({
    queryKey: ['platform', 'measurement-types'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/measurement-types', {});
      if (error || !data) throw new Error('Failed to load measurement types');
      return data.measurement_types ?? [];
    },
    staleTime: 10 * 60 * 1000,
  });
  const rulesQ = useQuery({
    queryKey: ['platform', 'control-measurements', control.id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/admin/controls/{id}/measurements', { params: { path: { id: control.id } } });
      if (error || !data) throw new Error('Failed to load rules');
      return data.measurements ?? [];
    },
  });

  const types = useMemo(() => typesQ.data ?? [], [typesQ.data]);
  const typeById = useMemo(() => new Map(types.map((t) => [t.id, t])), [types]);
  const grouped = useMemo(() => {
    const g = new Map<string, MeasurementType[]>();
    for (const t of types) {
      const k = t.category || 'Other';
      if (!g.has(k)) g.set(k, []);
      g.get(k)!.push(t);
    }
    return [...g.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [types]);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['platform', 'control-measurements', control.id] });
    qc.invalidateQueries({ queryKey: ['platform', 'admin-frameworks'] });
  };
  const addMut = useMutation({
    mutationFn: async (body: MeasurementInput) => {
      const { error } = await clients.compliance.POST('/admin/controls/{id}/measurements', { params: { path: { id: control.id } }, body });
      if (error) throw new Error('Add rule failed (check the predicate is valid for the measurement type)');
    },
    onSuccess: invalidate,
  });
  const updateMut = useMutation({
    mutationFn: async ({ measurementId, body }: { measurementId: string; body: MeasurementInput }) => {
      const { error } = await clients.compliance.PUT('/admin/controls/{id}/measurements/{measurementId}', { params: { path: { id: control.id, measurementId } }, body });
      if (error) throw new Error('Update rule failed');
    },
    onSuccess: invalidate,
  });
  const deleteMut = useMutation({
    mutationFn: async (measurementId: string) => {
      const { error } = await clients.compliance.DELETE('/admin/controls/{id}/measurements/{measurementId}', { params: { path: { id: control.id, measurementId } } });
      if (error) throw new Error('Delete rule failed');
    },
    onSuccess: invalidate,
  });

  const startAdd = () => {
    const first = types[0];
    setForm(blankForm(first?.id ?? '', allowedRuleTypes(first)[0] ?? 'presence'));
  };

  const selectedType = form ? typeById.get(form.mtId) : undefined;
  const ruleChoices = allowedRuleTypes(selectedType);

  const formInvalid = (() => {
    if (!form || !form.mtId) return true;
    const w = Number(form.weight);
    if (Number.isNaN(w) || w < 1 || w > 10) return true;
    switch (form.ruleType) {
      case 'threshold':
        return !form.operator || form.value.trim() === '' || Number.isNaN(Number(form.value));
      case 'pattern':
        return form.pattern.trim() === '';
      case 'range':
        return form.min.trim() === '' && form.max.trim() === '';
      default:
        return false;
    }
  })();

  const buildPredicate = (f: FormState): Record<string, unknown> => {
    switch (f.ruleType) {
      case 'threshold':
        return { operator: f.operator, value: Number(f.value) };
      case 'presence':
        return { required: f.required };
      case 'pattern':
        return { pattern: f.pattern, flags: f.flags || 'i' };
      case 'range': {
        const p: Record<string, number> = {};
        if (f.min.trim() !== '') p.min = Number(f.min);
        if (f.max.trim() !== '') p.max = Number(f.max);
        return p;
      }
    }
  };

  const save = () => {
    if (!form) return;
    const body: MeasurementInput = {
      measurement_type_id: form.mtId,
      rule_type: form.ruleType,
      predicate: buildPredicate(form),
      weight: Number(form.weight),
      ...(form.severity ? { severity_override: form.severity } : {}),
    };
    const opts = {
      onSuccess: () => { toast.success(form.editingId ? 'Rule updated' : 'Rule added'); setForm(null); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (form.editingId) updateMut.mutate({ measurementId: form.editingId, body }, opts);
    else addMut.mutate(body, opts);
  };

  const rules = rulesQ.data ?? [];

  return (
    <Modal
      open onClose={onClose} size="lg"
      title={form ? (form.editingId ? 'Edit rule' : 'New rule') : `Rules — ${control.control_id}`}
      description={form ? 'A rule fails when the measured value violates the predicate.' : control.title}
      footerNote="Platform-admin · audited"
      primaryLabel={form ? 'Save rule' : undefined}
      onPrimary={form ? save : undefined}
      primaryLoading={addMut.isPending || updateMut.isPending}
      primaryDisabled={formInvalid}
    >
      {!form ? (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: 'var(--op-t3)' }}>A control passes when all its rules pass and fails if any fail. With no rules configured it is scored Not assessed and excluded from the score — never treated as a pass.</span>
            <div style={{ flex: 1 }} />
            <button className="op-btn sm" disabled={types.length === 0} onClick={startAdd}><Plus size={13} />Add rule</button>
          </div>
          {rulesQ.isLoading ? (
            <div style={{ fontSize: 12, color: 'var(--op-t3)', padding: '8px 0' }}>Loading rules…</div>
          ) : rules.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--op-t3)', padding: '8px 0' }}>No rules yet. Add one so this control evaluates something.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {rules.map((m) => {
                const t = typeById.get(m.measurement_type_id);
                return (
                  <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--op-border)', background: 'var(--op-panel2)' }}>
                    <Tag color="var(--info)">{m.rule_type}</Tag>
                    <span className="mono" style={{ flex: 1, fontSize: 12, color: 'var(--op-t1)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ruleSummary(m, t?.name ?? 'measurement')}</span>
                    {m.severity_override && <span style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>sev {m.severity_override}</span>}
                    <span className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>w{m.weight}</span>
                    <button className="op-btn icon sm" title="Edit rule" onClick={() => setForm(formFromMeasurement(m))}><Pencil size={12} /></button>
                    <button className="op-btn icon sm" title="Delete rule" disabled={deleteMut.isPending} onClick={() => { if (window.confirm('Delete this rule?')) deleteMut.mutate(m.id, { onSuccess: () => toast.success('Rule deleted'), onError: (e) => toast.error(errMsg(e)) }); }}><Trash2 size={12} /></button>
                  </div>
                );
              })}
            </div>
          )}
          {typesQ.isError && <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn't load measurement types — the rule builder needs them.</div>}
        </>
      ) : (
        <>
          <button className="op-btn sm ghost" style={{ alignSelf: 'flex-start' }} onClick={() => setForm(null)}><ArrowLeft size={13} />Back to rules</button>
          <ModalField label="Measurement">
            <select value={form.mtId} onChange={(e) => {
              const mt = typeById.get(e.target.value);
              const allowed = allowedRuleTypes(mt);
              setForm({ ...form, mtId: e.target.value, ruleType: allowed.includes(form.ruleType) ? form.ruleType : (allowed[0] ?? 'presence') });
            }} style={modalInputStyle}>
              {grouped.map(([cat, list]) => (
                <optgroup key={cat} label={cat}>
                  {list.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.code})</option>)}
                </optgroup>
              ))}
            </select>
          </ModalField>
          {selectedType?.description && <div style={{ fontSize: 11, color: 'var(--op-t3)', marginTop: -6 }}>{selectedType.description}{selectedType.units ? ` · ${selectedType.units}` : ''}</div>}
          <ModalField label="Rule type">
            <select value={form.ruleType} onChange={(e) => setForm({ ...form, ruleType: e.target.value as RuleType })} style={modalInputStyle}>
              {ruleChoices.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </ModalField>

          {form.ruleType === 'threshold' && (
            <ModalField label="Condition (fails when value is outside this)">
              <div style={{ display: 'flex', gap: 8 }}>
                <select value={form.operator} onChange={(e) => setForm({ ...form, operator: e.target.value })} style={{ ...modalInputStyle, maxWidth: 110 }}>
                  {validOperators(selectedType).map((op) => <option key={op} value={op}>{op}</option>)}
                </select>
                <input type="number" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="value" style={modalInputStyle} />
              </div>
            </ModalField>
          )}
          {form.ruleType === 'presence' && (
            <ModalField label="Presence">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.required} onChange={(e) => setForm({ ...form, required: e.target.checked })} />
                The measurement must be present (unchecked = must be absent)
              </label>
            </ModalField>
          )}
          {form.ruleType === 'pattern' && (
            <>
              <ModalField label="Regex pattern (a match counts as a violation)"><input value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} placeholder="e.g. ^(TLS1\\.0|TLS1\\.1)$" style={{ ...modalInputStyle, fontFamily: 'var(--font-mono, monospace)' }} /></ModalField>
              <ModalField label="Flags"><input value={form.flags} onChange={(e) => setForm({ ...form, flags: e.target.value })} placeholder="i" style={{ ...modalInputStyle, maxWidth: 100 }} /></ModalField>
              {(selectedType?.enum_values?.length ?? 0) > 0 && (
                <div style={{ fontSize: 11, color: 'var(--op-t3)', marginTop: -6 }}>Allowed values: {(selectedType!.enum_values as unknown[]).map(String).join(', ')}</div>
              )}
            </>
          )}
          {form.ruleType === 'range' && (
            <ModalField label="Range (fails outside [min, max]; leave a side blank for open-ended)">
              <div style={{ display: 'flex', gap: 8 }}>
                <input type="number" value={form.min} onChange={(e) => setForm({ ...form, min: e.target.value })} placeholder="min" style={modalInputStyle} />
                <input type="number" value={form.max} onChange={(e) => setForm({ ...form, max: e.target.value })} placeholder="max" style={modalInputStyle} />
              </div>
            </ModalField>
          )}

          <div style={{ display: 'flex', gap: 12 }}>
            <ModalField label="Weight (1–10)"><input type="number" min={1} max={10} value={form.weight} onChange={(e) => setForm({ ...form, weight: e.target.value })} style={modalInputStyle} /></ModalField>
            <ModalField label="Severity override">
              <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value as FormState['severity'] })} style={modalInputStyle}>
                <option value="">Use control baseline</option>
                {(['Low', 'Med', 'High', 'Critical'] as const).map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </ModalField>
          </div>
        </>
      )}
    </Modal>
  );
}
