// Custom-policy detail: the expandable controls panel for one tenant framework
// (control CRUD) plus the measurement rule builder per control. Mirrors the admin
// platform-framework authoring (admin-ui-v2 catalog-page + measurement-rules-modal)
// in the frontend-v2 idiom, over the /frameworks/tenant/* endpoints.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { STag } from './kit';
import { notAssessedReasonText } from '../findings/control-status';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';

type Control = complianceEngineComponents['schemas']['TenantFrameworkControl'];
type ControlInput = complianceEngineComponents['schemas']['TenantFrameworkControlInput'];
type MeasurementType = complianceEngineComponents['schemas']['MeasurementType'];
type ControlMeasurement = complianceEngineComponents['schemas']['ControlMeasurement'];
type MeasurementInput = complianceEngineComponents['schemas']['ControlMeasurementInput'];
type Severity = 'Low' | 'Med' | 'High' | 'Critical';
type RuleType = 'threshold' | 'presence' | 'pattern' | 'range';

const SEVERITY_COLOR: Record<string, string> = { Critical: 'var(--danger)', High: 'var(--warn-strong)', Med: 'var(--warn)', Low: 'var(--ok-lime)' };
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

// ─── Control form ──────────────────────────────────────────────────────────
function ControlModal({ policyId, control, onClose, qc }: { policyId: string; control: Control | null; onClose: () => void; qc: ReturnType<typeof useQueryClient> }) {
  const editing = !!control;
  const [controlId, setControlId] = useState(control?.control_id ?? '');
  const [title, setTitle] = useState(control?.title ?? '');
  const [description, setDescription] = useState(control?.description ?? '');
  const [severity, setSeverity] = useState<Severity>((control?.baseline_severity as Severity) ?? 'Med');
  const [cryptoRelevant, setCryptoRelevant] = useState(control?.crypto_relevant ?? false);
  const [error, setError] = useState<string | null>(null);
  const invalid = !controlId.trim() || !title.trim();

  const mut = useMutation({
    mutationFn: async () => {
      const body: ControlInput = { control_id: controlId.trim(), title: title.trim(), description, baseline_severity: severity, crypto_relevant: cryptoRelevant };
      if (editing) {
        const { error, response } = await clients.compliance.PUT('/frameworks/tenant/{id}/controls/{controlId}', { params: { path: { id: policyId, controlId: control!.id } }, body });
        if (error || !response.ok) throw new Error('Update control failed');
      } else {
        const { error, response } = await clients.compliance.POST('/frameworks/tenant/{id}/controls', { params: { path: { id: policyId } }, body });
        if (error || !response.ok) throw new Error('Add control failed');
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['custom-policy', policyId] });
      qc.invalidateQueries({ queryKey: ['settings', 'tenant-frameworks'] });
      onClose();
    },
    onError: (e) => setError(errMsg(e)),
  });

  return (
    <Modal
      open onClose={onClose} icon="sliders-horizontal" eyebrow="Control"
      title={editing ? `Edit control — ${control!.control_id}` : 'New control'}
      description="Controls define what a policy checks. Add measurement rules to a control to make it evaluate."
      footerNote={error ?? undefined}
      primary={<button className="ui-btn sm accent" disabled={invalid || mut.isPending} onClick={() => { setError(null); mut.mutate(); }}>{mut.isPending ? 'Saving…' : editing ? 'Save' : 'Add control'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
    >
      <ModalField label="Control ID"><ModalInput value={controlId} onChange={(e) => setControlId(e.target.value)} placeholder="e.g. SEC-1" /></ModalField>
      <ModalField label="Title"><ModalInput value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Control title" /></ModalField>
      <ModalField label="Baseline severity">
        <ModalSelect value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
          {(['Low', 'Med', 'High', 'Critical'] as Severity[]).map((s) => <option key={s} value={s}>{s}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this control requires" /></ModalField>
      <ModalField label="Cryptographically relevant">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--app-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={cryptoRelevant} onChange={(e) => setCryptoRelevant(e.target.checked)} />
          This control evaluates cryptographic posture
        </label>
      </ModalField>
    </Modal>
  );
}

// ─── Measurement rule builder ──────────────────────────────────────────────
interface RuleForm {
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
  severity: '' | Severity;
}
function blankForm(mtId: string, ruleType: RuleType): RuleForm {
  return { editingId: null, mtId, ruleType, operator: '>=', value: '', required: true, pattern: '', flags: 'i', min: '', max: '', weight: '1', severity: '' };
}
function formFromMeasurement(m: ControlMeasurement): RuleForm {
  const p = (m.predicate ?? {}) as Record<string, unknown>;
  return {
    editingId: m.id, mtId: m.measurement_type_id, ruleType: m.rule_type as RuleType,
    operator: String(p.operator ?? '>='), value: p.value != null ? String(p.value) : '',
    required: p.required !== false, pattern: String(p.pattern ?? ''), flags: String(p.flags ?? 'i'),
    min: p.min != null ? String(p.min) : '', max: p.max != null ? String(p.max) : '',
    weight: String(m.weight ?? 1), severity: (m.severity_override as RuleForm['severity']) || '',
  };
}

function RulesModal({ control, onClose }: { control: Control; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<RuleForm | null>(null);

  const typesQ = useQuery({
    queryKey: ['measurement-types'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/measurement-types', {});
      if (error || !data) throw new Error('Failed to load measurement types');
      return data.measurement_types ?? [];
    },
    staleTime: 10 * 60 * 1000,
  });
  const rulesQ = useQuery({
    queryKey: ['custom-policy-measurements', control.id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/tenant/controls/{id}/measurements', { params: { path: { id: control.id } } });
      if (error || !data) throw new Error('Failed to load rules');
      return data.measurements ?? [];
    },
  });

  const types = useMemo(() => typesQ.data ?? [], [typesQ.data]);
  const typeById = useMemo(() => new Map(types.map((t) => [t.id, t])), [types]);
  const grouped = useMemo(() => {
    const g = new Map<string, MeasurementType[]>();
    for (const t of types) { const k = t.category || 'Other'; if (!g.has(k)) g.set(k, []); g.get(k)!.push(t); }
    return [...g.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [types]);

  const invalidate = () => qc.invalidateQueries({ queryKey: ['custom-policy-measurements', control.id] });
  const saveMut = useMutation({
    mutationFn: async (f: RuleForm) => {
      const predicate: Record<string, unknown> =
        f.ruleType === 'threshold' ? { operator: f.operator, value: Number(f.value) }
        : f.ruleType === 'presence' ? { required: f.required }
        : f.ruleType === 'pattern' ? { pattern: f.pattern, flags: f.flags || 'i' }
        : (() => { const p: Record<string, number> = {}; if (f.min.trim() !== '') p.min = Number(f.min); if (f.max.trim() !== '') p.max = Number(f.max); return p; })();
      const body: MeasurementInput = { measurement_type_id: f.mtId, rule_type: f.ruleType, predicate, weight: Number(f.weight), ...(f.severity ? { severity_override: f.severity } : {}) };
      if (f.editingId) {
        const { error, response } = await clients.compliance.PUT('/frameworks/tenant/controls/{id}/measurements/{measurementId}', { params: { path: { id: control.id, measurementId: f.editingId } }, body });
        if (error || !response.ok) throw new Error('Update rule failed');
      } else {
        const { error, response } = await clients.compliance.POST('/frameworks/tenant/controls/{id}/measurements', { params: { path: { id: control.id } }, body });
        if (error || !response.ok) throw new Error('Add rule failed (check the predicate fits the measurement type)');
      }
    },
    onSuccess: () => { invalidate(); setForm(null); },
  });
  const deleteMut = useMutation({
    mutationFn: async (measurementId: string) => {
      const { error, response } = await clients.compliance.DELETE('/frameworks/tenant/controls/{id}/measurements/{measurementId}', { params: { path: { id: control.id, measurementId } } });
      if (error || !response.ok) throw new Error('Delete rule failed');
    },
    onSuccess: invalidate,
  });

  const selectedType = form ? typeById.get(form.mtId) : undefined;
  const ruleChoices = allowedRuleTypes(selectedType);
  const formInvalid = (() => {
    if (!form || !form.mtId) return true;
    const w = Number(form.weight);
    if (Number.isNaN(w) || w < 1 || w > 10) return true;
    if (form.ruleType === 'threshold') return !form.operator || form.value.trim() === '' || Number.isNaN(Number(form.value));
    if (form.ruleType === 'pattern') return form.pattern.trim() === '';
    if (form.ruleType === 'range') return form.min.trim() === '' && form.max.trim() === '';
    return false;
  })();
  const startAdd = () => { const first = types[0]; setForm(blankForm(first?.id ?? '', allowedRuleTypes(first)[0] ?? 'presence')); };
  const rules = rulesQ.data ?? [];

  return (
    <Modal
      open onClose={onClose} size="lg" icon="sliders-horizontal" eyebrow={`Rules — ${control.control_id}`}
      title={form ? (form.editingId ? 'Edit rule' : 'New rule') : control.title}
      description={form ? 'A rule fails when the measured value violates the predicate.' : `A control passes when all its rules pass and fails if any fail. ${notAssessedReasonText('no_measurements')} It's scored Not assessed, not a pass.`}
      footerNote={saveMut.isError ? errMsg(saveMut.error) : undefined}
      primary={form ? <button className="ui-btn sm accent" disabled={formInvalid || saveMut.isPending} onClick={() => form && saveMut.mutate(form)}>{saveMut.isPending ? 'Saving…' : 'Save rule'}</button> : undefined}
      secondary={<button className="ui-btn sm" onClick={onClose}>Close</button>}
    >
      {!form ? (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ flex: 1 }} />
            <button className="ui-btn sm" disabled={types.length === 0} onClick={startAdd}><Icon name="plus" size={13} />Add rule</button>
          </div>
          {rulesQ.isLoading ? (
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading rules…</div>
          ) : rules.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No rules yet. Add one so this control evaluates something.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {rules.map((m) => (
                <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel2)' }}>
                  <STag color="var(--info)">{m.rule_type}</STag>
                  <span className="mono" style={{ flex: 1, fontSize: 12, color: 'var(--app-t1)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ruleSummary(m, typeById.get(m.measurement_type_id)?.name ?? 'measurement')}</span>
                  {m.severity_override && <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>sev {m.severity_override}</span>}
                  <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>w{m.weight}</span>
                  <button className="ui-btn sm ghost" onClick={() => setForm(formFromMeasurement(m))}>Edit</button>
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} disabled={deleteMut.isPending} onClick={() => { if (window.confirm('Delete this rule?')) deleteMut.mutate(m.id); }}><Icon name="x" size={12} /></button>
                </div>
              ))}
            </div>
          )}
          {typesQ.isError && <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn't load measurement types — the rule builder needs them.</div>}
        </>
      ) : (
        <>
          <button className="ui-btn sm ghost" style={{ alignSelf: 'flex-start' }} onClick={() => setForm(null)}><Icon name="chevron-left" size={13} />Back to rules</button>
          <ModalField label="Measurement">
            <ModalSelect value={form.mtId} onChange={(e) => { const mt = typeById.get(e.target.value); const allowed = allowedRuleTypes(mt); setForm({ ...form, mtId: e.target.value, ruleType: allowed.includes(form.ruleType) ? form.ruleType : (allowed[0] ?? 'presence') }); }}>
              {grouped.map(([cat, list]) => <optgroup key={cat} label={cat}>{list.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.code})</option>)}</optgroup>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Rule type">
            <ModalSelect value={form.ruleType} onChange={(e) => setForm({ ...form, ruleType: e.target.value as RuleType })}>
              {ruleChoices.map((r) => <option key={r} value={r}>{r}</option>)}
            </ModalSelect>
          </ModalField>
          {form.ruleType === 'threshold' && (
            <ModalField label="Condition (fails when value is outside this)">
              <div style={{ display: 'flex', gap: 8 }}>
                <ModalSelect value={form.operator} onChange={(e) => setForm({ ...form, operator: e.target.value })}>{validOperators(selectedType).map((op) => <option key={op} value={op}>{op}</option>)}</ModalSelect>
                <ModalInput type="number" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder="value" />
              </div>
            </ModalField>
          )}
          {form.ruleType === 'presence' && (
            <ModalField label="Presence">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--app-t2)', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.required} onChange={(e) => setForm({ ...form, required: e.target.checked })} />
                Must be present (unchecked = must be absent)
              </label>
            </ModalField>
          )}
          {form.ruleType === 'pattern' && (
            <>
              <ModalField label="Regex pattern (a match counts as a violation)"><ModalInput value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} placeholder="e.g. ^(TLS1\\.0|TLS1\\.1)$" /></ModalField>
              <ModalField label="Flags"><ModalInput value={form.flags} onChange={(e) => setForm({ ...form, flags: e.target.value })} placeholder="i" /></ModalField>
            </>
          )}
          {form.ruleType === 'range' && (
            <ModalField label="Range (fails outside [min, max]; leave a side blank for open-ended)">
              <div style={{ display: 'flex', gap: 8 }}>
                <ModalInput type="number" value={form.min} onChange={(e) => setForm({ ...form, min: e.target.value })} placeholder="min" />
                <ModalInput type="number" value={form.max} onChange={(e) => setForm({ ...form, max: e.target.value })} placeholder="max" />
              </div>
            </ModalField>
          )}
          <div style={{ display: 'flex', gap: 12 }}>
            <ModalField label="Weight (1–10)"><ModalInput type="number" value={form.weight} onChange={(e) => setForm({ ...form, weight: e.target.value })} /></ModalField>
            <ModalField label="Severity override">
              <ModalSelect value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value as RuleForm['severity'] })}>
                <option value="">Use control baseline</option>
                {(['Low', 'Med', 'High', 'Critical'] as Severity[]).map((s) => <option key={s} value={s}>{s}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
        </>
      )}
    </Modal>
  );
}

// ─── Controls panel (the expanded policy body) ─────────────────────────────
export function CustomPolicyControls({ policyId, canManage }: { policyId: string; canManage: boolean }) {
  const qc = useQueryClient();
  const [controlModal, setControlModal] = useState<{ kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; control: Control }>({ kind: 'closed' });
  const [rulesControl, setRulesControl] = useState<Control | null>(null);

  const q = useQuery({
    queryKey: ['custom-policy', policyId],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/tenant/{id}', { params: { path: { id: policyId } } });
      if (error || !data) throw new Error('Failed to load policy');
      return data.framework;
    },
  });
  const removeMut = useMutation({
    mutationFn: async (controlId: string) => {
      const { error, response } = await clients.compliance.DELETE('/frameworks/tenant/{id}/controls/{controlId}', { params: { path: { id: policyId, controlId } } });
      if (error || !response.ok) throw new Error('Delete control failed');
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['custom-policy', policyId] }); qc.invalidateQueries({ queryKey: ['settings', 'tenant-frameworks'] }); },
  });

  const controls = (q.data?.controls ?? []) as Control[];

  return (
    <div style={{ padding: '12px 4px 4px 50px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <span style={{ fontWeight: 600, fontSize: 12.5, color: 'var(--app-t1)' }}>Controls</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{controls.length}</span>
        <div style={{ flex: 1 }} />
        {canManage && <button className="ui-btn sm" onClick={() => setControlModal({ kind: 'create' })}><Icon name="plus" size={13} />Add control</button>}
      </div>
      {q.isLoading ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading controls…</div>
      ) : controls.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No controls yet. Add controls so this policy evaluates something.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {controls.map((ctrl) => (
            <div key={ctrl.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel)' }}>
              <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--app-t2)', minWidth: 56 }}>{ctrl.control_id}</span>
              <span style={{ flex: 1, fontSize: 12.5, color: 'var(--app-t1)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ctrl.title}</span>
              {ctrl.crypto_relevant && <STag color="var(--info)">crypto</STag>}
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: SEVERITY_COLOR[ctrl.baseline_severity] ?? 'var(--app-t3)' }}>
                <span style={{ width: 6, height: 6, borderRadius: 50, background: SEVERITY_COLOR[ctrl.baseline_severity] ?? 'var(--app-t3)' }} />{ctrl.baseline_severity}
              </span>
              {canManage && (
                <>
                  <button className="ui-btn sm ghost" title="Measurement rules" onClick={() => setRulesControl(ctrl)}>Rules</button>
                  <button className="ui-btn sm ghost" onClick={() => setControlModal({ kind: 'edit', control: ctrl })}>Edit</button>
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} disabled={removeMut.isPending} onClick={() => { if (window.confirm(`Delete control "${ctrl.control_id}"?`)) removeMut.mutate(ctrl.id); }}><Icon name="x" size={12} /></button>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {controlModal.kind !== 'closed' && (
        <ControlModal policyId={policyId} control={controlModal.kind === 'edit' ? controlModal.control : null} onClose={() => setControlModal({ kind: 'closed' })} qc={qc} />
      )}
      {rulesControl && <RulesModal control={rulesControl} onClose={() => setRulesControl(null)} />}
    </div>
  );
}
