// VISTA Operations — Catalog → Algorithms.
// The crypto-grading SOURCE OF TRUTH (ADR-0003): the `algorithms` table
// (inventory-service /algorithms). Platform admins (algorithms.manage) maintain
// it here — edit assessment fields, create new algorithms, and deprecate (mark
// obsolete; no hard delete, since assets reference algorithms). User-facing
// severity is still derived deterministically from strength + deprecation +
// risk_score (severityOf). Writes are gated server-side; 403s surface as toasts.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Search, Pencil, Plus, Archive } from 'lucide-react';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { relTime } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';

type Algorithm = inventoryComponents['schemas']['Algorithm'];
type CreateAlgorithmRequest = inventoryComponents['schemas']['CreateAlgorithmRequest'];
type UpdateAlgorithmRequest = inventoryComponents['schemas']['UpdateAlgorithmRequest'];

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
const RATING_COLOR: Record<Severity, string> = {
  Critical: 'var(--danger)', High: 'var(--warn-strong)', Medium: 'var(--warn)', Low: 'var(--ok-lime)', Informational: 'var(--info)',
};

const STRENGTHS = ['weak', 'acceptable', 'strong', 'recommended'];
const DEP_STATUSES = ['current', 'deprecated', 'obsolete'];
const PQC_STATUSES = ['none', 'standardized', 'candidate', 'alternative'];
const CATEGORIES = ['hash', 'symmetric', 'key_exchange', 'signature', 'protocol_version', 'cipher_suite'];

// ADR-0003 severity mapping: severity is derived from the existing assessment
// fields (one vocabulary, not a second independent scale).
function severityOf(a: { strength?: string | null; deprecation_status?: string | null; risk_score?: number | null }): Severity {
  if (a.strength === 'weak' || a.deprecation_status === 'obsolete') return 'Critical';
  if (a.deprecation_status === 'deprecated') return 'High';
  if (a.strength === 'recommended') return 'Informational';
  if (a.strength === 'strong') return 'Low';
  const r = a.risk_score ?? 50;
  if (r >= 75) return 'High';
  if (r >= 50) return 'Medium';
  if (r >= 25) return 'Low';
  return 'Informational';
}

function useAlgorithms() {
  return useQuery({
    queryKey: ['platform', 'algorithms'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/algorithms', {});
      if (error || !data) throw new Error('Failed to load algorithms');
      return data.algorithms ?? [];
    },
    staleTime: 5 * 60 * 1000,
  });
}

function useUpdateAlgorithm() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ code, body }: { code: string; body: UpdateAlgorithmRequest }) => {
      const { error, response } = await clients.inventory.PUT('/algorithms/{code}', { params: { path: { code } }, body });
      if (error) {
        if (response?.status === 403) throw new Error('You do not have permission to edit algorithms (algorithms.manage required)');
        throw new Error('Update failed');
      }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['platform', 'algorithms'] }); },
  });
}

function useCreateAlgorithm() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CreateAlgorithmRequest) => {
      const { error, response } = await clients.inventory.POST('/algorithms', { body });
      if (error) {
        if (response?.status === 409) throw new Error('An algorithm with this code already exists');
        if (response?.status === 403) throw new Error('You do not have permission to create algorithms (algorithms.manage required)');
        if (response?.status === 400) throw new Error('Check the required fields (code, name, category) and enum values');
        throw new Error('Create failed');
      }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['platform', 'algorithms'] }); },
  });
}

// Blast-radius heads-up: how many of the admin's-tenant assets use this algorithm.
function useAlgorithmUsage(code: string | null) {
  return useQuery({
    enabled: !!code,
    queryKey: ['platform', 'algorithm-usage', code],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/algorithms/{code}/usage', { params: { path: { code: code! } } });
      if (error || !data) throw new Error('usage-unavailable');
      return data.usage;
    },
    staleTime: 60 * 1000,
    retry: false,
  });
}

const ROFlex = { display: 'flex', flexWrap: 'wrap' as const, gap: 8 };
function ReadOnlyField({ label, value }: { label: string; value?: string | number | null }) {
  return (
    <div style={{ minWidth: 120 }}>
      <div style={{ fontSize: 10.5, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4 }}>{label}</div>
      <div className="mono" style={{ fontSize: 12.5, color: 'var(--op-t1)' }}>{value === null || value === undefined || value === '' ? '—' : String(value)}</div>
    </div>
  );
}

function EditAlgorithmModal({ algo, onClose, mut }: { algo: Algorithm; onClose: () => void; mut: ReturnType<typeof useUpdateAlgorithm> }) {
  const [strength, setStrength] = useState(algo.strength ?? 'acceptable');
  const [risk, setRisk] = useState(String(algo.risk_score ?? 50));
  const [dep, setDep] = useState(algo.deprecation_status ?? 'current');
  const [depDate, setDepDate] = useState(algo.deprecation_date ?? '');
  const [isPqc, setIsPqc] = useState(!!algo.is_pqc);
  const [pqcStatus, setPqcStatus] = useState(algo.pqc_standardization_status ?? 'none');
  const [guidance, setGuidance] = useState(algo.migration_guidance ?? '');
  const [alts, setAlts] = useState((algo.recommended_alternatives ?? []).join(', '));
  const usageQ = useAlgorithmUsage(algo.code);
  const riskN = Number(risk);
  const invalid = Number.isNaN(riskN) || riskN < 0 || riskN > 100;

  const save = () => {
    const altsArr = alts.split(',').map((s) => s.trim()).filter(Boolean);
    const body: UpdateAlgorithmRequest = {
      strength: strength as UpdateAlgorithmRequest['strength'], risk_score: riskN,
      deprecation_status: dep as UpdateAlgorithmRequest['deprecation_status'],
      deprecation_date: depDate, is_pqc: isPqc,
      pqc_standardization_status: pqcStatus as UpdateAlgorithmRequest['pqc_standardization_status'],
      migration_guidance: guidance, recommended_alternatives: altsArr,
    };
    mut.mutate(
      { code: algo.code, body },
      { onSuccess: () => { toast.success(`Updated ${algo.name || algo.code}`); onClose(); }, onError: (e) => toast.error(e instanceof Error ? e.message : 'Update failed') },
    );
  };

  const usageNote = usageQ.isLoading
    ? 'Checking how many assets use this algorithm…'
    : usageQ.isError
      ? 'Usage check unavailable.'
      : `${usageQ.data?.in_use_count ?? 0} asset(s) use this algorithm — saving will re-grade them.`;

  return (
    <Modal open onClose={onClose} title={`Edit — ${algo.name || algo.code}`} description="Edits the global crypto-assessment source of truth. Affects table-driven assessments now; full posture once the engine reads the registry (ADR-0003 Phase 2)." footerNote="Logged to audit" primaryLabel="Save" onPrimary={save} primaryLoading={mut.isPending} primaryDisabled={invalid} size="lg">
      <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-btn)', padding: '8px 11px', fontSize: 11.5, color: 'var(--op-t2)' }}>{usageNote}</div>

      <div style={{ fontSize: 10.5, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 2 }}>Identity (read-only)</div>
      <div style={ROFlex}>
        <ReadOnlyField label="Code" value={algo.code} />
        <ReadOnlyField label="Category" value={algo.category} />
        <ReadOnlyField label="Family" value={algo.algorithm_family} />
        <ReadOnlyField label="Primitive" value={algo.primitive} />
        <ReadOnlyField label="Mode" value={algo.mode} />
        <ReadOnlyField label="OID" value={algo.oid} />
        <ReadOnlyField label="Curve" value={algo.curve} />
        <ReadOnlyField label="Classical bits" value={algo.classical_security_level} />
      </div>

      <div style={{ fontSize: 10.5, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 4 }}>Assessment</div>
      <ModalField label="Strength">
        <select value={strength} onChange={(e) => setStrength(e.target.value)} style={modalInputStyle}>
          {STRENGTHS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Risk score (0–100)">
        <input type="number" min={0} max={100} value={risk} onChange={(e) => setRisk(e.target.value)} style={{ ...modalInputStyle, borderColor: invalid ? 'var(--danger)' : 'var(--op-border2)' }} />
      </ModalField>
      <ModalField label="Deprecation status">
        <select value={dep} onChange={(e) => setDep(e.target.value)} style={modalInputStyle}>
          {DEP_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Deprecation date">
        <input type="date" value={depDate} onChange={(e) => setDepDate(e.target.value)} style={modalInputStyle} />
      </ModalField>
      <ModalField label="Post-quantum?">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--op-t1)' }}>
          <input type="checkbox" checked={isPqc} onChange={(e) => setIsPqc(e.target.checked)} /> is_pqc
        </label>
      </ModalField>
      <ModalField label="PQC standardization status">
        <select value={pqcStatus} onChange={(e) => setPqcStatus(e.target.value)} style={modalInputStyle}>
          {PQC_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Recommended alternatives (comma-separated codes)">
        <input value={alts} onChange={(e) => setAlts(e.target.value)} placeholder="AES-256-GCM, ML-KEM-768" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Migration guidance">
        <textarea value={guidance} onChange={(e) => setGuidance(e.target.value)} rows={3} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'var(--font-body)' }} />
      </ModalField>
    </Modal>
  );
}

function CreateAlgorithmModal({ onClose, mut }: { onClose: () => void; mut: ReturnType<typeof useCreateAlgorithm> }) {
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [category, setCategory] = useState('symmetric');
  const [family, setFamily] = useState('');
  const [primitive, setPrimitive] = useState('');
  const [oid, setOid] = useState('');
  const [strength, setStrength] = useState('acceptable');
  const [risk, setRisk] = useState('50');
  const [dep, setDep] = useState('current');
  const [isPqc, setIsPqc] = useState(false);
  const [pqcStatus, setPqcStatus] = useState('none');
  const [guidance, setGuidance] = useState('');
  const riskN = Number(risk);
  const invalid = !code.trim() || !name.trim() || Number.isNaN(riskN) || riskN < 0 || riskN > 100;

  const save = () => {
    const body: CreateAlgorithmRequest = {
      code: code.trim(), name: name.trim(), category: category as CreateAlgorithmRequest['category'],
      strength: strength as CreateAlgorithmRequest['strength'], risk_score: riskN,
      deprecation_status: dep as CreateAlgorithmRequest['deprecation_status'],
      is_pqc: isPqc, pqc_standardization_status: pqcStatus as CreateAlgorithmRequest['pqc_standardization_status'],
    };
    if (family.trim()) body.algorithm_family = family.trim();
    if (primitive.trim()) body.primitive = primitive.trim();
    if (oid.trim()) body.oid = oid.trim();
    if (guidance.trim()) body.migration_guidance = guidance.trim();
    mut.mutate(body, {
      onSuccess: () => { toast.success(`Created ${name || code}`); onClose(); },
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Create failed'),
    });
  };

  return (
    <Modal open onClose={onClose} title="New algorithm" description="Adds a new row to the crypto-assessment source of truth. Code is the immutable matching key." footerNote="Logged to audit" primaryLabel="Create" onPrimary={save} primaryLoading={mut.isPending} primaryDisabled={invalid} size="lg">
      <div style={{ fontSize: 10.5, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Identity</div>
      <ModalField label="Code *">
        <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="ML-KEM-768" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Name *">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ML-KEM-768" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Category *">
        <select value={category} onChange={(e) => setCategory(e.target.value)} style={modalInputStyle}>
          {CATEGORIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Algorithm family">
        <input value={family} onChange={(e) => setFamily(e.target.value)} placeholder="ML-KEM" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Primitive">
        <input value={primitive} onChange={(e) => setPrimitive(e.target.value)} placeholder="kem" style={modalInputStyle} />
      </ModalField>
      <ModalField label="OID">
        <input value={oid} onChange={(e) => setOid(e.target.value)} style={modalInputStyle} />
      </ModalField>

      <div style={{ fontSize: 10.5, color: 'var(--op-t3)', textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 4 }}>Assessment</div>
      <ModalField label="Strength">
        <select value={strength} onChange={(e) => setStrength(e.target.value)} style={modalInputStyle}>
          {STRENGTHS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Risk score (0–100)">
        <input type="number" min={0} max={100} value={risk} onChange={(e) => setRisk(e.target.value)} style={{ ...modalInputStyle, borderColor: Number.isNaN(riskN) || riskN < 0 || riskN > 100 ? 'var(--danger)' : 'var(--op-border2)' }} />
      </ModalField>
      <ModalField label="Deprecation status">
        <select value={dep} onChange={(e) => setDep(e.target.value)} style={modalInputStyle}>
          {DEP_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Post-quantum?">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--op-t1)' }}>
          <input type="checkbox" checked={isPqc} onChange={(e) => setIsPqc(e.target.checked)} /> is_pqc
        </label>
      </ModalField>
      <ModalField label="PQC standardization status">
        <select value={pqcStatus} onChange={(e) => setPqcStatus(e.target.value)} style={modalInputStyle}>
          {PQC_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Migration guidance">
        <textarea value={guidance} onChange={(e) => setGuidance(e.target.value)} rows={3} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'var(--font-body)' }} />
      </ModalField>
    </Modal>
  );
}

function DeprecateModal({ algo, onClose, mut }: { algo: Algorithm; onClose: () => void; mut: ReturnType<typeof useUpdateAlgorithm> }) {
  const confirm = () => {
    mut.mutate(
      { code: algo.code, body: { deprecation_status: 'obsolete' } },
      { onSuccess: () => { toast.success(`Deprecated ${algo.name || algo.code}`); onClose(); }, onError: (e) => toast.error(e instanceof Error ? e.message : 'Deprecate failed') },
    );
  };
  return (
    <Modal open onClose={onClose} tone="danger" title={`Deprecate — ${algo.name || algo.code}`} description="Marks this algorithm obsolete (deprecation_status = obsolete). It is not deleted — assets reference it — but it will grade as Critical. You can re-activate it later by editing the status." footerNote="Logged to audit" primaryLabel="Mark obsolete" onPrimary={confirm} primaryLoading={mut.isPending} />
  );
}

export function RatingsPage() {
  const algosQ = useAlgorithms();
  const updateMut = useUpdateAlgorithm();
  const createMut = useCreateAlgorithm();
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<Algorithm | null>(null);
  const [deprecating, setDeprecating] = useState<Algorithm | null>(null);
  const [creating, setCreating] = useState(false);

  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const order: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
    return (algosQ.data ?? [])
      .map((a) => ({ a, sev: severityOf(a), type: a.primitive || a.algorithm_family || a.category || '—' }))
      .filter((r) => !ql || (r.a.name ?? '').toLowerCase().includes(ql) || (r.a.code ?? '').toLowerCase().includes(ql) || r.type.toLowerCase().includes(ql))
      .sort((x, y) => order.indexOf(x.sev) - order.indexOf(y.sev) || (x.a.name ?? '').localeCompare(y.a.name ?? ''));
  }, [algosQ.data, q]);

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Algorithm source of truth</div>
            <div style={{ fontSize: 11, color: 'var(--op-t3)' }}>The crypto-assessment registry that grades cryptographic values across all tenants</div>
          </div>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, height: 30, padding: '0 11px', borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', minWidth: 200 }}>
            <Search size={14} style={{ color: 'var(--op-t3)' }} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search value, type…" style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: 'var(--op-t1)', fontSize: 12.5, fontFamily: 'var(--font-body)' }} />
          </div>
          <button className="op-btn sm primary" onClick={() => setCreating(true)} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><Plus size={14} /> New algorithm</button>
        </div>
        <table className="op-table">
          <thead><tr><th>Value</th><th>Type</th><th>Rating</th><th>Rationale</th><th>Updated</th><th /></tr></thead>
          <tbody>
            {rows.map(({ a, sev, type }) => (
              <tr key={a.code || a.name}>
                <td><span className="mono" style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{a.name || a.code}</span></td>
                <td className="t-muted" style={{ textTransform: 'capitalize' }}>{type}</td>
                <td><span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontWeight: 600, color: RATING_COLOR[sev] }}><span style={{ width: 7, height: 7, borderRadius: 50, background: RATING_COLOR[sev] }} />{sev}</span></td>
                <td className="t-muted" style={{ whiteSpace: 'normal', maxWidth: 360 }}>{a.migration_guidance || '—'}</td>
                <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(a.updated_at)}</td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button className="op-btn icon sm" title="Edit" onClick={() => setEditing(a)}><Pencil size={13} /></button>
                  {a.deprecation_status !== 'obsolete' && (
                    <button className="op-btn icon sm" title="Deprecate (mark obsolete)" onClick={() => setDeprecating(a)} style={{ marginLeft: 6 }}><Archive size={13} /></button>
                  )}
                </td>
              </tr>
            ))}
            {algosQ.isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading algorithms…</td></tr>}
            {algosQ.isError && !algosQ.isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load algorithms. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => algosQ.refetch()}>Retry</button></td></tr>}
            {!algosQ.isLoading && !algosQ.isError && rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No algorithms match.</td></tr>}
          </tbody>
        </table>
        <div style={{ padding: '9px 16px', borderTop: '1px solid var(--op-border)', fontSize: 11.5, color: 'var(--op-t3)' }}>
          {rows.length} algorithms · severity derived from strength + deprecation + risk score (ADR-0003). Edit / create / deprecate are live + audited (platform-admin, algorithms.manage).
        </div>
      </div>

      {editing && <EditAlgorithmModal algo={editing} onClose={() => setEditing(null)} mut={updateMut} />}
      {deprecating && <DeprecateModal algo={deprecating} onClose={() => setDeprecating(null)} mut={updateMut} />}
      {creating && <CreateAlgorithmModal onClose={() => setCreating(false)} mut={createMut} />}
    </div>
  );
}
