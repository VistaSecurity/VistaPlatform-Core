// VISTA Operations — Audit ▸ SIEM. Ported from the v1 admin-ui
// SIEMIntegrationsPanel: supported-platform catalog + configured integrations
// with add/edit/test/delete. Typed via clients.audit (GET /siem/types,
// GET/POST /siem/integrations, PUT/DELETE /siem/integrations/{id},
// POST /siem/integrations/test). `config` is a loose blob on the contract, so
// the form reads/writes its known fields (url, auth_type, token, format, batch).
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { CloudUpload, Plus, Pencil, Trash2, FlaskConical, Lock } from 'lucide-react';
import { Tag } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { useSiemTypes, useSiemIntegrations, useSiemMutations, siemEditionUnavailable, errMsg, type SIEMIntegration, type SIEMIntegrationInput } from './audit-queries';

// A supported-platform catalog entry from GET /siem/types. The contract types
// it loosely (id/name/description blob), so we read it via Record access.
type SiemType = NonNullable<ReturnType<typeof useSiemTypes>['data']>[number];

interface SiemForm {
  name: string;
  type: string;
  enabled: boolean;
  url: string;
  auth_type: string;
  auth_token: string;
  format: string;
  batch_size: number;
  flush_interval_sec: number;
}

const DEFAULT_FORM: SiemForm = {
  name: '', type: 'splunk', enabled: true, url: '', auth_type: 'bearer', auth_token: '', format: 'json', batch_size: 100, flush_interval_sec: 30,
};

function cfg(i: SIEMIntegration, key: string): unknown {
  return (i.config as Record<string, unknown> | undefined)?.[key];
}

function buildPayload(f: SiemForm): SIEMIntegrationInput {
  const config: Record<string, unknown> = {
    url: f.url, auth_type: f.auth_type, format: f.format, batch_size: f.batch_size, flush_interval_sec: f.flush_interval_sec,
  };
  if (f.auth_token) {
    if (f.auth_type === 'api_key') config.api_key = f.auth_token;
    else config.auth_token = f.auth_token;
  }
  return { name: f.name, type: f.type, enabled: f.enabled, config };
}

// Fallback option set when the live /siem/types catalog is empty/unavailable.
const FALLBACK_TYPE_OPTIONS: { id: string; name: string }[] = [
  { id: 'splunk', name: 'Splunk' },
  { id: 'datadog', name: 'Datadog' },
  { id: 'elastic', name: 'Elastic' },
  { id: 'generic_webhook', name: 'Generic Webhook' },
];

function SiemModal({ integration, types, onClose, mut }: { integration: SIEMIntegration | null; types: SiemType[]; onClose: () => void; mut: ReturnType<typeof useSiemMutations> }) {
  const editing = !!integration;
  // Drive the type selector from the fetched catalog; fall back to a static set
  // when the catalog is empty. Always include the current value as an option so
  // editing an integration whose type isn't in the catalog still renders.
  const typeOptions = useMemo(() => {
    const fromCatalog = types
      .map((t) => ({ id: String((t as Record<string, unknown>).id ?? ''), name: String((t as Record<string, unknown>).name ?? (t as Record<string, unknown>).id ?? '') }))
      .filter((o) => o.id);
    const base = fromCatalog.length > 0 ? fromCatalog : FALLBACK_TYPE_OPTIONS;
    if (integration && !base.some((o) => o.id === integration.type)) {
      return [...base, { id: integration.type, name: integration.type }];
    }
    return base;
  }, [types, integration]);
  const [form, setForm] = useState<SiemForm>(() => integration ? {
    name: integration.name,
    type: integration.type,
    enabled: integration.enabled,
    url: String(cfg(integration, 'url') ?? ''),
    auth_type: String(cfg(integration, 'auth_type') ?? 'bearer'),
    auth_token: '',
    format: String(cfg(integration, 'format') ?? 'json'),
    batch_size: Number(cfg(integration, 'batch_size') ?? 100),
    flush_interval_sec: Number(cfg(integration, 'flush_interval_sec') ?? 30),
  } : { ...DEFAULT_FORM, type: typeOptions[0]?.id ?? DEFAULT_FORM.type });
  const set = <K extends keyof SiemForm>(k: K, v: SiemForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const invalid = !form.name.trim() || !form.url.trim();

  const save = () => {
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Integration updated' : 'Integration created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) mut.update.mutate({ id: integration!.id, body: buildPayload(form) }, opts);
    else mut.create.mutate(buildPayload(form), opts);
  };

  const test = () =>
    mut.test.mutate(buildPayload(form), {
      onSuccess: () => toast.success('Connection test successful'),
      onError: (e) => toast.error(errMsg(e, 'Connection test failed')),
    });

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit SIEM integration — ${integration!.name}` : 'Add SIEM integration'}
      size="lg"
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Name"><input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. Production Splunk" style={modalInputStyle} /></ModalField>
        <ModalField label="Platform type">
          <select value={form.type} onChange={(e) => set('type', e.target.value)} style={modalInputStyle}>
            {typeOptions.map((o) => (
              <option key={o.id} value={o.id}>{o.name}</option>
            ))}
          </select>
        </ModalField>
      </div>
      <ModalField label="Endpoint URL"><input type="url" value={form.url} onChange={(e) => set('url', e.target.value)} placeholder="https://…" style={modalInputStyle} /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Auth type">
          <select value={form.auth_type} onChange={(e) => set('auth_type', e.target.value)} style={modalInputStyle}>
            <option value="bearer">Bearer Token</option>
            <option value="api_key">API Key</option>
            <option value="basic">Basic Auth</option>
          </select>
        </ModalField>
        <ModalField label="Token / Key"><input type="password" value={form.auth_token} onChange={(e) => set('auth_token', e.target.value)} placeholder={editing ? '•••••••• (unchanged)' : 'Enter token'} style={modalInputStyle} /></ModalField>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <ModalField label="Format">
          <select value={form.format} onChange={(e) => set('format', e.target.value)} style={modalInputStyle}>
            <option value="json">JSON</option>
            <option value="cef">CEF</option>
            <option value="leef">LEEF</option>
          </select>
        </ModalField>
        <ModalField label="Batch size"><input type="number" min={1} value={form.batch_size} onChange={(e) => set('batch_size', parseInt(e.target.value) || 100)} style={modalInputStyle} /></ModalField>
        <ModalField label="Flush (sec)"><input type="number" min={5} value={form.flush_interval_sec} onChange={(e) => set('flush_interval_sec', parseInt(e.target.value) || 30)} style={modalInputStyle} /></ModalField>
      </div>
      <ModalField label="Status">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />Enabled
        </label>
      </ModalField>
      <div>
        <button className="op-btn sm" disabled={mut.test.isPending || invalid} onClick={test}><FlaskConical size={13} />{mut.test.isPending ? 'Testing…' : 'Test connection'}</button>
      </div>
    </Modal>
  );
}

type ModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; integration: SIEMIntegration };

export function SiemPage() {
  const typesQ = useSiemTypes();
  const integrationsQ = useSiemIntegrations();
  const mut = useSiemMutations();
  const [modal, setModal] = useState<ModalState>({ kind: 'closed' });

  const types = typesQ.data ?? [];
  const integrations = integrationsQ.data ?? [];
  // Core build: /siem/** is not mounted at all (audit-service/ee/siemexport).
  // Render an edition notice rather than "couldn't load" + a Retry that can
  // never succeed, and drop every CRUD affordance.
  const editionUnavailable = siemEditionUnavailable(typesQ, integrationsQ);

  const typeName = (t: string): string => {
    const found = types.find((x) => (x as Record<string, unknown>).id === t);
    return (found?.name as string) ?? t;
  };

  const onTest = (i: SIEMIntegration) => {
    const body: SIEMIntegrationInput = { name: i.name, type: i.type, enabled: i.enabled, config: i.config };
    mut.test.mutate(body, { onSuccess: () => toast.success('Connection test successful'), onError: (e) => toast.error(errMsg(e, 'Connection test failed')) });
  };

  const remove = (i: SIEMIntegration) => {
    if (!window.confirm(`Delete integration "${i.name}"?`)) return;
    mut.remove.mutate(i.id, { onSuccess: () => toast.success('Integration deleted'), onError: (e) => toast.error(errMsg(e)) });
  };

  if (editionUnavailable) {
    return (
      <div className="op-fade" style={{ padding: '20px 24px 40px' }}>
        <div className="op-panel" style={{ padding: '44px 28px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <Lock size={26} style={{ color: 'var(--op-accent)' }} />
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>SIEM export is an Enterprise feature</div>
          <div className="t-muted" style={{ fontSize: 12.5, maxWidth: 460, lineHeight: 1.6 }}>
            This deployment runs the Core edition of audit-service, which does not include the
            outbound SIEM forwarder. Audit events are still captured, retained, searchable, and
            exportable from Activity Log &mdash; only forwarding them to Splunk, Datadog, or Elastic
            is gated. Run the Enterprise build of audit-service to configure integrations here.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* supported platforms */}
      <div className="op-panel" style={{ padding: '14px 16px' }}>
        <div className="op-eyebrow" style={{ marginBottom: 12 }}>Supported platforms</div>
        {types.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>{typesQ.isLoading ? 'Loading…' : 'No platform catalog available.'}</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
            {types.map((t, idx) => {
              const tt = t as Record<string, unknown>;
              return (
                <div key={String(tt.id ?? idx)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border)', background: 'var(--op-panel2)' }}>
                  <CloudUpload size={18} style={{ color: 'var(--op-accent)', flex: 'none' }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 12.5, color: 'var(--op-t1)' }}>{String(tt.name ?? tt.id)}</div>
                    {!!tt.description && <div className="t-muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{String(tt.description)}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* configured integrations */}
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <CloudUpload size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Configured integrations</span>
          <div style={{ flex: 1 }} />
          <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />Add integration</button>
        </div>

        {integrationsQ.isLoading && <div style={{ padding: 50, textAlign: 'center', color: 'var(--op-t3)' }}>Loading integrations…</div>}
        {integrationsQ.isError && !integrationsQ.isLoading && (
          <div style={{ padding: 50, textAlign: 'center', color: 'var(--op-t3)' }}>Couldn't load integrations. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => integrationsQ.refetch()}>Retry</button></div>
        )}
        {!integrationsQ.isLoading && !integrationsQ.isError && integrations.length === 0 && (
          <div style={{ padding: '40px 24px', textAlign: 'center', color: 'var(--op-t3)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <CloudUpload size={26} style={{ color: 'var(--op-t3)' }} />
            <span>No SIEM integrations configured</span>
            <span style={{ fontSize: 11.5 }}>Add one to start forwarding audit logs to your SIEM platform.</span>
          </div>
        )}
        {!integrationsQ.isLoading && !integrationsQ.isError && integrations.length > 0 && (
          <div>
            {integrations.map((i) => (
              <div key={i.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px', borderBottom: '1px solid var(--op-border)' }}>
                <CloudUpload size={18} style={{ color: 'var(--op-t3)', flex: 'none' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, color: 'var(--op-t1)', fontSize: 13 }}>{i.name}</div>
                  <div className="t-muted" style={{ fontSize: 11.5, marginTop: 2 }}>{typeName(i.type)} · {String(cfg(i, 'url') ?? '—')}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
                    <Tag color={i.enabled ? 'var(--ok)' : 'var(--neutral)'}>{i.enabled ? 'Active' : 'Disabled'}</Tag>
                    <span className="t-muted" style={{ fontSize: 11 }}>Format: {String(cfg(i, 'format') ?? 'json')}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="op-btn sm" disabled={mut.test.isPending} onClick={() => onTest(i)}><FlaskConical size={13} />Test</button>
                  <button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', integration: i })}><Pencil size={13} /></button>
                  <button className="op-btn icon sm" title="Delete" disabled={mut.remove.isPending} onClick={() => remove(i)}><Trash2 size={13} /></button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {modal.kind !== 'closed' && (
        <SiemModal integration={modal.kind === 'edit' ? modal.integration : null} types={types} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}
