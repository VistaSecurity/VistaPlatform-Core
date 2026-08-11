// VISTA Operations — Catalog → Frameworks (sub-page).
// The compliance-engine published framework catalog: create/edit/publish/delete
// frameworks, expand to manage their controls, and open the measurement-rules
// builder per control. This is work — relocated UNCHANGED from the
// old in-page Catalog tab into its own left-rail sub-page.
import { Fragment, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Library, Pencil, Plus, Trash2, Send, Archive, ChevronRight, ChevronDown, ListTree } from 'lucide-react';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Tag, relTime } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { MeasurementRulesModal } from './measurement-rules-modal';

type AdminFramework = complianceEngineComponents['schemas']['PublishedFramework'];
type FrameworkInput = complianceEngineComponents['schemas']['PlatformFrameworkInput'];

const FW_STATUS_COLOR: Record<string, string> = { draft: 'var(--warn)', published: 'var(--ok)', archived: 'var(--neutral)' };

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : 'Action failed';
}

// Platform-admin framework catalog — all statuses (draft/published/archived), authored here.
function useAdminFrameworks() {
  return useQuery({
    queryKey: ['platform', 'admin-frameworks'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/admin/frameworks', {});
      if (error || !data) throw new Error('Failed to load frameworks');
      return data.frameworks ?? [];
    },
    staleTime: 60 * 1000,
  });
}

function useFrameworkMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'admin-frameworks'] });
  const create = useMutation({
    mutationFn: async (body: FrameworkInput) => {
      const { error } = await clients.compliance.POST('/admin/frameworks', { body });
      if (error) throw new Error('Create failed (platform-admin required)');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: FrameworkInput }) => {
      const { error } = await clients.compliance.PUT('/admin/frameworks/{id}', { params: { path: { id } }, body });
      if (error) throw new Error('Update failed (drafts only)');
    },
    onSuccess: invalidate,
  });
  const publish = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: 'published' | 'archived' }) => {
      const { error } = await clients.compliance.POST('/admin/frameworks/{id}/publish', { params: { path: { id } }, body: { status } });
      if (error) throw new Error('Status change failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.compliance.DELETE('/admin/frameworks/{id}', { params: { path: { id } } });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: invalidate,
  });
  return { create, update, publish, remove };
}

type AdminControl = complianceEngineComponents['schemas']['PublishedFrameworkControl'];
type ControlInput = complianceEngineComponents['schemas']['PlatformFrameworkControlInput'];
type ControlSeverity = 'Low' | 'Med' | 'High' | 'Critical';
const CONTROL_SEVERITY_COLOR: Record<string, string> = { Critical: 'var(--danger)', High: 'var(--warn-strong)', Med: 'var(--warn)', Low: 'var(--ok-lime)' };

function useControlMutations() {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform', 'admin-frameworks'] });
  const create = useMutation({
    mutationFn: async ({ frameworkId, body }: { frameworkId: string; body: ControlInput }) => {
      const { error } = await clients.compliance.POST('/admin/frameworks/{id}/controls', { params: { path: { id: frameworkId } }, body });
      if (error) throw new Error('Add control failed (platform-admin required)');
    },
    onSuccess: invalidate,
  });
  const update = useMutation({
    mutationFn: async ({ frameworkId, controlId, body }: { frameworkId: string; controlId: string; body: ControlInput }) => {
      const { error } = await clients.compliance.PUT('/admin/frameworks/{id}/controls/{controlId}', { params: { path: { id: frameworkId, controlId } }, body });
      if (error) throw new Error('Update control failed');
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async ({ frameworkId, controlId }: { frameworkId: string; controlId: string }) => {
      const { error } = await clients.compliance.DELETE('/admin/frameworks/{id}/controls/{controlId}', { params: { path: { id: frameworkId, controlId } } });
      if (error) throw new Error('Delete control failed');
    },
    onSuccess: invalidate,
  });
  return { create, update, remove };
}

function FrameworkFormModal({ framework, onClose, mut }: { framework: AdminFramework | null; onClose: () => void; mut: ReturnType<typeof useFrameworkMutations> }) {
  const editing = !!framework;
  const [code, setCode] = useState(framework?.code ?? '');
  const [name, setName] = useState(framework?.name ?? '');
  const [version, setVersion] = useState(framework?.version ?? '');
  const [organization, setOrganization] = useState(framework?.organization ?? '');
  const [description, setDescription] = useState(framework?.description ?? '');
  const invalid = !code.trim() || !name.trim() || !version.trim();

  const save = () => {
    const body: FrameworkInput = { code: code.trim(), name: name.trim(), version: version.trim(), organization, description };
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Framework updated' : 'Framework created (draft)'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) mut.update.mutate({ id: framework!.id, body }, opts);
    else mut.create.mutate(body, opts);
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit framework — ${framework!.name}` : 'New framework'}
      description={editing ? 'Only draft frameworks can be edited. Code, name and version are required.' : 'Creates a draft. Add controls, then publish to make it available to tenants.'}
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Code"><input value={code} onChange={(e) => setCode(e.target.value)} placeholder="e.g. PCI-DSS-4" style={modalInputStyle} /></ModalField>
      <ModalField label="Name"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. PCI-DSS v4.0" style={modalInputStyle} /></ModalField>
      <ModalField label="Version"><input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="e.g. 4.0" style={modalInputStyle} /></ModalField>
      <ModalField label="Organization"><input value={organization} onChange={(e) => setOrganization(e.target.value)} placeholder="e.g. PCI SSC" style={modalInputStyle} /></ModalField>
      <ModalField label="Description"><textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'var(--font-body)' }} /></ModalField>
    </Modal>
  );
}

function ControlFormModal({ frameworkId, control, onClose, mut }: { frameworkId: string; control: AdminControl | null; onClose: () => void; mut: ReturnType<typeof useControlMutations> }) {
  const editing = !!control;
  const [controlId, setControlId] = useState(control?.control_id ?? '');
  const [title, setTitle] = useState(control?.title ?? '');
  const [description, setDescription] = useState(control?.description ?? '');
  const [severity, setSeverity] = useState<ControlSeverity>((control?.baseline_severity as ControlSeverity) ?? 'Med');
  const [cryptoRelevant, setCryptoRelevant] = useState(control?.crypto_relevant ?? false);
  const invalid = !controlId.trim() || !title.trim();

  const save = () => {
    const body: ControlInput = { control_id: controlId.trim(), title: title.trim(), description, baseline_severity: severity, crypto_relevant: cryptoRelevant };
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Control updated' : 'Control added'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) mut.update.mutate({ frameworkId, controlId: control!.id, body }, opts);
    else mut.create.mutate({ frameworkId, body }, opts);
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit control — ${control!.control_id}` : 'New control'}
      description="Controls define what a framework checks. Add measurement rules to a control to make it evaluate (rule builder coming next)."
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Add control'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Control ID"><input value={controlId} onChange={(e) => setControlId(e.target.value)} placeholder="e.g. PCI 3.6" style={modalInputStyle} /></ModalField>
      <ModalField label="Title"><input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Control title" style={modalInputStyle} /></ModalField>
      <ModalField label="Baseline severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value as ControlSeverity)} style={modalInputStyle}>
          {(['Low', 'Med', 'High', 'Critical'] as ControlSeverity[]).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </ModalField>
      <ModalField label="Description"><textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'var(--font-body)' }} /></ModalField>
      <ModalField label="Cryptographically relevant">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={cryptoRelevant} onChange={(e) => setCryptoRelevant(e.target.checked)} />
          This control evaluates cryptographic posture
        </label>
      </ModalField>
    </Modal>
  );
}

type FwModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; framework: AdminFramework };
type ControlModalState = { kind: 'closed' } | { kind: 'create'; frameworkId: string } | { kind: 'edit'; frameworkId: string; control: AdminControl };

export function FrameworksPage() {
  const frameworksQ = useAdminFrameworks();
  const fwMut = useFrameworkMutations();
  const ctrlMut = useControlMutations();
  const [fwModal, setFwModal] = useState<FwModalState>({ kind: 'closed' });
  const [controlModal, setControlModal] = useState<ControlModalState>({ kind: 'closed' });
  const [rulesControl, setRulesControl] = useState<{ id: string; control_id: string; title: string } | null>(null);
  const [expandedFw, setExpandedFw] = useState<string | null>(null);

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
          <Library size={16} style={{ color: 'var(--op-t3)' }} />
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Compliance frameworks</div>
          <div style={{ flex: 1 }} />
          <button className="op-btn sm" onClick={() => setFwModal({ kind: 'create' })}><Plus size={14} />New framework</button>
        </div>
        <table className="op-table">
          <thead><tr><th>Framework</th><th>Version</th><th>Controls</th><th>Status</th><th>Updated</th><th /></tr></thead>
          <tbody>
            {(frameworksQ.data ?? []).map((f) => {
              const status = f.status ?? 'draft';
              const published = status === 'published';
              const expanded = expandedFw === f.id;
              const controls = f.controls ?? [];
              return (
                <Fragment key={f.id}>
                  <tr>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button className="op-btn icon sm" title={expanded ? 'Hide controls' : 'Manage controls'} onClick={() => setExpandedFw(expanded ? null : f.id)}>
                          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                        </button>
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--op-t1)' }}>{f.name}</div>
                          <div className="mono" style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>{f.code}{f.organization ? ` · ${f.organization}` : ''}</div>
                        </div>
                      </div>
                    </td>
                    <td className="mono t-muted">{f.version}</td>
                    <td className="mono t-muted">{f.controls_count ?? 0}</td>
                    <td><Tag color={FW_STATUS_COLOR[status] ?? 'var(--neutral)'}><span style={{ textTransform: 'capitalize' }}>{status}</span></Tag></td>
                    <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(f.updated_at)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                        {status === 'draft' && <button className="op-btn icon sm" title="Edit metadata" onClick={() => setFwModal({ kind: 'edit', framework: f })}><Pencil size={13} /></button>}
                        {published ? (
                          <button className="op-btn icon sm" title="Unpublish (archive)" disabled={fwMut.publish.isPending} onClick={() => fwMut.publish.mutate({ id: f.id, status: 'archived' }, { onSuccess: () => toast.success('Unpublished'), onError: (e) => toast.error(errMsg(e)) })}><Archive size={13} /></button>
                        ) : (
                          <button className="op-btn icon sm" title="Publish" disabled={fwMut.publish.isPending} onClick={() => fwMut.publish.mutate({ id: f.id, status: 'published' }, { onSuccess: () => toast.success('Published — tenants can now activate it'), onError: (e) => toast.error(errMsg(e)) })}><Send size={13} /></button>
                        )}
                        <button className="op-btn icon sm" title="Delete" disabled={fwMut.remove.isPending} onClick={() => { if (window.confirm(`Delete framework "${f.name}"? This cannot be undone.`)) fwMut.remove.mutate(f.id, { onSuccess: () => toast.success('Deleted'), onError: (e) => toast.error(errMsg(e)) }); }}><Trash2 size={13} /></button>
                      </div>
                    </td>
                  </tr>
                  {expanded && (
                    <tr>
                      <td colSpan={6} style={{ background: 'var(--op-panel2)', padding: 0 }}>
                        <div style={{ padding: '12px 16px 16px 46px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                            <ListTree size={14} style={{ color: 'var(--op-t3)' }} />
                            <span style={{ fontWeight: 600, fontSize: 12.5, color: 'var(--op-t1)' }}>Controls</span>
                            <span className="mono" style={{ fontSize: 11, color: 'var(--op-t3)' }}>{controls.length}</span>
                            <div style={{ flex: 1 }} />
                            <button className="op-btn sm" onClick={() => setControlModal({ kind: 'create', frameworkId: f.id })}><Plus size={13} />Add control</button>
                          </div>
                          {controls.length === 0 ? (
                            <div style={{ fontSize: 12, color: 'var(--op-t3)', padding: '6px 0' }}>No controls yet. Add controls so this framework evaluates something.</div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                              {controls.map((ctrl) => (
                                <div key={ctrl.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', borderRadius: 8, border: '1px solid var(--op-border)', background: 'var(--op-panel)' }}>
                                  <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--op-t2)', minWidth: 64 }}>{ctrl.control_id}</span>
                                  <span style={{ flex: 1, fontSize: 12.5, color: 'var(--op-t1)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ctrl.title}</span>
                                  {ctrl.crypto_relevant && <Tag color="var(--info)">crypto</Tag>}
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: CONTROL_SEVERITY_COLOR[ctrl.baseline_severity] ?? 'var(--op-t3)' }}>
                                    <span style={{ width: 6, height: 6, borderRadius: 50, background: CONTROL_SEVERITY_COLOR[ctrl.baseline_severity] ?? 'var(--op-t3)' }} />{ctrl.baseline_severity}
                                  </span>
                                  <button className="op-btn sm ghost" title="Manage measurement rules" onClick={() => setRulesControl({ id: ctrl.id, control_id: ctrl.control_id, title: ctrl.title })}>Rules</button>
                                  <button className="op-btn icon sm" title="Edit control" onClick={() => setControlModal({ kind: 'edit', frameworkId: f.id, control: ctrl })}><Pencil size={12} /></button>
                                  <button className="op-btn icon sm" title="Delete control" disabled={ctrlMut.remove.isPending} onClick={() => { if (window.confirm(`Delete control "${ctrl.control_id}"?`)) ctrlMut.remove.mutate({ frameworkId: f.id, controlId: ctrl.id }, { onSuccess: () => toast.success('Control deleted'), onError: (e) => toast.error(errMsg(e)) }); }}><Trash2 size={12} /></button>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {frameworksQ.isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading frameworks…</td></tr>}
            {frameworksQ.isError && !frameworksQ.isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load frameworks. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => frameworksQ.refetch()}>Retry</button></td></tr>}
            {!frameworksQ.isLoading && !frameworksQ.isError && (frameworksQ.data ?? []).length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No frameworks yet. Create one to get started.</td></tr>}
          </tbody>
        </table>
        <div style={{ padding: '9px 16px', borderTop: '1px solid var(--op-border)', fontSize: 11.5, color: 'var(--op-t3)' }}>
          Create a draft, expand a framework to manage its controls, then publish to make it available to tenants — publishing re-evaluates posture across tenants (ADR-0014). Measurement rule builder (what each control checks) lands next.
        </div>
      </div>

      {fwModal.kind !== 'closed' && (
        <FrameworkFormModal framework={fwModal.kind === 'edit' ? fwModal.framework : null} onClose={() => setFwModal({ kind: 'closed' })} mut={fwMut} />
      )}
      {controlModal.kind !== 'closed' && (
        <ControlFormModal frameworkId={controlModal.frameworkId} control={controlModal.kind === 'edit' ? controlModal.control : null} onClose={() => setControlModal({ kind: 'closed' })} mut={ctrlMut} />
      )}
      {rulesControl && (
        <MeasurementRulesModal control={rulesControl} onClose={() => setRulesControl(null)} />
      )}
    </div>
  );
}
