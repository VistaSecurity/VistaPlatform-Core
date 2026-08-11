// Scope editing modals — create / edit (name, description, predicate builder)
// and delete confirmation. Predicate builder exposes the most-used clause
// fields (environment, asset type, tags) per include/exclude as comma-
// separated lists; the full PredicateClause shape stays representable because
// unedited fields are carried through untouched on edit.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput } from '../../components/ui';
import type { components as CbomComponents } from '@vistasecurity/api-contract';

type Scope = CbomComponents['schemas']['Scope'];
type Predicate = CbomComponents['schemas']['Predicate'];
type PredicateClause = CbomComponents['schemas']['PredicateClause'];

const CLAUSE_FIELDS = [
  { key: 'environment', label: 'Environments', hint: 'e.g. production, prod' },
  { key: 'asset_type', label: 'Asset types', hint: 'e.g. server, load_balancer' },
  { key: 'tags_any_of', label: 'Tags (any of)', hint: 'case-insensitive tag match' },
] as const;
type ClauseKey = (typeof CLAUSE_FIELDS)[number]['key'];

function toCsv(v?: string[]): string {
  return (v ?? []).join(', ');
}
function fromCsv(s: string): string[] | undefined {
  const parts = s.split(',').map((x) => x.trim()).filter(Boolean);
  return parts.length ? parts : undefined;
}

function buildClause(base: PredicateClause | undefined, edited: Record<ClauseKey, string>): PredicateClause | undefined {
  // carry through clause fields the builder doesn't expose
  const out: PredicateClause = { ...(base ?? {}) };
  for (const f of CLAUSE_FIELDS) {
    const arr = fromCsv(edited[f.key]);
    if (arr) out[f.key] = arr;
    else delete out[f.key];
  }
  return Object.keys(out).length ? out : undefined;
}

function clauseState(c?: PredicateClause): Record<ClauseKey, string> {
  return {
    environment: toCsv(c?.environment),
    asset_type: toCsv(c?.asset_type),
    tags_any_of: toCsv(c?.tags_any_of),
  };
}

function ClauseEditor({ title, value, onChange }: {
  title: string;
  value: Record<ClauseKey, string>;
  onChange: (v: Record<ClauseKey, string>) => void;
}) {
  return (
    <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, padding: '13px 14px 2px', marginBottom: 14 }}>
      <div className="eyebrow-app" style={{ marginBottom: 10 }}>{title}</div>
      {CLAUSE_FIELDS.map((f) => (
        <ModalField key={f.key} label={f.label} hint={f.hint}>
          <ModalInput
            value={value[f.key]}
            placeholder="comma-separated; empty = no filter"
            onChange={(e) => onChange({ ...value, [f.key]: e.target.value })}
          />
        </ModalField>
      ))}
    </div>
  );
}

export function ScopeEditModal({ scope, open, onClose }: { scope: Scope | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = !!scope;
  const [name, setName] = useState(scope?.name ?? '');
  const [description, setDescription] = useState(scope?.description ?? '');
  const [include, setInclude] = useState(clauseState(scope?.predicate?.include));
  const [exclude, setExclude] = useState(clauseState(scope?.predicate?.exclude));

  const mutation = useMutation({
    mutationFn: async () => {
      const predicate: Predicate = {};
      const inc = buildClause(scope?.predicate?.include, include);
      const exc = buildClause(scope?.predicate?.exclude, exclude);
      if (inc) predicate.include = inc;
      if (exc) predicate.exclude = exc;
      const body = { name: name.trim(), description: description.trim() || undefined, predicate };
      if (isEdit) {
        const { error, response } = await clients.cbom.PUT('/scopes/{id}', { params: { path: { id: scope.id } }, body });
        if (error || !response.ok) throw new Error(typeof error === 'object' && error && 'error' in error ? String((error as { error: unknown }).error) : 'Failed to update the scope');
      } else {
        const { error, response } = await clients.cbom.POST('/scopes', { body });
        if (error || !response.ok) throw new Error(typeof error === 'object' && error && 'error' in error ? String((error as { error: unknown }).error) : 'Failed to create the scope');
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'scopes'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="crop"
      eyebrow="Policies · Scopes"
      title={isEdit ? `Edit scope — ${scope.name}` : 'New scope'}
      description={isEdit
        ? 'Changing the name or predicate bumps the scope version; existing CBOM artifacts keep the version they captured.'
        : 'A named, versioned asset boundary. CBOM artifacts generated against it record the exact predicate in force.'}
      primary={
        <button className="ui-btn sm accent" disabled={!name.trim() || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create scope'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Name">
        <ModalInput value={name} data-autofocus onChange={(e) => setName(e.target.value)} placeholder="e.g. PCI cardholder environment" />
      </ModalField>
      <ModalField label="Description" hint="Optional — shown in the scope list.">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What boundary does this scope attest to?" />
      </ModalField>
      <ClauseEditor title="Include — assets must match" value={include} onChange={setInclude} />
      <ClauseEditor title="Exclude — assets must NOT match" value={exclude} onChange={setExclude} />
      <p style={{ margin: '0 0 10px', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
        Empty include + exclude matches every asset in the tenant. Other clause fields (ownership, status, business unit, region, risk) are preserved on edit and arrive in the builder next.
      </p>
    </Modal>
  );
}

export function ScopeDeleteModal({ scope, open, onClose }: { scope: Scope | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      if (!scope) return;
      const { error, response } = await clients.cbom.DELETE('/scopes/{id}', { params: { path: { id: scope.id } } });
      if (error || !response.ok) throw new Error('Failed to delete the scope');
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'scopes'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="sm"
      tone="danger"
      icon="alert-triangle"
      eyebrow="Policies · Scopes"
      title={`Delete scope — ${scope?.name ?? ''}`}
      description="The scope is soft-deleted: CBOM artifacts that referenced it keep their snapshot and show the scope as deleted instead of breaking."
      primary={
        <button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Deleting…' : 'Delete scope'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    />
  );
}
