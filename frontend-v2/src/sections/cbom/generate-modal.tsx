// Generate-CBOM modal — scope picker + optional name. Composes the shared Modal
// primitive (never hand-rolls an overlay). Scopes come from the same cbom-service
// /scopes endpoint that Settings → Scopes manages.
import { useState } from 'react';
import { useFeature } from '@vistasecurity/primitives/features';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useGenerate, useScopes } from './queries';

export function GenerateModal({ open, onClose, onGenerated }: {
  open: boolean;
  onClose: () => void;
  onGenerated: (artifactId: string) => void;
}) {
  const scopesQ = useScopes();
  const gen = useGenerate();
  // Generation and CycloneDX export are Core; signing + attestation layers come
  // from cbom-service/ee. Don't promise evidence this build can't produce.
  const evidenceEntitled = useFeature('cbom_signing');
  const [scopeId, setScopeId] = useState('');
  const [name, setName] = useState('');

  const scopes = scopesQ.data ?? [];
  // Default to the first scope once they load.
  const selected = scopeId || scopes[0]?.id || '';

  const submit = async () => {
    if (!selected) return;
    const res = await gen.mutateAsync({ scope_id: selected, name: name.trim() || undefined });
    onGenerated(res.artifact_id);
  };

  const err = gen.error instanceof Error ? gen.error.message : scopesQ.isError ? 'Failed to load scopes' : null;

  return (
    <Modal
      open={open}
      onClose={gen.isPending ? undefined : onClose}
      dismissible={!gen.isPending}
      size="md"
      tone="accent"
      icon="file-badge"
      eyebrow="CBOM"
      title="Generate CBOM artifact"
      description={`Snapshots every cryptographic component matching the chosen scope right now, into one immutable, content-hashed artifact.${evidenceEntitled ? ' Signed and compliance-attested by default.' : ''}`}
      primary={
        <button className="ui-btn accent" onClick={submit} disabled={!selected || gen.isPending}>
          {gen.isPending ? 'Generating…' : 'Generate'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={gen.isPending}>Cancel</button>}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : 'Each generate creates a new dated artifact — history is kept.'}
    >
      <ModalField label="Scope" hint="The boundary the artifact attests to. Manage scopes in Settings → Scopes.">
        <ModalSelect
          data-autofocus
          value={selected}
          onChange={(e) => setScopeId(e.target.value)}
          disabled={scopesQ.isLoading || gen.isPending}
        >
          {scopesQ.isLoading && <option>Loading scopes…</option>}
          {!scopesQ.isLoading && scopes.length === 0 && <option value="">No scopes available</option>}
          {scopes.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}{s.is_system ? ' (system)' : ''} · v{s.version}
            </option>
          ))}
        </ModalSelect>
      </ModalField>
      <ModalField label="Name" hint="Optional. For audit submissions, name it after the engagement — e.g. “Q2 2026 PCI Submission.”">
        <ModalInput
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Unnamed → “<scope> — <date>”"
          disabled={gen.isPending}
        />
      </ModalField>
    </Modal>
  );
}
