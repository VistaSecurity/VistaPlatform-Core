// Generate-artifact modal — kind picker + scope picker + optional name.
// Composes the shared Modal primitive (never hand-rolls an overlay). Scopes
// come from the same cbom-service /scopes endpoint that Settings → Scopes
// manages.
import { useState } from 'react';
import { useFeature } from '@vistasecurity/primitives/features';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { ARTIFACT_KINDS } from './kit';
import { useGenerate, useScopes, type ArtifactKind } from './queries';

/**
 * The kind picker: four cards, each with a one-line statement of what the
 * artifact CONTAINS.
 *
 * Cards rather than a `<select>` because the choice is not obvious from the
 * names — "HBOM" tells a user nothing, and a dropdown has nowhere to put the
 * sentence that does. The blurb is the control's whole reason for existing: a
 * customer who picks the wrong kind finds out when an auditor opens the file.
 */
function KindPicker({ value, onChange, disabled }: {
  value: ArtifactKind;
  onChange: (k: ArtifactKind) => void;
  disabled?: boolean;
}) {
  return (
    <div role="radiogroup" aria-label="Artifact kind" style={{ display: 'grid', gap: 7 }}>
      {ARTIFACT_KINDS.map((k) => {
        const active = k.key === value;
        return (
          <button
            key={k.key}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled}
            onClick={() => onChange(k.key)}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
              width: '100%',
              textAlign: 'left',
              padding: '10px 12px',
              borderRadius: 10,
              cursor: disabled ? 'default' : 'pointer',
              border: `1px solid ${active ? k.tone : 'var(--app-border)'}`,
              background: active ? `color-mix(in srgb, ${k.tone} 9%, transparent)` : 'var(--app-panel2)',
              opacity: disabled ? 0.6 : 1,
            }}
          >
            <span style={{ flex: 'none', color: k.tone, paddingTop: 1 }}>
              <Icon name={k.icon} size={16} />
            </span>
            <span style={{ flex: 1, minWidth: 0 }}>
              <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{k.label}</span>
              <span style={{ display: 'block', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5, marginTop: 2 }}>{k.blurb}</span>
            </span>
            {active && (
              <span style={{ flex: 'none', color: k.tone, paddingTop: 1 }}>
                <Icon name="check" size={14} />
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

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
  // `cbom` is the default here for the same reason the server defaults to it:
  // this page was the CBOM page, and an existing user opening it to do what
  // they have always done should not have to re-choose it.
  const [kind, setKind] = useState<ArtifactKind>('cbom');
  const [scopeId, setScopeId] = useState('');
  const [name, setName] = useState('');

  const scopes = scopesQ.data ?? [];
  // Default to the first scope once they load.
  const selected = scopeId || scopes[0]?.id || '';

  const submit = async () => {
    if (!selected) return;
    const res = await gen.mutateAsync({ scope_id: selected, kind, name: name.trim() || undefined });
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
      eyebrow="Bill of materials"
      title="Generate artifact"
      description={`Snapshots everything matching the chosen scope right now, into one immutable, content-hashed artifact.${evidenceEntitled ? ' Signed and compliance-attested by default.' : ''}`}
      primary={
        <button className="ui-btn accent" onClick={() => void submit()} disabled={!selected || gen.isPending}>
          {gen.isPending ? 'Generating…' : 'Generate'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={gen.isPending}>Cancel</button>}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : 'Each generate creates a new dated artifact — history is kept.'}
    >
      <ModalField label="Kind" hint="What the artifact contains. All four share the same scope, hash, signature and comparison.">
        <KindPicker value={kind} onChange={setKind} disabled={gen.isPending} />
      </ModalField>
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
