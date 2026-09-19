// Create / edit an asset — driven by the class registry (ADR-0006 D8).
//
// The form used to be ten hand-written fields over the flat `network_assets`
// row. Under ADR-0002 an asset is a configuration item: its CLASS decides which
// attributes it has, its IDENTIFIERS are what make it one thing rather than
// several, and a port is an endpoint rather than a column. So the class picker
// comes first and the rest of the form follows from it — a server offers
// operating system and serial, an S3 bucket offers provider and account, and
// neither list is written down in this file.
import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { Asset, AssetInput } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import {
  ClassAttributeFields, ClassPicker, IdentifierEditor, attributesToValues,
  buildAttributes, isServiceBranch, type IdentifierDraft,
} from './class-picker';

const ENVIRONMENTS = ['production', 'staging', 'development', 'test'];

type TagRow = { key: string; value: string };

function tagsToRows(tags: unknown): TagRow[] {
  if (tags && typeof tags === 'object' && !Array.isArray(tags)) {
    return Object.entries(tags as Record<string, unknown>).map(([key, value]) => ({
      key,
      value: typeof value === 'string' ? value : JSON.stringify(value),
    }));
  }
  if (Array.isArray(tags)) return (tags as unknown[]).map((t) => ({ key: String(t), value: '' }));
  return [];
}

/**
 * Every identifier an existing asset carries, each carrying its source.
 *
 * ALL of them, including the collector-minted ones this used to filter out. The
 * editor locks the rows a person may not retire; dropping them here instead did
 * two wrong things at once — it showed the asset as having fewer ways of being
 * known than it has, and it left them out of the `identifiers` array on save,
 * which (now that the server honours that array) reads as a request to remove
 * them. They are kept either way, but asking is not nothing: the server answers
 * with a "kept" report, and a client that did not show it would be quietly
 * asking to delete facts on every save.
 */
export function identifiersToRows(asset: Asset | null | undefined): IdentifierDraft[] {
  return (asset?.identifiers ?? []).map((i) => ({
    kind: i.kind,
    value: i.value,
    sourceKind: i.source_kind,
    scope: i.scope,
  }));
}

export type IdentifierChange = { kind: string; value: string; reason?: string };

/**
 * What to say when the server kept an identifier the save asked to remove.
 *
 * Saying nothing would be the defect: the row disappears from the form, the
 * toast says "saved", and the identifier is still there on the next read. The
 * server sends its reason; this repeats it rather than inventing one.
 */
export function keptIdentifiersMessage(kept: IdentifierChange[]): string {
  if (kept.length === 0) return '';
  const listed = kept.slice(0, 3).map((k) => `${k.kind} ${k.value}`).join(', ');
  const more = kept.length > 3 ? `, and ${kept.length - 3} more` : '';
  const why = kept[0].reason ? ` — ${kept[0].reason}` : '';
  return kept.length === 1
    ? `Kept ${listed}${why}`
    : `Kept ${kept.length} identifiers: ${listed}${more}${why}`;
}

/**
 * The message for a refused identifier edit.
 *
 * An identifier that already belongs to another asset is a MERGE QUESTION, not
 * a validation error, and the server has already opened the proposal by the
 * time it answers 409 — so the message must send the operator to Approvals
 * rather than leave them retyping a value that was never wrong.
 */
export function identifierUpdateError(error: unknown): string {
  const e = error as { message?: string; error?: string; merge_proposal_id?: string } | undefined;
  const base = e?.message ?? e?.error ?? 'Failed to update asset';
  if (e?.merge_proposal_id) {
    return `${base} Review it in Discovery → Approvals; nothing was merged.`;
  }
  return base;
}

/**
 * What the form will not let you save, and why.
 *
 * The floor is ADR-0002's: an asset is never created with no identifier, because
 * an asset nothing can be recognised by can never be matched to a later sighting
 * — it becomes a duplicate on the next scan. A declared SERVICE is the one
 * legitimate exception and it has its own requirement: a name, which becomes its
 * `name` identifier.
 */
export function validateAssetForm(input: {
  classKey: string;
  displayName: string;
  identifiers: IdentifierDraft[];
  metadataError: string | null;
}): string | null {
  if (!input.classKey) return 'Pick a class first — it decides which fields this asset has.';
  const filled = input.identifiers.filter((i) => i.value.trim() !== '');
  if (isServiceBranch(input.classKey)) {
    if (!input.displayName.trim()) {
      return 'A service is identified by its name, so a name is required.';
    }
  } else if (filled.length === 0) {
    return 'Add at least one identifier — a hostname, FQDN, IP or serial. Without one this asset can never be matched to a later sighting.';
  }
  if (input.metadataError) return input.metadataError;
  return null;
}

export function AssetFormModal({ open, asset, onClose, onSaved }: {
  open: boolean;
  /** Present → edit mode; absent/null → create mode. */
  asset?: Asset | null;
  onClose: () => void;
  onSaved?: (a: Asset) => void;
}) {
  const isEdit = !!asset?.id;
  const qc = useQueryClient();

  const [classKey, setClassKey] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [identifiers, setIdentifiers] = useState<IdentifierDraft[]>([]);
  const [attributes, setAttributes] = useState<Record<string, string>>({});
  const [environment, setEnvironment] = useState('');
  const [supportGroup, setSupportGroup] = useState('');
  const [businessUnit, setBusinessUnit] = useState('');
  const [ownerEmail, setOwnerEmail] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState<TagRow[]>([]);
  const [metadataText, setMetadataText] = useState('{}');

  // (Re)hydrate from the target asset whenever it changes or the modal reopens.
  useEffect(() => {
    setClassKey(asset?.class_key ?? '');
    setDisplayName(asset?.display_name ?? '');
    setIdentifiers(identifiersToRows(asset));
    setAttributes(attributesToValues(asset?.attributes));
    setEnvironment(asset?.environment ?? '');
    setSupportGroup(asset?.support_group ?? '');
    setBusinessUnit(asset?.business_unit ?? '');
    setOwnerEmail(asset?.owner_email ?? '');
    setDescription(asset?.description ?? '');
    setTags(tagsToRows(asset?.tags));
    setMetadataText(JSON.stringify((asset?.metadata as object) ?? {}, null, 2));
  }, [asset, open]);

  const meta = useMemo<{ value: Record<string, unknown> | null; error: string | null }>(() => {
    if (!metadataText.trim()) return { value: {}, error: null };
    try {
      const v: unknown = JSON.parse(metadataText);
      if (typeof v !== 'object' || Array.isArray(v) || v === null) return { value: null, error: 'Metadata must be a JSON object' };
      return { value: v as Record<string, unknown>, error: null };
    } catch {
      return { value: null, error: 'Invalid JSON' };
    }
  }, [metadataText]);

  const problem = validateAssetForm({ classKey, displayName, identifiers, metadataError: meta.error });
  const serviceBranch = isServiceBranch(classKey);

  const save = useMutation({
    mutationFn: async (): Promise<{ asset?: Asset; observationID?: string; kept: IdentifierChange[] }> => {
      const tagsObj: Record<string, unknown> = {};
      tags.forEach(({ key, value }) => { if (key.trim()) tagsObj[key.trim()] = value; });
      const body: AssetInput = {
        class_key: classKey,
        display_name: displayName.trim() || undefined,
        // The DESIRED set, locked rows included: on update, an identifier left
        // out of this array is a request to retire it, and nothing on this form
        // is a request to retire a fact a collector recorded. `scope` goes back
        // as the server gave it, so a hostname keeps the segment it was scoped
        // to rather than being re-scoped by whatever segment this edit resolves.
        identifiers: identifiers
          .filter((i) => i.value.trim() !== '')
          .map((i) => ({ kind: i.kind, value: i.value.trim(), ...(i.scope ? { scope: i.scope } : {}) })),
        attributes: buildAttributes(classKey, attributes),
        support_group: supportGroup.trim() || undefined,
        environment: environment || undefined,
        business_unit: businessUnit.trim() || undefined,
        owner_email: ownerEmail.trim() || undefined,
        description: description.trim() || undefined,
        tags: tagsObj,
        metadata: meta.value ?? {},
      };
      if (isEdit) {
        const { data, error } = await clients.inventory.PUT('/infrastructure-assets/{id}', {
          params: { path: { id: asset!.id } }, body,
        });
        if (error || !data) throw new Error(identifierUpdateError(error));
        // What the server DID to the identifiers, which is not always what was
        // asked. A kept identifier reported as removed would be a lie the next
        // read exposes.
        return { asset: data.asset, kept: data.identifiers?.kept ?? [] };
      }
      const { data, error } = await clients.inventory.POST('/infrastructure-assets', { body });
      if (error || !data) throw new Error('Failed to create asset');
      if (!('asset' in data)) {
        if (!data.observation_id) throw new Error('The server did not return an asset or retained observation');
        return { observationID: data.observation_id, kept: [] };
      }
      return { asset: data.asset, kept: [] };
    },
    onSuccess: ({ asset: a, observationID, kept }) => {
      void qc.invalidateQueries({ queryKey: ['inventory'] });
      void qc.invalidateQueries({ queryKey: ['identity-summary'] });
      if (observationID) {
        void qc.invalidateQueries({ queryKey: ['identity-observations'] });
        toast('Evidence saved. Review it in Discovery → Observations to establish its identity.', { duration: 7000 });
        onClose();
        return;
      }
      if (!a) return;
      void qc.invalidateQueries({ queryKey: ['asset-detail', a.id] });
      void qc.invalidateQueries({ queryKey: ['asset-configs', a.id] });
      if (kept.length > 0) toast(keptIdentifiersMessage(kept), { icon: 'ℹ️', duration: 7000 });
      onSaved?.(a);
      onClose();
    },
  });

  const footerErr = save.isError ? (save.error as Error).message : problem;

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon={isEdit ? 'database' : 'plus'}
      eyebrow="Inventory"
      title={isEdit ? 'Edit asset' : 'New asset'}
      description="Pick the class first — it decides which fields this asset has. Identifiers are what let a later sighting recognise this thing rather than create a second copy of it."
      primary={
        <button className="ui-btn accent" disabled={!!problem || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create asset'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      {/* The class comes first, and on an EDIT it is changeable: reclassifying a
          thing that was wrongly classed is an ordinary correction, and the
          history tab records it. */}
      <ClassPicker value={classKey} onChange={setClassKey} disabled={save.isPending} />

      <ModalField
        label={serviceBranch ? 'Name (required)' : 'Display name'}
        hint={serviceBranch
          ? 'A service identifies by its name — it has no address or serial to be known by, so this is its identity, not a label.'
          : 'What a person calls this thing. Optional: the platform derives one from the identifiers.'}
      >
        <ModalInput
          data-autofocus
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder={serviceBranch ? 'Payroll' : 'web-prod-01'}
        />
      </ModalField>

      {!serviceBranch && <IdentifierEditor rows={identifiers} onChange={setIdentifiers} />}

      {classKey && (
        <>
          <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Class attributes</div>
          <ClassAttributeFields
            classKey={classKey}
            values={attributes}
            onChange={(name, v) => setAttributes((prev) => ({ ...prev, [name]: v }))}
          />
        </>
      )}

      <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Context</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Environment">
          <ModalSelect value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="">—</option>
            {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
          </ModalSelect>
        </ModalField>
        {/* New in phase 1. "Who do I page about this?" is the first question of
            the ops journey, and the old form had nowhere to record the answer. */}
        <ModalField label="Support group" hint="The team on the hook for this asset.">
          <ModalInput value={supportGroup} onChange={(e) => setSupportGroup(e.target.value)} placeholder="Platform SRE" />
        </ModalField>
        <ModalField label="Business unit">
          <ModalInput value={businessUnit} onChange={(e) => setBusinessUnit(e.target.value)} placeholder="Payments" />
        </ModalField>
        <ModalField label="Owner email">
          <ModalInput type="email" value={ownerEmail} onChange={(e) => setOwnerEmail(e.target.value)} placeholder="owner@example.com" />
        </ModalField>
      </div>

      <ModalField label="Description">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Short description" />
      </ModalField>

      {/* Tags — flat key/value rows, serialized to a JSONB object map. */}
      <div style={{ marginBottom: 15 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Tags</div>
          <button className="ui-btn sm" onClick={() => setTags([...tags, { key: '', value: '' }])}><Icon name="plus" size={12} />Add tag</button>
        </div>
        {tags.length === 0 && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No tags.</div>}
        {tags.map((row, idx) => (
          <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
            <ModalInput value={row.key} placeholder="key (e.g. tier)" style={{ flex: 1 }} onChange={(e) => { const n = [...tags]; n[idx] = { ...n[idx], key: e.target.value }; setTags(n); }} />
            <ModalInput value={row.value} placeholder="value" style={{ flex: 1 }} onChange={(e) => { const n = [...tags]; n[idx] = { ...n[idx], value: e.target.value }; setTags(n); }} />
            <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)', flex: 'none' }} title="Remove tag" onClick={() => setTags(tags.filter((_, i) => i !== idx))}><Icon name="x" size={13} /></button>
          </div>
        ))}
      </div>

      <ModalField label="Metadata (JSON)" hint="Optional. Arbitrary JSON object stored with the asset — for anything the class schema does not declare.">
        <textarea
          value={metadataText}
          onChange={(e) => setMetadataText(e.target.value)}
          rows={4}
          spellCheck={false}
          className="mono"
          aria-label="Metadata (JSON)"
          style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: `1px solid ${meta.error ? 'var(--danger)' : 'var(--app-border2)'}`, background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
        />
      </ModalField>
    </Modal>
  );
}
