// Create / edit an infrastructure asset. Restores the write surface the rebuild
// dropped (old web-ui had asset-form-modal.tsx). Wired through the typed
// inventory-service client — POST /infrastructure-assets (create) and
// PUT /infrastructure-assets/{id} (edit). Composes the shared Modal primitive.
import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Asset, AssetInput } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';

const ASSET_TYPES = ['server', 'endpoint', 'service', 'appliance'];
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

export function AssetFormModal({ open, asset, onClose, onSaved }: {
  open: boolean;
  /** Present → edit mode; absent/null → create mode. */
  asset?: Asset | null;
  onClose: () => void;
  onSaved?: (a: Asset) => void;
}) {
  const isEdit = !!asset?.id;
  const qc = useQueryClient();

  const [hostname, setHostname] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [port, setPort] = useState('');
  const [assetType, setAssetType] = useState('server');
  const [operatingSystem, setOperatingSystem] = useState('');
  const [environment, setEnvironment] = useState('');
  const [businessUnit, setBusinessUnit] = useState('');
  const [ownerEmail, setOwnerEmail] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState<TagRow[]>([]);
  const [metadataText, setMetadataText] = useState('{}');

  // (Re)hydrate from the target asset whenever it changes or the modal reopens.
  useEffect(() => {
    setHostname(asset?.hostname ?? '');
    setIpAddress(asset?.ip_address ?? '');
    setPort(asset?.port != null ? String(asset.port) : '');
    setAssetType(asset?.asset_type || 'server');
    setOperatingSystem(asset?.operating_system ?? '');
    setEnvironment(asset?.environment ?? '');
    setBusinessUnit(asset?.business_unit ?? '');
    setOwnerEmail(asset?.owner_email ?? '');
    setDescription(asset?.description ?? '');
    setTags(tagsToRows(asset?.tags));
    setMetadataText(JSON.stringify((asset?.metadata as object) ?? {}, null, 2));
  }, [asset, open]);

  const meta = useMemo<{ value: Record<string, unknown> | null; error: string | null }>(() => {
    if (!metadataText.trim()) return { value: {}, error: null };
    try {
      const v = JSON.parse(metadataText);
      if (typeof v !== 'object' || Array.isArray(v) || v === null) return { value: null, error: 'Metadata must be a JSON object' };
      return { value: v as Record<string, unknown>, error: null };
    } catch {
      return { value: null, error: 'Invalid JSON' };
    }
  }, [metadataText]);

  const portNum = port.trim() ? Number(port) : undefined;
  const portValid = portNum === undefined || (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535);
  const valid = !!(hostname.trim() || ipAddress.trim()) && !!assetType && !meta.error && portValid;

  const save = useMutation({
    mutationFn: async (): Promise<Asset> => {
      const tagsObj: Record<string, unknown> = {};
      tags.forEach(({ key, value }) => { if (key.trim()) tagsObj[key.trim()] = value; });
      const body: AssetInput = {
        asset_type: assetType,
        hostname: hostname.trim() || undefined,
        ip_address: ipAddress.trim() || undefined,
        port: portNum,
        operating_system: operatingSystem.trim() || undefined,
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
        if (error || !data) throw new Error('Failed to update asset');
        return data.asset;
      }
      const { data, error } = await clients.inventory.POST('/infrastructure-assets', { body });
      if (error || !data) throw new Error('Failed to create asset');
      return data.asset;
    },
    onSuccess: (a) => {
      // List keys are ['inventory','assets',...]; detail/config keys are by id.
      qc.invalidateQueries({ queryKey: ['inventory'] });
      qc.invalidateQueries({ queryKey: ['asset-detail', a.id] });
      qc.invalidateQueries({ queryKey: ['asset-configs', a.id] });
      onSaved?.(a);
      onClose();
    },
  });

  const footerErr = save.isError ? (save.error as Error).message : meta.error || (!portValid ? 'Port must be 1–65535' : null);

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon={isEdit ? 'database' : 'plus'}
      eyebrow="Inventory"
      title={isEdit ? 'Edit asset' : 'New infrastructure asset'}
      description="Hostname or IP is required, plus an asset type. Tags and metadata are optional."
      primary={
        <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create asset'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Hostname"><ModalInput data-autofocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="web-prod-01.example.com" /></ModalField>
        <ModalField label="IP address"><ModalInput value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="10.0.0.1" /></ModalField>
        <ModalField label="Asset type">
          <ModalSelect value={assetType} onChange={(e) => setAssetType(e.target.value)}>
            {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Port"><ModalInput value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" inputMode="numeric" /></ModalField>
        <ModalField label="Environment">
          <ModalSelect value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="">—</option>
            {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Operating system"><ModalInput value={operatingSystem} onChange={(e) => setOperatingSystem(e.target.value)} placeholder="Linux" /></ModalField>
        <ModalField label="Business unit"><ModalInput value={businessUnit} onChange={(e) => setBusinessUnit(e.target.value)} placeholder="Payments" /></ModalField>
        <ModalField label="Owner email"><ModalInput type="email" value={ownerEmail} onChange={(e) => setOwnerEmail(e.target.value)} placeholder="owner@example.com" /></ModalField>
      </div>

      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Short description" /></ModalField>

      {/* Tags — flat key/value rows, serialized to a JSONB object map. */}
      <div style={{ marginBottom: 15 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Tags</div>
          <button className="ui-btn sm" onClick={() => setTags([...tags, { key: '', value: '' }])}><Icon name="plus" size={12} />Add tag</button>
        </div>
        {tags.length === 0 && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No tags.</div>}
        {tags.map((row, idx) => (
          <div key={idx} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
            <ModalInput value={row.key} placeholder="key (e.g. location.region)" style={{ flex: 1 }} onChange={(e) => { const n = [...tags]; n[idx] = { ...n[idx], key: e.target.value }; setTags(n); }} />
            <ModalInput value={row.value} placeholder="value" style={{ flex: 1 }} onChange={(e) => { const n = [...tags]; n[idx] = { ...n[idx], value: e.target.value }; setTags(n); }} />
            <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)', flex: 'none' }} title="Remove tag" onClick={() => setTags(tags.filter((_, i) => i !== idx))}><Icon name="x" size={13} /></button>
          </div>
        ))}
      </div>

      <ModalField label="Metadata (JSON)" hint="Optional. Arbitrary JSON object stored with the asset.">
        <textarea
          value={metadataText}
          onChange={(e) => setMetadataText(e.target.value)}
          rows={4}
          spellCheck={false}
          className="mono"
          style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: `1px solid ${meta.error ? 'var(--danger)' : 'var(--app-border2)'}`, background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
        />
      </ModalField>
    </Modal>
  );
}
