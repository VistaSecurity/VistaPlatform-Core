// The asset form's hardware fields (DCIM BUILD_PLAN row 2.2): Device type (a
// search select showing each type's height), Device role, Platform (OS),
// Serial and Asset tag. They are written by PATCH /dcim/assets/{id}/hardware
// after the asset itself saves, and only when one of them changed, so the
// asset write and its form stay as they were.
//
// A device type applies to hardware-class assets only (the server refuses it
// on any other class), so the field is shown for those; role, platform, serial
// and asset tag are shown for every class.
import { useMemo, useState } from 'react';
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import {
  patchAssetHardware, uHeightText, useAssetHardware, useCatalogueList,
  type AssetHardware, type HardwarePatch,
} from './catalogue-queries';

/** Whether a class key is in the hardware branch (where a device type applies). */
export function isHardwareClass(classKey: string): boolean {
  const path = ASSET_CLASSES[classKey as AssetClassKey]?.path ?? '';
  return path === 'hardware' || path.startsWith('hardware.');
}

export interface HardwareDraft {
  device_type_id: string;
  device_role_id: string;
  platform_id: string;
  serial: string;
  asset_tag: string;
}

export const EMPTY_HARDWARE: HardwareDraft = { device_type_id: '', device_role_id: '', platform_id: '', serial: '', asset_tag: '' };

export function draftOf(hw: AssetHardware | undefined | null): HardwareDraft {
  if (!hw) return EMPTY_HARDWARE;
  return {
    device_type_id: hw.device_type?.id ?? '', device_role_id: hw.device_role?.id ?? '', platform_id: hw.platform?.id ?? '',
    serial: hw.serial ?? '', asset_tag: hw.asset_tag ?? '',
  };
}

/** The fields that differ from `base`, as the PATCH body ("" clears). */
export function hardwareChanges(base: HardwareDraft, draft: HardwareDraft): HardwarePatch | null {
  const out: Record<string, string | null> = {};
  for (const k of Object.keys(draft) as (keyof HardwareDraft)[]) {
    if (draft[k].trim() !== base[k].trim()) out[k] = draft[k].trim() || null;
  }
  return Object.keys(out).length ? out : null;
}

/**
 * The form's hardware state: the draft, its baseline from the server (empty for
 * a new asset), and `save(assetId)` to write what changed.
 */
export function useHardwareDraft(assetId: string | null | undefined, open: boolean) {
  const hw = useAssetHardware(open ? assetId : null);
  const data = hw.data;
  const base = useMemo(() => draftOf(assetId ? data : null), [assetId, data]);
  // The person's edits belong to one opening of the form over one read of the
  // asset: a new key (another asset, a reopen, a refetch) starts from the
  // server's values again. Derived rather than reset in an effect.
  const key = `${assetId ?? ''}:${open}:${hw.dataUpdatedAt}`;
  const [state, setState] = useState<{ key: string; edits: HardwareDraft | null }>({ key, edits: null });
  const draft = state.key === key && state.edits ? state.edits : base;
  const setDraft = (d: HardwareDraft) => setState({ key, edits: d });
  const save = async (id: string) => {
    const body = hardwareChanges(base, draft);
    if (body) await patchAssetHardware(id, body);
  };
  return { draft, setDraft, save, loading: !!assetId && hw.isLoading, current: data };
}

/** The device-type search select: type to filter, pick from the matches. */
export function DeviceTypeSelect({ value, current, onChange }: {
  value: string;
  /** The assigned type, so it stays listed whatever the search shows. */
  current?: { id: string; name: string; u_height?: number | null } | null;
  onChange: (id: string) => void;
}) {
  const [search, setSearch] = useState('');
  const q = useCatalogueList('device-types', { limit: 50, ...(search.trim() ? { q: search.trim() } : {}) });
  const rows = q.data?.rows ?? [];
  const listed = rows.some((r) => r.id === value);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <ModalInput aria-label="Search device types" placeholder="Search model or part number" value={search} onChange={(e) => setSearch(e.target.value)} />
      <ModalSelect aria-label="Device type" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{q.isLoading ? 'Loading…' : q.isError ? 'Could not load device types' : 'None'}</option>
        {value && !listed && current && current.id === value && (
          <option value={current.id}>{`${current.name} · ${uHeightText(current.u_height)}`}</option>
        )}
        {rows.map((r) => (
          <option key={r.id} value={r.id}>{`${r.manufacturer?.name ?? ''} ${r.model}${r.part_number ? ` (${r.part_number})` : ''} · ${uHeightText(r.u_height)}`.trim()}</option>
        ))}
      </ModalSelect>
    </div>
  );
}

export function AssetHardwareFields({ draft, onChange, isHardware, current }: {
  draft: HardwareDraft;
  onChange: (d: HardwareDraft) => void;
  isHardware: boolean;
  current?: AssetHardware | null;
}) {
  const roles = useCatalogueList('device-roles', { limit: 1000 });
  const platforms = useCatalogueList('platforms', { limit: 1000 });
  const set = (k: keyof HardwareDraft, v: string) => onChange({ ...draft, [k]: v });
  return (
    <div data-testid="asset-hardware-fields">
      <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Hardware</div>
      {isHardware && (
        <ModalField label="Device type" hint="The model from the device catalogue. Its interfaces are created with “Apply templates” on the asset page.">
          <DeviceTypeSelect value={draft.device_type_id} current={current?.device_type} onChange={(v) => set('device_type_id', v)} />
        </ModalField>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Device role">
          <ModalSelect aria-label="Device role" value={draft.device_role_id} onChange={(e) => set('device_role_id', e.target.value)}>
            <option value="">{roles.isLoading ? 'Loading…' : roles.isError ? 'Could not load roles' : 'None'}</option>
            {(roles.data?.rows ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Platform (OS)">
          <ModalSelect aria-label="Platform (OS)" value={draft.platform_id} onChange={(e) => set('platform_id', e.target.value)}>
            <option value="">{platforms.isLoading ? 'Loading…' : platforms.isError ? 'Could not load platforms' : 'None'}</option>
            {(platforms.data?.rows ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Serial">
          <ModalInput aria-label="Serial" className="mono" value={draft.serial} onChange={(e) => set('serial', e.target.value)} placeholder="FOC1234X0YZ" />
        </ModalField>
        <ModalField label="Asset tag">
          <ModalInput aria-label="Asset tag" className="mono" value={draft.asset_tag} onChange={(e) => set('asset_tag', e.target.value)} placeholder="IT-0042" />
        </ModalField>
      </div>
    </div>
  );
}
