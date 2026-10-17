// The asset page's Hardware card (DCIM BUILD_PLAN row 2.2): manufacturer,
// model, part number, height, serial, asset tag, device role and platform (OS),
// read from /dcim/assets/{id}/hardware, and "Apply templates", which assigns the
// device type and creates its interfaces — merged by name with the ones
// collectors measured, never duplicating them. Rendered for hardware-class
// assets only; the edit happens in the asset form.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import { uHeightText, useApplyDeviceType, useAssetHardware, type ApplyDeviceTypeResult } from './catalogue-queries';

const has = (s?: string | null): s is string => (s ?? '') !== '';

function Row({ k, v, mono }: { k: string; v?: string | null; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '5px 0', fontSize: 12.5 }}>
      <span style={{ color: 'var(--app-t3)' }}>{k}</span>
      <span className={mono ? 'mono' : undefined} style={{ color: has(v) ? 'var(--app-t1)' : 'var(--app-t3)', textAlign: 'right' }}>{has(v) ? v : '—'}</span>
    </div>
  );
}

/** What an apply did, in words. */
export function applySummary(r: ApplyDeviceTypeResult): string {
  const i = r.interfaces;
  const parts = [`${i.created} interface${i.created === 1 ? '' : 's'} added`];
  if (i.updated) parts.push(`${i.updated} measured interface${i.updated === 1 ? '' : 's'} typed`);
  if (i.removed) parts.push(`${i.removed} left from the previous type removed`);
  if (!i.created && !i.updated && !i.removed) return 'Already applied: nothing to change.';
  return `${parts.join(', ')}.`;
}

export function HardwareCard({ assetId }: { assetId: string }) {
  const q = useAssetHardware(assetId);
  const apply = useApplyDeviceType(assetId);
  const [done, setDone] = useState<ApplyDeviceTypeResult | null>(null);
  const hw = q.data;
  if (hw && !hw.is_hardware) return null;

  // Anything recorded at all: an empty card says so rather than listing dashes.
  const recorded = !!hw && (!!hw.device_type || !!hw.device_role || !!hw.platform || has(hw.serial) || has(hw.asset_tag));
  const pending = hw?.device_type ? Object.entries(hw.template_counts).filter(([k, n]) => k !== 'interface-templates' && n > 0) : [];

  return (
    <div data-testid="hardware-card" style={{ border: '1px solid var(--app-border)', borderRadius: 14, padding: '14px 16px', background: 'var(--app-panel)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>
          <Icon name="server" size={14} />Hardware
        </div>
        {hw?.device_type && (
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            <button type="button" className="ui-btn sm" data-testid="apply-templates" disabled={apply.isPending}
              title="Create this device type's interfaces on the asset, merged with the ones already measured"
              onClick={() => { setDone(null); apply.mutateAsync(hw.device_type!.id).then(setDone, () => undefined); }}>
              <Icon name="list-checks" size={12} />{apply.isPending ? 'Applying…' : 'Apply templates'}
            </button>
          </PermissionGate>
        )}
      </div>
      {q.isLoading && <PanelLoading label="Loading hardware…" />}
      {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
      {hw && !recorded && (
        <PanelEmpty icon="server" title="No hardware recorded"
          message="Pick a device type, role and platform (OS) in the asset form. A device type brings its interfaces with it." />
      )}
      {hw && recorded && (
        <div data-testid="hardware-rows">
          <Row k="Manufacturer" v={hw.manufacturer?.name} />
          <Row k="Model" v={hw.device_type?.name} />
          <Row k="Part number" v={hw.device_type?.part_number} mono />
          <Row k="Height" v={hw.device_type ? uHeightText(hw.device_type.u_height) : null} />
          <Row k="Serial" v={hw.serial} mono />
          <Row k="Asset tag" v={hw.asset_tag} mono />
          <Row k="Device role" v={hw.device_role?.name} />
          <Row k="Platform (OS)" v={hw.platform?.name} />
          {pending.length > 0 && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 6, lineHeight: 1.5 }}>
              The type also declares {pending.map(([k, n]) => `${n} ${k.replace('-templates', '').replace(/-/g, ' ')}${n === 1 ? '' : 's'}`).join(', ')};
              those components arrive with a later release and are not created yet.
            </div>
          )}
        </div>
      )}
      {apply.isError && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 8 }}>{apply.error.message}</div>}
      {done && <div role="status" data-testid="apply-result" style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 8 }}>{applySummary(done)}</div>}
    </div>
  );
}
