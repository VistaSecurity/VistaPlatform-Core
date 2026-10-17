// The asset page's Ports tab (DCIM BUILD_PLAN row 3.1; asset-inventory
// ADR-0010 D3), headed by row 3.4's faceplate: the asset's console ports, console server ports, front ports,
// rear ports and device bays, one section per kind, with add / edit / delete
// and an "Apply templates" action that instantiates the device type's templates
// for EVERY component kind (interfaces included) and reports what it did.
//
// Five states per section: loading, error, empty (nothing reported or declared,
// which is not "this asset has none"), the table, and the result panel after
// Apply templates. Reads need dcim.read; writes need dcim.manage. Power ports
// and outlets have an API and no UI (ADR-0010 D9).
import { useState } from 'react';
import { Link } from 'react-router';
import type { UseQueryResult } from '@tanstack/react-query';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import {
  CONSOLE_PORT_TYPES, CONSOLE_PORT_TYPE_LABELS, PORT_TYPES, PORT_TYPE_LABELS,
} from '@vistasecurity/primitives/dcim';
import { DrawerCloseBtn, DrawerShell, Icon, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import {
  PORT_KINDS, PORT_OBJECT_KIND, PortWriteError, applySummary, useApplyTemplates, useAssetHardware, useAssetPorts,
  useCreatePort, useDeletePort, usePatchPort,
  type ApplyDeviceTypeResult, type ConsolePort, type DeviceBay, type FrontPort, type PortKind, type PortPage, type PortRow, type RearPort,
} from './component-queries';
import { ObjectChanges } from './object-changes';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import { CableCell } from './cable-column';
import { useAssetCables, type CableTerminationKind } from './cable-queries';
import { Faceplate } from '../cabling/faceplate';

interface KindInfo {
  label: string;
  singular: string;
  icon: string;
  emptyMessage: string;
}

export const PORT_KIND_INFO: Record<PortKind, KindInfo> = {
  'console-ports': {
    label: 'Console ports', singular: 'console port', icon: 'terminal',
    emptyMessage: 'Nothing has reported this asset\'s console ports and none has been declared, so this says nothing about whether it has any.',
  },
  'console-server-ports': {
    label: 'Console server ports', singular: 'console server port', icon: 'server',
    emptyMessage: 'No console server ports are declared. A console server (or a switch used as one) lists the ports other devices plug into.',
  },
  'front-ports': {
    label: 'Front ports', singular: 'front port', icon: 'plug',
    emptyMessage: 'No front ports are declared. Each one is mapped to a position of a rear port, so declare the rear ports first.',
  },
  'rear-ports': {
    label: 'Rear ports', singular: 'rear port', icon: 'cable',
    emptyMessage: 'No rear ports are declared. A patch panel\'s rear ports carry several front-port positions each.',
  },
  'device-bays': {
    label: 'Device bays', singular: 'device bay', icon: 'server-cog',
    emptyMessage: 'No device bays are declared. A bay holds one child asset, such as a blade in a chassis.',
  },
};

export function PortsTab({ asset }: { asset: Asset }) {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={<PanelEmpty icon="lock" title="You can't view ports" message="Ports need the DCIM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <PortsBody asset={asset} />
    </PermissionGate>
  );
}

function PortsBody({ asset }: { asset: Asset }) {
  const [kind, setKind] = useState<PortKind>('console-ports');
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.dcim.manage);
  const editable = !asset.deleted_at && asset.asset_status !== 'archived';
  // Every kind is loaded so the section strip shows counts, and so front ports
  // can name their rear port.
  const lists = {
    'console-ports': useAssetPorts(asset.id, 'console-ports'),
    'console-server-ports': useAssetPorts(asset.id, 'console-server-ports'),
    'front-ports': useAssetPorts(asset.id, 'front-ports'),
    'rear-ports': useAssetPorts(asset.id, 'rear-ports'),
    'device-bays': useAssetPorts(asset.id, 'device-bays'),
  };
  const [applied, setApplied] = useState<ApplyDeviceTypeResult | null>(null);

  return (
    <div data-testid="ports-tab">
      {/* The faceplate (row 3.4): every port of the asset, interfaces first. */}
      <Faceplate asset={asset} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}>
        <div role="tablist" aria-label="Port kinds" style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {PORT_KINDS.map((k) => {
            const total = lists[k].data?.total;
            const active = k === kind;
            return (
              <button
                key={k}
                type="button"
                role="tab"
                aria-selected={active}
                className={`ui-btn sm${active ? ' primary' : ''}`}
                onClick={() => setKind(k)}
              >
                <Icon name={PORT_KIND_INFO[k].icon} size={12} />{PORT_KIND_INFO[k].label}
                {total !== undefined && <span data-testid={`count-${k}`} style={{ marginLeft: 4, opacity: 0.75 }}>{total}</span>}
              </button>
            );
          })}
        </div>
        <div style={{ flex: 1 }} />
        {canManage && editable && <ApplyTemplates asset={asset} onApplied={setApplied} />}
      </div>
      {applied && <ApplyResult result={applied} onDismiss={() => setApplied(null)} />}
      <KindSection asset={asset} kind={kind} canManage={canManage && editable} lists={lists} />
    </div>
  );
}

type Lists = { [K in PortKind]: UseQueryResult<PortPage<K>> };

function ApplyTemplates({ asset, onApplied }: { asset: Asset; onApplied: (r: ApplyDeviceTypeResult) => void }) {
  const hw = useAssetHardware(asset.id);
  const apply = useApplyTemplates(asset.id);
  const dt = hw.data?.device_type ?? null;
  const [error, setError] = useState<string | null>(null);
  let title = 'Create this asset\'s interfaces and ports from its device type\'s templates. Nothing already set is overwritten.';
  if (hw.isLoading) title = 'Loading the asset\'s device type…';
  else if (hw.data && !hw.data.is_hardware) title = 'A device type applies to hardware assets only.';
  else if (hw.data && !dt) title = 'This asset has no device type. Assign one on the Overview tab first.';
  return (
    <>
      {error && <span data-testid="apply-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{error}</span>}
      <button
        type="button"
        className="ui-btn sm"
        title={title}
        disabled={!dt || apply.isPending}
        onClick={() => {
          if (!dt) return;
          setError(null);
          apply.mutate(dt.id, { onSuccess: onApplied, onError: (e) => setError(e.message) });
        }}
      >
        <Icon name="server" size={13} />Apply templates
      </button>
    </>
  );
}

function ApplyResult({ result, onDismiss }: { result: ApplyDeviceTypeResult; onDismiss: () => void }) {
  const rows = applySummary(result).filter((r) => r.created + r.updated + r.unchanged + r.removed + r.skipped.length > 0);
  const waiting = Object.entries(result.not_instantiated);
  return (
    <div data-testid="apply-result" role="status" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 13px', marginBottom: 12, fontSize: 12.5 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <Icon name="circle-check" size={14} style={{ color: 'var(--ok)' }} />
        <strong style={{ flex: 1, color: 'var(--app-t1)' }}>Templates applied{result.hardware.device_type ? ` — ${result.hardware.device_type.name}` : ''}</strong>
        <button type="button" className="ui-btn sm" aria-label="Dismiss result" onClick={onDismiss}><Icon name="x" size={12} /></button>
      </div>
      {rows.length === 0 && <div style={{ color: 'var(--app-t3)' }}>The device type has no templates, so nothing was created.</div>}
      {rows.map((r) => (
        <div key={r.label} data-testid="apply-row" style={{ color: 'var(--app-t2)', padding: '1px 0' }}>
          <span style={{ display: 'inline-block', minWidth: 170, fontWeight: 600 }}>{r.label}</span>
          {r.created} created · {r.updated} filled · {r.unchanged} unchanged{r.removed > 0 ? ` · ${r.removed} removed` : ''}
          {r.skipped.length > 0 && <div style={{ marginLeft: 170, color: 'var(--app-t3)' }}>Skipped: {r.skipped.join('; ')}</div>}
        </div>
      ))}
      {waiting.length > 0 && (
        <div style={{ color: 'var(--app-t3)', marginTop: 4 }}>
          Kept on the type, placed later: {waiting.map(([k, n]) => `${n} ${k.replace(/-templates$/, '').replace(/-/g, ' ')} template${n === 1 ? '' : 's'}`).join(', ')}.
        </div>
      )}
    </div>
  );
}

function KindSection({ asset, kind, canManage, lists }: { asset: Asset; kind: PortKind; canManage: boolean; lists: Lists }) {
  const info = PORT_KIND_INFO[kind];
  const q = lists[kind] as UseQueryResult<PortPage<PortKind>>;
  const [editing, setEditing] = useState<PortRow | 'new' | null>(null);
  const [deleting, setDeleting] = useState<PortRow | null>(null);
  const del = useDeletePort(asset.id, kind);
  const cables = useAssetCables(asset.id);
  const rows = (q.data?.rows ?? []) as PortRow[];
  const rearById = new Map((lists['rear-ports'].data?.rows ?? []).map((r) => [r.id, r]));
  const frontsPerRear = new Map<string, number>();
  for (const f of lists['front-ports'].data?.rows ?? []) frontsPerRear.set(f.rear_port_id, (frontsPerRear.get(f.rear_port_id) ?? 0) + 1);

  let body: React.ReactNode;
  if (q.isLoading) body = <PanelLoading label={`Loading ${info.label.toLowerCase()}…`} />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if (rows.length === 0) body = <PanelEmpty icon={info.icon} title={`No ${info.label.toLowerCase()} yet`} message={info.emptyMessage} />;
  else {
    const cols = columnsFor(kind);
    body = (
      <div style={{ overflowX: 'auto', border: '1px solid var(--app-border)', borderRadius: 10 }}>
        <table data-testid="ports-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {[...cols, ...(CABLED_KIND[kind] ? ['Cable'] : []), 'Label', 'Description', ''].map((h, i) => <th key={h + i} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} data-testid="port-row" style={{ borderTop: '1px solid var(--app-border)', opacity: r.status === 'stale' ? 0.6 : 1 }}>
                <td style={{ padding: '8px 11px', whiteSpace: 'nowrap' }}>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{r.name}</span>
                </td>
                {cellsFor(kind, r, rearById, frontsPerRear).map((c, i) => <td key={i} style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{c}</td>)}
                {CABLED_KIND[kind] && (
                  <td style={{ padding: '8px 11px' }} data-testid="port-cable">
                    <CableCell
                      port={{ kind: CABLED_KIND[kind], id: r.id, name: r.name, cableId: r.cable_id, markConnected: r.mark_connected }}
                      cables={cables}
                      canManage={canManage}
                    />
                  </td>
                )}
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{r.label ?? ''}</td>
                <td style={{ padding: '8px 11px', color: 'var(--app-t2)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description ?? ''}</td>
                <td style={{ padding: '8px 11px', whiteSpace: 'nowrap', textAlign: 'right' }}>
                  <button type="button" className="ui-btn sm" aria-label={`Open ${r.name}`} onClick={() => setEditing(r)}>
                    <Icon name={canManage ? 'sliders-horizontal' : 'eye'} size={12} />
                  </button>
                  {canManage && (
                    <button type="button" className="ui-btn sm" aria-label={`Delete ${r.name}`} style={{ marginLeft: 4 }} onClick={() => setDeleting(r)}>
                      <Icon name="trash-2" size={12} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div data-testid={`ports-section-${kind}`}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{info.label}</div>
        <div style={{ flex: 1 }} />
        {canManage && (
          <button type="button" className="ui-btn sm primary" onClick={() => setEditing('new')}>
            <Icon name="plus" size={13} />Add {info.singular}
          </button>
        )}
      </div>
      {body}
      {editing && (
        <PortDrawer
          asset={asset}
          kind={kind}
          row={editing === 'new' ? null : editing}
          rearPorts={lists['rear-ports'].data?.rows ?? []}
          readOnly={!canManage}
          onClose={() => setEditing(null)}
        />
      )}
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title={`Delete ${deleting?.name ?? info.singular}?`}
        description={kind === 'rear-ports' ? 'The front ports mapped to this rear port are deleted with it. The change log keeps what they were.' : 'The change log keeps what it was.'}
        secondary={<button type="button" className="ui-btn" onClick={() => setDeleting(null)}>Cancel</button>}
        primary={(
          <button
            type="button"
            className="ui-btn danger"
            disabled={del.isPending}
            onClick={() => { if (deleting) del.mutate(deleting, { onSettled: () => setDeleting(null) }); }}
          >
            Delete
          </button>
        )}
      />
    </div>
  );
}

// The kinds that take a cable (a device bay does not), by object kind.
const CABLED_KIND: Record<PortKind, CableTerminationKind | null> = {
  'console-ports': 'console_port',
  'console-server-ports': 'console_server_port',
  'front-ports': 'front_port',
  'rear-ports': 'rear_port',
  'device-bays': null,
};

function columnsFor(kind: PortKind): string[] {
  switch (kind) {
    case 'console-ports':
    case 'console-server-ports': return ['Name', 'Type', 'Speed'];
    case 'front-ports': return ['Name', 'Type', 'Rear port', 'Position'];
    case 'rear-ports': return ['Name', 'Type', 'Positions', 'Mapped'];
    case 'device-bays': return ['Name', 'Installed asset'];
  }
}

function typeText(type: string | null, labels: Record<string, string>): string {
  if (!type) return '—';
  return labels[type] ?? type;
}

function cellsFor(kind: PortKind, r: PortRow, rear: Map<string, RearPort>, fronts: Map<string, number>): React.ReactNode[] {
  switch (kind) {
    case 'console-ports':
    case 'console-server-ports': {
      const c = r as ConsolePort;
      return [typeText(c.type, CONSOLE_PORT_TYPE_LABELS), c.speed != null ? `${c.speed} baud` : '—'];
    }
    case 'front-ports': {
      const f = r as FrontPort;
      return [typeText(f.type, PORT_TYPE_LABELS), rear.get(f.rear_port_id)?.name ?? 'unknown', f.rear_port_position];
    }
    case 'rear-ports': {
      const p = r as RearPort;
      const mapped = fronts.get(p.id) ?? 0;
      return [typeText(p.type, PORT_TYPE_LABELS), p.positions, `${mapped} of ${p.positions}`];
    }
    case 'device-bays': {
      const b = r as DeviceBay;
      return [b.installed_asset_id
        ? <Link key="i" to={`/inventory/assets/${b.installed_asset_id}`} style={{ color: 'var(--accent)' }}>Open installed asset</Link>
        : <span key="i" style={{ color: 'var(--app-t3)' }}>Empty</span>];
    }
  }
}

// ------------------------------------------------------------------ drawer --

export interface PortDraft {
  name: string;
  label: string;
  description: string;
  type: string;
  speed: string;
  color: string;
  positions: string;
  rear_port_id: string;
  rear_port_position: string;
  installed_asset_id: string;
}

export function draftOf(_kind: PortKind, r: PortRow | null): PortDraft {
  const any = (r ?? {}) as Partial<ConsolePort & FrontPort & RearPort & DeviceBay>;
  return {
    name: any.name ?? '',
    label: any.label ?? '',
    description: any.description ?? '',
    type: any.type ?? '',
    speed: any.speed != null ? String(any.speed) : '',
    color: any.color ?? '',
    positions: any.positions != null ? String(any.positions) : '1',
    rear_port_id: any.rear_port_id ?? '',
    rear_port_position: any.rear_port_position != null ? String(any.rear_port_position) : '1',
    installed_asset_id: any.installed_asset_id ?? '',
  };
}

const nullIfEmpty = (s: string) => (s.trim() === '' ? null : s.trim());

/** The body a draft saves as, for its kind. */
export function bodyOf(kind: PortKind, d: PortDraft): Record<string, unknown> {
  const common = { name: d.name.trim(), label: nullIfEmpty(d.label), description: nullIfEmpty(d.description) };
  switch (kind) {
    case 'console-ports':
    case 'console-server-ports':
      return { ...common, type: nullIfEmpty(d.type), speed: d.speed.trim() === '' ? null : Number(d.speed) };
    case 'front-ports':
      return { ...common, type: d.type, color: nullIfEmpty(d.color), rear_port_id: d.rear_port_id, rear_port_position: Number(d.rear_port_position) };
    case 'rear-ports':
      return { ...common, type: d.type, color: nullIfEmpty(d.color), positions: Number(d.positions) };
    case 'device-bays':
      return { ...common, installed_asset_id: nullIfEmpty(d.installed_asset_id) };
  }
}

/** What stops a draft saving, before the server is asked. */
export function draftProblem(kind: PortKind, d: PortDraft, rearPorts: readonly RearPort[]): string | null {
  if (!d.name.trim()) return 'A name is required.';
  if (d.name.trim().length > 64) return 'A name is at most 64 characters.';
  if ((kind === 'front-ports' || kind === 'rear-ports') && !d.type) return 'Choose a type.';
  if ((kind === 'console-ports' || kind === 'console-server-ports') && d.speed.trim() && !(Number(d.speed) >= 1)) return 'Speed must be a positive number.';
  if (kind === 'rear-ports') {
    const n = Number(d.positions);
    if (!Number.isInteger(n) || n < 1 || n > 1024) return 'Positions must be a whole number between 1 and 1024.';
  }
  if (kind === 'front-ports') {
    if (!d.rear_port_id) return 'Choose the rear port this maps to.';
    const rp = rearPorts.find((r) => r.id === d.rear_port_id);
    const pos = Number(d.rear_port_position);
    if (!Number.isInteger(pos) || pos < 1) return 'Position must be a whole number from 1.';
    if (rp && pos > rp.positions) return `${rp.name} has ${rp.positions} position${rp.positions === 1 ? '' : 's'}.`;
  }
  if ((kind === 'front-ports' || kind === 'rear-ports') && d.color.trim() && !/^#?[0-9a-fA-F]{6}$/.test(d.color.trim())) return 'Colour is six hex digits.';
  return null;
}

function PortDrawer({ asset, kind, row, rearPorts, readOnly, onClose }: {
  asset: Asset; kind: PortKind; row: PortRow | null; rearPorts: readonly RearPort[]; readOnly: boolean; onClose: () => void;
}) {
  const info = PORT_KIND_INFO[kind];
  const [d, setD] = useState<PortDraft>(() => draftOf(kind, row));
  const [serverError, setServerError] = useState<string | null>(null);
  const create = useCreatePort(asset.id, kind);
  const patch = usePatchPort(asset.id, kind);
  const set = <K extends keyof PortDraft>(k: K, v: PortDraft[K]) => setD((cur) => ({ ...cur, [k]: v }));
  const problem = draftProblem(kind, d, rearPorts);
  const busy = create.isPending || patch.isPending;

  const save = () => {
    if (problem) return;
    setServerError(null);
    const body = bodyOf(kind, d);
    const done = { onSuccess: onClose, onError: (e: Error) => setServerError(e instanceof PortWriteError ? e.message : e.message) };
    if (row) patch.mutate({ id: row.id, patch: body }, done);
    else create.mutate({ ...body, asset_id: asset.id }, done);
  };

  const typeOptions = kind === 'console-ports' || kind === 'console-server-ports'
    ? CONSOLE_PORT_TYPES.map((t) => [t, CONSOLE_PORT_TYPE_LABELS[t]] as const)
    : PORT_TYPES.map((t) => [t, PORT_TYPE_LABELS[t]] as const);
  const hasType = kind !== 'device-bays';

  return (
    <DrawerShell onClose={onClose} width={480}>
      <div data-testid="port-drawer" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <Icon name={info.icon} size={16} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, fontSize: 15, fontWeight: 700, color: 'var(--app-t1)' }}>{row ? row.name : `Add ${info.singular}`}</div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <fieldset disabled={readOnly || busy} style={{ border: 0, padding: 0, margin: 0 }}>
          <ModalField label="Name">
            <ModalInput aria-label="Name" value={d.name} onChange={(e) => set('name', e.target.value)} />
          </ModalField>
          {hasType && (
            <ModalField label="Type">
              <ModalSelect aria-label="Type" value={d.type} onChange={(e) => set('type', e.target.value)}>
                <option value="">{kind === 'console-ports' || kind === 'console-server-ports' ? 'Unspecified' : 'Choose a type…'}</option>
                {typeOptions.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </ModalSelect>
            </ModalField>
          )}
          {(kind === 'console-ports' || kind === 'console-server-ports') && (
            <ModalField label="Speed (baud)">
              <ModalInput aria-label="Speed" inputMode="numeric" value={d.speed} onChange={(e) => set('speed', e.target.value)} />
            </ModalField>
          )}
          {kind === 'rear-ports' && (
            <ModalField label="Positions" hint="How many front-port positions this rear port carries (a 12-fibre trunk has 12).">
              <ModalInput aria-label="Positions" inputMode="numeric" value={d.positions} onChange={(e) => set('positions', e.target.value)} />
            </ModalField>
          )}
          {kind === 'front-ports' && (
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
              <ModalField label="Rear port" hint={rearPorts.length === 0 ? 'Declare a rear port first.' : undefined}>
                <ModalSelect aria-label="Rear port" value={d.rear_port_id} disabled={rearPorts.length === 0} onChange={(e) => set('rear_port_id', e.target.value)}>
                  <option value="">Choose a rear port…</option>
                  {rearPorts.map((r) => <option key={r.id} value={r.id}>{r.name} ({r.positions} position{r.positions === 1 ? '' : 's'})</option>)}
                </ModalSelect>
              </ModalField>
              <ModalField label="Position">
                <ModalInput aria-label="Position" inputMode="numeric" value={d.rear_port_position} onChange={(e) => set('rear_port_position', e.target.value)} />
              </ModalField>
            </div>
          )}
          {(kind === 'front-ports' || kind === 'rear-ports') && (
            <ModalField label="Colour" hint="Six hex digits, e.g. 2196f3.">
              <ModalInput aria-label="Colour" value={d.color} onChange={(e) => set('color', e.target.value)} />
            </ModalField>
          )}
          {kind === 'device-bays' && (
            <ModalField label="Installed asset" hint="The id of the asset sitting in this bay; leave empty for an empty bay.">
              <ModalInput aria-label="Installed asset" value={d.installed_asset_id} onChange={(e) => set('installed_asset_id', e.target.value)} />
            </ModalField>
          )}
          <ModalField label="Label">
            <ModalInput aria-label="Label" value={d.label} onChange={(e) => set('label', e.target.value)} />
          </ModalField>
          <ModalField label="Description">
            <ModalInput aria-label="Description" value={d.description} onChange={(e) => set('description', e.target.value)} />
          </ModalField>
        </fieldset>
        {!readOnly && (problem !== null || serverError !== null) && (
          <div data-testid="port-form-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginBottom: 8 }}>
            {serverError ?? problem}
          </div>
        )}
        {!readOnly && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="ui-btn" onClick={onClose}>Cancel</button>
            <button type="button" className="ui-btn primary" disabled={!!problem || busy} onClick={save}>
              {row ? 'Save' : `Add ${info.singular}`}
            </button>
          </div>
        )}
        {row && (
          <>
            <SectionLabel icon="git-compare">Changes</SectionLabel>
            <ObjectChanges kind={PORT_OBJECT_KIND[kind]} id={row.id} />
          </>
        )}
      </div>
    </DrawerShell>
  );
}
