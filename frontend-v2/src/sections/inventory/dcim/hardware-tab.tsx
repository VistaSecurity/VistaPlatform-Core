// The asset page's Hardware tab (DCIM BUILD_PLAN row 2.4; asset-inventory
// ADR-0010 D4): what the asset is physically made of.
//
//   - Device type: the catalogue entry the asset is an instance of.
//   - Modules: the asset's module bays as a grid. An empty bay offers Install
//     module (a module-type search and a serial); an installed one shows its
//     module type, serial and how many interfaces it carries, and Remove.
//     Installing creates the module type's interfaces and ports on the asset
//     (`{module}` becomes the bay position) and keeps every port a collector
//     already measured; removing keeps anything that carries measured data.
//   - Inventory items: the hardware parts a collector listed (power supplies,
//     fans, transceivers) or someone declared, as a tree, each linked to the
//     interface or module it is. Remove to stock and RMA (DCIM gap 8,
//     spares/spare-actions.tsx) take a part off the asset to a stock location
//     or open a return case for it.
//   - Virtual chassis: the chassis this asset is a member of, its members with
//     position and priority and the master; add or remove a member.
//   - Device bays: the bays of row 3.1 with the child asset in each; install a
//     child or empty the bay.
//   - Virtual device contexts (DCIM gap 1): the device's VDOMs, vsys, VDCs or
//     route domains, with the interfaces in each (vdc-section.tsx).
//   - Lifecycle (DCIM gap 4): purchase, warranty, support contract and the
//     device type's and platform's end-of-support dates (lifecycle-card.tsx).
//
// Every section has its five states: loading, error, empty (nothing declared
// or reported — which is not "this asset has none"), the list, and the result
// of a write. Reads need dcim.read; writes need dcim.manage.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { useAssetHardware, useAssetPorts, usePatchPort, type DeviceBay } from './component-queries';
import {
  itemTree, useAddChassisMember, useAssetInventoryItems, useAssetModuleBays, useAssetModules, useAssetVirtualChassis,
  useCreateVirtualChassis, useInstallModule, useInventoryItemRoles, useModuleTypes, useRemoveChassisMember, useRemoveModule,
  type InventoryItem, type Module, type ModuleBay,
} from './hardware-queries';
import { useAssetInterfaces } from './interface-queries';
import { LifecycleCard } from './lifecycle-card';
import { OpenRmaModal, RemoveToStockModal } from '../spares/spare-actions';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';
import { VirtualDeviceContextsSection } from './vdc-section';

export function HardwareTab({ asset }: { asset: Asset }) {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={<PanelEmpty icon="lock" title="You can't view hardware" message="Hardware needs the DCIM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <HardwareBody asset={asset} />
    </PermissionGate>
  );
}

function HardwareBody({ asset }: { asset: Asset }) {
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.dcim.manage) && !asset.deleted_at && asset.asset_status !== 'archived';
  return (
    <div data-testid="hardware-tab" style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
      <DeviceTypeLine asset={asset} />
      <LifecycleCard assetId={asset.id} canManage={canManage} />
      <ModulesSection asset={asset} canManage={canManage} />
      <InventoryItemsSection asset={asset} canManage={canManage} />
      <VirtualChassisSection asset={asset} canManage={canManage} />
      <DeviceBaysSection asset={asset} canManage={canManage} />
      <VirtualDeviceContextsSection asset={asset} canManage={canManage} />
    </div>
  );
}

function SectionHead({ title, icon, children }: { title: string; icon: string; children?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
      <Icon name={icon} size={14} style={{ color: 'var(--accent)' }} />
      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ flex: 1 }} />
      {children}
    </div>
  );
}

const box: React.CSSProperties = { border: '1px solid var(--app-border)', borderRadius: 10 };
const cell: React.CSSProperties = { padding: '8px 11px', color: 'var(--app-t2)' };
const errMsg = (e: unknown) => (e instanceof Error ? e.message : 'Request failed');

function DeviceTypeLine({ asset }: { asset: Asset }) {
  const hw = useAssetHardware(asset.id);
  if (hw.isLoading) return <PanelLoading label="Loading the device type…" />;
  if (hw.isError) return <PanelError message={errMsg(hw.error)} onRetry={() => { void hw.refetch(); }} />;
  const h = hw.data;
  return (
    <div data-testid="hardware-device-type" style={{ ...box, padding: '10px 13px', fontSize: 12.5, color: 'var(--app-t2)', display: 'flex', gap: 18, flexWrap: 'wrap' }}>
      <span><strong style={{ color: 'var(--app-t1)' }}>Device type</strong> {h?.device_type ? `${h.manufacturer?.name ?? ''} ${h.device_type.name}`.trim() : 'None assigned'}</span>
      <span><strong style={{ color: 'var(--app-t1)' }}>Serial</strong> <span className="mono">{h?.serial ?? '—'}</span></span>
      <span><strong style={{ color: 'var(--app-t1)' }}>Asset tag</strong> <span className="mono">{h?.asset_tag ?? '—'}</span></span>
      {h && !h.device_type && h.is_hardware && <span style={{ color: 'var(--app-t3)' }}>Assign one and apply its templates (Ports tab) to create the module bays.</span>}
    </div>
  );
}

// ------------------------------------------------------------------ modules --

function ModulesSection({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const bays = useAssetModuleBays(asset.id);
  const modules = useAssetModules(asset.id);
  const ifaces = useAssetInterfaces(asset.id);
  const remove = useRemoveModule(asset.id);
  const [installing, setInstalling] = useState<ModuleBay | null>(null);
  const [removing, setRemoving] = useState<Module | null>(null);
  const moduleInBay = useMemo(() => new Map((modules.data ?? []).filter((m) => m.status !== 'rejected').map((m) => [m.module_bay_id, m])), [modules.data]);
  const ifaceCount = useMemo(() => {
    const out = new Map<string, number>();
    for (const i of ifaces.data?.rows ?? []) {
      const mid = (i as { module_id?: string | null }).module_id;
      if (mid) out.set(mid, (out.get(mid) ?? 0) + 1);
    }
    return out;
  }, [ifaces.data]);

  let body: React.ReactNode;
  if (bays.isLoading || modules.isLoading) body = <PanelLoading label="Loading module bays…" />;
  else if (bays.isError || modules.isError) {
    body = <PanelError message={errMsg(bays.error ?? modules.error)} onRetry={() => { void bays.refetch(); void modules.refetch(); }} />;
  } else if ((bays.data ?? []).length === 0) {
    body = <PanelEmpty icon="blocks" title="No module bays" message="This asset has no module bays. They come from its device type's templates (Apply templates on the Ports tab), or are declared by hand." />;
  } else {
    body = (
      <div data-testid="module-bays" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 10 }}>
        {(bays.data ?? []).map((b) => {
          const m = moduleInBay.get(b.id);
          return (
            <div key={b.id} data-testid="module-bay" style={{ ...box, padding: '10px 12px', fontSize: 12.5, borderStyle: m ? 'solid' : 'dashed' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="mono" style={{ fontWeight: 700, color: 'var(--app-t1)' }}>{b.name}</span>
                {b.position && <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>position {b.position}</span>}
              </div>
              {m ? (
                <div data-testid="module-card" style={{ marginTop: 6, color: 'var(--app-t2)' }}>
                  <div><ModuleTypeName id={m.module_type_id} /></div>
                  <div className="mono" style={{ fontSize: 11.5 }}>{m.serial ? `SN ${m.serial}` : 'No serial'}{m.source_kind === 'measured' ? ' · discovered' : ''}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{ifaceCount.get(m.id) ?? 0} interface{(ifaceCount.get(m.id) ?? 0) === 1 ? '' : 's'} · {m.operational_status}</div>
                  {canManage && (
                    <button type="button" className="ui-btn sm" style={{ marginTop: 6 }} aria-label={`Remove module from ${b.name}`} onClick={() => setRemoving(m)}>
                      <Icon name="trash-2" size={12} />Remove
                    </button>
                  )}
                </div>
              ) : (
                <div style={{ marginTop: 6 }}>
                  <div style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>Empty</div>
                  {canManage && (
                    <button type="button" className="ui-btn sm" style={{ marginTop: 6 }} aria-label={`Install module in ${b.name}`} onClick={() => setInstalling(b)}>
                      <Icon name="plus" size={12} />Install module
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return (
    <section data-testid="hardware-modules">
      <SectionHead title="Modules" icon="blocks" />
      {body}
      {installing && <InstallModuleModal asset={asset} bay={installing} onClose={() => setInstalling(null)} />}
      <Modal
        open={removing !== null}
        onClose={() => setRemoving(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title="Remove this module?"
        description="The interfaces and ports it created are deleted unless something was measured on them, cabled to them or assigned to them; those stay on the asset. The change log keeps what was removed."
        secondary={<button type="button" className="ui-btn" onClick={() => setRemoving(null)}>Cancel</button>}
        primary={(
          <button type="button" className="ui-btn danger" disabled={remove.isPending}
            onClick={() => { if (removing) remove.mutate(removing.id, { onSettled: () => setRemoving(null) }); }}>
            Remove
          </button>
        )}
      />
    </section>
  );
}

function ModuleTypeName({ id }: { id: string }) {
  const types = useModuleTypes('');
  const t = types.data?.find((x) => x.id === id);
  return <span style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{t ? t.model : 'Module'}</span>;
}

export function InstallModuleModal({ asset, bay, onClose }: { asset: Asset; bay: ModuleBay; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [typeId, setTypeId] = useState('');
  const [serial, setSerial] = useState('');
  const [error, setError] = useState<string | null>(null);
  const types = useModuleTypes(q);
  const install = useInstallModule(asset.id);
  const submit = () => {
    if (!typeId) return;
    setError(null);
    install.mutate(
      { module_bay_id: bay.id, module_type_id: typeId, serial: serial.trim() || null },
      { onSuccess: onClose, onError: (e) => setError(e.message) },
    );
  };
  return (
    <Modal
      open
      onClose={onClose}
      icon="blocks"
      title={`Install a module in ${bay.name}`}
      description={bay.position
        ? `Its interfaces and ports are created on this asset, with {module} in their names read as position ${bay.position}. A port a collector already reported is kept and joined to the module.`
        : 'This bay has no position, so a module type whose templates name {module} cannot be installed here.'}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={<button type="button" className="ui-btn primary" disabled={!typeId || install.isPending} onClick={submit}>Install</button>}
    >
      <div data-testid="install-module-modal">
        <ModalField label="Find a module type">
          <ModalInput aria-label="Find a module type" value={q} placeholder="Model or part number" onChange={(e) => setQ(e.target.value)} />
        </ModalField>
        <ModalField label="Module type" hint={types.isError ? errMsg(types.error) : types.isLoading ? 'Loading…' : (types.data ?? []).length === 0 ? 'No module type matches. Add one in Infrastructure → Device catalog.' : undefined}>
          <ModalSelect aria-label="Module type" value={typeId} onChange={(e) => setTypeId(e.target.value)}>
            <option value="">Choose a module type…</option>
            {(types.data ?? []).map((t) => <option key={t.id} value={t.id}>{t.model}{t.part_number && t.part_number !== t.model ? ` (${t.part_number})` : ''}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Serial">
          <ModalInput aria-label="Serial" value={serial} onChange={(e) => setSerial(e.target.value)} />
        </ModalField>
        {error && <div data-testid="install-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{error}</div>}
      </div>
    </Modal>
  );
}

// --------------------------------------------------------- inventory items --

function InventoryItemsSection({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const items = useAssetInventoryItems(asset.id);
  const [removing, setRemoving] = useState<InventoryItem | null>(null);
  const [rma, setRma] = useState<InventoryItem | null>(null);
  const roles = useInventoryItemRoles();
  const bays = useAssetModuleBays(asset.id);
  const modules = useAssetModules(asset.id);
  const ifaces = useAssetInterfaces(asset.id);
  const roleName = new Map((roles.data ?? []).map((r) => [r.id, r.name]));
  const ifaceName = new Map((ifaces.data?.rows ?? []).map((i) => [i.id, i.name]));
  const bayName = new Map((bays.data ?? []).map((b) => [b.id, b.name]));
  const moduleBay = new Map((modules.data ?? []).map((m) => [m.id, bayName.get(m.module_bay_id) ?? 'a bay']));
  const tree = itemTree(items.data ?? []);

  const link = (i: InventoryItem): React.ReactNode => {
    if (i.component_kind === 'interface' && i.component_id) {
      return <Link to={`/inventory/assets/${asset.id}/interfaces`} style={{ color: 'var(--accent)' }}>{ifaceName.get(i.component_id) ?? 'interface'}</Link>;
    }
    if (i.component_kind === 'module' && i.component_id) return <span>Module in {moduleBay.get(i.component_id) ?? 'a bay'}</span>;
    return <span style={{ color: 'var(--app-t3)' }}>—</span>;
  };

  let body: React.ReactNode;
  if (items.isLoading) body = <PanelLoading label="Loading inventory items…" />;
  else if (items.isError) body = <PanelError message={errMsg(items.error)} onRetry={() => { void items.refetch(); }} />;
  else if (tree.length === 0) {
    body = <PanelEmpty icon="boxes" title="No inventory items" message="No collector has listed this asset's parts and none has been declared, so this says nothing about whether it has any. SNMP (ENTITY-MIB) and Cisco interrogation report power supplies, fans and transceivers." />;
  } else {
    body = (
      <div style={{ ...box, overflowX: 'auto' }}>
        <table data-testid="inventory-items" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Name', 'Role', 'Part', 'Serial', 'Is', ''].map((h) => <th key={h} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {tree.map(({ item: i, depth }) => (
              <tr key={i.id} data-testid="inventory-item-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={{ ...cell, paddingLeft: 11 + depth * 18, whiteSpace: 'nowrap' }}>
                  {depth > 0 && <Icon name="chevron-right" size={11} style={{ color: 'var(--app-t3)', marginRight: 4 }} />}
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{i.name}</span>
                </td>
                <td style={cell}>{i.role_id ? roleName.get(i.role_id) ?? '—' : '—'}</td>
                <td style={cell} className="mono">{i.part_id ?? '—'}</td>
                <td style={cell} className="mono">{i.serial ?? '—'}</td>
                <td style={cell}>{link(i)}</td>
                <td style={{ ...cell, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  {i.stock_state === 'rma' && <span data-testid="rma-badge" title="Out for RMA" style={{ fontSize: 11, padding: '1px 6px', borderRadius: 6, marginRight: 4, background: 'color-mix(in srgb, var(--warn) 14%, transparent)', color: 'var(--app-t1)' }}>out for RMA</span>}
                  {i.discovered && <span data-testid="discovered-badge" title="Reported by a collector" style={{ fontSize: 11, padding: '1px 6px', borderRadius: 6, background: 'color-mix(in srgb, var(--accent) 12%, transparent)', color: 'var(--accent)' }}>discovered</span>}
                  {canManage && (
                    <>
                      <button type="button" className="ui-btn sm ghost" style={{ marginLeft: 4 }} aria-label={`Remove ${i.name} to stock`} onClick={() => setRemoving(i)}>
                        <Icon name="archive" size={12} />To stock
                      </button>
                      {i.stock_state === 'installed' && (
                        <button type="button" className="ui-btn sm ghost" aria-label={`Open RMA for ${i.name}`} onClick={() => setRma(i)}>
                          <Icon name="recycle" size={12} />RMA
                        </button>
                      )}
                    </>
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
    <section data-testid="hardware-inventory-items">
      <SectionHead title="Inventory items" icon="boxes" />
      {body}
      {removing && <RemoveToStockModal item={removing} assetId={asset.id} onClose={() => setRemoving(null)} />}
      {rma && <OpenRmaModal item={rma} assetId={asset.id} onClose={() => setRma(null)} />}
    </section>
  );
}

// --------------------------------------------------------- virtual chassis --

function VirtualChassisSection({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const vc = useAssetVirtualChassis(asset.id);
  const create = useCreateVirtualChassis(asset.id);
  const add = useAddChassisMember(asset.id);
  const remove = useRemoveChassisMember(asset.id);
  const [name, setName] = useState('');
  const [member, setMember] = useState('');
  const [position, setPosition] = useState('');
  const [priority, setPriority] = useState('');
  const [error, setError] = useState<string | null>(null);
  const chassis = vc.data?.virtual_chassis ?? null;
  const num = (s: string) => (s.trim() === '' ? null : Number(s));
  const badNumber = [position, priority].some((s) => s.trim() !== '' && !(Number.isInteger(Number(s)) && Number(s) >= 0 && Number(s) <= 255));

  let body: React.ReactNode;
  if (vc.isLoading) body = <PanelLoading label="Loading the virtual chassis…" />;
  else if (vc.isError) body = <PanelError message={errMsg(vc.error)} onRetry={() => { void vc.refetch(); }} />;
  else if (!chassis) {
    body = (
      <div>
        <PanelEmpty icon="layers" title="Not in a virtual chassis" message="This asset is not a member of a virtual chassis. Discovery files the members of a switch it interrogates; you can also create one with this asset as its master." />
        {canManage && (
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <ModalInput aria-label="Virtual chassis name" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
            <button type="button" className="ui-btn sm primary" disabled={!name.trim() || create.isPending}
              onClick={() => { setError(null); create.mutate({ name: name.trim(), master_asset_id: asset.id }, { onError: (e) => setError(e.message) }); }}>
              <Icon name="plus" size={12} />Create virtual chassis
            </button>
          </div>
        )}
      </div>
    );
  } else {
    body = (
      <div>
        <div style={{ fontSize: 12.5, color: 'var(--app-t2)', marginBottom: 8 }}>
          <strong style={{ color: 'var(--app-t1)' }}>{chassis.name}</strong>{chassis.domain ? ` · domain ${chassis.domain}` : ''}
        </div>
        <div style={{ ...box, overflowX: 'auto' }}>
          <table data-testid="chassis-members" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
                {['Position', 'Member', 'Serial', 'Priority', ''].map((h) => <th key={h} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {(vc.data?.members ?? []).map((m) => (
                <tr key={m.asset_id} data-testid="chassis-member" style={{ borderTop: '1px solid var(--app-border)' }}>
                  <td style={cell} className="mono">{m.vc_position ?? '—'}</td>
                  <td style={cell}>
                    {m.asset_id === asset.id ? <strong>{m.display_name}</strong> : <Link to={`/inventory/assets/${m.asset_id}/hardware`} style={{ color: 'var(--accent)' }}>{m.display_name}</Link>}
                    {m.is_master && <span data-testid="master-badge" style={{ marginLeft: 6, fontSize: 11, padding: '1px 6px', borderRadius: 6, background: 'color-mix(in srgb, var(--ok) 14%, transparent)', color: 'var(--ok)' }}>master</span>}
                  </td>
                  <td style={cell} className="mono">{m.serial ?? '—'}</td>
                  <td style={cell} className="mono">{m.vc_priority ?? '—'}</td>
                  <td style={{ ...cell, textAlign: 'right' }}>
                    {canManage && (
                      <button type="button" className="ui-btn sm" aria-label={`Remove ${m.display_name} from the chassis`}
                        onClick={() => remove.mutate({ vc: chassis.id, member: m.asset_id })}>
                        <Icon name="x" size={12} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {canManage && (
          <div data-testid="add-member" style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr auto', gap: 8, marginTop: 8, alignItems: 'center' }}>
            <ModalInput aria-label="Member asset id" placeholder="Asset id" value={member} onChange={(e) => setMember(e.target.value)} />
            <ModalInput aria-label="Member position" placeholder="Position" inputMode="numeric" value={position} onChange={(e) => setPosition(e.target.value)} />
            <ModalInput aria-label="Member priority" placeholder="Priority" inputMode="numeric" value={priority} onChange={(e) => setPriority(e.target.value)} />
            <button type="button" className="ui-btn sm" disabled={!member.trim() || badNumber || add.isPending}
              onClick={() => {
                setError(null);
                add.mutate({ vc: chassis.id, asset_id: member.trim(), vc_position: num(position), vc_priority: num(priority) }, {
                  onSuccess: () => { setMember(''); setPosition(''); setPriority(''); },
                  onError: (e) => setError(e.message),
                });
              }}>
              <Icon name="plus" size={12} />Add member
            </button>
          </div>
        )}
        {badNumber && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 4 }}>Position and priority are whole numbers from 0 to 255.</div>}
      </div>
    );
  }
  return (
    <section data-testid="hardware-virtual-chassis">
      <SectionHead title="Virtual chassis" icon="layers" />
      {body}
      {error && <div data-testid="chassis-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{error}</div>}
    </section>
  );
}

// ------------------------------------------------------------- device bays --

function DeviceBaysSection({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const bays = useAssetPorts(asset.id, 'device-bays');
  const patch = usePatchPort(asset.id, 'device-bays');
  const [installing, setInstalling] = useState<DeviceBay | null>(null);
  const [child, setChild] = useState('');
  const [error, setError] = useState<string | null>(null);

  let body: React.ReactNode;
  if (bays.isLoading) body = <PanelLoading label="Loading device bays…" />;
  else if (bays.isError) body = <PanelError message={errMsg(bays.error)} onRetry={() => { void bays.refetch(); }} />;
  else if ((bays.data?.rows ?? []).length === 0) {
    body = <PanelEmpty icon="server-cog" title="No device bays" message="This asset has no device bays. A chassis's bays come from its device type's templates; each holds one child asset, such as a blade." />;
  } else {
    body = (
      <div style={{ ...box, overflowX: 'auto' }}>
        <table data-testid="device-bays" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <tbody>
            {(bays.data?.rows ?? []).map((b) => (
              <tr key={b.id} data-testid="device-bay-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={cell}><span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{b.name}</span></td>
                <td style={cell}>
                  {b.installed_asset_id
                    ? <Link to={`/inventory/assets/${b.installed_asset_id}`} style={{ color: 'var(--accent)' }}>Open installed asset</Link>
                    : <span style={{ color: 'var(--app-t3)' }}>Empty</span>}
                </td>
                <td style={{ ...cell, textAlign: 'right' }}>
                  {canManage && (b.installed_asset_id
                    ? <button type="button" className="ui-btn sm" aria-label={`Empty ${b.name}`} onClick={() => patch.mutate({ id: b.id, patch: { installed_asset_id: null } }, { onError: (e) => setError(e.message) })}>Remove child</button>
                    : <button type="button" className="ui-btn sm" aria-label={`Install a child in ${b.name}`} onClick={() => { setInstalling(b); setChild(''); setError(null); }}>Install child</button>)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <section data-testid="hardware-device-bays">
      <SectionHead title="Device bays" icon="server-cog" />
      {body}
      {error && !installing && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{error}</div>}
      <Modal
        open={installing !== null}
        onClose={() => setInstalling(null)}
        size="sm"
        icon="server-cog"
        title={`Install a child in ${installing?.name ?? 'the bay'}`}
        description="The child asset sits in this bay and takes no rack units of its own. An asset placed in a rack must be unplaced first."
        secondary={<button type="button" className="ui-btn" onClick={() => setInstalling(null)}>Cancel</button>}
        primary={(
          <button type="button" className="ui-btn primary" disabled={!child.trim() || patch.isPending}
            onClick={() => {
              if (!installing) return;
              patch.mutate({ id: installing.id, patch: { installed_asset_id: child.trim() } }, {
                onSuccess: () => setInstalling(null),
                onError: (e) => setError(e.message),
              });
            }}>
            Install
          </button>
        )}
      >
        <ModalField label="Child asset id">
          <ModalInput aria-label="Child asset id" value={child} onChange={(e) => setChild(e.target.value)} />
        </ModalField>
        {error && installing && <div data-testid="device-bay-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{error}</div>}
      </Modal>
    </section>
  );
}
