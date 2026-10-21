// The asset page's IP Addresses tab (DCIM gap 2; BUILD_PLAN row 1.8's leftover):
// every address the asset holds in one table — through an interface, or named
// as its primary IPv4, primary IPv6 or out-of-band address. A row opens the
// address (details, edit, change record); Set as primary / Set as OOB write the
// asset's three address columns.
//
// Five states: loading, error, empty (two kinds — "nothing has reported this
// asset's interfaces" says nothing about its addresses, "interfaces recorded but
// no addresses" does), and the table. Reads need ipam.read, writes ipam.manage.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { DrawerCloseBtn, DrawerShell, Icon } from '../../../components/ui';
import { IP_FIELDS } from '../ipam/prefix-panel';
import { IP_STATUS_LABEL, useIpamList, type IpAddress } from '../ipam/ipam-queries';
import { Chip, IpamFormModal } from '../ipam/ipam-ui';
import { useAssetInterfaces } from './interface-queries';
import { useSetAssetIp, type AssetIpField } from './ip-address-queries';
import { ObjectChanges } from './object-changes';
import { PanelEmpty, PanelError, PanelLoading, whenText } from './substrate-states';

const SOURCE_LABEL: Record<string, string> = { measured: 'Measured', declared: 'Declared', imported: 'Imported', inferred: 'Inferred' };
const SEEN_BY_LABEL: Record<string, string> = { arp: 'ARP', dhcp: 'DHCP', passive: 'passive capture', probe: 'probe', agent: 'agent', cloud: 'cloud', declared: 'declared' };

const dash = (s?: string) => (s === undefined || s === '' ? '—' : s);
const isV6 = (address: string) => address.includes(':');
const primaryField = (address: string): AssetIpField => (isV6(address) ? 'primary_ip6_id' : 'primary_ip4_id');

/** Which of the asset's address columns name this address. The server resolves
 *  one holder per address; the flags only mean something for that holder. */
export function roleFlags(ip: IpAddress, assetId: string): { primary: boolean; oob: boolean } {
  const a = ip.asset;
  if (!a || a.id !== assetId) return { primary: false, oob: false };
  return { primary: isV6(ip.address) ? a.is_primary_ip6 : a.is_primary_ip4, oob: a.is_oob_ip };
}

export function sourceText(ip: Pick<IpAddress, 'source_kind' | 'last_seen_source'>): string {
  const kind = SOURCE_LABEL[ip.source_kind] ?? ip.source_kind;
  return ip.last_seen_source && ip.last_seen_source !== 'declared' ? `${kind} · ${SEEN_BY_LABEL[ip.last_seen_source] ?? ip.last_seen_source}` : kind;
}

export function IpAddressesTab({ asset }: { asset: Asset }) {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.ipam.read}
      fallback={<PanelEmpty icon="lock" title="You can't view IP addresses" message="IP addresses need the IPAM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <IpAddressesBody asset={asset} />
    </PermissionGate>
  );
}

function IpAddressesBody({ asset }: { asset: Asset }) {
  const ips = useIpamList('ip-addresses', { asset_id: asset.id, limit: 500 });
  const ifaces = useAssetInterfaces(asset.id);
  const vrfs = useIpamList('vrfs', { limit: 500 });
  const set = useSetAssetIp(asset.id);
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.ipam.manage);
  const editable = !asset.deleted_at && asset.asset_status !== 'archived';
  const [open, setOpen] = useState<IpAddress | null>(null);
  const ifaceName = useMemo(() => new Map((ifaces.data?.rows ?? []).map((i) => [i.id, i.name])), [ifaces.data]);
  const vrfName = useMemo(() => new Map((vrfs.data?.rows ?? []).map((v) => [v.id, v.name])), [vrfs.data]);
  const rows = ips.data?.rows ?? [];

  if (ips.isLoading) return <PanelLoading label="Loading IP addresses…" />;
  if (ips.isError) {
    return <PanelError message={ips.error instanceof Error ? ips.error.message : 'Request failed'} onRetry={() => { void ips.refetch(); }} />;
  }
  if (rows.length === 0) {
    // Whether the asset has interfaces decides what "no addresses" means.
    if (ifaces.isLoading) return <PanelLoading label="Loading IP addresses…" />;
    const noInterfaces = !ifaces.isError && (ifaces.data?.rows.length ?? 0) === 0;
    return noInterfaces ? (
      <PanelEmpty
        icon="network"
        title="No interfaces recorded"
        message="This asset has not been interrogated and none of its interfaces has been declared, so this says nothing about whether it has addresses. They appear here once discovery interrogates it, or when an address is assigned to one of its interfaces."
      />
    ) : (
      <PanelEmpty
        icon="network"
        title="No IP addresses"
        message="This asset's interfaces are recorded, but no address is assigned to any of them. Assign one from the Interfaces tab or Infrastructure → Networks."
      />
    );
  }

  return (
    <>
      <div style={{ overflowX: 'auto', border: '1px solid var(--app-border)', borderRadius: 10 }}>
        <table data-testid="ip-addresses-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Address', 'VRF', 'Interface', 'Role', 'Status', 'DNS name', 'Source', 'First seen', 'Last seen', ''].map((h, i) => (
                <th key={h || `c${i}`} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((ip) => {
              const { primary, oob } = roleFlags(ip, asset.id);
              const iface = ip.assigned_kind === 'interface' && ip.assigned_id ? ifaceName.get(ip.assigned_id) : undefined;
              const first = ip.first_seen_at ? whenText(ip.first_seen_at) : null;
              const last = ip.last_seen_at ? whenText(ip.last_seen_at) : null;
              const field = primaryField(ip.address);
              return (
                <tr key={ip.id} data-testid="ip-address-row" onClick={() => setOpen(ip)} style={{ borderTop: '1px solid var(--app-border)', cursor: 'pointer', opacity: ip.status === 'stale' ? 0.6 : 1 }}>
                  <td style={{ padding: '8px 11px', whiteSpace: 'nowrap' }}>
                    <button type="button" className="mono" aria-label={`Open ${ip.address}`} onClick={(e) => { e.stopPropagation(); setOpen(ip); }}
                      style={{ background: 'none', border: 0, padding: 0, font: 'inherit', fontWeight: 600, color: 'var(--app-t1)', cursor: 'pointer' }}>{ip.address}</button>
                    {primary && <span data-testid="primary-badge" style={{ marginLeft: 6 }}><Chip tone="var(--accent)" title="This asset's primary address of this family">Primary</Chip></span>}
                    {oob && <span data-testid="oob-badge" style={{ marginLeft: 6 }}><Chip tone="var(--warn)" title="This asset's out-of-band management address">OOB</Chip></span>}
                    {ip.status === 'pending' && <span style={{ marginLeft: 6 }}><Chip tone="var(--warn)" title="Discovered while waiting for approval">Pending</Chip></span>}
                  </td>
                  <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{ip.vrf_id ? (vrfName.get(ip.vrf_id) ?? 'VRF') : 'Global'}</td>
                  <td style={{ padding: '8px 11px' }} onClick={(e) => e.stopPropagation()}>
                    {ip.assigned_kind === 'interface'
                      ? <Link to={`/inventory/assets/${asset.id}/interfaces`} data-testid="ip-interface-link" className="mono">{iface ?? 'Interface'}</Link>
                      : <span style={{ color: 'var(--app-t3)' }} title="Held as a primary or out-of-band address without an interface">—</span>}
                  </td>
                  <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{ip.role ?? '—'}</td>
                  <td style={{ padding: '8px 11px' }}><Chip>{IP_STATUS_LABEL[ip.operational_status]}</Chip></td>
                  <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{ip.dns_name ?? '—'}</td>
                  <td style={{ padding: '8px 11px', color: 'var(--app-t2)', whiteSpace: 'nowrap' }}>{sourceText(ip)}</td>
                  <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }} title={first?.full}>{dash(first?.short)}</td>
                  <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }} title={last?.full}>{dash(last?.short)}</td>
                  <td style={{ padding: '8px 11px', whiteSpace: 'nowrap', textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                    <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
                      {canManage && editable && (
                        <>
                          <button type="button" className="ui-btn sm" disabled={set.isPending} data-testid="set-primary"
                            onClick={() => set.mutate({ field, addressId: primary ? null : ip.id })}>
                            {primary ? 'Unset primary' : 'Set as primary'}
                          </button>{' '}
                          <button type="button" className="ui-btn sm" disabled={set.isPending} data-testid="set-oob"
                            onClick={() => set.mutate({ field: 'oob_ip_id', addressId: oob ? null : ip.id })}>
                            {oob ? 'Unset OOB' : 'Set as OOB'}
                          </button>
                        </>
                      )}
                    </PermissionGate>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {open && <AddressDrawer ip={open} assetId={asset.id} iface={open.assigned_id ? ifaceName.get(open.assigned_id) : undefined} canEdit={canManage && editable} onClose={() => setOpen(null)} />}
    </>
  );
}

function AddressDrawer({ ip, assetId, iface, canEdit, onClose }: { ip: IpAddress; assetId: string; iface?: string; canEdit: boolean; onClose: () => void }) {
  const [editing, setEditing] = useState(false);
  const { primary, oob } = roleFlags(ip, assetId);
  const rowsOf: [string, React.ReactNode][] = [
    ['Status', IP_STATUS_LABEL[ip.operational_status]],
    ['Role', ip.role ?? '—'],
    ['Interface', iface ?? '—'],
    ['DNS name', ip.dns_name ?? '—'],
    ['MAC address', ip.mac_address ?? '—'],
    ['Source', sourceText(ip)],
    ['Asset address', [primary && 'Primary', oob && 'Out-of-band'].filter(Boolean).join(', ') || '—'],
  ];
  return (
    <DrawerShell onClose={onClose} width={480}>
      <div data-testid="ip-address-drawer" style={{ padding: '18px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <Icon name="route" size={16} style={{ color: 'var(--accent)' }} />
          <div className="mono" style={{ flex: 1, fontSize: 15, fontWeight: 700, color: 'var(--app-t1)' }}>{ip.address}</div>
          {canEdit && <button type="button" className="ui-btn sm" onClick={() => setEditing(true)}><Icon name="sliders-horizontal" size={12} />Edit</button>}
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <dl style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px 10px', fontSize: 12.5, margin: 0 }}>
          {rowsOf.map(([k, v]) => (
            <div key={k} style={{ display: 'contents' }}>
              <dt style={{ color: 'var(--app-t3)' }}>{k}</dt>
              <dd style={{ margin: 0, color: 'var(--app-t1)' }}>{v}</dd>
            </div>
          ))}
        </dl>
        <h3 className="eyebrow-app" style={{ margin: '18px 0 6px' }}>Changes</h3>
        <ObjectChanges kind="ip_address" id={ip.id} />
      </div>
      {editing && (
        <IpamFormModal route="ip-addresses" title={`Edit ${ip.address}`} fields={IP_FIELDS} editId={ip.id}
          initial={{ address: ip.address, operational_status: ip.operational_status, role: ip.role ?? '', dns_name: ip.dns_name ?? '', description: ip.description ?? '' }}
          onClose={() => setEditing(false)} onSaved={onClose} />
      )}
    </DrawerShell>
  );
}
