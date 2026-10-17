// The asset page's Wireless LANs panel (DCIM BUILD_PLAN row 4.4; asset-inventory
// ADR-0010 D8): the SSIDs an access point's radios serve, each with its
// authentication and the catalogue's verdict on its cipher. Mounted under the
// Interfaces tab, and only for an asset that has a wireless interface, so a
// switch does not grow an empty "wireless" section.
//
// Five states: permission notice, loading, error, empty (no SSID reported - which
// does not mean none is broadcast), and the table. Reads need wireless.read.
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { SectionLabel } from '../../../components/ui';
import { useIpamList } from '../ipam/ipam-queries';
import { authText, AuthRisk, keyText } from './wireless-auth';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';

export function WirelessLansPanel({ assetId }: { assetId: string }) {
  return (
    <div data-testid="wireless-panel" style={{ marginTop: 22 }}>
      <SectionLabel icon="wifi">Wireless LANs</SectionLabel>
      <PermissionGate
        permission={TENANT_PERMISSIONS.wireless.read}
        fallback={<PanelEmpty icon="lock" title="You can't view wireless LANs" message="Wireless LANs need the wireless read permission. Ask an organisation admin to grant it to your role." />}
      >
        <WirelessLansBody assetId={assetId} />
      </PermissionGate>
    </div>
  );
}

function WirelessLansBody({ assetId }: { assetId: string }) {
  const q = useIpamList('wireless-lans', { asset_id: assetId, limit: 200 });
  if (q.isLoading) return <PanelLoading label="Loading wireless LANs…" />;
  if (q.isError) return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  const rows = q.data?.rows ?? [];
  if (rows.length === 0) {
    return (
      <PanelEmpty
        icon="wifi"
        title="No wireless LANs reported"
        message="No controller has reported an SSID on this asset's radios and none is declared, so this says nothing about what it broadcasts. They appear when a wireless controller is interrogated."
      />
    );
  }
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--app-border)', borderRadius: 10 }}>
      <table data-testid="wireless-lans-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
        <thead>
          <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
            {['SSID', 'Authentication', 'Key', 'Cipher risk', 'Status'].map((h) => <th key={h} style={{ padding: '8px 11px', fontWeight: 600 }}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((l) => (
            <tr key={l.id} data-testid="wireless-lan-row" style={{ borderTop: '1px solid var(--app-border)' }}>
              <td className="mono" style={{ padding: '8px 11px', fontWeight: 600, color: 'var(--app-t1)' }}>{l.ssid}</td>
              <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{authText(l)}</td>
              <td style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{keyText(l)}</td>
              <td style={{ padding: '8px 11px' }}><AuthRisk lan={l} /></td>
              <td style={{ padding: '8px 11px', color: l.status === 'pending' ? 'var(--warn)' : 'var(--app-t3)' }}>{l.status === 'pending' ? 'Pending approval' : l.operational_status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
