// The VLAN page (DCIM gap 7) — `/inventory/vlans/:id`: group, site, status, the
// prefixes it carries and the interfaces using it (untagged or tagged), then the
// substrate panels. Editing stays in the VLANs lens (`ipam.manage`).
import { Link, useLocation, useParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, MetaRow, SectionLabel } from '../../../components/ui';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { LIFECYCLE_LABEL, useIpamList, useIpamWrite } from '../ipam/ipam-queries';
import { Chip } from '../ipam/ipam-ui';
import { useSites } from '../sites/sites-queries';
import { ObjectPageShell } from './object-page-shell';
import { fromState, interfaceHref } from './object-links';
import { isNotFound, useVlanById, useVlanInterfaces } from './object-queries';

export function VlanPage() {
  const { id } = useParams();
  const loc = useLocation();
  const q = useVlanById(id);
  const groups = useIpamList('vlan-groups', { limit: 1000 });
  const prefixes = useIpamList('prefixes', id ? { vlan_id: id, limit: 200 } : {}, { enabled: !!id });
  const sites = useSites();
  const ifaces = useVlanInterfaces(id);
  const { update } = useIpamWrite('vlans');
  const v = q.data;
  const group = (groups.data?.rows ?? []).find((g) => g.id === v?.group_id)?.name;
  const site = (sites.data ?? []).find((s) => s.id === v?.site_id)?.name;

  return (
    <ObjectPageShell
      kind="vlan" id={id} icon="layers"
      status={q.isLoading ? 'loading' : q.isError ? (isNotFound(q.error) ? 'not-found' : 'error') : v ? 'ready' : 'loading'}
      errorMessage={q.error instanceof Error ? q.error.message : undefined} onRetry={() => { void q.refetch(); }}
      breadcrumbName={v ? `VLAN ${v.vid}` : undefined}
      title={v && <><span className="mono">{v.vid}</span> {v.name}</>}
      badges={v && (
        <>
          <Chip>{v.operational_status}</Chip>
          {v.status !== 'active' && <Chip tone="var(--warn)">{LIFECYCLE_LABEL[v.status]}</Chip>}
        </>
      )}
      subtitle={v?.description}
      customFields={v && (
        <CustomFieldsPanel kind="vlan" id={v.id} values={v.custom_fields} permission={TENANT_PERMISSIONS.ipam.manage}
          onChange={(custom_fields) => update.mutateAsync({ id: v.id, body: { custom_fields } })} />
      )}
      actions={v && (
        <PermissionGate permission={TENANT_PERMISSIONS.ipam.manage}>
          <Link to={`/inventory?lens=vlans&vlan=${v.id}`} className="ui-btn sm" data-testid="vlan-edit-in-lens"><Icon name="sliders-horizontal" size={13} />Edit in VLANs</Link>
        </PermissionGate>
      )}
    >
      {v && (
        <>
          <MetaRow k="VLAN group" v={group} />
          <MetaRow k="Site" v={site} />
          <MetaRow k="Q-in-Q role" v={v.qinq_role ?? ''} />

          <SectionLabel icon="network">Prefixes</SectionLabel>
          <div data-testid="vlan-prefixes">
            {prefixes.isLoading ? <PanelLoading label="Loading prefixes…" />
              : prefixes.isError ? <PanelError message="Couldn't load the prefixes on this VLAN." onRetry={() => { void prefixes.refetch(); }} />
                : (prefixes.data?.rows ?? []).length === 0 ? <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>No prefix is carried on this VLAN.</div>
                  : (prefixes.data?.rows ?? []).map((p) => (
                    <Link key={p.id} to={`/inventory/prefixes/${p.id}`} state={fromState(loc)} className="mono" style={{ display: 'block', fontSize: 12.5, padding: '3px 0' }}>{p.prefix}</Link>
                  ))}
          </div>

          <SectionLabel icon="ethernet-port">Interfaces using this VLAN</SectionLabel>
          <div data-testid="vlan-interfaces">
            {ifaces.isLoading ? <PanelLoading label="Loading interfaces…" />
              : ifaces.isError ? <PanelError message={ifaces.error instanceof Error ? ifaces.error.message : 'Request failed'} onRetry={() => { void ifaces.refetch(); }} />
                : (ifaces.data?.rows ?? []).length === 0
                  ? <PanelEmpty icon="ethernet-port" title="No interfaces" message="No interface is recorded as untagged or tagged on this VLAN." />
                  : (ifaces.data?.rows ?? []).map((i) => (
                    <div key={i.id} data-testid="vlan-interface" style={{ display: 'flex', gap: 8, fontSize: 12.5, padding: '4px 0', borderBottom: '1px solid var(--app-border)' }}>
                      <Link to={interfaceHref(i.id)} state={fromState(loc)} className="mono">{i.name}</Link>
                      <span style={{ color: 'var(--app-t3)' }}>{i.untagged_vlan_id === v.id ? 'untagged' : 'tagged'}</span>
                    </div>
                  ))}
            {ifaces.data && ifaces.data.total > ifaces.data.rows.length && (
              <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 6 }}>Showing {ifaces.data.rows.length} of {ifaces.data.total}.</div>
            )}
          </div>
        </>
      )}
    </ObjectPageShell>
  );
}
