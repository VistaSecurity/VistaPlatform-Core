// The prefix page (DCIM gap 7) — `/inventory/prefixes/:id`. The Networks
// lens's prefix panel as a bookmarkable page: tree position, utilisation, child
// prefixes, addresses, VLAN, role and gateway, then the substrate panels.
import { useMemo } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { MetaRow } from '../../../components/ui';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { PrefixPanel } from '../ipam/prefix-panel';
import { PREFIX_STATUS_LABEL, useIpamList, useIpamWrite, usePrefixDetail } from '../ipam/ipam-queries';
import { Chip } from '../ipam/ipam-ui';
import { useBusinessUnits } from '../../settings/business-units-queries';
import { ObjectPageShell } from './object-page-shell';
import { fromState, prefixHref, vlanHref, OBJECT_PAGE_LENS } from './object-links';
import { isNotFound } from './object-queries';
import { useLocation } from 'react-router';

export function PrefixPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const loc = useLocation();
  const q = usePrefixDetail(id ?? null);
  const roles = useIpamList('prefix-roles', { limit: 1000 });
  const vlans = useIpamList('vlans', { limit: 1000 });
  const units = useBusinessUnits();
  const { update } = useIpamWrite('prefixes');
  const p = q.data?.prefix;
  const role = useMemo(() => (roles.data?.rows ?? []).find((r) => r.id === p?.role_id)?.name, [roles.data, p]);
  const vlan = useMemo(() => (vlans.data?.rows ?? []).find((v) => v.id === p?.vlan_id), [vlans.data, p]);
  const unit = useMemo(() => (units.data ?? []).find((u) => u.id === p?.business_unit_id)?.name, [units.data, p]);
  const lens = OBJECT_PAGE_LENS.prefix;

  return (
    <ObjectPageShell
      kind="prefix" id={id} icon="network"
      status={q.isLoading ? 'loading' : q.isError ? (isNotFound(q.error) ? 'not-found' : 'error') : p ? 'ready' : 'loading'}
      errorMessage={q.error instanceof Error ? q.error.message : undefined} onRetry={() => { void q.refetch(); }}
      breadcrumbName={p?.prefix} title={<span className="mono">{p?.prefix}</span>}
      badges={p && <Chip>{PREFIX_STATUS_LABEL[p.operational_status]}</Chip>}
      subtitle={p?.description}
      customFields={p && (
        <CustomFieldsPanel kind="prefix" id={p.id} values={p.custom_fields} permission={TENANT_PERMISSIONS.ipam.manage}
          onChange={(custom_fields) => update.mutateAsync({ id: p.id, body: { custom_fields } })} />
      )}
    >
      {p && id && (
        <>
          <div data-testid="prefix-page-facts" style={{ marginBottom: 12 }}>
            <MetaRow k="VLAN" v={vlan ? <Link to={vlanHref(vlan.id)} state={fromState(loc)}>{vlan.vid} {vlan.name}</Link> : p.vlan_id ? 'Assigned' : ''} />
            <MetaRow k="Role" v={role ?? (p.role_id ? 'Assigned' : '')} />
            <MetaRow k="Business unit" v={unit ?? (p.business_unit_id ? 'Assigned' : '')} />
          </div>
          <PrefixPanel embedded id={id} onClose={() => { void nav(lens.href); }} onSelect={(next) => { void nav(prefixHref(next), { state: { from: (loc.state as { from?: string } | null)?.from ?? lens.href } }); }} />
        </>
      )}
    </ObjectPageShell>
  );
}
