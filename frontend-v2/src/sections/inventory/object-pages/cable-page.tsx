// The cable page (DCIM gap 7) — `/inventory/cables/:id`: A and B ends, type,
// status, length, LLDP / CDP confirmation and the trace, then the substrate
// panels. The Cabling lens's drawer body, reused.
import { useNavigate, useParams } from 'react-router';
import { TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { CableDetails, CableDisconnect } from '../cabling/cabling-lens';
import { lengthText, statusText, typeText } from '../cabling/cabling-model';
import { useCable, useUpdateCable } from '../cabling/cabling-queries';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { Chip } from '../ipam/ipam-ui';
import { ObjectPageShell } from './object-page-shell';
import { OBJECT_PAGE_LENS } from './object-links';
import { isNotFound } from './object-queries';
import { useBusinessUnits } from '../../settings/business-units-queries';

export function CablePage() {
  const { id } = useParams();
  const nav = useNavigate();
  const q = useCable(id ?? null);
  const update = useUpdateCable();
  const units = useBusinessUnits();
  const c = q.data;
  const unit = (units.data ?? []).find((u) => u.id === c?.business_unit_id)?.name;

  return (
    <ObjectPageShell
      kind="cable" id={id} icon="cable"
      status={q.isLoading ? 'loading' : q.isError ? (isNotFound(q.error) ? 'not-found' : 'error') : c ? 'ready' : 'loading'}
      errorMessage={q.error instanceof Error ? q.error.message : undefined} onRetry={() => { void q.refetch(); }}
      breadcrumbName={c ? (c.label?.trim() ? c.label.trim() : 'Cable') : undefined}
      title={c && <span className="mono">{c.label?.trim() ? c.label : 'Cable'}</span>}
      subtitle={c && [typeText(c.type), lengthText(c), unit].filter((x) => x && x !== '—').join(' · ')}
      badges={c && <Chip tone={c.status === 'pending' || c.operational_status !== 'connected' ? 'var(--warn)' : undefined}>{statusText(c)}</Chip>}
      actions={c && <CableDisconnect cable={c} onDone={() => { void nav(OBJECT_PAGE_LENS.cable.href); }} />}
      customFields={c && (
        <CustomFieldsPanel kind="cable" id={c.id} values={c.custom_fields} permission={TENANT_PERMISSIONS.dcim.manage}
          onChange={(custom_fields) => update.mutateAsync({ id: c.id, patch: { custom_fields: custom_fields as Record<string, never> } })} />
      )}
    >
      {c && <CableDetails cable={c} substrate={false} />}
    </ObjectPageShell>
  );
}
