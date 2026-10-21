// The circuit page (DCIM gap 7) — `/inventory/circuits/:id`: provider, type,
// status, commit rate, the A and Z terminations (editable, with a trace of each
// cabled end), then the substrate panels. The Circuits lens's drawer body,
// reused, not rebuilt.
import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, SectionLabel } from '../../../components/ui';
import { TraceBody } from '../cabling/trace-view';
import { CircuitDetails, circuitFields, circuitInitial, type CircuitRow } from '../circuits/circuits-lens';
import { CIRCUIT_STATUS_LABEL, useCircuitList, useCircuitWrite } from '../circuits/circuits-queries';
import { CustomFieldsPanel } from '../dcim/custom-fields-panel';
import { PanelEmpty } from '../dcim/substrate-states';
import { Chip, ObjectDeleteModal, ObjectFormModal } from '../ipam/ipam-ui';
import { ObjectPageShell } from './object-page-shell';
import { OBJECT_PAGE_LENS } from './object-links';
import { isNotFound, useCircuitById } from './object-queries';

export function CircuitPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const q = useCircuitById(id);
  const c: CircuitRow | undefined = q.data;
  const terms = useCircuitList('circuit-terminations', id ? { circuit_id: id } : {}, { enabled: !!id });
  const providers = useCircuitList('providers', { limit: 1000 });
  const accounts = useCircuitList('provider-accounts', { limit: 1000 });
  const types = useCircuitList('circuit-types', { limit: 1000 });
  const write = useCircuitWrite('circuits');
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [traceSide, setTraceSide] = useState<'A' | 'Z' | null>(null);
  const cabled = (terms.data?.rows ?? []).filter((t) => t.cable_id);
  const traceFrom = cabled.find((t) => t.term_side === traceSide) ?? cabled[0];

  return (
    <ObjectPageShell
      kind="circuit" id={id} icon="cable"
      status={q.isLoading ? 'loading' : q.isError ? (isNotFound(q.error) ? 'not-found' : 'error') : c ? 'ready' : 'loading'}
      errorMessage={q.error instanceof Error ? q.error.message : undefined} onRetry={() => { void q.refetch(); }}
      breadcrumbName={c?.cid} title={<span className="mono">{c?.cid}</span>}
      subtitle={c && `${c.provider_name ?? 'Provider not recorded'} · ${c.type_name ?? 'Type not recorded'}`}
      badges={c && <Chip>{CIRCUIT_STATUS_LABEL[c.operational_status]}</Chip>}
      actions={c && (
        <PermissionGate permission={TENANT_PERMISSIONS.circuits.manage}>
          <button type="button" className="ui-btn sm" data-testid="circuit-edit" onClick={() => setEditing(true)}><Icon name="sliders-horizontal" size={13} />Edit</button>
          <button type="button" className="ui-btn sm" data-testid="circuit-delete" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(true)}><Icon name="trash-2" size={13} />Delete</button>
        </PermissionGate>
      )}
      customFields={c && (
        <CustomFieldsPanel kind="circuit" id={c.id} values={c.custom_fields} permission={TENANT_PERMISSIONS.circuits.manage}
          onChange={(custom_fields) => write.update.mutateAsync({ id: c.id, body: { custom_fields } })} />
      )}
    >
      {c && (
        <>
          <CircuitDetails circuit={c} substrate={false} />
          <SectionLabel icon="route">Trace{traceFrom ? ` from the ${traceFrom.term_side} end` : ''}</SectionLabel>
          <div data-testid="circuit-trace">
            {cabled.length > 1 && (
              <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                {cabled.map((t) => (
                  <button key={t.id} type="button" className="ui-btn sm" data-testid={`trace-from-${t.term_side}`} onClick={() => setTraceSide(t.term_side)}>{t.term_side} end</button>
                ))}
              </div>
            )}
            {traceFrom
              ? <TraceBody kind="circuit_termination" id={traceFrom.id} />
              : <PanelEmpty icon="route" title="Nothing to trace" message="Neither end of this circuit is cabled to a port, so there is no cable path to follow." />}
          </div>
          {editing && (
            <ObjectFormModal write={write} icon="cable" title={`Edit ${c.cid}`} editId={c.id}
              fields={circuitFields(providers.data?.rows ?? [], accounts.data?.rows ?? [], types.data?.rows ?? [])}
              initial={circuitInitial(c)} onClose={() => setEditing(false)} />
          )}
          {deleting && (
            <ObjectDeleteModal write={write} id={c.id} what={`circuit ${c.cid}`} onClose={() => setDeleting(false)} onDeleted={() => { void nav(OBJECT_PAGE_LENS.circuit.href); }} />
          )}
        </>
      )}
    </ObjectPageShell>
  );
}

