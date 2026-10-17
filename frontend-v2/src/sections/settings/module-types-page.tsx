// Settings → Module Types (DCIM BUILD_PLAN row 2.4; asset-inventory ADR-0010
// D4): the module-type catalogue an asset's Install module dialog searches —
// the platform's (read-only) and the organisation's own. A module type's
// templates (interfaces with NetBox's {module} placeholder, ports, nested
// module bays) are placed on an asset when a module of the type is installed.
// Row 2.2 left module types API-only; its Device Types page is not on main
// yet, so this is its own Settings page until that page can take it as a tab.
// Reads need dcim.read; create and delete need dcim.manage.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, StateNote } from './kit';
import {
  isPlatformRow, useCreateModuleType, useDeleteModuleType, useManufacturers, useModuleTypes, type ModuleType,
} from '../inventory/dcim/hardware-queries';
import type { SettingsNavItem } from './nav';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

export function ModuleTypesPage({ meta }: { meta: SettingsNavItem }) {
  const [q, setQ] = useState('');
  const types = useModuleTypes(q);
  const manufacturers = useManufacturers();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<ModuleType | null>(null);
  const del = useDeleteModuleType();
  const mfrName = new Map((manufacturers.data ?? []).map((m) => [m.id, m.name]));
  const cols = [
    { label: 'Model' }, { label: 'Manufacturer', w: '180px' }, { label: 'Part number', w: '170px' },
    { label: 'Source', w: '100px' }, { label: '', w: '60px', align: 'right' as const },
  ];
  const rows = types.data ?? [];

  return (
    <SPage
      eyebrow="Infrastructure" title="Module Types" job={meta.job} maxWidth={1100}
      actions={
        <PermissionGate permission={MANAGE}>
          <button className="ui-btn sm accent" onClick={() => setCreating(true)}><Icon name="plus" size={14} />New module type</button>
        </PermissionGate>
      }
    >
      <div style={{ marginBottom: 12 }}>
        <ModalInput aria-label="Search module types" placeholder="Search by model or part number" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {types.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load module types" message={types.error instanceof Error ? types.error.message : 'The module type list failed to load.'} /></SCard>
      ) : types.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading module types…" message="Fetching the platform's and your organisation's module types." /></SCard>
      ) : rows.length === 0 ? (
        <SCard><StateNote icon="blocks" tone="var(--app-t3)" title="No module types" message={q.trim()
          ? 'No module type matches that search.'
          : 'No module types are defined. Add one (a line card, a network module, a power supply) to install it into an asset\'s module bays.'} /></SCard>
      ) : (
        <SSection title="Module types">
          <STable cols={cols}>
            {rows.map((t, i) => (
              <STableRow key={t.id} first={i === 0} cols={cols} cells={[
                <span data-testid="module-type-row" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{t.model}</span>,
                <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{mfrName.get(t.manufacturer_id) ?? '—'}</span>,
                <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{t.part_number ?? '—'}</span>,
                <STag>{isPlatformRow(t) ? 'Platform' : 'Yours'}</STag>,
                isPlatformRow(t) ? <span /> : (
                  <PermissionGate permission={MANAGE} fallback={<span />}>
                    <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} aria-label={`Delete ${t.model}`} title="Delete" onClick={() => setDeleting(t)}>
                      <Icon name="x" size={13} />
                    </button>
                  </PermissionGate>
                ),
              ]} />
            ))}
          </STable>
        </SSection>
      )}
      {creating && <CreateModuleTypeModal onClose={() => setCreating(false)} />}
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title={`Delete ${deleting?.model ?? 'module type'}?`}
        description="A module type an installed module uses cannot be deleted; remove those modules first."
        secondary={<button type="button" className="ui-btn" onClick={() => setDeleting(null)}>Cancel</button>}
        primary={(
          <button type="button" className="ui-btn danger" disabled={del.isPending}
            onClick={() => { if (deleting) del.mutate(deleting, { onSettled: () => setDeleting(null) }); }}>
            Delete
          </button>
        )}
      />
    </SPage>
  );
}

function CreateModuleTypeModal({ onClose }: { onClose: () => void }) {
  const manufacturers = useManufacturers();
  const create = useCreateModuleType();
  const [manufacturerId, setManufacturerId] = useState('');
  const [model, setModel] = useState('');
  const [partNumber, setPartNumber] = useState('');
  const [error, setError] = useState<string | null>(null);
  const problem = !manufacturerId ? 'Choose a manufacturer.' : !model.trim() ? 'A model is required.' : null;
  return (
    <Modal
      open
      onClose={onClose}
      icon="blocks"
      title="New module type"
      description="Add its interface, port and module bay templates through the API; {module} in a template name becomes the position of the bay a module is installed in."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={(
        <button type="button" className="ui-btn primary" disabled={!!problem || create.isPending}
          onClick={() => {
            setError(null);
            create.mutate({ manufacturer_id: manufacturerId, model: model.trim(), part_number: partNumber.trim() || null },
              { onSuccess: onClose, onError: (e) => setError(e.message) });
          }}>
          Create
        </button>
      )}
    >
      <div data-testid="module-type-form">
        <ModalField label="Manufacturer">
          <ModalSelect aria-label="Manufacturer" value={manufacturerId} onChange={(e) => setManufacturerId(e.target.value)}>
            <option value="">Choose a manufacturer…</option>
            {(manufacturers.data ?? []).map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Model">
          <ModalInput aria-label="Model" value={model} onChange={(e) => setModel(e.target.value)} />
        </ModalField>
        <ModalField label="Part number" hint="Discovery installs a module whose reported part number matches.">
          <ModalInput aria-label="Part number" value={partNumber} onChange={(e) => setPartNumber(e.target.value)} />
        </ModalField>
        {error && <div data-testid="module-type-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{error}</div>}
      </div>
    </Modal>
  );
}
