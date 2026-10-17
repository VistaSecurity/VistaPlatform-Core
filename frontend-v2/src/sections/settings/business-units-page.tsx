// Settings -> Business Units (DCIM 1.1). A tree of the parties assets belong to
// (NetBox Tenants), with create / edit / delete-with-reassign. Reads need
// dcim.read; every write control is behind business_units.manage.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { unwrap } from '../../lib/api-result';
import { CustomFieldsPanel } from '../inventory/dcim/custom-fields-panel';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SPage, SCard, STable, STableRow, STag, StateNote } from './kit';
import { ObjectChanges } from '../inventory/dcim/object-changes';
import { ObjectJournal } from '../inventory/dcim/object-journal';
import { ExportButton } from '../inventory/dcim/export-button';
import type { SettingsNavItem } from './nav';
import {
  BUSINESS_UNITS_KEY, MAX_BUSINESS_UNIT_DEPTH, descendantIds, flattenTree, levelOf, useBusinessUnits,
  type BusinessUnit,
} from './business-units-queries';

const MANAGE = TENANT_PERMISSIONS.business_units.manage;

export function BusinessUnitsPage({ meta }: { meta: SettingsNavItem }) {
  const [createOpen, setCreateOpen] = useState(false);
  const [edit, setEdit] = useState<BusinessUnit | null>(null);
  const [del, setDel] = useState<BusinessUnit | null>(null);
  const q = useBusinessUnits();
  const units = q.data ?? [];
  const rows = flattenTree(units);
  const cols = [
    { label: 'Name' }, { label: 'Slug', w: '180px' }, { label: 'Assets', w: '80px', align: 'right' as const },
    { label: '', w: '88px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="Infrastructure" title="Business Units" job={meta.job}
      actions={
        <>
          <ExportButton kind="business_unit" />
          <PermissionGate permission={MANAGE}>
            <button className="ui-btn sm accent" onClick={() => setCreateOpen(true)}><Icon name="plus" size={14} />New business unit</button>
          </PermissionGate>
        </>
      }
    >
      {q.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load business units" message="The business unit list failed to load." /></SCard>
      ) : q.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading business units…" message="Fetching the business unit tree." /></SCard>
      ) : units.length === 0 ? (
        <SCard><StateNote icon="building-2" tone="var(--app-t3)" title="No business units" message="No business units are defined yet. Create one, then assign assets to it from the asset form." /></SCard>
      ) : (
        <STable cols={cols}>
          {rows.map(({ unit, depth }, i) => (
            <STableRow key={unit.id} first={i === 0} cols={cols} cells={[
              <span data-testid="bu-name" style={{ fontSize: 12.5, color: 'var(--app-t1)', paddingLeft: depth * 18 }}>
                {depth > 0 && <span style={{ color: 'var(--app-t3)', marginRight: 6 }}>↳</span>}
                <span style={{ fontWeight: 600 }}>{unit.name}</span>
                {unit.description && <span style={{ color: 'var(--app-t3)', marginLeft: 8 }}>{unit.description}</span>}
              </span>,
              <STag>{unit.slug}</STag>,
              <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{unit.asset_count}</span>,
              <PermissionGate permission={MANAGE} fallback={<span />}>
                <span style={{ display: 'inline-flex', justifyContent: 'flex-end', gap: 6 }}>
                  <button className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${unit.name}`} onClick={() => setEdit(unit)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Delete" aria-label={`Delete ${unit.name}`} onClick={() => setDel(unit)}><Icon name="x" size={13} /></button>
                </span>
              </PermissionGate>,
            ]} />
          ))}
        </STable>
      )}

      {(createOpen || edit) && <BusinessUnitModal key={edit?.id ?? 'new'} open unit={edit} units={units} onClose={() => { setCreateOpen(false); setEdit(null); }} />}
      {del && <DeleteBusinessUnitModal open unit={del} units={units} onClose={() => setDel(null)} />}
    </SPage>
  );
}

export function BusinessUnitModal({ open, unit, units, onClose }: {
  open: boolean; unit: BusinessUnit | null; units: readonly BusinessUnit[]; onClose: () => void;
}) {
  const qc = useQueryClient();
  const isEdit = !!unit;
  // Form state is keyed by the unit being edited: the modal remounts its form
  // (see the `key` where <BusinessUnitModal> is rendered) instead of resetting state in
  // an effect, which the react-hooks lint flags as a cascading render.
  const [name, setName] = useState(unit?.name ?? '');
  const [slug, setSlug] = useState(unit?.slug ?? '');
  const [parentId, setParentId] = useState(unit?.parent_id ?? '');
  const [description, setDescription] = useState(unit?.description ?? '');

  // A unit cannot go under itself or its own descendants, nor deeper than the cap.
  const blocked = unit ? descendantIds(units, unit.id) : new Set<string>();
  const parentOptions = flattenTree(units).filter(({ unit: u }) => !blocked.has(u.id) && levelOf(units, u.id) < MAX_BUSINESS_UNIT_DEPTH);
  const valid = name.trim().length > 0;

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(),
        // On create the slug is derived unless typed; on edit it is sent as shown.
        ...(slug.trim() ? { slug: slug.trim() } : {}),
        parent_id: parentId || null,
        description: description.trim() || null,
      };
      const res = isEdit
        ? await clients.inventory.PUT('/dcim/business-units/{id}', { params: { path: { id: unit.id } }, body })
        : await clients.inventory.POST('/dcim/business-units', { body });
      unwrap(res, 'Failed to save business unit');
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: BUSINESS_UNITS_KEY }); onClose(); },
  });

  return (
    <Modal
      open={open} onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending}
      size="md" tone="accent" icon="building-2" eyebrow="Infrastructure · Business Units"
      title={isEdit ? `Edit ${unit.name}` : 'New business unit'}
      description="A business unit is the party an asset belongs to or is billed to. Units nest up to four levels."
      primary={<button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create business unit'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Finance" /></ModalField>
      <ModalField label="Slug" hint="Optional — derived from the name when left empty.">
        <ModalInput aria-label="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="finance" />
      </ModalField>
      <ModalField label="Parent business unit" hint="Optional — nest under another unit.">
        <ModalSelect aria-label="Parent business unit" value={parentId} onChange={(e) => setParentId(e.target.value)}>
          <option value="">None (top level)</option>
          {parentOptions.map(({ unit: u, depth }) => <option key={u.id} value={u.id}>{`${'  '.repeat(depth)}${u.name}`}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Description">
        <ModalInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" />
      </ModalField>
      {isEdit && (
        <div data-testid="bu-custom-fields" style={{ marginTop: 6 }}>
          {/* Custom fields (DCIM row 5.1): saved on their own through the
              unit's PUT, which changes only the fields named. */}
          <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Custom fields</div>
          <CustomFieldsPanel kind="business_unit" id={unit.id} values={unit.custom_fields} permission={TENANT_PERMISSIONS.business_units.manage}
            onChange={async (custom_fields) => {
              unwrap(await clients.inventory.PUT('/dcim/business-units/{id}', { params: { path: { id: unit.id } }, body: { custom_fields } }), 'Could not save the custom fields');
              void qc.invalidateQueries({ queryKey: BUSINESS_UNITS_KEY });
            }} />
        </div>
      )}
      {isEdit && (
        <div data-testid="bu-history" style={{ marginTop: 6 }}>
          <div className="eyebrow-app" style={{ margin: '4px 0 8px' }}>Changes</div>
          <ObjectChanges kind="business_unit" id={unit.id} />
          <div className="eyebrow-app" style={{ margin: '14px 0 8px' }}>Journal</div>
          <ObjectJournal kind="business_unit" id={unit.id} />
        </div>
      )}
    </Modal>
  );
}

export function DeleteBusinessUnitModal({ open, unit, units, onClose }: {
  open: boolean; unit: BusinessUnit; units: readonly BusinessUnit[]; onClose: () => void;
}) {
  const qc = useQueryClient();
  const [target, setTarget] = useState('');
  const inUse = unit.asset_count > 0;
  const others = flattenTree(units).filter(({ unit: u }) => u.id !== unit.id);
  const del = useMutation({
    mutationFn: async () => {
      const res = await clients.inventory.DELETE('/dcim/business-units/{id}', {
        params: { path: { id: unit.id }, query: target ? { reassign_to: target } : {} },
      });
      unwrap(res, 'Delete failed');
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: BUSINESS_UNITS_KEY }); onClose(); },
  });
  return (
    <Modal
      open={open} onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending}
      size="sm" tone="danger" icon="octagon-alert" eyebrow="Infrastructure · Business Units"
      title="Delete business unit?"
      description={`“${unit.name}” will be removed. Units beneath it move up one level.`}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending || (inUse && !target)} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error.message}</span> : undefined}
    >
      {inUse && (
        <ModalField label="Move its assets to" hint={`${unit.asset_count} asset${unit.asset_count === 1 ? ' is' : 's are'} assigned to this unit; choose where they go.`}>
          <ModalSelect aria-label="Move its assets to" value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">Choose a business unit…</option>
            {others.map(({ unit: u, depth }) => <option key={u.id} value={u.id}>{`${'  '.repeat(depth)}${u.name}`}</option>)}
          </ModalSelect>
        </ModalField>
      )}
    </Modal>
  );
}
