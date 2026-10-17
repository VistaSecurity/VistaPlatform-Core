// Settings → Infrastructure → Device Types (DCIM BUILD_PLAN row 2.2; ADR-0010
// D4). The device catalogue: browse by manufacturer and search, open a type to
// see its component templates by kind, import types from the NetBox community
// device-type library (YAML paste or upload), and create or edit the tenant's
// own types and their templates. Types the product ships (the library seed
// subset) are listed as "Built in" and are read-only. Reading needs `dcim.read`
// (the nav entry); every write control sits behind `dcim.manage`.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField } from '../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../inventory/dcim/substrate-states';
import { CatalogueDeleteModal, CatalogueFormModal, type CatalogueField } from '../inventory/dcim/catalogue-form';
import {
  TEMPLATE_KINDS, isPlatformRow, uHeightText, useCatalogueList, useCatalogueWrite, useImportDeviceTypes,
  useTemplateWrite, useTemplates, type DeviceType, type ImportedDeviceType, type Manufacturer, type TemplateKind,
} from '../inventory/dcim/catalogue-queries';
import { SPage, SSection, STable, STableRow, STag, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

const AIRFLOW = ['front-to-rear', 'rear-to-front', 'left-to-right', 'right-to-left', 'side-to-rear', 'rear-to-side',
  'bottom-to-top', 'top-to-bottom', 'passive', 'mixed'];

function deviceTypeFields(mfrs: Manufacturer[]): CatalogueField[] {
  return [
    { name: 'manufacturer_id', label: 'Manufacturer', kind: 'select', required: true,
      options: [{ value: '', label: 'Choose a manufacturer' }, ...mfrs.map((m) => ({ value: m.id, label: m.name }))] },
    { name: 'model', label: 'Model', required: true, placeholder: 'Catalyst 9300-48P' },
    { name: 'slug', label: 'Slug', hint: 'Left blank, it is made from the model.' },
    { name: 'part_number', label: 'Part number', mono: true, placeholder: 'C9300-48P' },
    { name: 'u_height', label: 'Height (U)', kind: 'number', hint: '0 for a device that is not rack-mounted; half units allowed.' },
    { name: 'is_full_depth', label: 'Full depth (occupies the front and rear of the rack)', kind: 'bool' },
    { name: 'airflow', label: 'Airflow', kind: 'select', options: [{ value: '', label: '—' }, ...AIRFLOW.map((a) => ({ value: a, label: a }))] },
    { name: 'description', label: 'Description' },
  ];
}

/** The editable fields of one template kind. */
function templateFields(kind: TemplateKind): CatalogueField[] {
  const base: CatalogueField[] = [{ name: 'name', label: 'Name', required: true, mono: true }, { name: 'label', label: 'Label' }];
  switch (kind) {
    case 'interface-templates':
      return [...base, { name: 'type', label: 'Type', required: true, mono: true, placeholder: '1000base-t' },
        { name: 'mgmt_only', label: 'Management only', kind: 'bool' }, { name: 'enabled', label: 'Enabled', kind: 'bool' },
        { name: 'poe_mode', label: 'PoE mode', kind: 'select', options: [{ value: '', label: '—' }, { value: 'pse', label: 'PSE (supplies power)' }, { value: 'pd', label: 'PD (draws power)' }] },
        { name: 'description', label: 'Description' }];
    case 'front-port-templates':
    case 'rear-port-templates':
      return [...base, { name: 'type', label: 'Type', required: true, mono: true, placeholder: '8p8c' }, { name: 'description', label: 'Description' }];
    case 'module-bay-templates':
      return [...base, { name: 'position', label: 'Position' }, { name: 'description', label: 'Description' }];
    case 'device-bay-templates':
      return [...base, { name: 'description', label: 'Description' }];
    default:
      return [...base, { name: 'type', label: 'Type', mono: true }, { name: 'description', label: 'Description' }];
  }
}

interface TemplateRowLike { id: string; name: string; label?: string | null; type?: string | null; description?: string | null }

function TemplatesTab({ dt, kind }: { dt: DeviceType; kind: TemplateKind }) {
  const q = useTemplates(dt.id, kind);
  const write = useTemplateWrite(dt.id, kind);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<TemplateRowLike | null>(null);
  const [deleting, setDeleting] = useState<TemplateRowLike | null>(null);
  const readOnly = isPlatformRow(dt);
  const label = TEMPLATE_KINDS.find((k) => k.kind === kind)?.label.toLowerCase() ?? 'templates';
  const rows = (q.data ?? []) as unknown as TemplateRowLike[];
  const cols: STableCol[] = [{ label: 'Name', w: '1.3fr' }, { label: 'Type', w: '1fr' }, { label: 'Label', w: '1fr' }, { label: '', w: '84px', align: 'right' }];
  return (
    <div data-testid={`templates-${kind}`}>
      {!readOnly && (
        <PermissionGate permission={MANAGE}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
            <button type="button" className="ui-btn sm" onClick={() => setAdding(true)}><Icon name="plus" size={12} />Add</button>
          </div>
        </PermissionGate>
      )}
      {q.isLoading && <PanelLoading label={`Loading ${label}…`} />}
      {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
      {q.data && rows.length === 0 && <PanelEmpty icon="list" title={`No ${label}`} message={`This device type declares no ${label}.`} />}
      {rows.length > 0 && (
        <STable cols={cols}>
          {rows.map((t, i) => (
            <STableRow key={t.id} first={i === 0} cols={cols} cells={[
              <span key="n" className="mono" data-testid="template-name">{t.name}</span>,
              <span key="t" className="mono">{t.type ?? '—'}</span>,
              t.label ?? '—',
              readOnly ? <span key="r" /> : (
                <PermissionGate key="a" permission={MANAGE} fallback={<span />}>
                  <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${t.name}`} onClick={() => setEditing(t)}><Icon name="sliders-horizontal" size={13} /></button>
                  <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${t.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(t)}><Icon name="x" size={13} /></button>
                </PermissionGate>
              ),
            ]} />
          ))}
        </STable>
      )}
      {adding && <CatalogueFormModal title="Add template" editing={false} fields={templateFields(kind)} initial={{ enabled: true }}
        onSubmit={(body) => write.create.mutateAsync(body)} onClose={() => setAdding(false)} />}
      {editing && <CatalogueFormModal title={`Edit ${editing.name}`} editing fields={templateFields(kind)} initial={editing as unknown as Record<string, unknown>}
        onSubmit={(body) => write.update.mutateAsync({ id: editing.id, body })} onClose={() => setEditing(null)} />}
      {deleting && <CatalogueDeleteModal what={deleting.name} onConfirm={() => write.remove.mutateAsync(deleting.id)} onClose={() => setDeleting(null)} />}
    </div>
  );
}

function DeviceTypeDetail({ dt, manufacturer, onClose }: { dt: DeviceType; manufacturer: string; onClose: () => void }) {
  const [kind, setKind] = useState<TemplateKind>('interface-templates');
  const lib = (dt.external_ids as { library?: { path?: string } } | undefined)?.library;
  return (
    <Modal open onClose={onClose} size="lg" icon="server" eyebrow="Infrastructure · Device Types" title={`${manufacturer} ${dt.model}`}
      description={isPlatformRow(dt) ? 'Built in: shipped with the product from the device-type library. Read-only — import or create your own type to change it.' : 'Your organization’s device type.'}
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Close</button>}>
      <div data-testid="device-type-detail" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0,1fr))', gap: 10, marginBottom: 14, fontSize: 12.5 }}>
        <div><div style={{ color: 'var(--app-t3)' }}>Part number</div><div className="mono">{dt.part_number ?? '—'}</div></div>
        <div><div style={{ color: 'var(--app-t3)' }}>Height</div><div>{uHeightText(dt.u_height)}</div></div>
        <div><div style={{ color: 'var(--app-t3)' }}>Airflow</div><div>{dt.airflow ?? '—'}</div></div>
        <div><div style={{ color: 'var(--app-t3)' }}>Library</div><div className="mono" style={{ wordBreak: 'break-all' }}>{lib?.path ?? '—'}</div></div>
      </div>
      <div role="tablist" style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
        {TEMPLATE_KINDS.map((k) => (
          <button key={k.kind} type="button" role="tab" aria-selected={kind === k.kind} className={`ui-btn sm${kind === k.kind ? ' accent' : ''}`} onClick={() => setKind(k.kind)}>{k.label}</button>
        ))}
      </div>
      <TemplatesTab key={kind} dt={dt} kind={kind} />
    </Modal>
  );
}

/** "Import from library": paste or upload devicetype-library YAML. */
export function ImportDeviceTypesModal({ onClose }: { onClose: () => void }) {
  const [yaml, setYaml] = useState('');
  const imp = useImportDeviceTypes();
  const [result, setResult] = useState<ImportedDeviceType[] | null>(null);
  const readFile = (f: File | undefined) => {
    if (!f) return;
    void f.text().then((t) => setYaml(t));
  };
  return (
    <Modal open onClose={imp.isPending ? undefined : onClose} size="lg" icon="upload" eyebrow="Infrastructure · Device Types" title="Import from library"
      description="Paste or upload one or more files from the NetBox community device-type library (github.com/netbox-community/devicetype-library). Each becomes your organization’s own device type with its interfaces and ports; a type already in the catalogue is left as it is."
      primary={result ? <button type="button" className="ui-btn accent" onClick={onClose}>Done</button> : (
        <button type="button" className="ui-btn accent" data-testid="import-submit" disabled={!yaml.trim() || imp.isPending}
          onClick={() => { imp.mutateAsync(yaml).then(setResult, () => undefined); }}>
          {imp.isPending ? 'Importing…' : 'Import'}
        </button>
      )}
      secondary={result ? undefined : <button type="button" className="ui-btn" onClick={onClose} disabled={imp.isPending}>Cancel</button>}>
      {imp.isError && <div role="alert" data-testid="catalogue-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 10 }}>{imp.error.message}</div>}
      {result ? (
        <div data-testid="import-result">
          {result.map((r) => (
            <div key={`${r.manufacturer}/${r.model}`} style={{ padding: '7px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
              <span style={{ fontWeight: 600 }}>{r.manufacturer} {r.model}</span>{' '}
              <STag>{r.status === 'created' ? `Imported · ${r.templates} templates` : 'Already in the catalogue'}</STag>
              {r.warnings.length > 0 && (
                <ul style={{ margin: '4px 0 0 18px', color: 'var(--app-t3)' }}>{r.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
              )}
            </div>
          ))}
        </div>
      ) : (
        <>
          <ModalField label="Library YAML" hint="Separate several files with a line containing only ---.">
            <textarea aria-label="Library YAML" value={yaml} onChange={(e) => setYaml(e.target.value)} rows={12} spellCheck={false} className="mono"
              placeholder={'manufacturer: Cisco\nmodel: Catalyst 9300-48P\nslug: cisco-c9300-48p\nu_height: 1\ninterfaces:\n  - name: GigabitEthernet1/0/1\n    type: 1000base-t'}
              style={{ width: '100%', padding: '8px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12 }} />
          </ModalField>
          <ModalField label="Or upload a file">
            <input type="file" aria-label="Upload a library file" accept=".yaml,.yml,text/yaml" onChange={(e) => readFile(e.target.files?.[0])} />
          </ModalField>
        </>
      )}
    </Modal>
  );
}

export function DeviceTypesPage({ meta }: { meta: SettingsNavItem }) {
  const [mfr, setMfr] = useState('');
  const [scope, setScope] = useState('');
  const [q, setQ] = useState('');
  const query: Record<string, string | number> = { limit: 500 };
  if (mfr) query.manufacturer_id = mfr;
  if (scope) query.scope = scope;
  if (q.trim()) query.q = q.trim();
  const list = useCatalogueList('device-types', query);
  const mfrs = useCatalogueList('manufacturers', { limit: 1000 });
  const write = useCatalogueWrite('device-types');
  const [open, setOpen] = useState<DeviceType | null>(null);
  const [importing, setImporting] = useState(false);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<DeviceType | null>(null);
  const [deleting, setDeleting] = useState<DeviceType | null>(null);
  const rows = list.data?.rows ?? [];
  const mfrRows = mfrs.data?.rows ?? [];
  const mfrName = (dt: DeviceType) => dt.manufacturer?.name ?? mfrRows.find((m) => m.id === dt.manufacturer_id)?.name ?? '—';
  const cols: STableCol[] = [
    { label: 'Manufacturer', w: '1fr' }, { label: 'Model', w: '1.5fr' }, { label: 'Part number', w: '1fr' },
    { label: 'Height', w: '0.6fr' }, { label: 'Interfaces', w: '0.6fr', align: 'right' }, { label: '', w: '84px', align: 'right' },
  ];
  const selectStyle = { padding: '5px 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5 };

  return (
    <SPage eyebrow="Infrastructure" title="Device Types" job={meta.job} actions={(
      <PermissionGate permission={MANAGE}>
        <span style={{ display: 'inline-flex', gap: 8 }}>
          <button type="button" className="ui-btn sm" onClick={() => setImporting(true)}><Icon name="upload" size={14} />Import from library</button>
          <button type="button" className="ui-btn sm accent" onClick={() => setAdding(true)}><Icon name="plus" size={14} />New device type</button>
        </span>
      </PermissionGate>
    )}>
      <SSection title="Catalogue" desc="Hardware models, with the interfaces and ports each one has. Assign one to an asset from the asset form; “Apply templates” on the asset’s Hardware card creates its interfaces." action={(
        <span style={{ display: 'inline-flex', gap: 8 }}>
          <select aria-label="Manufacturer" value={mfr} onChange={(e) => setMfr(e.target.value)} style={selectStyle}>
            <option value="">All manufacturers</option>
            {mfrRows.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </select>
          <select aria-label="Source" value={scope} onChange={(e) => setScope(e.target.value)} style={selectStyle}>
            <option value="">Built in and yours</option>
            <option value="platform">Built in</option>
            <option value="tenant">Yours</option>
          </select>
          <input aria-label="Search device types" placeholder="Search model or part number" value={q} onChange={(e) => setQ(e.target.value)} style={{ ...selectStyle, width: 220 }} />
        </span>
      )}>
        <div data-testid="device-types">
          {list.isLoading && <PanelLoading label="Loading device types…" />}
          {list.isError && <PanelError message={list.error instanceof Error ? list.error.message : 'Request failed'} onRetry={() => { void list.refetch(); }} />}
          {list.data && rows.length === 0 && (
            <PanelEmpty icon="server" title={mfr || scope || q.trim() ? 'No device types match' : 'No device types'}
              message="Import a type from the device-type library, or create one." />
          )}
          {rows.length > 0 && (
            <>
              <STable cols={cols}>
                {rows.map((dt, i) => (
                  <STableRow key={dt.id} first={i === 0} cols={cols} onClick={() => setOpen(dt)} cells={[
                    mfrName(dt),
                    <span key="m" data-testid="device-type-model" style={{ fontWeight: 600 }}>{dt.model}</span>,
                    <span key="p" className="mono">{dt.part_number ?? '—'}</span>,
                    uHeightText(dt.u_height),
                    <span key="i" className="mono">{dt.interface_template_count ?? '—'}</span>,
                    isPlatformRow(dt) ? <STag key="b">Built in</STag> : (
                      <PermissionGate key="a" permission={MANAGE} fallback={<span />}>
                        <span onClick={(e) => e.stopPropagation()} style={{ display: 'inline-flex' }}>
                          <button type="button" className="ui-btn sm ghost" title="Edit" aria-label={`Edit ${dt.model}`} onClick={() => setEditing(dt)}><Icon name="sliders-horizontal" size={13} /></button>
                          <button type="button" className="ui-btn sm ghost" title="Delete" aria-label={`Delete ${dt.model}`} style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(dt)}><Icon name="x" size={13} /></button>
                        </span>
                      </PermissionGate>
                    ),
                  ]} />
                ))}
              </STable>
              {(list.data?.total ?? 0) > rows.length && (
                <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 8 }}>Showing {rows.length} of {list.data?.total}. Narrow by manufacturer or search.</div>
              )}
            </>
          )}
        </div>
      </SSection>

      {open && <DeviceTypeDetail dt={open} manufacturer={mfrName(open)} onClose={() => setOpen(null)} />}
      {importing && <ImportDeviceTypesModal onClose={() => setImporting(false)} />}
      {adding && <CatalogueFormModal title="New device type" editing={false} fields={deviceTypeFields(mfrRows)} initial={{ u_height: 1, is_full_depth: true }}
        onSubmit={(body) => write.create.mutateAsync(body)} onClose={() => setAdding(false)} />}
      {editing && (
        <CatalogueFormModal title={`Edit ${editing.model}`} editing fields={deviceTypeFields(mfrRows)}
          initial={{ manufacturer_id: editing.manufacturer_id, model: editing.model, slug: editing.slug, part_number: editing.part_number ?? '',
            u_height: editing.u_height, is_full_depth: editing.is_full_depth, airflow: editing.airflow ?? '', description: editing.description ?? '' }}
          onSubmit={(body) => write.update.mutateAsync({ id: editing.id, body })} onClose={() => setEditing(null)} />
      )}
      {deleting && <CatalogueDeleteModal what={deleting.model} onConfirm={() => write.remove.mutateAsync(deleting.id)} onClose={() => setDeleting(null)} />}
    </SPage>
  );
}
