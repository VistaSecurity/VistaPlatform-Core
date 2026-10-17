// Settings -> Saved Filters (DCIM BUILD_PLAN row 5.4). Every Saved Filter the
// caller can use: the organisation's shared ones and their own, with edit and
// delete. A personal filter is its owner's to change; a shared one needs
// permission to change organization settings, and the controls say so rather
// than failing on click.
import { useState } from 'react';
import { OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { SPage, SCard, STable, STableRow, STag, StateNote } from './kit';
import type { SettingsNavItem } from './nav';
import {
  SAVED_FILTER_KINDS, useDeleteFilter, useSavedFilters, useUpdateFilter, type SavedFilter,
} from '../inventory/saved-filter-queries';

const kindLabel = (k: ObjectKind) => OBJECT_KIND_LABELS[k]?.plural ?? k;

export function SavedFiltersPage({ meta }: { meta: SettingsNavItem }) {
  const q = useSavedFilters();
  const [edit, setEdit] = useState<SavedFilter | null>(null);
  const [del, setDel] = useState<SavedFilter | null>(null);
  const filters = q.data?.filters ?? [];
  const canShare = q.data?.canShare === true;
  const cols = [
    { label: 'Name', w: '1.2fr' }, { label: 'Applies to', w: '1fr' }, { label: 'Query', w: '2fr' },
    { label: 'Scope', w: '90px' }, { label: '', w: '88px', align: 'right' as const },
  ];

  return (
    <SPage eyebrow="Infrastructure" title="Saved Filters" job={meta.job}>
      {q.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load saved filters" message={q.error instanceof Error ? q.error.message : 'The saved filter list failed to load.'} /></SCard>
      ) : q.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading saved filters…" message="Fetching your filters and the ones shared with your organization." /></SCard>
      ) : filters.length === 0 ? (
        <SCard><StateNote icon="bookmark" tone="var(--app-t3)" title="No saved filters" message="Build a query on a lens with a query bar (Inventory → All assets), open Filters and choose Save current filter." /></SCard>
      ) : (
        <STable cols={cols}>
          {filters.map((f, i) => {
            const mayChange = !f.shared || canShare;
            return (
              <STableRow key={f.id} first={i === 0} cols={cols} cells={[
                <span data-testid="sf-name" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{f.name}</span>,
                <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{f.object_kinds.map(kindLabel).join(', ')}</span>,
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', wordBreak: 'break-all' }}>{f.query}</span>,
                <STag color={f.shared ? 'var(--accent)' : undefined}>{f.shared ? 'Shared' : 'Personal'}</STag>,
                mayChange ? (
                  <span style={{ display: 'inline-flex', gap: 4 }}>
                    <button className="ui-btn sm ghost" aria-label={`Edit ${f.name}`} onClick={() => setEdit(f)}><Icon name="sliders-horizontal" size={13} /></button>
                    <button className="ui-btn sm ghost" aria-label={`Delete ${f.name}`} style={{ color: 'var(--danger-text)' }} onClick={() => setDel(f)}><Icon name="trash-2" size={13} /></button>
                  </span>
                ) : (
                  <span data-testid="sf-locked" title="Editing a shared filter needs permission to change organization settings" style={{ color: 'var(--app-t3)' }}><Icon name="lock" size={13} /></span>
                ),
              ]} />
            );
          })}
        </STable>
      )}
      {edit && <EditFilterModal key={edit.id} filter={edit} canShare={canShare} onClose={() => setEdit(null)} />}
      {del && <DeleteFilterModal filter={del} onClose={() => setDel(null)} />}
    </SPage>
  );
}

function EditFilterModal({ filter, canShare, onClose }: { filter: SavedFilter; canShare: boolean; onClose: () => void }) {
  const [name, setName] = useState(filter.name);
  const [query, setQuery] = useState(filter.query);
  const [kinds, setKinds] = useState<ObjectKind[]>(filter.object_kinds);
  const [shared, setShared] = useState(filter.shared);
  const update = useUpdateFilter();
  const valid = name.trim() !== '' && query.trim() !== '' && kinds.length > 0;
  const toggle = (k: ObjectKind) => setKinds((ks) => (ks.includes(k) ? ks.filter((x) => x !== k) : [...ks, k]));
  return (
    <Modal
      open onClose={update.isPending ? undefined : onClose} dismissible={!update.isPending}
      size="md" tone="accent" icon="bookmark" eyebrow="Infrastructure · Saved Views" title={`Edit ${filter.name}`}
      description="The query is checked against every kind you choose before it is saved."
      primary={
        <button className="ui-btn accent" disabled={!valid || update.isPending}
          onClick={() => update.mutate(
            { id: filter.id, body: { name: name.trim(), query: query.trim(), object_kinds: kinds, shared, description: filter.description } },
            { onSuccess: onClose },
          )}
        >{update.isPending ? 'Saving…' : 'Save changes'}</button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={update.isPending}>Cancel</button>}
      footerNote={update.isError ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{update.error.message}</span> : undefined}
    >
      <ModalField label="Name"><ModalInput data-autofocus aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} /></ModalField>
      <ModalField label="Query"><ModalInput aria-label="Query" className="mono" value={query} onChange={(e) => setQuery(e.target.value)} /></ModalField>
      <ModalField label="Applies to">
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          {SAVED_FILTER_KINDS.map((k) => (
            <label key={k} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
              <input type="checkbox" aria-label={kindLabel(k)} checked={kinds.includes(k)} onChange={() => toggle(k)} style={{ accentColor: 'var(--accent)' }} />{kindLabel(k)}
            </label>
          ))}
        </div>
      </ModalField>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, opacity: canShare ? 1 : 0.6 }}>
        <input type="checkbox" aria-label="Share with my organization" disabled={!canShare} checked={shared} onChange={(e) => setShared(e.target.checked)} style={{ accentColor: 'var(--accent)' }} />
        Share with my organization
      </label>
    </Modal>
  );
}

function DeleteFilterModal({ filter, onClose }: { filter: SavedFilter; onClose: () => void }) {
  const del = useDeleteFilter();
  return (
    <Modal
      open onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending}
      size="sm" tone="danger" icon="trash-2" eyebrow="Infrastructure · Saved Views" title="Delete this filter?"
      description={`“${filter.name}” will be removed${filter.shared ? ' for everyone in your organization' : ''}. The objects it selects are not affected.`}
      primary={<button className="ui-btn" style={{ color: 'var(--danger-text)', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate(filter.id, { onSuccess: onClose })}>{del.isPending ? 'Deleting…' : 'Delete filter'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
    />
  );
}
