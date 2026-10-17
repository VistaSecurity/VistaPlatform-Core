// The Filters menu (DCIM BUILD_PLAN row 5.4): a lens that has a query bar offers
// the organisation's shared Saved Filters, then the caller's own, for its object
// kind, and saves the current query as a new one.
//
// A Saved Filter is exactly its query text (ADR-0006 D2): applying one writes
// the query into the bar, so the language is learned by reading what a filter
// says. The server validates the query against the kind's catalogue on save, so
// nothing in this menu can open to an error someone else's name is on.
import { useState } from 'react';
import { Link } from 'react-router';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { BUILTIN_VIEWS } from './builtin-views';
import { checkAssetQuery } from './query-editor';
import {
  savedFiltersMenuState, useDeleteFilter, useSaveFilter, useSavedFilters, type SavedFilter,
} from './saved-filter-queries';

export function SavedFilters({ kind, query, onApply, builtins = false }: {
  kind: ObjectKind;
  query: string;
  onApply: (q: string) => void;
  /** Offer the built-in filters (the assets lens's "Never scanned"). */
  builtins?: boolean;
}) {
  const listQ = useSavedFilters(kind);
  const save = useSaveFilter();
  const remove = useDeleteFilter();
  const [open, setOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [name, setName] = useState('');
  const [shared, setShared] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<SavedFilter | null>(null);

  const filters = listQ.data?.filters ?? [];
  const canShare = listQ.data?.canShare === true;
  const menu = savedFiltersMenuState(listQ, filters.length);
  const current = filters.find((f) => f.query.trim() === query.trim());
  const builtin = builtins ? BUILTIN_VIEWS.find((v) => v.query === query.trim()) : undefined;
  // The asset editor's catalogue is the one the browser can check; the server
  // checks every other kind when the filter is saved.
  const checked = kind === 'asset' ? checkAssetQuery(query) : { ok: true, canonical: query.trim() };
  const canSave = query.trim() !== '' && checked.ok;
  const sharedList = filters.filter((f) => f.shared);
  const mine = filters.filter((f) => !f.shared);

  const row = (f: SavedFilter) => (
    <div key={f.id} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 6, borderRadius: 8 }}>
      <button
        role="menuitem"
        onClick={() => { onApply(f.query); setOpen(false); }}
        style={{ display: 'block', flex: 1, minWidth: 0, textAlign: 'left', padding: '7px 9px', border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--app-t1)' }}
      >
        <div style={{ fontSize: 12.5, fontWeight: f.id === current?.id ? 700 : 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.name}</div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.query}</div>
      </button>
      {f.shared && (
        <span title="Shared with your organization" style={{ flex: 'none', color: 'var(--app-t3)', padding: '0 4px' }}><Icon name="users" size={12} /></span>
      )}
      {/* A shared filter is deleted by whoever may manage shared filters; a
          personal one by its owner, who is the only person it is listed for. */}
      {(!f.shared || canShare) && (
        <button
          className="ui-btn sm ghost" title={`Delete “${f.name}”`} aria-label={`Delete ${f.name}`}
          onClick={() => { setConfirmDelete(f); setOpen(false); }}
          style={{ color: 'var(--danger-text)', flex: 'none', padding: '0 7px' }}
        ><Icon name="trash-2" size={12} /></button>
      )}
    </div>
  );

  return (
    <>
      <div style={{ position: 'relative' }}>
        <button
          className="ui-btn" onClick={() => setOpen((o) => !o)} title="Saved Filters" aria-haspopup="menu" aria-expanded={open}
          style={{ height: 33, padding: '0 11px', fontSize: 12.5, maxWidth: 210 }}
        >
          <Icon name="bookmark" size={13} />
          <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {current ? current.name : builtin ? builtin.name : 'Filters'}
          </span>
          <Icon name="chevron-down" size={12} />
        </button>
        {open && (
          <>
            <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 30 }} />
            <div
              role="menu" data-testid="saved-filters-menu"
              style={{ position: 'absolute', zIndex: 31, top: 37, right: 0, minWidth: 268, maxHeight: 320, overflowY: 'auto', borderRadius: 11, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 12px 34px rgba(0,0,0,.24)', padding: 5 }}
            >
              {builtins && BUILTIN_VIEWS.map((v) => (
                <button
                  key={v.name} role="menuitem" className="row-hover" title={v.description}
                  onClick={() => { onApply(v.query); setOpen(false); }}
                  style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 9px', border: 'none', borderRadius: 8, background: 'transparent', cursor: 'pointer', color: 'var(--app-t1)' }}
                >
                  <div style={{ fontSize: 12.5, fontWeight: builtin === v ? 700 : 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Icon name="radar" size={12} style={{ color: 'var(--app-t3)' }} />{v.name}
                  </div>
                  <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{v.description}</div>
                </button>
              ))}
              {builtins && <div style={{ borderTop: '1px solid var(--app-border)', margin: '4px 0' }} />}
              {menu === 'loading' && <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '9px 10px' }}>Loading filters…</div>}
              {menu === 'failed' && (
                <div data-testid="saved-filters-error" style={{ fontSize: 12, color: 'var(--app-t2)', padding: '9px 10px', lineHeight: 1.5 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--danger-text)', fontWeight: 600 }}>
                    <Icon name="alert-triangle" size={12} />Couldn&rsquo;t load your saved filters
                  </div>
                  <div style={{ color: 'var(--app-t3)', marginTop: 3 }}>
                    {listQ.error instanceof Error ? listQ.error.message : 'The request failed.'} Any filters you have are still there.
                  </div>
                  <button className="ui-btn sm" onClick={() => { void listQ.refetch(); }} style={{ marginTop: 7 }}>Retry</button>
                </div>
              )}
              {menu === 'empty' && (
                <div data-testid="saved-filters-empty" style={{ fontSize: 12, color: 'var(--app-t3)', padding: '9px 10px', lineHeight: 1.5 }}>
                  No saved filters yet. Build a query, then save it here to reuse it or share it with your team.
                </div>
              )}
              {sharedList.length > 0 && <div className="eyebrow-app" style={{ padding: '6px 9px 2px' }}>Shared</div>}
              {sharedList.map(row)}
              {mine.length > 0 && <div className="eyebrow-app" style={{ padding: '6px 9px 2px' }}>Mine</div>}
              {mine.map(row)}
              <div style={{ borderTop: '1px solid var(--app-border)', marginTop: 4, paddingTop: 4 }}>
                <button
                  className="ui-btn sm" disabled={!canSave}
                  title={canSave ? 'Save the current query as a filter' : query.trim() === '' ? 'Build a query first' : 'Fix the query first'}
                  onClick={() => { setName(''); setShared(false); save.reset(); setSaveOpen(true); setOpen(false); }}
                  style={{ width: '100%', justifyContent: 'flex-start', opacity: canSave ? 1 : 0.5 }}
                ><Icon name="plus" size={12} />Save current filter…</button>
                <Link
                  to="/inventory/manage/saved-filters" role="menuitem" onClick={() => setOpen(false)}
                  className="ui-btn sm ghost" style={{ width: '100%', justifyContent: 'flex-start', marginTop: 2 }}
                ><Icon name="settings" size={12} />Manage saved views</Link>
              </div>
            </div>
          </>
        )}
      </div>

      <Modal
        open={saveOpen}
        onClose={save.isPending ? undefined : () => setSaveOpen(false)}
        dismissible={!save.isPending}
        size="sm" tone="accent" icon="bookmark" eyebrow="Saved Filters" title="Save this filter"
        description="A filter is its query. Anyone who can see it runs the same predicate, so the rows they see are the rows you saw."
        primary={
          <button
            className="ui-btn accent" disabled={!name.trim() || save.isPending}
            onClick={() => save.mutate(
              { name: name.trim(), object_kinds: [kind], query: checked.canonical || query.trim(), shared },
              { onSuccess: () => setSaveOpen(false) },
            )}
          >{save.isPending ? 'Saving…' : 'Save filter'}</button>
        }
        secondary={<button className="ui-btn" disabled={save.isPending} onClick={() => setSaveOpen(false)}>Cancel</button>}
        footerNote={save.isError ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
      >
        <ModalField label="Name">
          <ModalInput data-autofocus aria-label="Filter name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Production servers at risk" />
        </ModalField>
        <ModalField label="Query" hint="Stored in canonical form, the same predicate however you spelled it.">
          <div className="mono" style={{ padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', fontSize: 12, color: 'var(--app-t2)', wordBreak: 'break-all' }}>
            {checked.canonical || query.trim()}
          </div>
        </ModalField>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: canShare ? 'pointer' : 'not-allowed', marginBottom: 4, opacity: canShare ? 1 : 0.6 }}>
          <input type="checkbox" aria-label="Share with my organization" disabled={!canShare} checked={shared && canShare} onChange={(e) => setShared(e.target.checked)} style={{ accentColor: 'var(--accent)', marginTop: 2 }} />
          <span>
            <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Share with my organization</span>
            <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.45 }}>
              {canShare
                ? 'Everyone can use it; only people who can change organization settings can edit or delete it.'
                : 'Sharing needs permission to change organization settings. This filter will be yours alone.'}
            </span>
          </span>
        </label>
      </Modal>

      <Modal
        open={!!confirmDelete}
        onClose={remove.isPending ? undefined : () => setConfirmDelete(null)}
        dismissible={!remove.isPending}
        size="sm" tone="danger" icon="trash-2" eyebrow="Saved Filters" title="Delete this filter?"
        description={confirmDelete
          ? `“${confirmDelete.name}” will be removed${confirmDelete.shared ? ' for everyone in your organization' : ''}. The assets it selects are not affected.`
          : ''}
        primary={
          <button
            className="ui-btn" style={{ color: 'var(--danger-text)', borderColor: 'var(--danger)' }} disabled={remove.isPending}
            onClick={() => { if (confirmDelete) remove.mutate(confirmDelete.id); setConfirmDelete(null); }}
          >{remove.isPending ? 'Deleting…' : 'Delete filter'}</button>
        }
        secondary={<button className="ui-btn" disabled={remove.isPending} onClick={() => setConfirmDelete(null)}>Cancel</button>}
      />
    </>
  );
}
