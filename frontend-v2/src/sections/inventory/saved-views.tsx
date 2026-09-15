// Saved views — a named, shareable query string (ADR-0006 D2).
//
// "Saved views are the beginner's surface; the facet rail writes the query for
// them and shows it, so the language is learned by reading." A view is exactly
// its query text, which is why there is no separate "view definition" model to
// keep in step with the language: saving is storing the canonical form of what
// is already in the URL.
import { useState } from 'react';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';
import { useCreateSavedView, useDeleteSavedView, useSavedViews, type SavedView } from './asset-queries';
import { checkAssetQuery } from './query-editor';

/**
 * What the views menu should show.
 *
 * "No saved views yet" is a statement about the tenant's data, and a failed
 * read is not evidence for it — a user whose views did not load was told they
 * had none and invited to create one they may already have. A failure gets its
 * own state and a retry.
 */
export function savedViewsMenuState(
  q: { isLoading: boolean; isError: boolean },
  count: number,
): 'loading' | 'failed' | 'empty' | 'list' {
  if (q.isError) return 'failed';
  if (q.isLoading) return 'loading';
  return count === 0 ? 'empty' : 'list';
}

export function SavedViews({ query, onApply }: { query: string; onApply: (q: string) => void }) {
  const viewsQ = useSavedViews();
  const create = useCreateSavedView();
  const remove = useDeleteSavedView();
  const [open, setOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [name, setName] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<SavedView | null>(null);
  const [shared, setShared] = useState(true);

  const views = viewsQ.data ?? [];
  const menu = savedViewsMenuState(viewsQ, views.length);
  const current = views.find((v) => v.query.trim() === query.trim());
  // Only a VALID query can be saved. A saved view is a predicate other people
  // will run; storing one that does not parse would hand them an error card
  // with someone else's name on it.
  const checked = checkAssetQuery(query);
  const canSave = query.trim() !== '' && checked.ok;

  return (
    <>
      <div style={{ position: 'relative' }}>
        <button
          className="ui-btn"
          onClick={() => setOpen((o) => !o)}
          title="Saved views"
          style={{ height: 33, padding: '0 11px', fontSize: 12.5, maxWidth: 210 }}
        >
          <Icon name="bookmark" size={13} />
          <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {current ? current.name : 'Views'}
          </span>
          <Icon name="chevron-down" size={12} />
        </button>
        {open && (
          <>
            <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 30 }} />
            <div
              role="menu"
              style={{ position: 'absolute', zIndex: 31, top: 37, right: 0, minWidth: 268, maxHeight: 320, overflowY: 'auto', borderRadius: 11, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 12px 34px rgba(0,0,0,.24)', padding: 5 }}
            >
              {menu === 'loading' && <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '9px 10px' }}>Loading views…</div>}
              {menu === 'failed' && (
                <div data-testid="saved-views-error" style={{ fontSize: 12, color: 'var(--app-t2)', padding: '9px 10px', lineHeight: 1.5 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--danger-text)', fontWeight: 600 }}>
                    <Icon name="alert-triangle" size={12} />Couldn&rsquo;t load your saved views
                  </div>
                  <div style={{ color: 'var(--app-t3)', marginTop: 3 }}>
                    {viewsQ.error instanceof Error ? viewsQ.error.message : 'The request failed.'} Any views you have are still there.
                  </div>
                  <button className="ui-btn sm" onClick={() => { void viewsQ.refetch(); }} style={{ marginTop: 7 }}>Retry</button>
                </div>
              )}
              {menu === 'empty' && (
                <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '9px 10px', lineHeight: 1.5 }}>
                  No saved views yet. Build a filter, then save it here to share the exact query with your team.
                </div>
              )}
              {views.map((v) => (
                <div key={v.id} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 6, borderRadius: 8 }}>
                  <button
                    onClick={() => { onApply(v.query); setOpen(false); }}
                    style={{ display: 'block', flex: 1, minWidth: 0, textAlign: 'left', padding: '7px 9px', border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--app-t1)' }}
                  >
                    <div style={{ fontSize: 12.5, fontWeight: v.id === current?.id ? 700 : 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v.name}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v.query || 'everything'}</div>
                  </button>
                  {/* Only a view's OWNER may edit or delete it — sharing is
                      publishing, not handing over — and the server enforces
                      that. This list does not know who the caller is, so the
                      button stays and a refusal surfaces as a toast rather than
                      the row guessing and hiding it from the person who can. */}
                  {v.is_shared && (
                    <span title="Shared with your organization" style={{ flex: 'none', color: 'var(--app-t3)', padding: '0 4px' }}>
                      <Icon name="users" size={12} />
                    </span>
                  )}
                  <button
                    className="ui-btn sm ghost"
                    title={`Delete “${v.name}”`}
                    aria-label={`Delete ${v.name}`}
                    onClick={() => { setConfirmDelete(v); setOpen(false); }}
                    style={{ color: 'var(--danger-text)', flex: 'none', padding: '0 7px' }}
                  >
                    <Icon name="trash-2" size={12} />
                  </button>
                </div>
              ))}
              <div style={{ borderTop: '1px solid var(--app-border)', marginTop: 4, paddingTop: 4 }}>
                <button
                  className="ui-btn sm"
                  disabled={!canSave}
                  title={canSave ? 'Save the current query as a view' : query.trim() === '' ? 'Build a filter first' : 'Fix the query first'}
                  onClick={() => { setName(''); setShared(true); setSaveOpen(true); setOpen(false); }}
                  style={{ width: '100%', justifyContent: 'flex-start', opacity: canSave ? 1 : 0.5 }}
                >
                  <Icon name="plus" size={12} />Save current query…
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      <Modal
        open={saveOpen}
        onClose={create.isPending ? undefined : () => setSaveOpen(false)}
        dismissible={!create.isPending}
        size="sm"
        tone="accent"
        icon="bookmark"
        eyebrow="Inventory"
        title="Save this view"
        description="A view is its query. Anyone you share the link with runs the same predicate, so the rows they see are the rows you saw."
        primary={
          <button
            className="ui-btn accent"
            disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate(
              { name: name.trim(), query: checked.canonical, is_shared: shared },
              { onSuccess: () => setSaveOpen(false) },
            )}
          >
            {create.isPending ? 'Saving…' : 'Save view'}
          </button>
        }
        secondary={<button className="ui-btn" disabled={create.isPending} onClick={() => setSaveOpen(false)}>Cancel</button>}
      >
        <ModalField label="Name">
          <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Production servers at risk" />
        </ModalField>
        <ModalField label="Query" hint="Stored in canonical form — the same predicate however you spelled it.">
          <div className="mono" style={{ padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', fontSize: 12, color: 'var(--app-t2)', wordBreak: 'break-all' }}>
            {checked.canonical || 'everything'}
          </div>
        </ModalField>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', marginBottom: 4 }}>
          <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} style={{ accentColor: 'var(--accent)', marginTop: 2 }} />
          <span>
            <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Share with my organization</span>
            <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.45 }}>
              Everyone can open it; only you can edit or delete it. Leave it off to keep the view to yourself.
            </span>
          </span>
        </label>
      </Modal>

      <Modal
        open={!!confirmDelete}
        onClose={remove.isPending ? undefined : () => setConfirmDelete(null)}
        dismissible={!remove.isPending}
        size="sm"
        tone="danger"
        icon="trash-2"
        eyebrow="Saved views"
        title="Delete this view?"
        description={confirmDelete
          ? `“${confirmDelete.name}” will be removed${confirmDelete.is_shared ? ' for everyone in your organization' : ''}. The assets it selects are not affected. Only the view's owner may delete it.`
          : ''}
        primary={
          <button
            className="ui-btn"
            style={{ color: 'var(--danger-text)', borderColor: 'var(--danger)' }}
            disabled={remove.isPending}
            onClick={() => { if (confirmDelete) remove.mutate(confirmDelete.id); setConfirmDelete(null); }}
          >
            {remove.isPending ? 'Deleting…' : 'Delete view'}
          </button>
        }
        secondary={<button className="ui-btn" disabled={remove.isPending} onClick={() => setConfirmDelete(null)}>Cancel</button>}
      />
    </>
  );
}
