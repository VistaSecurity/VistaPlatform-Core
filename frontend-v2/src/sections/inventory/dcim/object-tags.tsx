// <ObjectTags kind id /> — the tags on one object (`object_tags`) as chips,
// with an editor for dcim.manage. Saving PUTs the object's new tag set; the
// server applies the difference and records it as one change on the object.
//
// On the asset page this reads the substrate's tags, NOT the legacy
// `assets.tags` map the Overview tab still shows; the two meet when phase 1.1
// retires the column.
import { useMemo, useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import { useCreateTag, useObjectTags, useSetObjectTags, useTags, type Tag } from './substrate-queries';

function Chip({ tag }: { tag: Tag }) {
  const color = tag.color ? `#${tag.color}` : 'var(--app-t3)';
  return (
    <span data-testid="tag-chip" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, padding: '2px 8px', borderRadius: 40, border: '1px solid var(--app-border2)', color: 'var(--app-t1)' }}>
      <span aria-hidden style={{ width: 7, height: 7, borderRadius: 7, background: color }} />
      {tag.name}
    </span>
  );
}

/** Whether a tag may go on an object of `kind` (empty restriction = any). */
export function tagAppliesTo(tag: Tag, kind: ObjectKind): boolean {
  return tag.object_kinds.length === 0 || tag.object_kinds.includes(kind);
}

function Editor({ kind, id, current, onClose }: { kind: ObjectKind; id: string; current: Tag[]; onClose: () => void }) {
  const all = useTags();
  const save = useSetObjectTags(kind, id);
  const create = useCreateTag();
  const [selected, setSelected] = useState<Set<string>>(() => new Set(current.map((t) => t.id)));
  const [newName, setNewName] = useState('');
  const choices = useMemo(() => (all.data ?? []).filter((t) => tagAppliesTo(t, kind)), [all.data, kind]);

  const toggle = (tid: string) => setSelected((s) => {
    const next = new Set(s);
    if (next.has(tid)) next.delete(tid); else next.add(tid);
    return next;
  });
  const addNew = () => {
    const name = newName.trim();
    if (!name) return;
    create.mutate(name, {
      onSuccess: (t) => {
        setSelected((s) => new Set(s).add(t.id));
        setNewName('');
      },
    });
  };
  const unchanged = selected.size === current.length && current.every((t) => selected.has(t.id));

  return (
    <div role="dialog" aria-label="Edit tags" style={{ marginTop: 8, padding: 12, borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', maxWidth: 420 }}>
      {all.isLoading && <div data-testid="tags-editor-loading" style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading tags…</div>}
      {all.isError && (
        <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>
          {all.error instanceof Error ? all.error.message : 'Failed to load tags'}{' '}
          <button type="button" className="ui-btn sm" onClick={() => { void all.refetch(); }}>Retry</button>
        </div>
      )}
      {all.isSuccess && choices.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No tags yet. Create the first one below.</div>
      )}
      {choices.length > 0 && (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, maxHeight: 200, overflowY: 'auto' }}>
          {choices.map((t) => (
            <li key={t.id}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12.5, padding: '3px 0', cursor: 'pointer' }}>
                <input type="checkbox" checked={selected.has(t.id)} onChange={() => toggle(t.id)} />
                <Chip tag={t} />
              </label>
            </li>
          ))}
        </ul>
      )}
      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
        <input
          aria-label="New tag name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addNew(); } }}
          placeholder="New tag"
          maxLength={100}
          className="ui-input"
          style={{ flex: 1, height: 28, fontSize: 12.5 }}
        />
        <button type="button" className="ui-btn sm" onClick={addNew} disabled={!newName.trim() || create.isPending}>
          <Icon name="plus" size={12} />Create
        </button>
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginTop: 10 }}>
        <button type="button" className="ui-btn sm" onClick={onClose}>Cancel</button>
        <button
          type="button"
          className="ui-btn sm primary"
          disabled={unchanged || save.isPending}
          onClick={() => save.mutate([...selected], { onSuccess: onClose })}
        >
          {save.isPending ? 'Saving…' : 'Save tags'}
        </button>
      </div>
    </div>
  );
}

export function ObjectTags({ kind, id }: { kind: ObjectKind; id: string }) {
  const q = useObjectTags(kind, id);
  const [editing, setEditing] = useState(false);
  const tags = q.data ?? [];

  return (
    <div data-testid="object-tags" style={{ marginTop: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 5 }}>
        <Icon name="tags" size={12} style={{ color: 'var(--app-t3)' }} />
        {q.isLoading && <span data-testid="tags-loading" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Loading tags…</span>}
        {q.isError && (
          <span role="alert" style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>
            Tags unavailable{' '}
            <button type="button" className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button>
          </span>
        )}
        {q.isSuccess && tags.length === 0 && <span data-testid="tags-empty" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No tags</span>}
        {tags.map((t) => <Chip key={t.id} tag={t} />)}
        {q.isSuccess && !editing && (
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            <button type="button" className="ui-btn sm" onClick={() => setEditing(true)} style={{ height: 22, fontSize: 11.5 }}>
              <Icon name="tag" size={11} />Edit tags
            </button>
          </PermissionGate>
        )}
      </div>
      {editing && <Editor kind={kind} id={id} current={tags} onClose={() => setEditing(false)} />}
    </div>
  );
}
