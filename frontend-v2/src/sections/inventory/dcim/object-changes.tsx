// <ObjectChanges kind id /> — the change record of one object (`object_changes`,
// asset-inventory ADR-0010 D5). Reusable on any object page; the asset page is
// its first home (DCIM BUILD_PLAN row 0.3). Row 5.2 added the per-change diff
// (click "Show changes"), `includeRelated` (an asset's tab also lists its
// interfaces', addresses' and journal changes) and the Inventory → Changes lens.
import { useState } from 'react';
import { OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import { ChangeDiff } from './change-diff';
import { useObjectChanges, type ObjectChange } from './substrate-queries';
import { PanelEmpty, PanelError, PanelLoading, whenText } from './substrate-states';

const ACTION_TEXT: Record<ObjectChange['action'], { verb: string; icon: string }> = {
  create: { verb: 'Created', icon: 'plus' },
  update: { verb: 'Updated', icon: 'sliders-horizontal' },
  delete: { verb: 'Deleted', icon: 'trash-2' },
};

/** Where a change came from, in words. */
export function changeSourceText(source: string): string {
  if (source === 'ui') return 'Web UI';
  if (source === 'api') return 'API';
  if (source === 'system') return 'System';
  if (source.startsWith('intake:')) return `Discovery (${source.slice('intake:'.length)})`;
  if (source.startsWith('sync:')) return `Sync (${source.slice('sync:'.length)})`;
  return source;
}

function ChangeRow({ c, panelKind }: { c: ObjectChange; panelKind: ObjectKind }) {
  const [open, setOpen] = useState(false);
  const a = ACTION_TEXT[c.action];
  const when = whenText(c.created_at);
  // user_name is stored with the change (the actor's email at the time), so a
  // missing one means the actor had none — not that the user was deleted.
  const who = c.user_name ?? (c.user_id ? 'A user' : changeSourceText(c.source));
  return (
    <li data-testid="change-row" style={{ display: 'flex', gap: 10, padding: '9px 0', borderBottom: '1px solid var(--app-border)' }}>
      <Icon name={a.icon} size={14} style={{ color: 'var(--app-t3)', flex: 'none', marginTop: 2 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>
          {/* A related object's change names what changed; the object's own does not. */}
          {c.object_kind !== panelKind && (
            <span>{OBJECT_KIND_LABELS[c.object_kind]?.uiLabel ?? c.object_kind}{c.object_label ? ` ${c.object_label}` : ''} </span>
          )}
          <strong>{c.object_kind !== panelKind ? a.verb.toLowerCase() : a.verb}</strong>
          {c.action === 'update' && c.changed_fields.length > 0 && (
            <>
              {' '}
              {c.changed_fields.map((f) => (
                <code key={f} className="mono" style={{ fontSize: 11, padding: '1px 5px', marginRight: 4, borderRadius: 4, background: 'var(--app-panel2)' }}>{f}</code>
              ))}
            </>
          )}
        </div>
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
          {who} · {changeSourceText(c.source)} · <span title={when.full}>{when.short}</span>
          {c.changed_fields.length > 0 && (
            <>
              {' · '}
              <button type="button" data-testid="change-toggle" aria-expanded={open} onClick={() => setOpen(!open)}
                style={{ all: 'unset', cursor: 'pointer', color: 'var(--accent)', fontSize: 11.5 }}>
                {open ? 'Hide changes' : 'Show changes'}
              </button>
            </>
          )}
        </div>
        {open && <div style={{ marginTop: 6 }}><ChangeDiff id={c.id} /></div>}
      </div>
    </li>
  );
}

export function ObjectChanges({ kind, id, includeRelated = false }: { kind: ObjectKind; id: string; includeRelated?: boolean }) {
  const q = useObjectChanges(kind, id, true, includeRelated);
  if (q.isLoading) return <PanelLoading label="Loading changes…" />;
  if (q.isError) {
    return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  }
  const page = q.data ?? { rows: [], total: 0 };
  if (page.rows.length === 0) {
    return (
      <PanelEmpty
        icon="git-compare"
        title="No changes recorded yet"
        message={includeRelated
          ? "Changes to this object, its interfaces, IP addresses, tags and journal are recorded here, with who made them and when."
          : "Changes to this object are recorded here, with who made them and when."}
      />
    );
  }
  return (
    <div data-testid="object-changes">
      <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
        {page.rows.map((c) => <ChangeRow key={c.id} c={c} panelKind={kind} />)}
      </ul>
      {page.total > page.rows.length && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>
          Showing the latest {page.rows.length} of {page.total} changes.
        </div>
      )}
    </div>
  );
}
