// Inventory → Changes (DCIM BUILD_PLAN row 5.2; asset-inventory ADR-0010 D5):
// the tenant's whole change record — who changed what, when and from where —
// filterable by object kind, object name, user, source, action and date, with a
// field-level diff in a drawer and a CSV export of the rows on screen. Every
// create, update and delete of a DCIM object lands in `object_changes` (written
// by the service that made it), so this is the one place to answer "what
// happened to this estate this week?". Reading needs `dcim.read`.
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { OBJECT_KINDS, OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { DrawerCloseBtn, DrawerShell, Icon, MetaRow, SectionLabel } from '../../../components/ui';
import { changeSourceText } from '../dcim/object-changes';
import { ChangeDiff } from '../dcim/change-diff';
import { PanelEmpty, PanelError, PanelLoading, whenText } from '../dcim/substrate-states';
import { useChangeLog, type ObjectChange } from '../dcim/substrate-queries';

export const CHANGES_PAGE = 50;

const SOURCES: Array<{ value: string; label: string }> = [
  { value: '', label: 'Any source' },
  { value: 'ui', label: 'Web UI' },
  { value: 'api', label: 'API' },
  { value: 'system', label: 'System' },
  { value: 'intake:', label: 'Discovery' },
  { value: 'sync:', label: 'Sync' },
];
const ACTIONS: Array<{ value: string; label: string }> = [
  { value: '', label: 'Any action' },
  { value: 'create', label: 'Created' },
  { value: 'update', label: 'Updated' },
  { value: 'delete', label: 'Deleted' },
];
const ACTION_LABEL: Record<ObjectChange['action'], string> = { create: 'Created', update: 'Updated', delete: 'Deleted' };
const COLS = '110px 1.1fr 0.9fr 1fr 1.3fr 90px 1.4fr';

export const kindLabel = (k: string): string => OBJECT_KIND_LABELS[k as ObjectKind]?.uiLabel ?? k;

/** Where clicking an object's name goes, when its kind has a page of its own. */
export function objectHref(c: Pick<ObjectChange, 'object_kind' | 'object_id' | 'action'>): string | null {
  if (c.action === 'delete') return null; // the object is gone
  if (c.object_kind === 'asset') return `/inventory/assets/${c.object_id}`;
  return null;
}

const whoText = (c: ObjectChange) => c.user_name ?? (c.user_id ? 'A user' : changeSourceText(c.source));

// --- CSV --------------------------------------------------------------------

export const CHANGES_CSV_HEADER = ['when', 'who', 'source', 'kind', 'object', 'object_id', 'action', 'fields_changed'];

/** A cell that a spreadsheet would run as a formula is prefixed so it reads as text. */
const csvCell = (v: string): string => {
  const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

export function changesCsv(rows: ObjectChange[]): string {
  const lines = rows.map((c) => [
    c.created_at, whoText(c), c.source, c.object_kind, c.object_label ?? '', c.object_id, c.action, c.changed_fields.join(';'),
  ].map(csvCell).join(','));
  return [CHANGES_CSV_HEADER.join(','), ...lines].join('\n');
}

function downloadCsv(rows: ObjectChange[]) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([changesCsv(rows)], { type: 'text/csv' }));
  a.download = 'change-log.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// --- drawer -----------------------------------------------------------------

function ChangeDrawer({ change, onClose }: { change: ObjectChange; onClose: () => void }) {
  const when = whenText(change.created_at);
  const href = objectHref(change);
  return (
    <DrawerShell onClose={onClose} width={620}>
      <div data-testid="change-drawer" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="git-compare" size={18} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 700, fontSize: 15 }}>{ACTION_LABEL[change.action]} {kindLabel(change.object_kind).toLowerCase()}</div>
            <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>{change.object_label ?? change.object_id}</div>
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <SectionLabel icon="file-text">Details</SectionLabel>
        <MetaRow k="When" v={when.full} />
        <MetaRow k="Who" v={whoText(change)} />
        <MetaRow k="Source" v={changeSourceText(change.source)} />
        <MetaRow k="Object" v={href ? <Link to={href}>{change.object_label ?? change.object_id}</Link> : (change.object_label ?? change.object_id)} />
        {change.related_kind && change.related_id && (
          <MetaRow k="Belongs to" v={objectHref({ object_kind: change.related_kind, object_id: change.related_id, action: 'update' })
            ? <Link to={objectHref({ object_kind: change.related_kind, object_id: change.related_id, action: 'update' })!}>{kindLabel(change.related_kind)}</Link>
            : kindLabel(change.related_kind)} />
        )}
        <MetaRow k="Request" v={change.request_id} />
        <SectionLabel icon="git-compare">What changed</SectionLabel>
        <ChangeDiff id={change.id} />
      </div>
    </DrawerShell>
  );
}

// --- lens -------------------------------------------------------------------

function dayStart(d: string): string | undefined {
  return d ? new Date(`${d}T00:00:00`).toISOString() : undefined;
}
/** The day AFTER d, so the range includes all of d. */
function dayAfter(d: string): string | undefined {
  if (!d) return undefined;
  const t = new Date(`${d}T00:00:00`);
  t.setDate(t.getDate() + 1);
  return t.toISOString();
}

function ChangesBody() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? '';
  const set = (k: string, v: string) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    n.delete('page');
    setParams(n, { replace: true });
  };
  const page = Math.max(1, Number(params.get('page')) || 1);
  const [openId, setOpenId] = useState<string | null>(null);
  const [objectQ, setObjectQ] = useState(get('q'));
  const [userQ, setUserQ] = useState(get('who'));

  const paramString = params.toString();
  const filters = useMemo(() => ({
    object_kind: (get('kind') || undefined) as ObjectKind | undefined,
    q: get('q') || undefined,
    user_name: get('who') || undefined,
    source: get('source') || undefined,
    action: (get('action') || undefined) as ObjectChange['action'] | undefined,
    since: dayStart(get('from')),
    until: dayAfter(get('to')),
    limit: CHANGES_PAGE,
    offset: (page - 1) * CHANGES_PAGE,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [paramString]);
  const log = useChangeLog(filters);
  const rows = log.data?.rows ?? [];
  const total = log.data?.total ?? 0;
  const filtered = ['kind', 'q', 'who', 'source', 'action', 'from', 'to'].some((k) => get(k) !== '');
  const open = rows.find((r) => r.id === openId) ?? null;
  const pages = Math.max(1, Math.ceil(total / CHANGES_PAGE));

  return (
    <div data-testid="changes-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="git-compare" size={17} style={{ color: 'var(--accent)' }} />Changes
        </h1>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{log.data ? `${total} ${total === 1 ? 'change' : 'changes'}` : ''}</span>
        <div style={{ marginLeft: 'auto' }}>
          <button type="button" className="ui-btn sm" data-testid="export-changes" disabled={rows.length === 0} onClick={() => downloadCsv(rows)}
            title="Download the rows on this page as CSV">
            <Icon name="download" size={13} />Export page
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <select aria-label="Object kind" className="ui-input" value={get('kind')} onChange={(e) => set('kind', e.target.value)}>
          <option value="">Any kind</option>
          {OBJECT_KINDS.map((k) => <option key={k} value={k}>{kindLabel(k)}</option>)}
        </select>
        <input aria-label="Search objects" className="ui-input" placeholder="Object name…" value={objectQ} style={{ width: 160 }}
          onChange={(e) => setObjectQ(e.target.value)} onBlur={() => set('q', objectQ.trim())} onKeyDown={(e) => { if (e.key === 'Enter') set('q', objectQ.trim()); }} />
        <input aria-label="Search users" className="ui-input" placeholder="User…" value={userQ} style={{ width: 140 }}
          onChange={(e) => setUserQ(e.target.value)} onBlur={() => set('who', userQ.trim())} onKeyDown={(e) => { if (e.key === 'Enter') set('who', userQ.trim()); }} />
        <select aria-label="Source" className="ui-input" value={get('source')} onChange={(e) => set('source', e.target.value)}>
          {SOURCES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select aria-label="Action" className="ui-input" value={get('action')} onChange={(e) => set('action', e.target.value)}>
          {ACTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <label style={{ fontSize: 12, color: 'var(--app-t3)', display: 'flex', alignItems: 'center', gap: 4 }}>From
          <input aria-label="From date" type="date" className="ui-input" value={get('from')} onChange={(e) => set('from', e.target.value)} />
        </label>
        <label style={{ fontSize: 12, color: 'var(--app-t3)', display: 'flex', alignItems: 'center', gap: 4 }}>To
          <input aria-label="To date" type="date" className="ui-input" value={get('to')} onChange={(e) => set('to', e.target.value)} />
        </label>
        {filtered && (
          <button type="button" className="ui-btn sm ghost" data-testid="clear-filters"
            onClick={() => { setObjectQ(''); setUserQ(''); setParams(new URLSearchParams({ lens: 'changes' }), { replace: true }); }}>Clear</button>
        )}
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>When</span><span>Who</span><span>Source</span><span>Kind</span><span>Object</span><span>Action</span><span>Fields changed</span>
        </div>
        {log.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading changes…" /></div>}
        {log.isError && <div style={{ padding: 14 }}><PanelError message={log.error instanceof Error ? log.error.message : 'Request failed'} onRetry={() => { void log.refetch(); }} /></div>}
        {log.data && rows.length === 0 && (
          <PanelEmpty icon="git-compare" title={filtered ? 'No changes match' : 'No changes recorded yet'}
            message={filtered ? 'Nothing in the change log matches these filters.' : 'Every create, update and delete of a device, interface, address, rack, circuit and the like is recorded here with who made it and where it came from.'} />
        )}
        {rows.map((c) => {
          const when = whenText(c.created_at);
          const href = objectHref(c);
          return (
            <div key={c.id} data-testid="change-log-row" role="button" tabIndex={0} onClick={() => setOpenId(c.id)}
              onKeyDown={(e) => { if (e.key === 'Enter') setOpenId(c.id); }}
              style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: openId === c.id ? 'var(--app-panel2)' : undefined }}>
              <span title={when.full} style={{ color: 'var(--app-t2)' }}>{when.short}</span>
              <span>{whoText(c)}</span>
              <span style={{ color: 'var(--app-t2)' }}>{changeSourceText(c.source)}</span>
              <span>{kindLabel(c.object_kind)}</span>
              <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {href
                  ? <Link to={href} onClick={(e) => e.stopPropagation()} data-testid="change-object-link">{c.object_label ?? c.object_id}</Link>
                  : (c.object_label ?? <span className="mono" style={{ color: 'var(--app-t3)' }}>{c.object_id.slice(0, 8)}</span>)}
              </span>
              <span>{ACTION_LABEL[c.action]}</span>
              <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {c.changed_fields.slice(0, 4).map((f) => <code key={f} className="mono" style={{ fontSize: 11, padding: '1px 5px', borderRadius: 4, background: 'var(--app-panel2)' }}>{f}</code>)}
                {c.changed_fields.length > 4 && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>+{c.changed_fields.length - 4}</span>}
              </span>
            </div>
          );
        })}
      </div>

      {total > CHANGES_PAGE && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--app-t3)' }}>
          <button type="button" className="ui-btn sm" data-testid="changes-prev" disabled={page <= 1}
            onClick={() => { const n = new URLSearchParams(params); n.set('page', String(page - 1)); setParams(n, { replace: true }); }}>Previous</button>
          <span>Page {page} of {pages}</span>
          <button type="button" className="ui-btn sm" data-testid="changes-next" disabled={page >= pages}
            onClick={() => { const n = new URLSearchParams(params); n.set('page', String(page + 1)); setParams(n, { replace: true }); }}>Next</button>
        </div>
      )}

      {open && <ChangeDrawer change={open} onClose={() => setOpenId(null)} />}
    </div>
  );
}

export function ChangesLens() {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={<PanelEmpty icon="lock" title="You can't view changes" message="The change log needs the DCIM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <ChangesBody />
    </PermissionGate>
  );
}
