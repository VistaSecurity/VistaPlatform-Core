// <ObjectJournal kind id /> — dated, attributed comments on one object
// (`journal_entries`, NetBox's journal). Reading needs dcim.read; the add form
// is shown to dcim.manage only.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import { useAddJournalEntry, useObjectJournal, type JournalEntry, type JournalKind } from './substrate-queries';
import { PanelEmpty, PanelError, PanelLoading, whenText } from './substrate-states';

const KINDS: { key: JournalKind; text: string; color: string }[] = [
  { key: 'info', text: 'Info', color: 'var(--accent)' },
  { key: 'success', text: 'Success', color: 'var(--success, #2e9d5b)' },
  { key: 'warning', text: 'Warning', color: 'var(--warning, #c98a16)' },
  { key: 'danger', text: 'Danger', color: 'var(--danger)' },
];

function kindMeta(k: JournalKind) {
  return KINDS.find((x) => x.key === k) ?? KINDS[0];
}

function EntryRow({ e }: { e: JournalEntry }) {
  const meta = kindMeta(e.kind);
  const when = whenText(e.created_at);
  return (
    <li data-testid="journal-row" style={{ padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--app-t3)' }}>
        <span style={{ fontWeight: 700, color: meta.color }}>{meta.text}</span>
        <span>{e.created_by_name ?? (e.created_by ? 'A deleted user' : 'System')}</span>
        <span title={when.full}>{when.short}</span>
      </div>
      <div style={{ fontSize: 13, color: 'var(--app-t1)', marginTop: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{e.comments}</div>
    </li>
  );
}

function AddEntry({ kind, id }: { kind: ObjectKind; id: string }) {
  const [text, setText] = useState('');
  const [entryKind, setEntryKind] = useState<JournalKind>('info');
  const add = useAddJournalEntry(kind, id);
  const submit = (ev: React.FormEvent) => {
    ev.preventDefault();
    const comments = text.trim();
    if (!comments) return;
    add.mutate({ kind: entryKind, comments }, { onSuccess: () => setText('') });
  };
  return (
    <form onSubmit={submit} aria-label="Add journal entry" style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
      <textarea
        aria-label="Journal entry"
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={3}
        maxLength={10000}
        placeholder="What happened to this object — a repair, a move, a decision…"
        style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-body)', fontSize: 13, padding: 8, borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)' }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <select aria-label="Entry kind" value={entryKind} onChange={(e) => setEntryKind(e.target.value as JournalKind)} className="ui-select" style={{ height: 30, fontSize: 12.5 }}>
          {KINDS.map((k) => <option key={k.key} value={k.key}>{k.text}</option>)}
        </select>
        <button type="submit" className="ui-btn sm" disabled={!text.trim() || add.isPending}>
          <Icon name="plus" size={12} />{add.isPending ? 'Adding…' : 'Add entry'}
        </button>
      </div>
    </form>
  );
}

export function ObjectJournal({ kind, id }: { kind: ObjectKind; id: string }) {
  const q = useObjectJournal(kind, id);
  let body: React.ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading the journal…" />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if ((q.data?.rows ?? []).length === 0) {
    body = <PanelEmpty icon="file-text" title="No journal entries yet" message="Journal entries are dated notes on this object that everyone in your organisation can read." />;
  } else {
    const page = q.data!;
    body = (
      <>
        <ul data-testid="object-journal" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {page.rows.map((e) => <EntryRow key={e.id} e={e} />)}
        </ul>
        {page.total > page.rows.length && (
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>Showing the latest {page.rows.length} of {page.total} entries.</div>
        )}
      </>
    );
  }
  return (
    <div>
      <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
        <AddEntry kind={kind} id={id} />
      </PermissionGate>
      {body}
    </div>
  );
}
