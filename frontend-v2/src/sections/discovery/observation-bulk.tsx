// The Observations bulk bar and its two dialogs ( D1, D4).
//
// Confirm is offered only when EVERY selected row is ready to confirm, judged
// on the rows as they are now — the caller passes the current page's rows, so
// a refetch that moves a row out of "ready" turns Confirm off even while it
// stays ticked. The server checks the same rule on the locked row; this is the
// UI not offering what the server would refuse.
import { useState } from 'react';
import { Modal, ModalField } from '../../components/ui';
import { MAX_REASON, batchReason, canBulkConfirm, canBulkDismiss, canBulkLink, type Observation } from './observation-review';

export type BulkAction = 'confirm' | 'link' | 'dismiss';

export function BulkBar({ rows, pending, onAction, onClear }: {
  rows: Observation[];
  pending: boolean;
  onAction: (a: BulkAction) => void;
  onClear: () => void;
}) {
  const confirmable = canBulkConfirm(rows);
  const linkable = canBulkLink(rows);
  return <div role="region" aria-label="Bulk actions" aria-busy={pending}
    style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: '10px 14px', marginBottom: 10, borderRadius: 12, border: '1px solid var(--accent)', background: 'color-mix(in srgb, var(--accent) 8%, transparent)' }}>
    <strong style={{ fontSize: 13 }}>{rows.length} selected</strong>
    <button type="button" className="ui-btn sm accent" disabled={pending || !confirmable} onClick={() => onAction('confirm')}>Confirm</button>
    <button type="button" className="ui-btn sm accent" disabled={pending || !linkable} onClick={() => onAction('link')}>Link to existing</button>
    <button type="button" className="ui-btn sm" disabled={pending || !canBulkDismiss(rows)} onClick={() => onAction('dismiss')}>Dismiss</button>
    <button type="button" className="ui-btn sm ghost" disabled={pending} onClick={onClear}>Clear selection</button>
    {pending
      ? <span role="status" style={{ fontSize: 12, color: 'var(--app-t2)' }}>Saving {rows.length} decision{rows.length === 1 ? '' : 's'}…</span>
      : !confirmable && !linkable && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Confirm is available when every selected row is ready to confirm; Link to existing when every selected row matches an asset you already have. Otherwise link one row at a time.</span>}
  </div>;
}

/**
 * The confirm / dismiss dialog. `rows` is the CURRENT selection; the reason is
 * proposed when the dialog opens and is the person's to edit from then on.
 */
export function BulkDialog({ action, rows, pending, error, onSubmit, onClose }: {
  action: BulkAction;
  rows: Observation[];
  pending: boolean;
  error: string | null;
  onSubmit: (reason: string) => void;
  onClose: () => void;
}) {
  const [reason, setReason] = useState(() => batchReason(rows, action));
  const n = rows.length;
  // Re-judged at submit time against the rows as they are now.
  const allowed = action === 'confirm' ? canBulkConfirm(rows) : action === 'link' ? canBulkLink(rows) : canBulkDismiss(rows);
  const title = action === 'confirm' ? `Create ${n} asset${n === 1 ? '' : 's'}`
    : action === 'link' ? `Link ${n} observation${n === 1 ? '' : 's'} to existing assets`
      : `Dismiss ${n} observation${n === 1 ? '' : 's'}`;
  const description = action === 'confirm'
    ? `Each then follows its network’s approval rules.`
    : action === 'link'
      ? `Each is linked to the asset that already owns its address. Those assets’ approval and history are kept.`
      : `They leave active review. Dismissing does not mean they are not real devices.`;
  return <Modal
    open onClose={pending ? undefined : onClose} dismissible={!pending}
    size="md" tone={action === 'dismiss' ? 'accent' : 'green'} icon={action === 'dismiss' ? 'x' : 'check'}
    eyebrow="Discovery · Observations" title={title} description={description}
    primary={<button type="button" className="ui-btn accent" disabled={pending || !allowed || !reason.trim()} onClick={() => onSubmit(reason.trim())}>
      {pending ? 'Saving…' : action === 'confirm' ? `Confirm ${n}` : action === 'link' ? `Link ${n}` : `Dismiss ${n}`}
    </button>}
    secondary={<button type="button" className="ui-btn" disabled={pending} onClick={onClose}>Cancel</button>}
    footerNote={error ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{error}</span>
      : !allowed ? <span role="alert" style={{ color: 'var(--danger-text)' }}>The selection changed: the rows no longer all qualify for this action. Close this and review the selection.</span>
      : undefined}
  >
    <ModalField label="Reason" hint="Recorded with every decision in the audit trail. Proposed from what was seen; edit it as you need.">
      <textarea className="ui-input" data-autofocus value={reason} required maxLength={MAX_REASON} rows={4} onChange={(e) => setReason(e.target.value)} />
    </ModalField>
  </Modal>;
}
