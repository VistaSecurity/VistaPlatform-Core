// Data subject request actions — export and erasure.
//
// These exist because the Privacy Policy this platform ships promises access,
// rectification, erasure and portability. Until now, honouring any of them
// meant an administrator writing SQL against production.
//
// Both are deliberately plain: a button that downloads a file, and a
// confirmation that spells out what erasure keeps and why before it will run.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';

/** Turn a fetched export document into a download without a round trip. */
function downloadJson(filename: string, body: unknown) {
  const blob = new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Download-my-data. No permission beyond being signed in — anyone may ask what
 * is held about them — and the subject comes from the session, never a
 * parameter.
 */
export function ExportMyDataButton() {
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: async () => {
      const { data, error: err } = await clients.auth.GET('/me/data-export', {});
      if (err || !data) throw new Error('Could not build your data export.');
      downloadJson('my-vista-platform-data.json', data);
    },
    onError: (e) => setError((e as Error).message),
    onSuccess: () => setError(null),
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <button
        className="ui-btn sm ghost"
        onClick={() => run.mutate()}
        disabled={run.isPending}
        data-testid="export-my-data"
      >
        <Icon name="download" size={14} />
        {run.isPending ? 'Preparing…' : 'Download my data'}
      </button>
      <div style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.5 }}>
        A JSON file containing your profile, the versions of the legal documents
        you accepted, your invitation, your API token names, and your activity
        from the last 12 months. It never contains passwords or token values,
        and it says inside what it leaves out.
      </div>
      {error && (
        <div style={{ fontSize: 12, color: 'var(--danger-text)' }} role="alert">{error}</div>
      )}
    </div>
  );
}

/**
 * Administrative export of one member's data, for answering a subject access
 * request. Gated on users.manage by the caller.
 */
export function ExportMemberDataButton({ userId, name }: { userId: string; name: string }) {
  const run = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.auth.GET('/users/{id}/data-export', {
        params: { path: { id: userId } },
      });
      if (error || !data) throw new Error('Could not build the data export.');
      downloadJson(`data-export-${userId}.json`, data);
    },
  });

  return (
    <button
      className="ui-btn sm ghost"
      title={`Export ${name}'s data (subject access request)`}
      onClick={() => run.mutate()}
      disabled={run.isPending}
      data-testid={`export-member-${userId}`}
    >
      <Icon name={run.isPending ? 'loader' : 'download'} size={14} />
    </button>
  );
}

interface EraseTarget {
  id: string;
  name: string;
  email: string;
}

/**
 * Erasure confirmation. It states what will be kept and why BEFORE the action
 * runs, because "we erased your data" and "we kept your acceptance records" have
 * to be the same conversation — an administrator who learns the second part
 * afterwards has already told the data subject something untrue.
 */
export function EraseMemberModal({
  target,
  tenantId,
  onClose,
}: {
  target: EraseTarget;
  tenantId?: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const confirmed = confirmText.trim().toLowerCase() === 'erase';

  const erase = useMutation({
    mutationFn: async () => {
      const { data, error: err } = await clients.auth.POST('/users/{id}/erase', {
        params: { path: { id: target.id } },
      });
      if (err || !data) {
        throw new Error(
          (err as { error?: string })?.error ?? 'The erasure did not complete. Nothing was changed.',
        );
      }
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', 'members', tenantId] });
      onClose();
    },
    onError: (e) => setError((e as Error).message),
  });

  return (
    <div className="ui-modal-backdrop" role="dialog" aria-label="Erase member data" data-testid="erase-member-modal">
      <div className="ui-modal" style={{ maxWidth: 560 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10 }}>
          <Icon name="alert-triangle" size={16} />
          <strong style={{ fontSize: 14 }}>Erase {target.name}'s personal data</strong>
        </div>

        <div style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            Their profile is replaced with an anonymous placeholder, their API
            tokens and invitation are deleted, and their name is removed from the
            activity trail. <strong>This cannot be undone.</strong>
          </div>

          <div>
            <div style={{ fontWeight: 600, color: 'var(--app-t1)', marginBottom: 4 }}>What is kept, and why</div>
            <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <li>
                <strong>Their acceptance of your legal documents</strong> — which version,
                when, and from where. This is your evidence that they agreed to your
                terms.
              </li>
              <li>
                <strong>The activity trail itself</strong>, with their identity removed.
                The events stay so the record remains complete; a log that can be
                selectively rewritten proves nothing.
              </li>
              <li>
                <strong>Tickets and comments they wrote</strong>, now shown as an
                anonymous author. The text is an operational record.
              </li>
            </ul>
          </div>

          <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>
            This does not reach backups, personal data that appears inside
            discovered certificates or key comments, or the value snapshots stored
            in older activity entries.
          </div>

          <label style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>
              Type <span className="mono" style={{ color: 'var(--app-t1)' }}>erase</span> to confirm
            </span>
            <input
              className="ui-input"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="erase"
              autoFocus
            />
          </label>

          {error && <div style={{ color: 'var(--danger-text)' }} role="alert">{error}</div>}
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <button className="ui-btn sm ghost" onClick={onClose} disabled={erase.isPending}>Cancel</button>
          <button
            className="ui-btn sm danger"
            onClick={() => erase.mutate()}
            disabled={!confirmed || erase.isPending}
            data-testid="confirm-erase"
          >
            {erase.isPending ? 'Erasing…' : 'Erase personal data'}
          </button>
        </div>
      </div>
    </div>
  );
}
