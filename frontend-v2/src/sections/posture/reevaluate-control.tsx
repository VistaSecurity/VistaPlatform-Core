// Risk & Compliance · POSTURE → "Re-evaluate now".
//
// Compliance findings are materialized: scores are recomputed on asset/cert change,
// framework activation/publish, or a manual re-evaluation — never by an upgrade. So
// after an engine fix the numbers on this very page can be stale, and until now the
// only manual trigger was platform-admin. Posture is where the score is shown, so it
// is where someone notices it looks stale; that is why the control lives here.
//
// Two rules this component exists to honour:
//
//  1. It is NEVER clickable during the cooldown. A button that is enabled and then
//     answers 429 is the exact "buttons that 403'd on click" defect this release
//     just finished removing. The server's own state drives `disabled`.
//  2. Success says "queued", not "done". The reconcile is asynchronous — implying
//     the numbers have already moved would be a lie the user can see through.
import { useEffect, useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { useReevaluate, useReevaluationState } from './queries';

/** "3h ago" / "12m ago" — coarse on purpose; the exact instant is in the tooltip. */
export function relativeSince(iso: string | null | undefined, now: number): string | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return null;
  const secs = Math.max(0, Math.round((now - t) / 1000));
  if (secs < 60) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/** "59m" / "45s" — how long until the button comes back. */
export function countdownLabel(seconds: number): string {
  if (seconds <= 0) return 'now';
  if (seconds < 60) return `${seconds}s`;
  return `${Math.ceil(seconds / 60)}m`;
}

/**
 * The whole enabled/disabled + label decision, as a pure function so it can be
 * tested without a DOM renderer (this app has no testing-library). The rule it
 * encodes: the control is disabled whenever the server says a run is not allowed
 * yet — never "enabled and then it 403s/429s".
 */
export function reevaluateControlView(
  st: { allowed: boolean; last_requested_at: string | null; next_allowed_at: string | null } | undefined,
  now: number,
  opts: { loading?: boolean; pending?: boolean } = {},
): { blocked: boolean; disabled: boolean; remaining: number; subtitle: string } {
  const nextMs = st?.next_allowed_at ? new Date(st.next_allowed_at).getTime() : 0;
  // Derive "blocked" from the timestamp rather than trusting the `allowed` flag
  // we fetched up to 30 seconds ago — otherwise the button stays disabled for up
  // to half a minute after the cooldown has actually elapsed.
  const remaining = nextMs ? Math.max(0, Math.ceil((nextMs - now) / 1000)) : 0;
  const blocked = !!st && !st.allowed && remaining > 0;
  // Unknown state is treated as blocked: until the server has told us, enabling
  // the button would be a guess, and a wrong guess is a click that fails.
  const disabled = !!opts.loading || !st || blocked || !!opts.pending;
  const last = relativeSince(st?.last_requested_at, now);
  const subtitle = opts.loading || !st
    ? ''
    : blocked
      ? `Available in ${countdownLabel(remaining)}`
      : last
        ? `Last re-evaluated ${last}`
        : 'Not re-evaluated yet';
  return { blocked, disabled, remaining, subtitle };
}

export function ReevaluateControl() {
  const stateQ = useReevaluationState();
  const run = useReevaluate();
  const [queued, setQueued] = useState(false);
  // Local clock so the countdown ticks between the 30s refetches; without it the
  // label sits on a stale number and the button looks stuck.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const st = stateQ.data;
  const nextMs = st?.next_allowed_at ? new Date(st.next_allowed_at).getTime() : 0;
  const { blocked, disabled, subtitle } = reevaluateControlView(st, now, {
    loading: stateQ.isLoading,
    pending: run.isPending,
  });

  const title = blocked
    ? `Re-evaluation runs at most once an hour per organization. Next available ${new Date(nextMs).toLocaleTimeString()}.`
    : 'Re-run compliance evaluation against your current inventory.';

  return (
    <PermissionGate permission={TENANT_PERMISSIONS.compliance.manage}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
        <button
          className="ui-btn sm"
          disabled={disabled}
          title={title}
          onClick={() => {
            setQueued(false);
            run.mutate(undefined, { onSuccess: () => setQueued(true) });
          }}
        >
          <Icon name="refresh" size={13} />
          {run.isPending ? 'Queueing…' : 'Re-evaluate now'}
        </button>
        {subtitle && (
          <span style={{ fontSize: 10.5, color: 'var(--app-t3)' }} title={st?.last_requested_at ? new Date(st.last_requested_at).toLocaleString() : undefined}>
            {subtitle}
          </span>
        )}
        {queued && !run.isError && (
          <span style={{ fontSize: 10.5, color: 'var(--ok)' }}>
            Queued — findings and scores refresh in the background.
          </span>
        )}
        {run.isError && (
          <span style={{ fontSize: 10.5, color: 'var(--danger-text)' }}>
            {run.error.message}
          </span>
        )}
      </div>
    </PermissionGate>
  );
}
