// Discovery → Cloud: one integration's ACCOUNT (asset-inventory ADR-0009 D1,
// D5, D7's integration card).
//
// Three things a tenant needs at the place they connected the account:
//
//  - the account itself, as the `cloud_account` asset every discovered
//    resource now hangs off (`hosted_on`) — a link to its asset page, where
//    the Relationships tab lists those resources;
//  - the account-level auto-approval switch. The copy is the owner's, and it
//    is the whole argument for the default being on;
//  - what the last run of this integration actually collected, per resource
//    type, in the same words the job detail uses (cloud-outcomes.ts) — so
//    "none in this account" and "could not look" stay different answers here
//    too.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { unwrap } from '../../lib/api-result';
import { useJobResults } from './queries';
import { outcomeView, resourceTypeLabel, type OutcomeTone } from './cloud-outcomes';
import { relTime } from './kit';
import { CloudOutcomeGrid } from './cloud-outcome-grid';
import type { CloudIntegration } from './cloud-modals';

/** The switch's copy (ADR-0009 D5) — pinned by the jsdom test. */
export const AUTO_APPROVE_COPY =
  'Resources discovered in this account are approved automatically. You supplied the credentials, so ownership is not in doubt.';

/** The jobs the page already loaded, narrowed to what the panel reads. */
export interface PanelJob {
  id: string;
  integration_id?: string | null;
  job_type?: string | null;
  status?: string | null;
  created_at?: string | null;
  completed_at?: string | null;
}

const SETTLED = new Set(['completed', 'failed', 'success', 'error', 'partial']);

/** The most recent settled cloud run of this integration, or undefined. */
export function lastSettledRun(jobs: PanelJob[], integrationId: string): PanelJob | undefined {
  return jobs
    .filter((j) => j.integration_id === integrationId && SETTLED.has((j.status ?? '').toLowerCase()))
    .sort((a, b) => (b.completed_at ?? b.created_at ?? '').localeCompare(a.completed_at ?? a.created_at ?? ''))[0];
}

const TONE: Record<OutcomeTone, string> = {
  ok: 'var(--ok)',
  warn: 'var(--warn-strong)',
  danger: 'var(--danger)',
  muted: 'var(--app-t3)',
};

function LastRunOutcomes({ job }: { job: PanelJob | undefined }) {
  const q = useJobResults(job?.id);
  if (!job) {
    return <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>Not run yet — use ▶ to run a discovery.</div>;
  }
  if (q.isLoading) return <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>Loading the last run…</div>;
  if (q.isError) {
    return <div role="alert" style={{ fontSize: 11, color: 'var(--danger-text)' }}>The last run’s outcome could not be loaded.</div>;
  }
  const types = q.data?.resource_types ?? [];
  if (types.length === 0) {
    return (
      <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>
        The last run ({relTime(job.completed_at ?? job.created_at)}) reported no per-type outcome.
      </div>
    );
  }
  return (
    <div>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginBottom: 4 }}>
        Last run {relTime(job.completed_at ?? job.created_at)}
      </div>
      <ul data-testid="cloud-last-run-outcomes" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 3 }}>
        {types.map((t) => {
          const v = outcomeView(t);
          return (
            <li key={t.resource_type} style={{ display: 'flex', gap: 8, fontSize: 11, color: 'var(--app-t2)' }}>
              <span style={{ flex: 1, minWidth: 0 }}>{resourceTypeLabel(t.resource_type)}</span>
              <span style={{ color: TONE[v.tone], fontWeight: 600 }}>{v.label}</span>
              <span style={{ color: 'var(--app-t3)' }}>{v.detail}</span>
            </li>
          );
        })}
      </ul>
      {types.some((t) => (t.regions ?? []).length > 0) && (
        <div style={{ marginTop: 6 }}>
          <CloudOutcomeGrid types={types} compact />
        </div>
      )}
    </div>
  );
}

export function CloudAccountPanel({ integration, jobs }: { integration: CloudIntegration; jobs: PanelJob[] }) {
  const qc = useQueryClient();
  // What the switch shows: the value just asked for while (and after) it is
  // saved, else what the server last said. A failed save clears it, so the
  // switch snaps back to the stored value rather than lying about it.
  const [asked, setAsked] = useState<boolean | null>(null);
  const on = asked ?? integration.auto_approve_resources ?? true;
  const lastRun = useMemo(() => lastSettledRun(jobs, integration.id), [jobs, integration.id]);

  const save = useMutation({
    mutationFn: async (next: boolean) => {
      unwrap(
        await clients.devices.PUT('/integrations/{id}', {
          params: { path: { id: integration.id } },
          body: { auto_approve_resources: next },
        }),
        'Failed to save the auto-approve setting',
      );
      return next;
    },
    onMutate: (next) => setAsked(next),
    onError: () => setAsked(null),
    onSettled: () => qc.invalidateQueries({ queryKey: ['discovery', 'integrations'] }),
  });

  const account = integration.account_id?.trim();
  return (
    <div data-testid={`cloud-account-${integration.id}`} style={{ display: 'grid', gap: 8, padding: '8px 0 4px 12px', borderLeft: '2px solid var(--app-border2)' }}>
      <div style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>
        {integration.account_asset_id ? (
          <Link to={`/inventory/assets/${integration.account_asset_id}`} style={{ color: 'var(--accent)', fontWeight: 600 }}>
            Account {account}
          </Link>
        ) : (
          <span style={{ color: 'var(--app-t3)' }}>
            {account ? `Account ${account} — not in inventory yet` : 'Account not known yet — test the connection to learn it'}
          </span>
        )}
      </div>

      <PermissionGate
        permission={TENANT_PERMISSIONS.discovery.manage}
        fallback={
          <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>
            Auto-approve resources: {on ? 'on' : 'off'}
          </div>
        }
      >
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: save.isPending ? 'default' : 'pointer' }}>
          <input
            type="checkbox"
            role="switch"
            aria-label="Auto-approve resources"
            checked={on}
            disabled={save.isPending}
            onChange={(e) => save.mutate(e.target.checked)}
          />
          <span>
            <span style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--app-t1)' }}>Auto-approve resources</span>
            <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)' }}>{AUTO_APPROVE_COPY}</span>
          </span>
        </label>
      </PermissionGate>
      {save.isError && (
        <div role="alert" style={{ fontSize: 11, color: 'var(--danger-text)' }}>
          {save.error.message || 'Failed to save the auto-approve setting'}
        </div>
      )}

      <LastRunOutcomes job={lastRun} />
    </div>
  );
}
