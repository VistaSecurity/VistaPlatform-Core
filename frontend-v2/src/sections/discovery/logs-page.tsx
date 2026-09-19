import { useState } from 'react';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { PageWrap, queryNote, jobMeta, relTime, durationFmt, shortId, jobTypeLabel } from './kit';
import { useJobs } from './queries';
import { JobDetailModal } from './job-detail-modal';

// Discovery → Job Logs — the mock's `discovery-logs` stream: every job run as a
// log line (newest first, the API's order), failures carrying their live
// error_message instead of the mock's canned "connection refused".
//
// A line is a summary, not the log. Clicking one opens the run's detail —
// timeline, per-stage pipeline outcome, processing errors, and the assets it
// discovered.

type Job = deviceInterrogationComponents['schemas']['InterrogationJob'];
type EnumerationCounts = deviceInterrogationComponents['schemas']['CloudEnumerationCounts'];
type CloudIdentitySummary = deviceInterrogationComponents['schemas']['CloudIdentitySummary'];
type HostInventoryCounts = deviceInterrogationComponents['schemas']['HostInventoryCounts'];

export function cloudIdentitySummary(identity: CloudIdentitySummary | undefined): string | null {
  if (!identity) return null;
  return [
    `${identity.assets_created} created, ${identity.assets_matched} matched`,
    identity.observations_retained ? `${identity.observations_retained} observations retained — awaiting identity resolution` : null,
    identity.approval_pending ? `${identity.approval_pending} awaiting approval` : null,
    identity.conflicts ? `${identity.conflicts} identity conflicts` : null,
    identity.rejected_inputs ? `${identity.rejected_inputs} rejected inputs` : null,
  ].filter(Boolean).join(' · ');
}

/**
 * The enumeration half of a cloud discovery run, as one log-line fragment.
 *
 * `undefined` means the run did not enumerate — the integration has it off, or
 * the job is not a cloud discovery — and the fragment is omitted. All-zero
 * means it ran and the account was empty, which is a different statement and
 * says so ("no compute found"). Flattening the two would make "we did not
 * look" and "there was nothing there" the same line.
 *
 * Exported for the unit test: this is the only place the two are told apart.
 */
export function enumerationSummary(e: EnumerationCounts | undefined): string | null {
  if (!e) return null;
  const count = (n: number, one: string, many: string) => (n === 1 ? `1 ${one}` : `${n} ${many}`);
  const parts = [
    e.instances ? count(e.instances, 'instance', 'instances') : null,
    e.networks ? count(e.networks, 'network', 'networks') : null,
    e.subnets ? count(e.subnets, 'subnet', 'subnets') : null,
    e.security_groups ? count(e.security_groups, 'security group', 'security groups') : null,
  ].filter(Boolean);
  return parts.length ? parts.join(', ') : 'no compute found';
}

/**
 * The host-inventory half of a run, as one log-line fragment.
 *
 * `undefined` means the job is not a host inventory (or never reached the
 * consumer) and the fragment is omitted. A run that DID reach it always says
 * something, even when every number is zero — "collected nothing" is a real
 * outcome and the line has to be able to report it, because the failure this
 * whole workstream exists to avoid is a feature that silently does nothing.
 *
 * The package count is omitted when the collector's package step FAILED, rather
 * than rendered as "0 packages": a host whose package database could not be
 * read has not been enumerated, and saying zero would make the two look alike.
 *
 * `contested` leads, because it changes what the rest of the line MEANS: the
 * numbers describe a pending asset the engine created beside a merge proposal,
 * not a settled host.
 *
 * Exported for the unit test, like enumerationSummary above it.
 */
export function hostInventorySummary(h: HostInventoryCounts | undefined): string | null {
  if (!h) return null;
  // A run the consumer reached and could NOT materialise. The counts beside it
  // are what the consumer had assembled when it failed — 91 listeners it never
  // wrote — and rendering them made a failed run read "91 listeners", a
  // success for a host that was not in the inventory. The failure is the whole
  // line; nothing after it is true of the inventory.
  if (h.failed) return `host inventory NOT materialised — ${h.failed}`;
  if (h.identity_outcome === 'unresolved') return 'evidence retained — awaiting identity resolution in Discovery → Observations';
  const count = (n: number, one: string, many: string) => (n === 1 ? `1 ${one}` : `${n} ${many}`);
  const parts = [
    h.contested ? 'identity contested — merge proposal waiting' : null,
    h.packages != null ? count(h.packages, 'package', 'packages') : null,
    h.endpoints ? count(h.endpoints, 'listener', 'listeners') : null,
    h.facts ? count(h.facts, 'fact', 'facts') : null,
    h.installs_removed ? `${h.installs_removed} removed` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(', ') : 'collected nothing';
}

export function LogsPage() {
  const q = useJobs();
  const jobs = q.data?.jobs ?? [];
  const [selected, setSelected] = useState<Job | null>(null);

  const note = queryNote(q, jobs.length === 0, {
    thing: 'job logs',
    emptyTitle: 'No log entries',
    emptyMessage: 'Job runs appear here as a stream once discovery jobs execute.',
  });

  return (
    <PageWrap title="Job Logs" count={q.isLoading ? '' : jobs.length}>
      {note ?? (
        <div className="panel" style={{ padding: 0, overflow: 'hidden', borderRadius: 14 }}>
          {jobs.map((j, i) => {
            const m = jobMeta(j.status);
            const failed = (j.status || '').toLowerCase() === 'failed';
            return (
              <div
                key={j.id}
                className="row-hover"
                role="button"
                tabIndex={0}
                onClick={() => setSelected(j)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(j); } }}
                style={{ padding: '12px 18px', borderTop: i ? '1px solid var(--app-border)' : 'none', display: 'flex', gap: 12, alignItems: 'flex-start', cursor: 'pointer' }}
              >
                <span style={{ width: 7, height: 7, borderRadius: 50, background: m.c, marginTop: 6, flex: 'none' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 9, alignItems: 'center' }}>
                    <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)' }}>{shortId(j.id)}</span>
                    <span style={{ fontSize: 11, color: m.c }}>{m.l}</span>
                    <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{relTime(j.started_at || j.created_at)}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {[jobTypeLabel(j.job_type), j.device_name || j.integration_name ? `→ ${j.device_name || j.integration_name}` : null,
                      // A host inventory reports its own counts instead of
                      // "N assets": it materialises ONE host, and "1 assets"
                      // beside 412 packages is the least informative thing the
                      // line could say.
                      j.host_inventory || j.identity ? null : (j.assets_discovered != null ? `${j.assets_discovered} assets` : null),
                      enumerationSummary(j.enumeration),
                      cloudIdentitySummary(j.identity),
                      hostInventorySummary(j.host_inventory),
                      j.duration_seconds != null ? durationFmt(j.duration_seconds) : null,
                    ].filter(Boolean).join(' · ')}
                  </div>
                  {failed && j.error_message && (
                    <div className="mono" style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 4 }}>✗ {j.error_message}</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      <JobDetailModal job={selected} onClose={() => setSelected(null)} />
    </PageWrap>
  );
}
