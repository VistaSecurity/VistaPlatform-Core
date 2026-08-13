import { useState } from 'react';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { PageWrap, queryNote, jobMeta, relTime, durationFmt, shortId } from './kit';
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
                    {[j.job_type, j.device_name || j.integration_name ? `→ ${j.device_name || j.integration_name}` : null,
                      j.assets_discovered != null ? `${j.assets_discovered} assets` : null,
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
