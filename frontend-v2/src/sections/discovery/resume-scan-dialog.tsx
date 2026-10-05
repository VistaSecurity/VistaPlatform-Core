// "Resume scan" for a failed or queued discovery job: asks
// inventory-service to re-queue it (POST /discovery/jobs/{id}/rerun), which
// asks cluster-sensor-service to retry. A retry runs again only what the job
// had not finished — the hosts (a scan-plan job's work units) or targets
// (a legacy job) still open — and keeps what finished and what it found, so
// the confirm text says exactly that rather than "run it again".
//
// A refusal is shown in the server's words: 409 when the job is no longer
// queued or failed, 403 when the caller lacks the permission. NB the route is
// gated on discovery.create in inventory-service while cluster-sensor-service
// checks discovery.update on the same call, so a role holding only
// discovery.create is offered the button and refused with 403 — shown here as
// the server says it, not hidden.
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Modal } from '../../components/ui';
import { clients } from '../../lib/clients';
import { jobActionError } from './job-action-error';
import { shortId } from './kit';
import type { ScanJob } from './scan-job-state';

/** The tooltip on the row action — the same promise as the dialog. */
export const RESUME_TOOLTIP = 'Resume scan — runs again only what it had not finished; finished hosts and their results are kept';

export function resumeExplanation(job: Pick<ScanJob, 'status' | 'plan'>): string {
  const unit = job.plan ? 'hosts' : 'targets';
  const queued = ['queued', 'pending'].includes((job.status ?? '').toLowerCase());
  const lead = queued ? 'This scan has not started yet; resuming sends it to the scanner again.' : 'The scan is put back in the queue.';
  return `${lead} Only the ${unit} it had not finished are scanned again; ${unit} already finished, and what they found, are kept.`;
}

export function ResumeScanDialog({ job, onClose }: { job: ScanJob | null; onClose: () => void }) {
  const qc = useQueryClient();
  const resume = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.inventory.POST('/discovery/jobs/{id}/rerun', { params: { path: { id } } });
      if (error || !data) throw jobActionError(error, 'Failed to resume the scan');
      return data;
    },
    onSuccess: () => onClose(),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'scan-job'] });
    },
  });

  if (!job) return null;
  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      icon="play"
      eyebrow={`Job ${shortId(job.id)}`}
      title="Resume this scan?"
      description={resumeExplanation(job)}
      primary={
        <button className="ui-btn accent" disabled={resume.isPending} onClick={() => resume.mutate(job.id)}>
          {resume.isPending ? 'Resuming…' : 'Resume scan'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose}>Not now</button>}
      footerNote={resume.isError ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{resume.error.message}</span> : undefined}
    />
  );
}
