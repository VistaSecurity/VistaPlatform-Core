import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime, durationFmt, shortId } from './kit';
import { useDiscoveryJobs, useJobs } from './queries';
import { JobDetailModal } from './job-detail-modal';
import { DiscoveryJobDetailModal } from './discovery-job-detail-modal';
import {
  DEFAULT_FILTERS,
  type JobFilters,
  type StatusBucket,
  STATUS_BUCKET_LABELS,
  distinctExecutors,
  filterRows,
  kindLabel,
  mergeJobs,
} from './unified-jobs';
import type { ScanJob } from './scan-job-state';
import type { InterrogationJob } from './unified-jobs';

// Discovery → Discovery Jobs — the unified job list (morning-notes decision
// 7b): every discovery_jobs row (Active Scan, the Discover wizard, the
// automatic-scan sweep, from cluster-sensor-service via inventory-service)
// merged with device-interrogation-service's device_jobs, in one table.
//
// Before this, `discovery_jobs` had no listing page anywhere — a scan sent to
// a tenant sensor was visible only on the page that started it, or in the
// Active Scanning settings run list. This page is the single home for "what
// has run and where," across both job kinds.

const COLS = [
  { label: 'Kind', w: '110px' },
  { label: 'Job', w: '1.1fr' },
  { label: 'Target', w: '1.2fr' },
  { label: 'Executor', w: '0.9fr' },
  { label: 'Status', w: '1.1fr' },
  { label: 'Source', w: '0.8fr' },
  { label: 'Found', w: '60px', align: 'right' as const },
  { label: 'Started', w: '90px', align: 'right' as const },
  { label: 'Duration', w: '80px', align: 'right' as const },
  { label: '', w: '76px', align: 'right' as const },
];

// Interrogation-job write surface. Mirrors the Go handler's allowed set:
// pending / assigned / in-progress.
const INTERROGATION_CANCELLABLE = new Set(['pending', 'queued', 'assigned', 'in_progress', 'in-progress', 'running', 'processing']);
const INTERROGATION_RETRYABLE = new Set(['failed', 'error', 'cancelled', 'canceled']);
// Discovery-job write surface (queued/awaiting_sensor/running are cancellable).
const DISCOVERY_CANCELLABLE = new Set(['queued', 'pending', 'awaiting_sensor', 'running', 'in_progress', 'processing']);

function RowBtn({ icon, title, onClick, disabled }: { icon: string; title: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      className="ui-btn sm ghost"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      style={{ flex: 'none', padding: '0 7px' }}
    >
      <Icon name={icon} size={13} />
    </button>
  );
}

const KIND_OPTIONS: Array<{ value: JobFilters['kind']; label: string }> = [
  { value: 'all', label: 'All kinds' },
  { value: 'interrogation', label: kindLabel('interrogation') },
  { value: 'discovery', label: kindLabel('discovery') },
  { value: 'automatic', label: kindLabel('automatic') },
];

const STATUS_OPTIONS: Array<{ value: JobFilters['status']; label: string }> = [
  { value: 'all', label: 'All statuses' },
  ...(Object.keys(STATUS_BUCKET_LABELS) as StatusBucket[]).map((b) => ({ value: b, label: STATUS_BUCKET_LABELS[b] })),
];

export function JobsPage() {
  const interrogationQ = useJobs();
  const discoveryQ = useDiscoveryJobs();
  const qc = useQueryClient();

  const deviceJobs = useMemo(() => interrogationQ.data?.jobs ?? [], [interrogationQ.data]);
  const discoveryJobs = useMemo(() => (discoveryQ.data?.jobs ?? []) as ScanJob[], [discoveryQ.data]);
  const allRows = useMemo(() => mergeJobs(deviceJobs, discoveryJobs), [deviceJobs, discoveryJobs]);

  const [filters, setFilters] = useState<JobFilters>(DEFAULT_FILTERS);
  const rows = useMemo(() => filterRows(allRows, filters), [allRows, filters]);
  const executorOptions = useMemo(() => distinctExecutors(allRows), [allRows]);

  const [selectedInterrogation, setSelectedInterrogation] = useState<InterrogationJob | null>(null);
  const [selectedDiscovery, setSelectedDiscovery] = useState<ScanJob | null>(null);

  const invalidateInterrogation = () => qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
  const invalidateDiscovery = () => qc.invalidateQueries({ queryKey: ['discovery', 'scan-jobs'] });

  const retryInterrogation = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/jobs/{id}/retry', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to retry job');
      return data;
    },
    onSettled: invalidateInterrogation,
  });

  const cancelInterrogation = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/jobs/{id}/cancel', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to cancel job');
      return data;
    },
    onSettled: invalidateInterrogation,
  });

  const cancelDiscovery = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.inventory.POST('/discovery/jobs/{id}/cancel', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to cancel job');
      return data;
    },
    onSettled: invalidateDiscovery,
  });

  const busy = retryInterrogation.isPending || cancelInterrogation.isPending || cancelDiscovery.isPending;

  const note = queryNote([interrogationQ, discoveryQ], allRows.length === 0, {
    thing: 'jobs',
    emptyTitle: 'No jobs yet',
    emptyMessage: 'Start a scan from Discovery → Active Scan or run Discover to see jobs here.',
  });

  return (
    <PageWrap title="Discovery Jobs" count={interrogationQ.isLoading || discoveryQ.isLoading ? '' : allRows.length}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t2)' }}>
          Kind
          <select
            aria-label="Filter by kind"
            className="ui-select"
            value={filters.kind}
            onChange={(e) => setFilters((f) => ({ ...f, kind: e.target.value as JobFilters['kind'] }))}
          >
            {KIND_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t2)' }}>
          Status
          <select
            aria-label="Filter by status"
            className="ui-select"
            value={filters.status}
            onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value as JobFilters['status'] }))}
          >
            {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t2)' }}>
          Executor
          <select
            aria-label="Filter by executor"
            className="ui-select"
            value={filters.executor}
            onChange={(e) => setFilters((f) => ({ ...f, executor: e.target.value }))}
          >
            <option value="all">All executors</option>
            {executorOptions.map((e) => <option key={e} value={e}>{e}</option>)}
          </select>
        </label>
      </div>

      {note ?? (
        <DTable
          cols={COLS}
          rows={rows}
          rowKey={(r) => `${r.kind}-${r.id}`}
          onRow={(r) => (r.raw.source === 'interrogation' ? setSelectedInterrogation(r.raw.job) : setSelectedDiscovery(r.raw.job))}
          render={(r) => {
            const s = r.bucket;
            return (
              <>
                <span style={{ fontSize: 11, fontWeight: 600, color: r.kind === 'automatic' ? 'var(--info)' : 'var(--app-t2)' }}>{kindLabel(r.kind)}</span>
                <div style={{ minWidth: 0 }}>
                  <CellTxt v={r.label} c="var(--app-t1)" />
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{shortId(r.id)}</div>
                </div>
                <CellMono v={r.target} c="var(--app-t2)" />
                <CellTxt v={r.executor} />
                <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 600, color: r.statusColor }}>
                    <span style={{ width: 6, height: 6, borderRadius: 50, background: r.statusColor }} />{r.statusLabel}
                  </span>
                  {r.statusDetail && (
                    <span style={{ fontSize: 10, color: 'var(--app-t3)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.statusDetail}>
                      {r.statusDetail}
                    </span>
                  )}
                </span>
                <CellMono v={r.source} c="var(--app-t3)" />
                <CellMono right v={r.found} />
                <CellTxt v={relTime(r.startedAt)} c="var(--app-t3)" />
                <CellMono right v={durationFmt(r.durationSec)} c="var(--app-t3)" />
                <PermissionGate permission={TENANT_PERMISSIONS.discovery.update} fallback={<span />}>
                  <span style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
                    {r.kind === 'interrogation' && INTERROGATION_RETRYABLE.has(s) && (
                      <RowBtn icon="history" title="Retry job" onClick={() => retryInterrogation.mutate(r.id)} disabled={busy} />
                    )}
                    {r.kind === 'interrogation' && INTERROGATION_CANCELLABLE.has(s) && (
                      <RowBtn icon="x-circle" title="Cancel job" onClick={() => cancelInterrogation.mutate(r.id)} disabled={busy} />
                    )}
                    {r.kind !== 'interrogation' && DISCOVERY_CANCELLABLE.has(s) && (
                      <RowBtn icon="x-circle" title="Cancel job" onClick={() => cancelDiscovery.mutate(r.id)} disabled={busy} />
                    )}
                  </span>
                </PermissionGate>
              </>
            );
          }}
        />
      )}
      <JobDetailModal job={selectedInterrogation} onClose={() => setSelectedInterrogation(null)} />
      <DiscoveryJobDetailModal job={selectedDiscovery} onClose={() => setSelectedDiscovery(null)} />
    </PageWrap>
  );
}
