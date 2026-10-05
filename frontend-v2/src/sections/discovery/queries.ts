import { keepPreviousData, useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import type { inventoryOperations } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { MAX_BULK } from './observation-review';

// Typed live queries shared across the Discovery pages. Query keys are shared
// deliberately — the Command Center and the sub-pages reuse one cache entry.

export function useSensors() {
  return useQuery({
    queryKey: ['discovery', 'sensors'],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors', {});
      if (error || !data) throw new Error('Failed to load sensors');
      return data.sensors ?? [];
    },
  });
}

// Enrolled discovery (interrogation) agents — the downloadable device-agent
// binary, stored in device-interrogation-service (a different service/table than
// sensors). Rendered as their OWN table on Sensors & Agents, not merged into the
// sensor table: the two share almost no columns, and merging them meant agents
// showed "—" for the sensor-only ones while their real fields (addresses,
// profile, job history) had nowhere to go.
export function useDeviceAgents() {
  return useQuery({
    queryKey: ['discovery', 'device-agents'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/agents', {});
      if (error || !data) throw new Error('Failed to load device agents');
      return data.agents ?? [];
    },
  });
}

export function useSensorStats() {
  return useQuery({
    queryKey: ['discovery', 'sensor-stats'],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/stats', {});
      if (error || !data) throw new Error('Failed to load sensor stats');
      return data;
    },
  });
}

/** sensor id → discovery count ("assets found" per sensor). */
export function useDiscoveryCounts() {
  return useQuery({
    queryKey: ['discovery', 'sensor-discovery-counts'],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/discovery-counts', {});
      if (error || !data) throw new Error('Failed to load discovery counts');
      return data.counts ?? {};
    },
  });
}

export function useJobs(pageSize = 50) {
  return useQuery({
    queryKey: ['discovery', 'jobs', pageSize],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/jobs', { params: { query: { page: 1, page_size: pageSize } } });
      if (error || !data) throw new Error('Failed to load discovery jobs');
      return data;
    },
  });
}

// The tenant's discovery jobs — Active Scans, the automatic-scan sweep,
// Discover wizard runs — with each job's executor and dispatch timeline
//. A different table from the interrogation jobs above: those are
// device interrogations (device-interrogation-service), these are scans
// (cluster-sensor-service, proxied through inventory-service). The unified
// Discovery → Discovery Jobs page (morning-notes decision 7b) merges both.
//
// The list re-reads every 5 s while any job on it has not ended,
// so a running scan's row moves (the list carries a scan-plan job's progress
// while it runs), and stops once everything has settled. TanStack Query
// pauses the interval while the tab is hidden.
const SETTLED = new Set(['completed', 'failed', 'cancelled', 'success', 'error']);

export function useDiscoveryJobs(pageSize = 100) {
  return useQuery({
    queryKey: ['discovery', 'scan-jobs', pageSize],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs', { params: { query: { page: 1, page_size: pageSize } } });
      if (error || !data) throw new Error('Failed to load discovery jobs');
      return data;
    },
    refetchInterval: (query) => ((query.state.data?.jobs ?? []).some((j) => !SETTLED.has((j.status ?? '').toLowerCase())) ? 5000 : false),
  });
}

// One discovery job (an Active Scan the operator just started, or the job open
// in the Discovery Jobs detail), with its executor and dispatch state — and,
// for a scan-plan job, its plan, progress and coverage. Polls every 5 s while
// the job is still in flight and stops once it has settled.

export function useScanJob(jobId?: string | null) {
  return useQuery({
    queryKey: ['discovery', 'scan-job', jobId],
    enabled: !!jobId,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs/{id}', { params: { path: { id: jobId! } } });
      if (error || !data) throw new Error('Failed to load the scan');
      return data;
    },
    refetchInterval: (query) => (SETTLED.has((query.state.data?.status ?? '').toLowerCase()) ? false : 5000),
  });
}

// One job's discovered assets + the post-processing verdict, for the job detail
// modal. Enabled only when a job is selected so opening the page costs nothing.
// The payload is projected and scrubbed server-side (see JobResultsResponse).
export function useJobResults(jobId?: string | null) {
  return useQuery({
    queryKey: ['discovery', 'job-results', jobId],
    enabled: !!jobId,
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/jobs/{id}/results', {
        params: { path: { id: jobId! } },
      });
      if (error || !data) throw new Error('Failed to load job results');
      return data;
    },
  });
}

// A discovery job's findings + materialization split, for the unified Jobs
// page's discovery-job detail panel. Enabled only when a discovery/automatic
// row is selected.
// `live` re-reads every 5 s while the job runs.
export function useDiscoveryJobResults(jobId?: string | null, opts: { live?: boolean } = {}) {
  return useQuery({
    queryKey: ['discovery', 'scan-job-results', jobId],
    enabled: !!jobId,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs/{id}/results', {
        params: { path: { id: jobId! } },
      });
      if (error || !data) throw new Error("Failed to load this scan's results");
      return data;
    },
    refetchInterval: opts.live ? 5000 : false,
  });
}

// One page of a scan-plan job's results grouped by host ( H21): each host
// with all its ports, paged by HOST so a host is never split across pages and
// a 65k-port scan is never one 65k-row response. The previous page stays on
// screen while the next loads (no layout jump), and `live` re-reads the page
// every 5 s while the job runs so results appear as hosts finish.
export function useDiscoveryJobHosts(jobId: string | null | undefined, page: number, pageSize: number, opts: { live?: boolean } = {}) {
  return useQuery({
    queryKey: ['discovery', 'scan-job-hosts', jobId, page, pageSize],
    enabled: !!jobId,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs/{id}/results', {
        params: { path: { id: jobId! }, query: { group: 'host', page, page_size: pageSize } },
      });
      if (error || !data) throw new Error("Failed to load this scan's results by host");
      return { hosts: data.hosts ?? [], total: data.total_hosts ?? 0 };
    },
    placeholderData: keepPreviousData,
    refetchInterval: opts.live ? 5000 : false,
  });
}

export function useJobStats() {
  return useQuery({
    queryKey: ['discovery', 'job-stats'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/jobs/stats', {});
      if (error || !data) throw new Error('Failed to load job stats');
      return data.stats;
    },
  });
}

export function usePcapJobs() {
  return useQuery({
    queryKey: ['discovery', 'pcap-jobs'],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/pcap/jobs', { params: { query: { page: 1, limit: 20 } } });
      if (error || !data) throw new Error('Failed to load PCAP jobs');
      return data;
    },
    // Uploads land as queued jobs and progress server-side; poll while open.
    refetchInterval: 15_000,
  });
}

export function useDevices() {
  return useQuery({
    queryKey: ['discovery', 'devices'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/devices', {});
      if (error || !data) throw new Error('Failed to load devices');
      return data.devices ?? [];
    },
  });
}

export function useSchedules() {
  return useQuery({
    queryKey: ['discovery', 'schedules'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/schedules', {});
      if (error || !data) throw new Error('Failed to load schedules');
      return data.schedules ?? [];
    },
  });
}

export function useIntegrations() {
  return useQuery({
    queryKey: ['discovery', 'integrations'],
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/integrations', {});
      if (error || !data) throw new Error('Failed to load cloud integrations');
      return data.integrations ?? [];
    },
  });
}

// Pending-approval assets — the approval queue. The asset_status filter is
// required: without it the service returns its monitoring-only default view,
// which EXCLUDES pending assets (see the listInfrastructureAssets spec note).
export function usePendingAssets() {
  return useQuery({
    queryKey: ['discovery', 'pending-assets'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { asset_status: 'pending_approval', page: 1, page_size: 100 } },
      });
      if (error || !data) throw new Error('Failed to load pending assets');
      return data.assets ?? [];
    },
  });
}

// ---- Discovery → Observations ---------------------------------------
//
// Every key starts with 'identity-observations', so one invalidation covers the
// list, the expanded rows' detail reads and the asset page's provisional panel.

export type ObservationListQuery = NonNullable<inventoryOperations['listIdentityObservations']['parameters']['query']>;

export function useObservationList(query: ObservationListQuery, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: ['identity-observations', 'list', query],
    enabled: opts.enabled ?? true,
    queryFn: async () => {
      const { data, response } = await clients.inventory.GET('/discovery/observations', { params: { query } });
      if (!response.ok || !data) throw new Error('Unable to load observations');
      return data;
    },
    // The previous page stays on screen while the next one loads.
    placeholderData: keepPreviousData,
  });
}

/** One observation with its enrichment jobs and retained evidence (the detail read). */
export function useObservation(id: string | null | undefined) {
  return useQuery({
    queryKey: ['identity-observations', 'detail', id],
    enabled: !!id,
    queryFn: async () => {
      const { data, response } = await clients.inventory.GET('/discovery/observations/{id}', { params: { path: { id: id! } } });
      if (!response.ok || !data) throw new Error('Unable to load observation');
      return data;
    },
  });
}

/**
 * What any observation decision can change: the observations themselves, the
 * identity coverage strip, inventory (a confirm creates an asset) and the
 * approval queue (that asset is pending approval). Shared by the single-row
 * form and the bulk bar so the two cannot drift.
 */
export function invalidateObservationDecisions(cache: QueryClient) {
  return Promise.all([
    cache.invalidateQueries({ queryKey: ['identity-observations'] }),
    cache.invalidateQueries({ queryKey: ['identity-summary'] }),
    cache.invalidateQueries({ queryKey: ['inventory'] }),
    cache.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] }),
  ]);
}

export type BulkObservationInput = inventoryOperations['bulkDecideIdentityObservations']['requestBody']['content']['application/json'];

/**
 * Confirm or dismiss many observations with one reason. A 200 can carry failed
 * rows — that is per-row information, not an error, so it resolves; only a
 * refused REQUEST (400/403/5xx) rejects.
 */
export function useBulkObservationDecision() {
  const cache = useQueryClient();
  return useMutation({
    mutationFn: async (body: BulkObservationInput) => {
      if (body.ids.length === 0 || body.ids.length > MAX_BULK) throw new Error(`Select between 1 and ${MAX_BULK} observations.`);
      const { data, response } = await clients.inventory.POST('/discovery/observations/bulk', { body });
      if (!response.ok || !data) {
        throw new Error(response.status === 403
          ? 'You do not have permission to decide observations.'
          : 'The decision could not be saved. The list has been refreshed; check it and try again.');
      }
      return data;
    },
    onSettled: () => invalidateObservationDecisions(cache),
  });
}
