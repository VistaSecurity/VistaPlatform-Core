import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

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

// Active Scan coverage (): monitoring assets that have never been actively
// scanned (last_scanned_at IS NULL). Drives the Active Scan page — the "what's left to
// verify" list. Pending/imported assets are handled in Approvals + the import handoff.
export function useUnscannedAssets() {
  return useQuery({
    queryKey: ['discovery', 'unscanned-assets'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { unscanned_only: true, page: 1, page_size: 100 } },
      });
      if (error || !data) throw new Error('Failed to load unscanned assets');
      return data.assets ?? [];
    },
  });
}
