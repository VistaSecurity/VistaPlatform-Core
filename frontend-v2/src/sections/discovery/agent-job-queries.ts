// A discovery agent's recent jobs, for the agent drawer's Jobs and Health tabs.
//
// GET /jobs?agent_id= is the tenant job list narrowed to the jobs this agent
// was assigned. Only one page is read: the drawer shows the last few, and the
// list's `total` says how many there are in all.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { JOB_HISTORY_LIMIT } from './runtime-drawer';

const SETTLED = new Set(['completed', 'failed', 'cancelled', 'success', 'error']);

export function useAgentJobs(agentId: string, enabled = true) {
  return useQuery({
    queryKey: ['discovery', 'agent-jobs', agentId],
    enabled,
    // Re-read while anything shown is still moving, and stop once it settles.
    refetchInterval: (q) => {
      const jobs = q.state.data?.jobs ?? [];
      return jobs.some((j) => !SETTLED.has((j.status || '').toLowerCase())) ? 5000 : false;
    },
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/jobs', {
        params: { query: { agent_id: agentId, page: 1, page_size: JOB_HISTORY_LIMIT } },
      });
      if (error || !data) throw new Error('Failed to load the agent job history');
      return { jobs: data.jobs ?? [], total: data.total ?? 0 };
    },
  });
}

/** One job's projected results — fetched only when its row is expanded. The
 *  endpoint serves a projection, never the agent's raw payload, so nothing a
 *  vendor API returned alongside the posture reaches the page. */
export function useJobResults(jobId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'job-results', jobId],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/jobs/{id}/results', {
        params: { path: { id: jobId } },
      });
      if (error || !data) throw new Error('Failed to load the job results');
      return data;
    },
  });
}

/** This agent's log export state: whether its build can send logs, a request
 *  still waiting for it, and the latest lines it sent. Re-read every 5 s while a
 *  request is waiting, since the agent answers at its next heartbeat. */
export function useAgentLogs(agentId: string) {
  return useQuery({
    queryKey: ['discovery', 'agent-logs', agentId],
    refetchInterval: (q) => (q.state.data?.request ? 5000 : false),
    queryFn: async () => {
      const { data, error } = await clients.devices.GET('/agents/{id}/logs', {
        params: { path: { id: agentId } },
      });
      if (error || !data) throw new Error("Couldn't load this agent's logs");
      return data;
    },
  });
}

export function useRequestAgentLogs(agentId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (lines: number) => {
      const { data, error } = await clients.devices.POST('/agents/{id}/logs/request', {
        params: { path: { id: agentId } },
        body: { lines },
      });
      if (error || !data) throw new Error('Could not request the logs');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['discovery', 'agent-logs', agentId] }),
  });
}
