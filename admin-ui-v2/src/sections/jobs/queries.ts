// Shared read hook for GET /admin/jobs (device-interrogation-service). Jobs &
// Queues and Support ▸ Job Repair both list this endpoint; they used to fetch the
// newest 100 rows unfiltered under two different query keys and filter in the
// browser, so a busy fleet's healthy rows pushed stuck older jobs off the page.
// Status, page and page size now go to the server, which also reports the total.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

/**
 * A failed read that remembers its HTTP status, so the page can tell "you may
 * not see this" (403) from "the backend could not answer". The queue panel used
 * to render every failure as "NATS/JetStream not reachable" — including the
 * 403 an operator without platform.health gets — which sent people debugging a
 * healthy message bus.
 */
export class JobsReadError extends Error {
  constructor(readonly status: number | undefined, message: string) {
    super(message);
    this.name = 'JobsReadError';
  }
}

/** True when a query failed because the operator lacks the permission. */
export const isForbidden = (e: unknown): boolean => e instanceof JobsReadError && e.status === 403;

export const JOB_STATUSES = ['pending', 'assigned', 'in_progress', 'completed', 'failed', 'cancelled'] as const;
/** The states Job Repair treats as needing attention. */
export const PROBLEM_STATUSES: readonly string[] = ['failed', 'pending', 'assigned', 'in_progress'];

export const JOBS_PAGE_SIZE = 50;

export type AdminJobsFilters = {
  /** Operator scope; narrows server-side via tenant_id. */
  scopeId?: string | null;
  /** Server-side status filter; omit or empty for every status. */
  statuses?: readonly string[];
  page?: number;
  pageSize?: number;
};

/** One key factory for every consumer, so a repair mutation refreshes both pages. */
export const jobsKeys = {
  all: ['platform', 'jobs'] as const,
  list: (f: AdminJobsFilters) =>
    [
      ...jobsKeys.all,
      {
        scopeId: f.scopeId ?? null,
        statuses: [...(f.statuses ?? [])].sort(),
        page: f.page ?? 1,
        pageSize: f.pageSize ?? JOBS_PAGE_SIZE,
      },
    ] as const,
};

export function useAdminJobs(
  filters: AdminJobsFilters = {},
  opts: { refetchInterval?: number } = {},
) {
  const page = filters.page ?? 1;
  const pageSize = filters.pageSize ?? JOBS_PAGE_SIZE;
  const statuses = filters.statuses ?? [];
  return useQuery({
    queryKey: jobsKeys.list(filters),
    queryFn: async () => {
      const { data, error, response } = await clients.devices.GET('/admin/jobs', {
        params: {
          query: {
            page,
            page_size: pageSize,
            ...(statuses.length ? { status: [...statuses] } : {}),
            // Narrow server-side so other tenants' rows are never shipped to the client.
            ...(filters.scopeId ? { tenant_id: filters.scopeId } : {}),
          },
        },
      });
      if (error || !data) throw new JobsReadError(response?.status, 'Failed to load jobs');
      return {
        jobs: data.jobs ?? [],
        total: data.total ?? 0,
        page: data.page ?? page,
        pageSize: data.page_size ?? pageSize,
      };
    },
    // Keep the previous page on screen while the next one loads.
    placeholderData: (prev) => prev,
    staleTime: 20 * 1000,
    refetchInterval: opts.refetchInterval,
  });
}
