// The jobs list is filtered and paged by the SERVER. Job Repair used to fetch the
// newest 100 rows and filter in the browser, so stuck older jobs fell off the page.
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  get: vi.fn(),
  invalidate: vi.fn(),
  mutations: [] as Array<{ onSuccess: () => void }>,
  opts: undefined as undefined | { queryKey: unknown[]; queryFn: () => Promise<unknown> },
}));

vi.mock('@tanstack/react-query', () => ({
  useQuery: (o: { queryKey: unknown[]; queryFn: () => Promise<unknown> }) => { h.opts = o; return {}; },
  useMutation: (m: { onSuccess: () => void }) => { h.mutations.push(m); return {}; },
  useQueryClient: () => ({ invalidateQueries: h.invalidate }),
}));
vi.mock('../../lib/clients', () => ({ clients: { devices: { GET: h.get, POST: vi.fn() }, tenantHealth: {} } }));

import { useJobRepairMutations as mutationsHook } from '../support/support-queries';
import { useAdminJobs as hook, jobsKeys, PROBLEM_STATUSES, JobsReadError } from './queries';

beforeEach(() => {
  h.get.mockReset();
  h.get.mockResolvedValue({ data: { jobs: [], total: 0, page: 1, page_size: 50 }, response: { status: 200 } });
});

const query = async (filters: Parameters<typeof hook>[0]) => {
  hook(filters);
  await h.opts!.queryFn();
  return h.get.mock.calls[0][1].params.query as Record<string, unknown>;
};

describe('useAdminJobs (hook)', () => {
  it('sends the problem states to the server as status[]', async () => {
    const q = await query({ statuses: PROBLEM_STATUSES, page: 2 });
    expect(q.status).toEqual(['failed', 'pending', 'assigned', 'in_progress']);
    expect(q.page).toBe(2);
    expect(q.page_size).toBe(50);
  });

  it('omits status when unfiltered and sends tenant_id only when scoped', async () => {
    let q = await query({});
    expect(q).not.toHaveProperty('status');
    expect(q).not.toHaveProperty('tenant_id');
    h.get.mockClear();
    q = await query({ scopeId: 't-1' });
    expect(q.tenant_id).toBe('t-1');
  });

  it('exposes total and the page', async () => {
    h.get.mockResolvedValue({ data: { jobs: [{ id: 'a' }], total: 240, page: 3, page_size: 50 }, response: { status: 200 } });
    hook({ page: 3 });
    expect(await h.opts!.queryFn()).toEqual({ jobs: [{ id: 'a' }], total: 240, page: 3, pageSize: 50 });
  });

  it('keeps the HTTP status on failure so a 403 reads as no access', async () => {
    h.get.mockResolvedValue({ error: {}, response: { status: 403 } });
    hook({});
    await expect(h.opts!.queryFn()).rejects.toMatchObject({ name: 'JobsReadError', status: 403 });
    expect(new JobsReadError(403, 'x')).toBeInstanceOf(Error);
  });
});

describe('jobs query keys', () => {
  it('every consumer keys under jobsKeys.all and differs by filter', () => {
    hook({ statuses: PROBLEM_STATUSES });
    const repair = h.opts!.queryKey;
    hook({ scopeId: null });
    const jobsPage = h.opts!.queryKey;
    expect(repair.slice(0, 2)).toEqual([...jobsKeys.all]);
    expect(jobsPage.slice(0, 2)).toEqual([...jobsKeys.all]);
    expect(repair).not.toEqual(jobsPage);
    expect(jobsKeys.list({ statuses: ['b', 'a'] })).toEqual(jobsKeys.list({ statuses: ['a', 'b'] }));
  });

  it('a Job Repair retry/cancel invalidates the key Jobs & Queues reads', () => {
    h.mutations.length = 0;
    mutationsHook();
    expect(h.mutations).toHaveLength(2);
    h.mutations.forEach((m) => m.onSuccess());
    expect(h.invalidate).toHaveBeenCalledWith({ queryKey: [...jobsKeys.all] });
    hook({});
    expect(h.opts!.queryKey.slice(0, 2)).toEqual([...jobsKeys.all]);
  });
});
