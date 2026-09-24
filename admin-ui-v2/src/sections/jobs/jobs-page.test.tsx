// Jobs & Queues: a 403 reads as "no access", not as a broken message bus
// (support-comms-system-jobs-11). The queue panel used to render EVERY failure
// as "NATS/JetStream not reachable", which is what an operator without
// platform.health saw — and went debugging a healthy JetStream.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

type QState = { data?: unknown; isLoading: boolean; isError: boolean; error?: unknown; refetch: () => void };

const state = vi.hoisted(() => ({
  jobs: {} as QState,
  queues: {} as QState,
}));

vi.mock('@tanstack/react-query', () => ({
  useQuery: ({ queryKey }: { queryKey: unknown[] }) => (queryKey[1] === 'queues' ? state.queues : state.jobs),
}));
vi.mock('../../lib/clients', () => ({ clients: { devices: {} } }));
vi.mock('../../app/scope', () => ({ useScope: () => ({ scopeId: null }) }));

import { JobsPage, JobsReadError, isForbidden } from './jobs-page';

const failed = (status: number | undefined): QState => ({
  isLoading: false, isError: true, error: new JobsReadError(status, 'x'), refetch: vi.fn(),
});
const ok = (data: unknown): QState => ({ data, isLoading: false, isError: false, refetch: vi.fn() });

const render = () => renderToStaticMarkup(createElement(JobsPage));

beforeEach(() => {
  state.jobs = ok([]);
  state.queues = ok([]);
});

describe('Jobs & Queues failure states', () => {
  it('shows a 403 on the queues as no access', () => {
    state.queues = failed(403);
    const html = render();
    expect(html).toContain('have access to this');
    expect(html).toContain('platform.health');
    expect(html).not.toContain('NATS/JetStream not reachable');
  });

  it('still says JetStream is unreachable when it is', () => {
    state.queues = failed(503);
    const html = render();
    expect(html).toContain('NATS/JetStream not reachable');
    expect(html).not.toContain('have access to this');
  });

  it('shows a 403 on the job list as no access, without a Retry that cannot help', () => {
    state.jobs = failed(403);
    const html = render();
    expect(html).toContain('have access to this');
    expect(html).not.toContain("Couldn&#x27;t load jobs");
  });

  it('offers Retry for any other job-list failure', () => {
    state.jobs = failed(500);
    expect(render()).toContain("Couldn&#x27;t load jobs");
  });

  it('isForbidden only matches a 403', () => {
    expect(isForbidden(new JobsReadError(403, 'x'))).toBe(true);
    expect(isForbidden(new JobsReadError(401, 'x'))).toBe(false);
    expect(isForbidden(new JobsReadError(undefined, 'x'))).toBe(false);
    expect(isForbidden(new Error('x'))).toBe(false);
  });
});
