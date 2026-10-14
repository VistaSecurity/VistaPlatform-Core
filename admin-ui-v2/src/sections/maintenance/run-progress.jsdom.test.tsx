// @vitest-environment jsdom
//
// Maintenance ▸ a run's progress page: the polling state machine that
// TOLERATES the API disappearing while the update restarts the services (up to
// 15 minutes of failed polls read as "Services are restarting", with backoff;
// then an error with Retry), the step list with log tails, the success line,
// and "Roll back to <previous>" — offered only on a failed update whose
// failure may have changed the cluster, to a platform.maintenance holder.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HelmRelease, MaintenanceRun } from './maintenance-queries';

interface ProgressMocks {
  fetch: (id: string) => Promise<unknown>;
  candidate: HelmRelease | null;
  rollbackMutate: (rev: number, opts: { onSuccess: (r: { run: { id: string } }) => void }) => void;
  perms: Set<string>;
  releasesEnabled: boolean[];
}
const st: ProgressMocks = vi.hoisted(() => ({
  fetch: () => Promise.reject(new Error('unset')),
  candidate: null,
  rollbackMutate: () => {},
  perms: new Set<string>(['platform.maintenance']),
  releasesEnabled: [],
}));

vi.mock('./maintenance-queries', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    fetchRun: (id: string) => st.fetch(id),
    useReleases: (opts: { enabled?: boolean }) => {
      st.releasesEnabled.push(Boolean(opts.enabled));
      return { data: opts.enabled ? { releases: [], rollback_candidate: st.candidate } : undefined };
    },
    useRunMutations: () => ({ update: {}, rollback: { mutate: st.rollbackMutate, isPending: false, error: null } }),
    useMaintenanceRuns: () => ({ isLoading: false, isError: false, refetch: () => {}, data: [run({ id: 'r-9', status: 'succeeded' })] }),
  };
});
vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformPermissions: () => ({ hasPermission: (p: string) => st.perms.has(p) }) };
});

import {
  INITIAL_POLL,
  MAX_BACKOFF_MS,
  POLL_MS,
  RECONNECT_WINDOW_MS,
  RunProgressPage,
  nextPollDelay,
  nextPollState,
  offerRollback,
} from './run-progress';
import { RunNotFoundError } from './maintenance-queries';
import { RunHistory } from './run-history';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function run(over: Partial<MaintenanceRun> = {}): MaintenanceRun {
  return {
    id: 'r-1', kind: 'update', status: 'running', started_by: null, started_at: '2026-10-14T10:00:00Z', finished_at: null,
    from_version: '4.5.0', to_version: '4.6.0',
    steps: [
      { name: 'backup', executor: 'service', status: 'succeeded', log_tail: 'Backup ready' },
      { name: 'verify', executor: 'service', status: 'succeeded' },
      { name: 'upgrade', executor: 'job', status: 'running', log_tail: 'Release "vista" is being upgraded' },
      { name: 'smoke', executor: 'service', status: 'pending' },
    ],
    ...over,
  };
}
function failedAt(step: string, over: Partial<MaintenanceRun> = {}): MaintenanceRun {
  const r = run({ status: 'failed', error: 'BackoffLimitExceeded', finished_at: '2026-10-14T10:20:00Z', ...over });
  let hit = false;
  r.steps = r.steps.map((s) => {
    if (s.name === step) { hit = true; return { ...s, status: 'failed', error: 'helm: timed out waiting for the condition', log_tail: 'Error: UPGRADE FAILED: context deadline exceeded' }; }
    return hit ? { ...s, status: 'skipped' } : { ...s, status: 'succeeded' };
  });
  return r;
}
const prev: HelmRelease = { revision: 7, chart_version: '4.5.0', app_version: '4.5.0', status: 'deployed', updated: '2026-10-01T10:00:00Z' };

describe('polling state machine (pure)', () => {
  it('a failed poll inside the window is "reconnecting", keeping the last run', () => {
    const live = nextPollState(INITIAL_POLL, { ok: true, run: run() }, 0);
    const s1 = nextPollState(live, { ok: false }, 1000);
    expect(s1).toMatchObject({ phase: 'reconnecting', failures: 1, failingSince: 1000 });
    expect(s1.run?.id).toBe('r-1');
    const s2 = nextPollState(s1, { ok: false }, 1000 + RECONNECT_WINDOW_MS - 1);
    expect(s2.phase).toBe('reconnecting');
    const s3 = nextPollState(s2, { ok: false }, 1000 + RECONNECT_WINDOW_MS);
    expect(s3.phase).toBe('error');
    expect(nextPollDelay(s3)).toBeNull();
  });
  it('recovering resets the window', () => {
    const s = nextPollState(nextPollState(INITIAL_POLL, { ok: false }, 0), { ok: true, run: run() }, 5000);
    expect(s).toMatchObject({ phase: 'live', failures: 0, failingSince: null });
  });
  it('backs off while reconnecting, capped; polls steadily while live; stops when settled', () => {
    let s = INITIAL_POLL;
    const delays: number[] = [];
    for (let i = 0; i < 8; i++) { s = nextPollState(s, { ok: false }, i); delays.push(nextPollDelay(s)!); }
    expect(delays[0]).toBe(POLL_MS);
    expect(delays[1]).toBe(POLL_MS * 2);
    expect(delays.every((d, i) => i === 0 || d >= delays[i - 1])).toBe(true);
    expect(Math.max(...delays)).toBe(MAX_BACKOFF_MS);
    expect(nextPollDelay(nextPollState(INITIAL_POLL, { ok: true, run: run() }, 0))).toBe(POLL_MS);
    expect(nextPollDelay(nextPollState(INITIAL_POLL, { ok: true, run: run({ status: 'succeeded' }) }, 0))).toBeNull();
    expect(nextPollDelay(nextPollState(INITIAL_POLL, { ok: false, notFound: true }, 0))).toBeNull();
  });
});

describe('offerRollback (pure)', () => {
  it('only a failed update, failing where the cluster may have changed, with a candidate and the permission', () => {
    expect(offerRollback(failedAt('upgrade'), prev, true)).toBe(true);
    expect(offerRollback(failedAt('smoke'), prev, true)).toBe(true);
    expect(offerRollback(failedAt('backup'), prev, true)).toBe(false);
    expect(offerRollback(failedAt('verify'), prev, true)).toBe(false);
    expect(offerRollback(run({ status: 'succeeded' }), prev, true)).toBe(false);
    expect(offerRollback(run(), prev, true)).toBe(false);
    expect(offerRollback(failedAt('upgrade', { kind: 'rollback' }), prev, true)).toBe(false);
    expect(offerRollback(failedAt('upgrade'), null, true)).toBe(false);
    expect(offerRollback(failedAt('upgrade'), prev, false)).toBe(false);
  });
});

let root: Root | null = null;
let host: HTMLDivElement;
const byTest = (id: string) => host.querySelector(`[data-testid="${id}"]`);
const flush = async () => { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); };

function mountPage(path = '/maintenance/runs/r-1') {
  act(() => root!.render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/maintenance/runs/:id" element={<RunProgressPage />} />
        <Route path="/maintenance" element={<div data-testid="about">about</div>} />
      </Routes>
    </MemoryRouter>,
  ));
}

beforeEach(() => {
  vi.useFakeTimers();
  st.candidate = null;
  st.rollbackMutate = vi.fn();
  st.perms = new Set(['platform.maintenance']);
  st.releasesEnabled = [];
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
  vi.useRealTimers();
});

describe('RunProgressPage', () => {
  it('shows the steps with their log tails while the run is running', async () => {
    st.fetch = vi.fn(async () => run());
    mountPage();
    await flush();
    expect(byTest('run-progress')?.getAttribute('data-phase')).toBe('live');
    const steps = [...host.querySelectorAll('[data-testid="run-step"]')];
    expect(steps.map((s) => s.getAttribute('data-step'))).toEqual(['backup', 'verify', 'upgrade', 'smoke']);
    expect(host.querySelector('[data-step="upgrade"] [data-testid="step-log"]')?.textContent).toContain('being upgraded');
    expect(byTest('rollback-button')).toBeNull();
  });

  it('tolerates the API disappearing for up to 15 minutes, then shows an error with Retry', async () => {
    let calls = 0;
    st.fetch = vi.fn(async () => { calls++; if (calls === 1) return run(); throw new Error('HTTP 503'); });
    mountPage();
    await flush();
    expect(byTest('run-progress')?.getAttribute('data-phase')).toBe('live');
    await act(async () => { vi.advanceTimersByTime(POLL_MS); });
    await flush();
    expect(byTest('run-reconnecting')?.textContent).toContain('Services are restarting');
    expect(byTest('run-poll-error')).toBeNull();
    // The steps seen before the restart stay on screen.
    expect(host.querySelectorAll('[data-testid="run-step"]').length).toBe(4);
    // 14 minutes of failures: still reconnecting.
    for (let t = 0; t < 14 * 60 * 1000; t += MAX_BACKOFF_MS) {
      await act(async () => { vi.advanceTimersByTime(MAX_BACKOFF_MS); });
      await flush();
    }
    expect(byTest('run-progress')?.getAttribute('data-phase')).toBe('reconnecting');
    expect(byTest('run-poll-error')).toBeNull();
    // Past 15 minutes: an error with Retry.
    for (let t = 0; t < 2 * 60 * 1000; t += MAX_BACKOFF_MS) {
      await act(async () => { vi.advanceTimersByTime(MAX_BACKOFF_MS); });
      await flush();
    }
    expect(byTest('run-progress')?.getAttribute('data-phase')).toBe('error');
    expect(byTest('run-poll-error')?.textContent).toContain('15 minutes');
    // Retry starts over — and the service is back, with the run settled.
    st.fetch = vi.fn(async () => run({ status: 'succeeded', steps: run().steps.map((s) => ({ ...s, status: 'succeeded' })) }));
    act(() => (byTest('run-retry') as HTMLButtonElement).click());
    await flush();
    expect(byTest('run-progress')?.getAttribute('data-phase')).toBe('live');
    expect(byTest('run-success')?.textContent).toContain('Running Vista Platform 4.6.0');
  });

  it('reconnects when the new service answers, and shows "Running <version>" on success', async () => {
    let calls = 0;
    st.fetch = vi.fn(async () => {
      calls++;
      if (calls === 1) return run();
      if (calls < 4) throw new Error('HTTP 502');
      return run({ status: 'succeeded', finished_at: '2026-10-14T10:25:00Z', steps: run().steps.map((s) => ({ ...s, status: 'succeeded' })) });
    });
    mountPage();
    await flush();
    for (let i = 0; i < 6; i++) { await act(async () => { vi.advanceTimersByTime(MAX_BACKOFF_MS); }); await flush(); }
    expect(byTest('run-reconnecting')).toBeNull();
    expect(byTest('run-success')?.textContent).toContain('Running Vista Platform 4.6.0');
    expect(byTest('rollback-button')).toBeNull();
    const n = calls;
    await act(async () => { vi.advanceTimersByTime(10 * MAX_BACKOFF_MS); });
    expect(calls).toBe(n); // settled: polling stopped
  });

  it('a failed update shows the failed step, its log tail and Roll back to the previous version', async () => {
    st.fetch = vi.fn(async () => failedAt('upgrade'));
    st.candidate = prev;
    st.rollbackMutate = vi.fn((_rev: unknown, opts: { onSuccess: (r: { run: { id: string } }) => void }) => opts.onSuccess({ run: { id: 'r-2' } }));
    mountPage();
    await flush();
    expect(byTest('run-failure')?.textContent).toContain('Upgrade');
    expect(host.querySelector('[data-step="upgrade"] [data-testid="step-error"]')?.textContent).toContain('timed out');
    expect(host.querySelector('[data-step="upgrade"] [data-testid="step-log"]')?.textContent).toContain('UPGRADE FAILED');
    const btn = byTest('rollback-button') as HTMLButtonElement;
    expect(btn.textContent).toContain('Roll back to 4.5.0');
    act(() => btn.click());
    const confirm = [...document.querySelectorAll('[role="dialog"] button')].find((b) => b.textContent === 'Roll back to 4.5.0') as HTMLButtonElement;
    expect(confirm).toBeTruthy();
    expect(st.rollbackMutate).not.toHaveBeenCalled();
    act(() => confirm.click());
    expect(st.rollbackMutate).toHaveBeenCalledWith(7, expect.anything());
  });

  it('no Roll back when the update failed before Helm ran — it says nothing changed', async () => {
    st.fetch = vi.fn(async () => failedAt('backup'));
    st.candidate = prev;
    mountPage();
    await flush();
    expect(byTest('run-nothing-changed')?.textContent).toContain('4.5.0 is still running');
    expect(byTest('rollback-button')).toBeNull();
  });

  it('no Roll back without platform.maintenance', async () => {
    st.perms = new Set(['platform.health']);
    st.fetch = vi.fn(async () => failedAt('upgrade'));
    st.candidate = prev;
    mountPage();
    await flush();
    expect(byTest('run-failure')).not.toBeNull();
    expect(byTest('rollback-button')).toBeNull();
    expect(st.releasesEnabled.every((e) => !e)).toBe(true);
  });

  it('a skipped backup says the operator chose it', async () => {
    st.fetch = vi.fn(async () => run({ steps: [{ name: 'backup', executor: 'service', status: 'skipped', detail: 'skipped_by_operator' }, ...run().steps.slice(1)] }));
    mountPage();
    await flush();
    expect(host.querySelector('[data-step="backup"] [data-testid="step-detail"]')?.textContent).toContain('your own backup');
  });

  it('an unknown run says so and stops polling', async () => {
    st.fetch = vi.fn(async () => { throw new RunNotFoundError(); });
    mountPage();
    await flush();
    expect(byTest('run-not-found')).not.toBeNull();
    await act(async () => { vi.advanceTimersByTime(10 * MAX_BACKOFF_MS); });
    expect(st.fetch).toHaveBeenCalledTimes(1);
  });
});

describe('Run history rows link to their progress page', () => {
  it('each row is a link to /maintenance/runs/:id', () => {
    act(() => root!.render(<MemoryRouter><RunHistory /></MemoryRouter>));
    const link = byTest('run-link') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/maintenance/runs/r-9');
  });
});
