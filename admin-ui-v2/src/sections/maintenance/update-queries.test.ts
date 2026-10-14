// The update-check data layer: a 404 means maintenance-service is absent (never
// retried), a 409 from POST /updates/check becomes a typed conflict the page
// words, and a successful manual check replaces the cached row.
import { describe, expect, it, vi } from 'vitest';

const reply = vi.hoisted(() => ({ get: {}, post: {} }));
vi.mock('../../lib/clients', () => ({
  clients: { maintenance: { GET: vi.fn(async () => reply.get), POST: vi.fn(async () => reply.post) } },
}));

import {
  MaintenanceAbsentError,
  UpdateCheckConflictError,
  checkForUpdates,
  updateStatusQuery,
  type UpdateStatus,
} from './maintenance-queries';

const row: UpdateStatus = {
  checked_at: '2026-10-14T00:00:00Z', source: 'oci://ghcr.io/x/y', current_version: '4.5.0', latest_version: '4.6.0',
  notes_url: 'https://example/notes', error: null, prereleases_seen: [], update_available: true, check_enabled: true,
};

describe('update status query', () => {
  it('is fresh for an hour', () => {
    expect(updateStatusQuery().staleTime).toBe(60 * 60 * 1000);
  });

  it('turns a 404 into MaintenanceAbsentError and never retries it', async () => {
    reply.get = { error: { error: 'not found' }, response: { status: 404 } };
    const q = updateStatusQuery();
    const err = await q.queryFn().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MaintenanceAbsentError);
    expect(q.retry(0, err)).toBe(false);
  });

  it('retries another failure once', async () => {
    reply.get = { error: { error: 'boom' }, response: { status: 503 } };
    const q = updateStatusQuery();
    const err = await q.queryFn().catch((e: unknown) => e);
    expect(q.retry(0, err)).toBe(true);
    expect(q.retry(1, err)).toBe(false);
  });

  it('returns the row on success', async () => {
    reply.get = { data: row, response: { status: 200 } };
    await expect(updateStatusQuery().queryFn()).resolves.toEqual(row);
  });
});

describe('manual check', () => {
  it('returns the new row', async () => {
    reply.post = { data: row, response: { status: 200 } };
    await expect(checkForUpdates()).resolves.toEqual(row);
  });

  it('maps 409 check_in_progress and check_disabled to typed conflicts', async () => {
    reply.post = { error: { error: 'check_in_progress' }, response: { status: 409 } };
    await expect(checkForUpdates()).rejects.toMatchObject({ name: 'UpdateCheckConflictError', reason: 'check_in_progress' });
    reply.post = { error: { error: 'check_disabled' }, response: { status: 409 } };
    const err = await checkForUpdates().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UpdateCheckConflictError);
    expect((err as UpdateCheckConflictError).reason).toBe('check_disabled');
  });

  it('any other failure is a plain error', async () => {
    reply.post = { error: { error: 'check_failed' }, response: { status: 500 } };
    const err = await checkForUpdates().catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(UpdateCheckConflictError);
    expect((err as Error).message).toContain('failed');
  });
});
