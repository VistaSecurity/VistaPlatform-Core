// The hide rule: a 404 from GET /admin/maintenance/status means no
// maintenance-service is deployed (maintenance.enabled=false), and only that
// hides the Maintenance section. Same contract as src/lib/edition.ts.
import { describe, expect, it, vi } from 'vitest';

const reply = vi.hoisted(() => ({ value: {} }));
vi.mock('../../lib/clients', () => ({
  clients: { maintenance: { GET: vi.fn(async () => reply.value) } },
}));

import { visibleSections, SECTIONS } from '../../app/nav';
import {
  MaintenanceAbsentError,
  maintenanceStatusQuery,
  resolveMaintenanceAvailability,
  type MaintenanceStatus,
} from './maintenance-queries';

const status = {
  service: 'maintenance-service',
  capabilities: { helm_managed: true, gitops: false, backups: true, updates: true, reason: '' },
  release: { name: 'vista', namespace: 'vista' },
  single_node: false,
  versions: null,
} as MaintenanceStatus;

describe('maintenance status query', () => {
  it('turns a 404 into MaintenanceAbsentError and never retries it', async () => {
    reply.value = { error: { error: 'not found' }, response: { status: 404 } };
    const q = maintenanceStatusQuery();
    const err = await q.queryFn().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MaintenanceAbsentError);
    expect(q.retry(0, err)).toBe(false);
  });

  it('treats any other failure as an ordinary, retried error', async () => {
    reply.value = { error: { error: 'boom' }, response: { status: 503 } };
    const q = maintenanceStatusQuery();
    const err = await q.queryFn().catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(MaintenanceAbsentError);
    expect(q.retry(0, err)).toBe(true);
    expect(q.retry(1, err)).toBe(false);
  });

  it('returns the body on success', async () => {
    reply.value = { data: status, response: { status: 200 } };
    await expect(maintenanceStatusQuery().queryFn()).resolves.toEqual(status);
  });
});

describe('availability', () => {
  it('is pending until the read lands (the rail entry stays hidden)', () => {
    expect(resolveMaintenanceAvailability(undefined, null)).toBe('pending');
  });
  it('is absent only on a 404', () => {
    expect(resolveMaintenanceAvailability(undefined, new MaintenanceAbsentError())).toBe('absent');
  });
  it('fails open on any other error (the page shows its own error state)', () => {
    expect(resolveMaintenanceAvailability(undefined, new Error('503'))).toBe('available');
  });
  it('is available once the status answered', () => {
    expect(resolveMaintenanceAvailability(status, null)).toBe('available');
  });
});

describe('the rail hides Maintenance unless the service is available', () => {
  const ids = (available: boolean) =>
    visibleSections(() => true, { msp: true, billing: true }, SECTIONS, 'msp', () => available).map((s) => s.id);
  it('absent / pending → hidden', () => {
    expect(ids(false)).not.toContain('maintenance');
  });
  it('available → shown, and nothing else changes', () => {
    expect(ids(true)).toContain('maintenance');
    expect(ids(true).filter((id) => id !== 'maintenance')).toEqual(ids(false));
  });
  it('a section without a service gate is never affected', () => {
    expect(ids(false)).toContain('system');
  });
});
