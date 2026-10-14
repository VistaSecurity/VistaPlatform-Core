// Maintenance section data — TanStack Query over the generated
// maintenance-service client (api/openapi/maintenance-service.openapi.yaml).
//
// One query backs the whole section AND the decision whether to offer it:
// GET /admin/maintenance/status. A 404 means no maintenance-service is deployed
// (maintenance.enabled=false in the chart), and the section is hidden — the
// same rule src/lib/edition.ts applies to Enterprise routes a Core build never
// mounts. Absent, not forbidden: no permission check can stand in for it.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { maintenanceServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';

export type MaintenanceStatus = maintenanceServiceComponents['schemas']['MaintenanceStatus'];
export type MaintenanceCapabilities = maintenanceServiceComponents['schemas']['MaintenanceCapabilities'];
export type VersionReport = maintenanceServiceComponents['schemas']['VersionResponse'];
export type UpdateStatus = maintenanceServiceComponents['schemas']['UpdateStatus'];

/** The status route answered 404: maintenance-service is not deployed. */
export class MaintenanceAbsentError extends Error {
  constructor() {
    super('maintenance-service is not deployed in this install');
    this.name = 'MaintenanceAbsentError';
  }
}

export const maintenanceStatusKey = ['maintenance', 'status'] as const;

/**
 * Query options for the status read. Exported separately so tests can drive it
 * through a real QueryClient. An absent service is a settled fact, so a 404 is
 * never retried; anything else gets one retry for a transient blip.
 */
export function maintenanceStatusQuery() {
  return {
    queryKey: maintenanceStatusKey,
    queryFn: async (): Promise<MaintenanceStatus> => {
      const { data, error, response } = await clients.maintenance.GET('/admin/maintenance/status', {});
      if (response?.status === 404) throw new MaintenanceAbsentError();
      if (error || !data) throw new Error('Failed to load maintenance status');
      return data;
    },
    staleTime: 60 * 1000,
    retry: (failureCount: number, err: unknown) => !(err instanceof MaintenanceAbsentError) && failureCount < 1,
  };
}

export function useMaintenanceStatus(opts: { enabled?: boolean } = {}) {
  return useQuery({ ...maintenanceStatusQuery(), enabled: opts.enabled ?? true });
}

// ── Update check (WP2) ─────────────────────────────────────────────────────
// GET /admin/maintenance/updates is the stored result of the last check — the
// console reads that row, never the chart registry. It changes at most daily,
// so it is fresh for an hour; "Check now" writes the new row straight into the
// cache.

export const updateStatusKey = ['maintenance', 'updates'] as const;

export function updateStatusQuery() {
  return {
    queryKey: updateStatusKey,
    queryFn: async (): Promise<UpdateStatus> => {
      const { data, error, response } = await clients.maintenance.GET('/admin/maintenance/updates', {});
      if (response?.status === 404) throw new MaintenanceAbsentError();
      if (error || !data) throw new Error('Failed to load the update status');
      return data;
    },
    staleTime: 60 * 60 * 1000,
    retry: (failureCount: number, err: unknown) => !(err instanceof MaintenanceAbsentError) && failureCount < 1,
  };
}

export function useUpdateStatus(opts: { enabled?: boolean } = {}) {
  return useQuery({ ...updateStatusQuery(), enabled: opts.enabled ?? true });
}

/** Why POST /updates/check answered 409. */
export class UpdateCheckConflictError extends Error {
  readonly reason: 'check_in_progress' | 'check_disabled';
  constructor(reason: 'check_in_progress' | 'check_disabled') {
    super(reason === 'check_in_progress' ? 'An update check is already running.' : 'The update check is turned off for this install.');
    this.name = 'UpdateCheckConflictError';
    this.reason = reason;
  }
}

/** Run the update check now; the new row replaces the cached one. */
export async function checkForUpdates(): Promise<UpdateStatus> {
  const { data, error, response } = await clients.maintenance.POST('/admin/maintenance/updates/check', {});
  if (response?.status === 409) {
    const reason = (error as { error?: string } | undefined)?.error;
    throw new UpdateCheckConflictError(reason === 'check_disabled' ? 'check_disabled' : 'check_in_progress');
  }
  if (error || !data) throw new Error('The update check failed');
  return data;
}

export function useCheckForUpdates() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: checkForUpdates,
    onSuccess: (data) => { qc.setQueryData(updateStatusKey, data); },
  });
}

/**
 * Whether the Maintenance section exists in this install.
 *
 *   pending    the read-out has not landed — the rail entry is HIDDEN, so the
 *              nav only ever grows (same choice as CAPABILITIES_PENDING)
 *   absent     the status route 404'd: no maintenance-service is deployed
 *   available  it answered, or failed some other way. FAIL OPEN on other
 *              errors, like CAPABILITIES_UNKNOWN: a transient failure must not
 *              blank the section; the page renders its own error state.
 */
export type MaintenanceAvailability = 'pending' | 'available' | 'absent';

export function resolveMaintenanceAvailability(
  data: MaintenanceStatus | undefined,
  error: unknown,
): MaintenanceAvailability {
  if (data) return 'available';
  if (error instanceof MaintenanceAbsentError) return 'absent';
  if (error) return 'available';
  return 'pending';
}

/**
 * The availability hook the shell, palette and route guard share. `enabled`
 * lets the shell skip the request for an operator who cannot read the section
 * anyway (no platform.health); the section is permission-hidden for them.
 */
export function useMaintenanceAvailability(enabled = true): MaintenanceAvailability {
  const { data, error } = useMaintenanceStatus({ enabled });
  return resolveMaintenanceAvailability(data, error);
}

/* ------------------------------ Backups (WP3) ------------------------------ */

export type Backup = maintenanceServiceComponents['schemas']['Backup'];
export type BackupList = maintenanceServiceComponents['schemas']['BackupList'];
export type MaintenanceRun = maintenanceServiceComponents['schemas']['MaintenanceRun'];
export type MaintenanceRunStep = maintenanceServiceComponents['schemas']['MaintenanceRunStep'];
export type CreateBackupRequest = maintenanceServiceComponents['schemas']['CreateBackupRequest'];

export const backupsKey = ['maintenance', 'backups'] as const;
export const maintenanceRunsKey = ['maintenance', 'runs'] as const;

/** Minimum passphrase length — the service refuses shorter (bundlecrypt.MinPassphraseLen). */
export const MIN_BACKUP_PASSPHRASE = 12;

/** The message of a maintenance-service error body ({error, message}), or a fallback. */
function apiMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object') {
    const e = error as { message?: unknown; error?: unknown };
    if (typeof e.message === 'string' && e.message) return e.message;
    if (typeof e.error === 'string' && e.error) return e.error;
  }
  return fallback;
}

/** While anything runs, poll: the row moves Running… → Ready on its own. */
const POLL_WHILE_RUNNING_MS = 3000;

export function useBackups(opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: backupsKey,
    queryFn: async (): Promise<BackupList> => {
      const { data, error } = await clients.maintenance.GET('/admin/maintenance/backups', {});
      if (error || !data) throw new Error(apiMessage(error, 'Failed to load backups'));
      return data;
    },
    enabled: opts.enabled ?? true,
    staleTime: 10 * 1000,
    refetchInterval: (q) => (q.state.data?.backups.some((b) => b.status === 'running') ? POLL_WHILE_RUNNING_MS : false),
  });
}

/** The Run history card: the last `limit` backup / update / rollback runs. */
export function useMaintenanceRuns(limit = 20, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: [...maintenanceRunsKey, limit],
    queryFn: async (): Promise<MaintenanceRun[]> => {
      const { data, error } = await clients.maintenance.GET('/admin/maintenance/runs', { params: { query: { limit } } });
      if (error || !data) throw new Error(apiMessage(error, 'Failed to load maintenance runs'));
      return data.runs;
    },
    enabled: opts.enabled ?? true,
    staleTime: 10 * 1000,
    refetchInterval: (q) => (q.state.data?.some((r) => r.status === 'running') ? POLL_WHILE_RUNNING_MS : false),
  });
}

export function useBackupMutations() {
  const qc = useQueryClient();
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: backupsKey });
    void qc.invalidateQueries({ queryKey: maintenanceRunsKey });
  };
  const create = useMutation({
    mutationFn: async (body: CreateBackupRequest) => {
      const { data, error } = await clients.maintenance.POST('/admin/maintenance/backups', { body });
      if (error || !data) throw new Error(apiMessage(error, 'Could not start the backup'));
      return data;
    },
    onSettled: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.maintenance.DELETE('/admin/maintenance/backups/{id}', { params: { path: { id } } });
      if (error || (response && !response.ok)) throw new Error(apiMessage(error, 'Could not delete the backup'));
    },
    onSettled: invalidate,
  });
  return { create, remove };
}

/**
 * The download route, for a plain anchor: the browser streams the file to
 * disk itself (a multi-GB bundle must never pass through a fetch() buffer),
 * and the same-origin session cookie authenticates it.
 */
export function backupDownloadHref(id: string): string {
  return `/api/v1/maintenance-service/admin/maintenance/backups/${encodeURIComponent(id)}/download`;
}

/* ----------------------- Update and rollback (WP4) ----------------------- */

export type PreflightResult = maintenanceServiceComponents['schemas']['PreflightResult'];
export type PreflightCheck = maintenanceServiceComponents['schemas']['PreflightCheck'];
export type StartRunResponse = maintenanceServiceComponents['schemas']['StartRunResponse'];
export type HelmRelease = maintenanceServiceComponents['schemas']['HelmRelease'];
export type ReleaseList = maintenanceServiceComponents['schemas']['ReleaseList'];

/** POST /updates or /rollbacks answered 409: another run is running. */
export class RunInProgressError extends Error {
  constructor() {
    super('Another maintenance run is in progress. Wait for it to finish.');
    this.name = 'RunInProgressError';
  }
}

/** POST /updates answered 422 preflight_failed: the body carries the pre-flight. */
export class PreflightFailedError extends Error {
  readonly preflight: PreflightResult;
  constructor(preflight: PreflightResult, message: string) {
    super(message);
    this.name = 'PreflightFailedError';
    this.preflight = preflight;
  }
}

/**
 * Pre-flight for a target version. Never cached across dialog openings: the
 * answer depends on the cluster's state right now (a run in progress, a fresh
 * backup), so each opening asks again.
 */
export function usePreflight(version: string, opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: ['maintenance', 'preflight', version] as const,
    queryFn: async (): Promise<PreflightResult> => {
      const { data, error } = await clients.maintenance.POST('/admin/maintenance/updates/preflight', { body: { version } });
      if (error || !data) throw new Error(apiMessage(error, 'Pre-flight could not run'));
      return data;
    },
    enabled: (opts.enabled ?? true) && version !== '',
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });
}

export async function startUpdate(body: { version: string; skip_backup: boolean }): Promise<StartRunResponse> {
  const { data, error, response } = await clients.maintenance.POST('/admin/maintenance/updates', { body });
  if (response?.status === 409) throw new RunInProgressError();
  if (response?.status === 422 && error && typeof error === 'object' && 'preflight' in error) {
    const e = error as { preflight: PreflightResult; message?: string };
    throw new PreflightFailedError(e.preflight, e.message ?? 'Pre-flight failed');
  }
  if (error || !data) throw new Error(apiMessage(error, 'Could not start the update'));
  return data;
}

export async function startRollback(revision: number): Promise<StartRunResponse> {
  const { data, error, response } = await clients.maintenance.POST('/admin/maintenance/rollbacks', { body: { revision } });
  if (response?.status === 409) throw new RunInProgressError();
  if (error || !data) throw new Error(apiMessage(error, 'Could not start the rollback'));
  return data;
}

export function useRunMutations() {
  const qc = useQueryClient();
  const invalidate = () => { void qc.invalidateQueries({ queryKey: maintenanceRunsKey }); };
  return {
    update: useMutation({ mutationFn: startUpdate, onSettled: invalidate }),
    rollback: useMutation({ mutationFn: startRollback, onSettled: invalidate }),
  };
}

export const releasesKey = ['maintenance', 'releases'] as const;

/** The Helm release history and the revision a rollback would return to. */
export function useReleases(opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: releasesKey,
    queryFn: async (): Promise<ReleaseList> => {
      const { data, error } = await clients.maintenance.GET('/admin/maintenance/releases', {});
      if (error || !data) throw new Error(apiMessage(error, 'Failed to load the release history'));
      return data;
    },
    enabled: opts.enabled ?? true,
    staleTime: 10 * 1000,
  });
}

/** GET /runs/{id} said the run does not exist (a real answer, not a restart). */
export class RunNotFoundError extends Error {
  constructor() {
    super('No such maintenance run.');
    this.name = 'RunNotFoundError';
  }
}

/**
 * One read of a run. Anything but a 200 or the service's own not_found is
 * thrown as a plain Error — the progress page treats those as "the services
 * are restarting" for a while, because during an update they are.
 */
export async function fetchRun(id: string): Promise<MaintenanceRun> {
  const { data, error, response } = await clients.maintenance.GET('/admin/maintenance/runs/{id}', { params: { path: { id } } });
  if (response?.status === 404 && (error as { error?: string } | undefined)?.error === 'not_found') throw new RunNotFoundError();
  if (error || !data) throw new Error(`The maintenance service did not answer (HTTP ${response?.status ?? 'none'})`);
  return data;
}
