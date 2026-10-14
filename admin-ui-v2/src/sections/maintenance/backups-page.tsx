// VISTA Operations — Maintenance › Backups (spec platform-maintenance.md §1).
//
// Every state from the spec's screens table, in order of precedence:
//   unavailable   from the capability object (GET /admin/maintenance/status):
//                 not Kubernetes, the cluster API unreadable, or no backup
//                 storage (maintenance.backups.enabled=false)
//   loading       skeleton
//   error         retry
//   empty         "No backups yet · Create backup"
//   default       one row per backup: created, contents, size, status, and
//                 Download / Delete for platform.maintenance holders
// A row appears as "Running…" the moment a backup starts and turns Ready (or
// Failed) on its own: the list polls while anything runs. Below it, the Run
// history card (run-history.tsx), which WP4's update runs share.
//
// Download is a plain anchor to the download route: the browser streams the
// file to disk with the session cookie, so a multi-GB bundle never passes
// through a JavaScript buffer.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Archive, Download, Lock, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { Tag } from '../../components/ui/primitives';
import { Modal } from '../../components/ui/modal';
import { Panel } from '../system/parts';
import { CreateBackupDialog } from './create-backup-dialog';
import { formatWhen, RunHistory } from './run-history';
import {
  backupDownloadHref,
  useBackupMutations,
  useBackups,
  useMaintenanceStatus,
  type Backup,
  type BackupList,
  type MaintenanceStatus,
} from './maintenance-queries';

type BackupsState =
  | { kind: 'loading' }
  | { kind: 'error' }
  | { kind: 'unavailable'; title: string; body: string }
  | { kind: 'empty' }
  | { kind: 'list'; backups: Backup[] };

/** What the capability object says about backups: null when they are offered. */
function unavailableState(status: MaintenanceStatus): BackupsState | null {
  const caps = status.capabilities;
  if (caps.reason === 'not_kubernetes') {
    return {
      kind: 'unavailable',
      title: 'Not available in this deployment',
      body: 'Backups from the console need the Helm chart install on Kubernetes. Docker Compose is for evaluation only — back up its database with pg_dump.',
    };
  }
  if (caps.reason === 'cluster_api_unavailable' || caps.reason === 'release_unknown') {
    return {
      kind: 'unavailable',
      title: 'Backups are unavailable right now',
      body: 'The maintenance service cannot read the cluster, so it cannot run a backup. See About & Updates for the reason.',
    };
  }
  if (!caps.backups) {
    return {
      kind: 'unavailable',
      title: 'Backup storage is not configured',
      body: 'Backup storage is not configured for this install (maintenance.backups.enabled=false in the chart values). Enable it and re-apply the chart to back up from here.',
    };
  }
  return null;
}

/** The page state from the status and list queries (pure, for tests). */
export function backupsState(
  status: { isLoading: boolean; isError: boolean; data?: MaintenanceStatus },
  list: { isLoading: boolean; isError: boolean; data?: BackupList } = { isLoading: false, isError: false },
): BackupsState {
  if (status.isLoading) return { kind: 'loading' };
  if (status.isError || !status.data) return { kind: 'error' };
  const unavailable = unavailableState(status.data);
  if (unavailable) return unavailable;
  if (list.isLoading) return { kind: 'loading' };
  if (list.isError || !list.data) return { kind: 'error' };
  if (!list.data.available) {
    return {
      kind: 'unavailable',
      title: 'Backups are unavailable right now',
      body: 'The maintenance service reports that it cannot take a backup in this deployment. See About & Updates for the reason.',
    };
  }
  if (list.data.backups.length === 0) return { kind: 'empty' };
  return { kind: 'list', backups: list.data.backups };
}

/** 1.8 GB, 512 MB, 12 KB. */
export function formatSize(bytes: number | null | undefined): string {
  if (bytes == null) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${i === 0 || v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

const STATUS_META: Record<Backup['status'], { label: string; color: string }> = {
  running: { label: 'Running…', color: 'var(--op-accent)' },
  ready: { label: 'Ready', color: 'var(--ok)' },
  failed: { label: 'Failed', color: 'var(--danger)' },
  deleted: { label: 'Deleted', color: 'var(--op-t3)' },
};

function contentsLabel(b: Backup): string {
  return b.contents.secrets ? 'Database + encryption keys and install secrets' : 'Database';
}

function BackupRow({ b, canWrite, onDelete }: { b: Backup; canWrite: boolean; onDelete: (b: Backup) => void }) {
  const meta = STATUS_META[b.status];
  return (
    <tr data-testid="backup-row" data-status={b.status}>
      <td>{formatWhen(b.created_at)}</td>
      <td>{contentsLabel(b)}</td>
      <td>{formatSize(b.size_bytes)}</td>
      <td>
        <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
          <Tag color={meta.color}>{meta.label}</Tag>
          {b.encrypted && <Tag color="var(--warn)" icon={Lock}>Encrypted</Tag>}
        </span>
      </td>
      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
        {canWrite && b.status === 'ready' && (
          <a className="op-btn sm" href={backupDownloadHref(b.id)} download data-testid="download" style={{ marginRight: 6 }}>
            <Download size={12} /> Download
          </a>
        )}
        {canWrite && b.status !== 'running' && (
          <button className="op-btn ghost sm" onClick={() => onDelete(b)} aria-label="Delete backup"><Trash2 size={12} /> Delete</button>
        )}
      </td>
    </tr>
  );
}

export function BackupsPage() {
  const status = useMaintenanceStatus();
  const offered = status.data ? unavailableState(status.data) === null : false;
  const list = useBackups({ enabled: offered });
  const permissions = usePlatformPermissions();
  const canWrite = permissions.hasPermission(PLATFORM_PERMISSIONS.platform.maintenance);
  const mut = useBackupMutations();
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Backup | null>(null);
  const state = backupsState(status, list);

  const create = (body: Parameters<typeof mut.create.mutate>[0]) => {
    setCreateError(null);
    mut.create.mutate(body, {
      onSuccess: () => { toast.success('Backup started'); setCreating(false); },
      onError: (e: unknown) => setCreateError(e instanceof Error ? e.message : 'Could not start the backup'),
    });
  };
  const confirmDelete = () => {
    if (!deleting) return;
    mut.remove.mutate(deleting.id, {
      onSuccess: () => { toast.success('Backup deleted'); setDeleting(null); },
      onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'Could not delete the backup'),
    });
  };
  const retry = () => { void status.refetch(); if (offered) void list.refetch(); };
  const running = state.kind === 'list' && state.backups.some((b) => b.status === 'running');
  const createButton = canWrite && (
    <button className="op-btn primary sm" onClick={() => { setCreateError(null); setCreating(true); }} disabled={running} title={running ? 'A backup is running' : undefined}>
      <Plus size={13} /> Create backup
    </button>
  );

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <Panel title="Backups" icon={Archive}>
        <div data-testid="maintenance-backups" data-state={state.kind}>
          {state.kind === 'loading' && (
            <div style={{ padding: '28px 20px' }}>
              <div data-testid="skeleton" style={{ height: 40, borderRadius: 'var(--r-md, 8px)', background: 'var(--op-track)', opacity: 0.55 }} />
            </div>
          )}
          {state.kind === 'error' && (
            <div style={{ padding: '28px 20px', textAlign: 'center', color: 'var(--op-t3)', fontSize: 12.5 }}>
              Couldn’t load the backups.
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={retry}><RefreshCw size={12} /> Retry</button>
            </div>
          )}
          {state.kind === 'unavailable' && (
            <div style={{ padding: '28px 20px', textAlign: 'center', color: 'var(--op-t3)', fontSize: 12.5 }}>
              <div style={{ color: 'var(--op-t1)', fontWeight: 600, fontSize: 13 }}>{state.title}</div>
              <div style={{ marginTop: 4, lineHeight: 1.55 }}>{state.body}</div>
            </div>
          )}
          {state.kind === 'empty' && (
            <div style={{ padding: '28px 20px', textAlign: 'center', color: 'var(--op-t3)', fontSize: 12.5 }}>
              <div style={{ color: 'var(--op-t1)', fontWeight: 600, fontSize: 13 }}>No backups yet</div>
              <div style={{ marginTop: 4, lineHeight: 1.55 }}>
                A backup is a <code>pg_dump</code> of the platform database you can download — and, if you choose, the encryption
                keys a restore needs.
              </div>
              {createButton && <div style={{ marginTop: 12 }}>{createButton}</div>}
            </div>
          )}
          {state.kind === 'list' && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid var(--op-border)', fontSize: 12, color: 'var(--op-t3)' }}>
                <span>The newest {list.data?.retention ?? 5} ready backups are kept; older ones are removed after each new backup.</span>
                <div style={{ flex: 1 }} />
                {createButton}
              </div>
              <table className="op-table">
                <thead><tr><th>Created</th><th>Contents</th><th>Size</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {state.backups.map((b) => <BackupRow key={b.id} b={b} canWrite={canWrite} onDelete={setDeleting} />)}
                </tbody>
              </table>
            </>
          )}
        </div>
      </Panel>

      {status.data && <RunHistory />}

      {creating && (
        <CreateBackupDialog
          onClose={() => setCreating(false)}
          onCreate={create}
          pending={mut.create.isPending}
          error={createError}
        />
      )}
      {deleting && (
        <Modal
          open
          onClose={() => setDeleting(null)}
          tone="danger"
          size="sm"
          title="Delete this backup?"
          description={`The backup from ${formatWhen(deleting.created_at)} is removed from backup storage. A copy you downloaded is not affected. This cannot be undone.`}
          primaryLabel="Delete backup"
          primaryLoadingLabel="Deleting…"
          onPrimary={confirmDelete}
          primaryLoading={mut.remove.isPending}
        />
      )}
    </div>
  );
}
