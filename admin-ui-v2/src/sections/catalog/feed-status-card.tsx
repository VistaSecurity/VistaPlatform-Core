// VISTA Operations — the mirror-feed status card, shared by Catalog ▸
// End-of-life and Catalog ▸ Vulnerability feed.
//
// It answers four questions an operator actually has: is the feed switched on,
// when did it last run, did it work, and how do I make it run now. The fifth —
// "how do I fill this catalogue with no internet" — is the Import bundle
// control at the foot of the card.
//
// Every state is rendered explicitly, including the ones that are easy to leave
// out: never run, running, failed (with the error), and disabled by the
// deployment. A feed that has never run is LISTED rather than omitted, because
// a shorter list than the product has feeds reads as "there is no such feed".
import { useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { RefreshCw, Upload, Rss, AlertTriangle, PowerOff } from 'lucide-react';
import { PlatformPermissionGate, PLATFORM_PERMISSIONS } from '@vistasecurity/primitives/platform-auth';
import { relTime, num } from '../../components/ui/primitives';
import {
  useCatalogFeeds, useSyncCatalogFeed, useImportCatalogBundle, BundleImportError,
  FEED_LABEL, errMsg, type FeedName, type CatalogFeedStatus,
} from './catalog-queries';

const STATUS_STYLE: Record<string, { color: string; label: string }> = {
  ok: { color: 'var(--ok)', label: 'OK' },
  running: { color: 'var(--info)', label: 'Running' },
  error: { color: 'var(--danger)', label: 'Failed' },
  never: { color: 'var(--neutral)', label: 'Never run' },
};

function StatusPill({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? { color: 'var(--neutral)', label: status };
  return (
    <span
      data-testid={`feed-status-${status}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 9px',
        borderRadius: 'var(--r-sm)', fontSize: 11.5, fontWeight: 600, color: s.color,
        background: `color-mix(in srgb, ${s.color} 10%, transparent)`,
        border: `1px solid color-mix(in srgb, ${s.color} 20%, transparent)`, whiteSpace: 'nowrap',
      }}
    >
      {s.label}
    </span>
  );
}

function FeedRow({
  feed, enabled, onSync, syncing,
}: {
  feed: CatalogFeedStatus;
  enabled: boolean;
  onSync: (f: FeedName) => void;
  syncing: boolean;
}) {
  return (
    <tr>
      <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>
        {FEED_LABEL[feed.feed] ?? feed.feed}
        <span className="mono t-muted" style={{ marginLeft: 8, fontSize: 11 }}>{feed.feed}</span>
      </td>
      <td><StatusPill status={feed.last_status} /></td>
      <td className="t-muted mono" style={{ fontSize: 11 }}>
        {feed.last_run_at ? relTime(feed.last_run_at) : 'never'}
      </td>
      <td className="t-muted mono" style={{ fontSize: 11 }}>
        {feed.last_status === 'never' ? '—' : num(feed.row_count)}
      </td>
      <td
        className="t-muted mono"
        title={feed.cursor ?? 'No bookmark yet — the next run starts from the default window.'}
        style={{ fontSize: 11, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
      >
        {feed.cursor ?? '—'}
      </td>
      <td style={{ textAlign: 'right' }}>
        <PlatformPermissionGate permission={PLATFORM_PERMISSIONS.catalogs.manage}>
          <button
            className="op-btn sm"
            disabled={!enabled || syncing || feed.last_status === 'running'}
            title={
              !enabled
                ? 'Catalogue feeds are disabled on this deployment (CATALOG_FEEDS_ENABLED=false)'
                : feed.last_status === 'running'
                  ? 'A sync is already running'
                  : 'Run this feed now'
            }
            onClick={() => onSync(feed.feed)}
          >
            <RefreshCw size={13} />Sync now
          </button>
        </PlatformPermissionGate>
      </td>
    </tr>
  );
}

export function FeedStatusCard({ feeds: only, title }: { feeds: FeedName[]; title: string }) {
  const { data, isLoading, isError, refetch } = useCatalogFeeds();
  const sync = useSyncCatalogFeed();
  const importBundle = useImportCatalogBundle();
  const fileRef = useRef<HTMLInputElement>(null);
  const [syncingFeed, setSyncingFeed] = useState<string | null>(null);

  const all = data?.feeds ?? [];
  const rows = all.filter((f) => only.includes(f.feed));
  const enabled = data?.enabled ?? false;
  const intervalHours = data ? Math.round((data.interval_seconds / 3600) * 10) / 10 : null;
  const failing = rows.filter((f) => f.last_status === 'error');

  const runSync = (feed: FeedName) => {
    setSyncingFeed(feed);
    sync.mutate(feed, {
      onSuccess: () => toast.success(`${FEED_LABEL[feed] ?? feed} sync started — this can take several minutes.`),
      onError: (e) => toast.error(errMsg(e, 'Could not start the sync')),
      onSettled: () => setSyncingFeed(null),
    });
  };

  const onFile = (file: File | undefined) => {
    if (!file) return;
    importBundle.mutate(file, {
      onSuccess: (res) =>
        toast.success(
          `Imported ${num(res.eol_rows)} end-of-life rows and ${num(res.vulnerability_rows)} vulnerabilities.`,
          { duration: 6000 },
        ),
      onError: (e) => toast.error(errMsg(e, 'Bundle import failed'), { duration: 10000 }),
    });
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
        <Rss size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>{title}</span>
        <div style={{ flex: 1 }} />
        {intervalHours !== null && enabled && (
          <span className="t-muted" style={{ fontSize: 11.5 }}>
            Scheduled every {intervalHours === 24 ? '24 hours' : `${intervalHours} hours`}
          </span>
        )}
      </div>

      {!isLoading && !isError && !enabled && (
        <div
          data-testid="feeds-disabled-banner"
          style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', borderBottom: '1px solid var(--op-border)', background: 'color-mix(in srgb, var(--neutral) 8%, transparent)', fontSize: 12.5, color: 'var(--op-t2)' }}
        >
          <PowerOff size={14} style={{ color: 'var(--op-t3)', flex: 'none' }} />
          <span>
            Catalogue feeds are <strong>disabled</strong> on this deployment
            (<span className="mono">CATALOG_FEEDS_ENABLED=false</span>). Nothing is scheduled and
            Sync now is refused. An offline bundle can still be imported.
          </span>
        </div>
      )}

      {failing.length > 0 && (
        <div
          data-testid="feed-error-banner"
          style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 16px', borderBottom: '1px solid var(--op-border)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)', fontSize: 12.5, color: 'var(--op-t2)' }}
        >
          <AlertTriangle size={14} style={{ color: 'var(--danger)', flex: 'none', marginTop: 2 }} />
          <div>
            {failing.map((f) => (
              <div key={f.feed} style={{ marginBottom: 2 }}>
                <strong>{FEED_LABEL[f.feed] ?? f.feed}</strong> failed on its last run:{' '}
                <span className="mono" style={{ fontSize: 11.5 }}>{f.last_error ?? 'no detail recorded'}</span>
              </div>
            ))}
            <div className="t-muted" style={{ fontSize: 11.5, marginTop: 2 }}>
              The bookmark was not advanced, so the next run retries the same window.
            </div>
          </div>
        </div>
      )}

      <table className="op-table">
        <thead>
          <tr><th>Feed</th><th>Status</th><th>Last run</th><th>Rows</th><th>Bookmark</th><th /></tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <FeedRow
              key={f.feed}
              feed={f}
              enabled={enabled}
              syncing={sync.isPending && syncingFeed === f.feed}
              onSync={runSync}
            />
          ))}
          {isLoading && (
            <tr><td colSpan={6} style={{ textAlign: 'center', padding: 28, color: 'var(--op-t3)' }}>Loading feed status…</td></tr>
          )}
          {isError && !isLoading && (
            <tr><td colSpan={6} style={{ textAlign: 'center', padding: 28, color: 'var(--op-t3)' }}>
              Couldn't load feed status.
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
            </td></tr>
          )}
          {!isLoading && !isError && rows.length === 0 && (
            <tr><td colSpan={6} style={{ textAlign: 'center', padding: 28, color: 'var(--op-t3)' }}>
              This deployment reports no feeds for this catalogue.
            </td></tr>
          )}
        </tbody>
      </table>

      <PlatformPermissionGate permission={PLATFORM_PERMISSIONS.catalogs.manage}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderTop: '1px solid var(--op-border)' }}>
          <div style={{ flex: 1, fontSize: 12, color: 'var(--op-t3)' }}>
            <strong style={{ color: 'var(--op-t2)' }}>Air-gapped?</strong> Build a bundle on a connected
            install with <span className="mono">make build-catalog-bundle</span> and import it here. Every
            file's SHA-256 and row count is checked before a single row is applied.
          </div>
          <input
            ref={fileRef}
            type="file"
            accept=".gz,.tgz,application/gzip,application/x-gzip"
            style={{ display: 'none' }}
            data-testid="bundle-file-input"
            onChange={(e) => onFile(e.target.files?.[0])}
          />
          <button
            className="op-btn sm"
            disabled={importBundle.isPending}
            onClick={() => fileRef.current?.click()}
          >
            <Upload size={13} />{importBundle.isPending ? 'Importing…' : 'Import bundle'}
          </button>
        </div>
      </PlatformPermissionGate>

      {importBundle.isSuccess && importBundle.data && (
        <div
          data-testid="bundle-import-result"
          style={{ padding: '10px 16px', borderTop: '1px solid var(--op-border)', fontSize: 12, color: 'var(--op-t2)', background: 'color-mix(in srgb, var(--ok) 6%, transparent)' }}
        >
          Imported {num(importBundle.data.eol_rows)} end-of-life rows,{' '}
          {num(importBundle.data.vulnerability_rows)} vulnerabilities and{' '}
          {num(importBundle.data.match_rows)} match rules
          {importBundle.data.generated_at
            ? ` from a bundle built ${new Date(importBundle.data.generated_at).toISOString().slice(0, 10)}.`
            : '.'}
        </div>
      )}

      {importBundle.isError && (
        <div
          data-testid="bundle-import-error"
          style={{ padding: '10px 16px', borderTop: '1px solid var(--op-border)', fontSize: 12, color: 'var(--op-t2)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)' }}
        >
          <strong style={{ color: 'var(--danger)' }}>
            {importBundle.error instanceof BundleImportError && importBundle.error.applied
              ? 'Bundle partly applied.'
              : 'Bundle refused.'}
          </strong>{' '}
          <span className="mono" style={{ fontSize: 11.5 }}>{errMsg(importBundle.error, 'Import failed')}</span>
          <div className="t-muted" style={{ fontSize: 11.5, marginTop: 2 }}>
            {/* Only a REFUSAL leaves the catalogue untouched. A failure after
                verification passed has already written rows, and saying
                otherwise sends the operator away believing a half-imported
                catalogue is an untouched one. */}
            {importBundle.error instanceof BundleImportError && importBundle.error.applied
              ? 'Verification passed and the apply failed partway, so some rows were written. Import the same bundle again — import is idempotent.'
              : 'Nothing was applied — verification runs before the first row is written.'}
          </div>
        </div>
      )}
    </div>
  );
}
