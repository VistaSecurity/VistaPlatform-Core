// Shell-level "a newer Vista Platform release is out" banner (platform
// maintenance spec §1, WP2). Rendered by the app shell on every admin page
// beside the licence-cap banner, because the notice matters wherever the
// operator is.
//
// Shown only while GET /admin/maintenance/updates says update_available AND the
// viewer has not dismissed THIS version. Everything else renders nothing — no
// permission, still loading, a failed read, the Maintenance section hidden
// (maintenance-service not deployed): a banner that could appear on a failed
// read would cry wolf, and the About & Updates page carries the check error.
//
// Dismissal is a per-viewer convenience kept in localStorage under
// `maintenance.update-banner.dismissed=<version>`; the next version brings the
// banner back. Storage can throw (private window, blocked site data), so every
// access is wrapped and the banner works without it.
import { useState } from 'react';
import { Link } from 'react-router';
import { PackageCheck, X } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { useMaintenanceAvailability, useUpdateStatus } from '../sections/maintenance/maintenance-queries';

export const UPDATE_BANNER_DISMISSED_KEY = 'maintenance.update-banner.dismissed';

function readDismissed(): string | null {
  try {
    return window.localStorage.getItem(UPDATE_BANNER_DISMISSED_KEY);
  } catch {
    return null;
  }
}

function writeDismissed(version: string) {
  try {
    window.localStorage.setItem(UPDATE_BANNER_DISMISSED_KEY, version);
  } catch {
    // Storage unavailable: the dismissal lasts for this page view only.
  }
}

export function UpdateBanner() {
  const { hasPermission } = usePlatformPermissions();
  const canRead = hasPermission(PLATFORM_PERMISSIONS.platform.health);
  const availability = useMaintenanceAvailability(canRead);
  const { data } = useUpdateStatus({ enabled: canRead && availability === 'available' });
  const [dismissed, setDismissed] = useState<string | null>(readDismissed);

  const version = data?.update_available ? data.latest_version : null;
  if (!canRead || availability !== 'available' || !version || dismissed === version) return null;

  return (
    <div
      role="status"
      data-testid="update-banner"
      data-version={version}
      style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '9px 22px',
        background: 'color-mix(in srgb, var(--op-accent) 11%, transparent)',
        borderBottom: '1px solid color-mix(in srgb, var(--op-accent) 32%, transparent)',
        fontSize: 12.5,
      }}
    >
      <PackageCheck size={15} style={{ color: 'var(--op-accent)', flex: 'none' }} />
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexWrap: 'wrap', gap: '2px 14px', alignItems: 'baseline' }}>
        <span style={{ color: 'var(--op-t1)', fontWeight: 600 }}>Vista Platform {version} is available</span>
        {data?.notes_url && (
          <a href={data.notes_url} target="_blank" rel="noopener noreferrer" data-testid="update-banner-notes" style={{ color: 'var(--op-t2)' }}>
            What’s new
          </a>
        )}
        <Link to="/maintenance/about" data-testid="update-banner-details" style={{ color: 'var(--op-t2)' }}>See details</Link>
      </div>
      <button
        type="button"
        className="op-btn ghost sm"
        aria-label={`Dismiss the Vista Platform ${version} notice`}
        data-testid="update-banner-dismiss"
        onClick={() => { writeDismissed(version); setDismissed(version); }}
      >
        <X size={14} />
      </button>
    </div>
  );
}
