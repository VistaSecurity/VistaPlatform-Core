// Shell-level banner for the MSP soft cap on tenants (edition-licensing spec
// §1 "Soft-cap banner"). Rendered by the app shell on every page — not on a
// specific one — because the overage matters wherever the operator is.
//
// Hidden unless the install is over its licensed tenant count: in grace it
// warns with the days left, after grace it states that new tenants are
// blocked. Loading, errors, no permission, Core and Enterprise all render
// nothing — a banner that could appear on a failed read would cry wolf.
import { AlertTriangle, OctagonAlert } from 'lucide-react';
import { capBanner, useLicenseCap } from '../lib/license-cap';

export function LicenseCapBanner() {
  const { data } = useLicenseCap();
  const banner = capBanner(data);
  if (!banner) return null;
  const danger = banner.tone === 'danger';
  const color = danger ? 'var(--danger)' : 'var(--warn)';
  const Icon = danger ? OctagonAlert : AlertTriangle;
  return (
    <div
      role={danger ? 'alert' : 'status'}
      data-testid="license-cap-banner"
      data-state={data?.state}
      style={{
        display: 'flex', alignItems: 'flex-start', gap: 10, padding: '9px 22px',
        background: `color-mix(in srgb, ${color} 12%, transparent)`,
        borderBottom: `1px solid color-mix(in srgb, ${color} 35%, transparent)`,
        fontSize: 12.5,
      }}
    >
      <Icon size={15} style={{ color, flex: 'none', marginTop: 1 }} />
      <div style={{ minWidth: 0 }}>
        <div style={{ color: 'var(--op-t1)', fontWeight: 600 }}>{banner.title}</div>
        <div style={{ color: 'var(--op-t2)', marginTop: 2 }}>{banner.detail}</div>
      </div>
    </div>
  );
}
