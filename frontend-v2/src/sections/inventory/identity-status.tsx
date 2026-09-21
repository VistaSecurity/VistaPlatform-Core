import type { AssetLike } from './asset-shape';

export function identityStatusLabel(status: AssetLike['identity_status']): string {
  switch (status) {
    case 'established': return 'Identity established';
    case 'operator_confirmed': return 'Identity confirmed by an operator';
    // D8. A provisional item is real inventory with a stable id, inferred
    // from an advertisement no collector has met directly. The label says both
    // halves out loud because the row looks exactly like any other asset, and
    // "unverified" is the only thing distinguishing a device we heard ABOUT
    // from one we have seen.
    case 'provisional': return 'Provisional identity — unverified';
    case 'legacy': return 'Identity not evaluated';
    default: return 'Identity evidence not evaluated';
  }
}

export function IdentityStatus({ asset }: { asset: AssetLike }) {
  const provisional = asset.identity_status === 'provisional';
  return <div
    // `role="status"` on the provisional marker so a screen reader announces the
    // one identity state that changes what the row MEANS. The colour is the
    // existing warn token — a provisional item is not an error and gets no new
    // palette entry.
    {...(provisional ? { 'data-identity': 'provisional', role: 'status' } : {})}
    style={{ fontSize: 11, color: asset.has_identity_conflict || provisional ? 'var(--warn)' : 'var(--app-t3)' }}
  >
    <span>{identityStatusLabel(asset.identity_status)}</span>
    {asset.has_identity_conflict && <span> · Identity conflict needs review</span>}
  </div>;
}
