import type { AssetLike } from './asset-shape';

export function identityStatusLabel(status: AssetLike['identity_status']): string {
  switch (status) {
    case 'established': return 'Identity established';
    case 'operator_confirmed': return 'Identity confirmed by an operator';
    case 'legacy': return 'Legacy — identity not reevaluated';
    default: return 'Identity evidence not evaluated';
  }
}

export function IdentityStatus({ asset }: { asset: AssetLike }) {
  return <div style={{ fontSize: 11, color: asset.has_identity_conflict ? 'var(--warn)' : 'var(--app-t3)' }}>
    <span>{identityStatusLabel(asset.identity_status)}</span>
    {asset.has_identity_conflict && <span> · Identity conflict needs review</span>}
  </div>;
}
