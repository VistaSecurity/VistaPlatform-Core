// The asset page's Placement section for a cloud resource (asset-inventory
// ADR-0009 D7; DCIM row 4.6): account › region › network prefix › child
// prefix, the provider's type string, and the security groups the resource is
// a member of. Read from GET /infrastructure-assets/{id}/cloud-placement, which
// reads what the intake stored and synthesises nothing — a step the resource
// does not have is not drawn.
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { Icon } from '../../../components/ui';
import { clients } from '../../../lib/clients';
import { errorMessage } from '../asset-queries';
import { placementSteps, type CloudPlacement } from './cloud-model';

export function useCloudPlacement(assetId: string, enabled = true) {
  return useQuery({
    queryKey: ['inventory', 'cloud-placement', assetId],
    enabled,
    queryFn: async (): Promise<CloudPlacement> => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}/cloud-placement', {
        params: { path: { id: assetId } },
      });
      if (error || !data) throw new Error(errorMessage(error) ?? 'Failed to load the placement');
      return data.placement;
    },
    staleTime: 60_000,
  });
}

const STEP_ICON: Record<string, string> = {
  account: 'cloud',
  region: 'map-pin',
  network: 'network',
  prefix: 'network',
};

export function CloudPlacementSection({ assetId }: { assetId: string }) {
  const q = useCloudPlacement(assetId);
  if (q.isLoading) return <div data-testid="placement-loading" style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading placement…</div>;
  if (q.isError) {
    return (
      <div data-testid="placement-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>
        The placement could not be loaded. {q.error instanceof Error ? q.error.message : ''}
      </div>
    );
  }
  const p = q.data;
  if (!p) return null;
  const steps = placementSteps(p);
  return (
    <div data-testid="cloud-placement">
      {steps.length === 0 ? (
        <div data-testid="placement-empty" style={{ fontSize: 12, color: 'var(--app-t3)' }}>
          No account, region or network is recorded for this resource yet.
        </div>
      ) : (
        <nav aria-label="Placement" data-testid="placement-breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', fontSize: 12.5 }}>
          {steps.map((s, i) => (
            <span key={s.kind} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {i > 0 && <span aria-hidden style={{ color: 'var(--app-t3)' }}>›</span>}
              <Icon name={STEP_ICON[s.kind]} size={12} style={{ color: 'var(--app-t3)' }} />
              {s.href
                ? <Link to={s.href} data-step={s.kind} className={s.kind === 'account' ? undefined : 'mono'} style={{ color: 'var(--accent)', textDecoration: 'none' }}>{s.label}</Link>
                : <span data-step={s.kind} className="mono" style={{ color: 'var(--app-t1)' }}>{s.label}</span>}
            </span>
          ))}
        </nav>
      )}
      {p.provider_type && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 6 }}>
          Provider type <span className="mono" style={{ color: 'var(--app-t2)' }}>{p.provider_type}</span>
        </div>
      )}
      <div style={{ marginTop: 8 }} data-testid="placement-groups">
        <div className="eyebrow-app" style={{ marginBottom: 4 }}>Security groups</div>
        {p.security_groups.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Member of none that were listed.</div>
        ) : (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {p.security_groups.map((g) => (g.asset_id ? (
              <Link key={g.id} to={`/inventory/assets/${g.asset_id}`} title={g.id} style={{ fontSize: 11.5, padding: '2px 9px', borderRadius: 40, border: '1px solid var(--app-border2)', color: 'var(--accent)', textDecoration: 'none' }}>
                {g.name || g.id}
              </Link>
            ) : (
              <span key={g.id} title={`${g.id} — not in the inventory (its listing was not run)`} style={{ fontSize: 11.5, padding: '2px 9px', borderRadius: 40, border: '1px dashed var(--app-border2)', color: 'var(--app-t2)' }}>
                {g.name || g.id}
              </span>
            )))}
          </div>
        )}
      </div>
    </div>
  );
}
