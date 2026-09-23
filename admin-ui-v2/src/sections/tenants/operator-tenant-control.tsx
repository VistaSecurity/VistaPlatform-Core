// Tenants ▸ a tenant ▸ Overview ▸ Tenant controls: "MSP's own tenant".
//
// On an MSP licence with a tenant limit, the MSP's own tenant(s) — the
// organisation running the install — are not customers and are never counted.
// This control marks them (PUT /admin/tenants/{id}/operator, audited).
//
// Rendered only on an MSP licence: the licensed-tenant read (useLicenseCap)
// reports the active licence's edition, and on Core or Enterprise there is no
// limit for the flag to affect (the server refuses it there with 409 anyway).
// Operators without tenants.manage see the current value, read-only.
import toast from 'react-hot-toast';
import { Building } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { useLicenseCap } from '../../lib/license-cap';
import { type Tenant, useSetTenantOperator } from './queries';

export function OperatorTenantControl({ tenant }: { tenant: Tenant }) {
  const cap = useLicenseCap();
  const { hasPermission } = usePlatformPermissions();
  const setOperator = useSetTenantOperator();

  if (cap.data?.edition !== 'msp') return null;

  const canManage = hasPermission(PLATFORM_PERMISSIONS.tenants.manage);
  const checked = tenant.is_operator;

  const toggle = (next: boolean) => {
    const verb = next ? 'Mark' : 'Unmark';
    if (!window.confirm(`${verb} ${tenant.name} as your own tenant? Your own tenants are not counted against your licensed tenant limit. This is logged to audit.`)) return;
    setOperator.mutate(
      { id: tenant.id, isOperator: next },
      {
        onSuccess: () => toast.success(next ? `${tenant.name} is marked as your own tenant` : `${tenant.name} now counts as a customer tenant`),
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to update the tenant'),
      },
    );
  };

  return (
    <label
      data-testid="operator-tenant-control"
      style={{ display: 'flex', alignItems: 'flex-start', gap: 9, marginTop: 12, fontSize: 12.5, color: 'var(--op-t1)', cursor: canManage ? 'pointer' : 'default' }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={!canManage || setOperator.isPending}
        onChange={(e) => toggle(e.target.checked)}
        style={{ marginTop: 2 }}
      />
      <span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontWeight: 600 }}><Building size={13} />Your own tenant</span>
        <span style={{ display: 'block', fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>
          Not counted against your licensed tenant limit{cap.data.licensed != null ? ` (${cap.data.current} of ${cap.data.licensed} in use)` : ''}.
        </span>
      </span>
    </label>
  );
}
