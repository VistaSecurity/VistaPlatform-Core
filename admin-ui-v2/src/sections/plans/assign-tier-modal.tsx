// Assign a plan to a tenant — POST /admin/tiers/{id}/assign (FE-3). The tier
// composer (TiersPage / PlanBuilder) let an operator author and price plans
// with no way to actually put a tenant on one; this closes that gap with a
// single small modal, no new abstractions.
//
// Record-only for invoice-billed plans: the tenant's subscription_tier_id is
// updated immediately, entitlements take effect on the next resolve, and
// Sales invoices out-of-band. Stripe-billed plans still need the tenant to
// complete checkout separately — this only points the assignment.
//
// TENANT PICKER. /admin/tenants (the directory) is ee/msp — a Core build has
// no console-visible list of tenants, just the one organization running it
// (see tenant-switcher.tsx and nav.ts's `overrides` entry for the same
// reasoning). Rather than making this action MSP-only too, fall back to a
// plain tenant-id field on Core: the operator still has exactly one tenant
// and can look its id up (e.g. via GET /admin/tenants/:id/limits, the one
// Core keeps). On MSP builds, search the real directory like the topbar
// TenantSwitcher does.
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { usePlatformEdition } from '../../lib/edition';
import { useTenants } from '../tenants/queries';

type SubscriptionTier = adminServiceComponents['schemas']['SubscriptionTier'];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function AssignTierModal({ tier, onClose }: { tier: SubscriptionTier; onClose: () => void }) {
  const qc = useQueryClient();
  const { has } = usePlatformEdition();
  const hasDirectory = has('msp');

  // Hooks run unconditionally; the query itself no-ops on Core (useTenants is
  // internally gated on has('msp')).
  const tenantsQ = useTenants();
  const tenants = useMemo(() => tenantsQ.data ?? [], [tenantsQ.data]);

  const [tenantId, setTenantId] = useState('');
  const [q, setQ] = useState('');
  const [manualId, setManualId] = useState('');

  const ql = q.trim().toLowerCase();
  const matches = useMemo(
    () => tenants.filter((t) => !ql || t.name.toLowerCase().includes(ql) || t.slug.toLowerCase().includes(ql)).slice(0, 20),
    [tenants, ql],
  );

  const selected = tenants.find((t) => t.id === tenantId);
  const effectiveTenantId = hasDirectory ? tenantId : manualId.trim();
  const error = !effectiveTenantId
    ? 'Pick a tenant'
    : !UUID_RE.test(effectiveTenantId)
      ? 'Not a valid tenant id'
      : null;

  const assign = useMutation({
    mutationFn: async () => {
      const { error: apiError } = await clients.admin.POST('/admin/tiers/{id}/assign', {
        params: { path: { id: tier.id } },
        body: { tenant_id: effectiveTenantId },
      });
      if (apiError) throw new Error('Failed to assign plan');
    },
    onSuccess: () => {
      toast.success(`Assigned ${tier.display_name || tier.name}${selected ? ` to ${selected.name}` : ''}`);
      void qc.invalidateQueries({ queryKey: ['platform', 'tenants'] });
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Assign failed'),
  });

  return (
    <Modal
      open
      onClose={onClose}
      title={`Assign ${tier.display_name || tier.name}`}
      description="Points the tenant's plan at this tier. Invoice-billed plans take effect immediately; Stripe-billed plans still require the tenant to complete checkout."
      size="md"
      primaryLabel="Assign"
      onPrimary={() => { if (error) { toast.error(error); return; } assign.mutate(); }}
      primaryDisabled={!!error || assign.isPending}
      primaryLoading={assign.isPending}
    >
      {hasDirectory ? (
        <ModalField label="Tenant">
          <input
            value={selected ? `${selected.name}${selected.domain ? ` · ${selected.domain}` : ''}` : q}
            onChange={(e) => { setQ(e.target.value); setTenantId(''); }}
            placeholder="Search tenants by name or slug…"
            style={modalInputStyle}
            autoFocus
          />
          {!selected && (
            <div style={{ maxHeight: 180, overflowY: 'auto', marginTop: 6, border: '1px solid var(--op-border)', borderRadius: 'var(--r-md)' }}>
              {tenantsQ.isLoading ? (
                <div style={{ padding: 10, fontSize: 12, color: 'var(--op-t3)' }}>Loading tenants…</div>
              ) : matches.length === 0 ? (
                <div style={{ padding: 10, fontSize: 12, color: 'var(--op-t3)' }}>No match.</div>
              ) : matches.map((t) => (
                <button
                  key={t.id}
                  onClick={() => { setTenantId(t.id); setQ(''); }}
                  className="row-hover"
                  style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 10px', border: 'none', background: 'transparent', cursor: 'pointer', fontSize: 12.5, color: 'var(--op-t1)' }}
                >
                  {t.name}{t.domain ? <span style={{ color: 'var(--op-t3)' }}> · {t.domain}</span> : null}
                  {t.subscription_tier ? <span style={{ color: 'var(--op-t3)' }}> — currently {t.subscription_tier}</span> : null}
                </button>
              ))}
            </div>
          )}
        </ModalField>
      ) : (
        <ModalField label="Tenant ID">
          <input value={manualId} onChange={(e) => setManualId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" style={modalInputStyle} autoFocus />
          <div style={{ fontSize: 11, color: 'var(--op-t3)', marginTop: 4 }}>
            This deployment has no tenant directory — Core administers one organization. Paste its tenant id.
          </div>
        </ModalField>
      )}
    </Modal>
  );
}
