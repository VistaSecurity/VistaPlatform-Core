// Self-serve billing mutations + modals — restores the mutating billing surface
// (change plan / cancel / reactivate / Stripe portal) that admin-service has
// always exposed but frontend-v2 never called. All wired through the typed
// admin-service client; tiers come from auth-service's public /tiers list.
import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalSelect } from '../../components/ui';

function money(cents: number, currency = 'USD'): string {
  return new Intl.NumberFormat(undefined, { style: 'currency', currency, maximumFractionDigits: 0 }).format(cents / 100);
}

// ---- mutations ------------------------------------------------------------
const SUB_KEY = ['settings', 'my-subscription'];

/** Open a Stripe-hosted billing portal session and return the redirect URL. */
export function usePortalSession() {
  return useMutation({
    mutationFn: async (): Promise<string> => {
      const { data, error, response } = await clients.admin.POST('/my-billing/portal-session', {
        body: { return_url: window.location.href },
      });
      if (!response.ok || error || !data?.url) throw new Error('Could not open the billing portal');
      return data.url;
    },
  });
}

export function useChangePlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { tier_id: string; billing_interval?: string }) => {
      const { data, error } = await clients.admin.POST('/my-billing/subscription/change-plan', { body });
      if (error || !data) throw new Error('Plan change failed');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SUB_KEY }),
  });
}

export function useCancelSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (reason?: string) => {
      const { data, error } = await clients.admin.POST('/my-billing/subscription/cancel', {
        body: reason?.trim() ? { reason: reason.trim() } : {},
      });
      if (error || !data) throw new Error('Cancellation failed');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SUB_KEY }),
  });
}

export function useReactivate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.admin.POST('/my-billing/subscription/reactivate', {});
      if (error || !data) throw new Error('Reactivation failed');
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SUB_KEY }),
  });
}

// ---- change-plan modal ----------------------------------------------------
export function ChangePlanModal({ open, currentTierId, currentInterval, currentPriceCents, onClose }: {
  open: boolean;
  currentTierId?: string;
  currentInterval?: string;
  /** Monthly price of the current tier — used to hide downgrades, which are
   * support-granted only under the 12-month agreement. */
  currentPriceCents?: number;
  onClose: () => void;
}) {
  const tiersQ = useQuery({
    queryKey: ['settings', 'public-tiers'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tiers', {});
      if (error || !data) throw new Error('Failed to load plans');
      return data.tiers ?? [];
    },
    enabled: open,
  });
  const change = useChangePlan();
  const [tierId, setTierId] = useState('');
  const [interval, setInterval] = useState('monthly');

  useEffect(() => {
    setTierId(currentTierId ?? '');
    setInterval(currentInterval === 'annual' || currentInterval === 'year' ? 'annual' : 'monthly');
  }, [currentTierId, currentInterval, open]);

  // Dedupe by tier id (the public list can carry a row per billing interval).
  // Upgrade-only: plans priced below the current one are hidden —
  // mid-contract downgrades are granted by support, not self-served.
  const tiers = Array.from(new Map((tiersQ.data ?? []).filter((t) => t.is_active).map((t) => [t.id, t])).values())
    .filter((t) => t.id === currentTierId || currentPriceCents == null || t.price_cents >= currentPriceCents);
  const onTopPlan = tiers.length === 1 && tiers[0]?.id === currentTierId;
  const selected = tiers.find((t) => t.id === tierId);
  const noChange = tierId === currentTierId && interval === (currentInterval === 'annual' || currentInterval === 'year' ? 'annual' : 'monthly');
  const priceOf = (t: typeof tiers[number]) => interval === 'annual' && t.annual_price_cents != null
    ? `${money(t.annual_price_cents)}/yr` : `${money(t.price_cents)}/mo`;

  const submit = async () => {
    if (!tierId) return;
    await change.mutateAsync({ tier_id: tierId, billing_interval: interval });
    onClose();
  };

  const err = change.error instanceof Error ? change.error.message : tiersQ.isError ? 'Failed to load plans' : null;

  return (
    <Modal
      open={open}
      onClose={change.isPending ? undefined : onClose}
      dismissible={!change.isPending}
      size="md"
      tone="accent"
      icon="gem"
      eyebrow="Billing"
      title="Change plan"
      description={onTopPlan
        ? "You're on the top plan. To move to a lower plan, contact support — mid-agreement downgrades are handled by your account team."
        : 'Upgrade your subscription tier — upgrades take effect immediately (prorated by Stripe) and your 12-month agreement dates are unchanged. To move to a lower plan, contact support.'}
      primary={<button className="ui-btn accent" disabled={!tierId || noChange || change.isPending} onClick={submit}>{change.isPending ? 'Changing…' : 'Change plan'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={change.isPending}>Cancel</button>}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : noChange ? 'This is your current plan.' : undefined}
    >
      <ModalField label="Plan" hint="Manage tiers and pricing with your account team for custom plans.">
        <ModalSelect data-autofocus value={tierId} onChange={(e) => setTierId(e.target.value)} disabled={tiersQ.isLoading || change.isPending}>
          {tiersQ.isLoading && <option value="">Loading plans…</option>}
          {!tiersQ.isLoading && tiers.length === 0 && <option value="">No plans available</option>}
          {tiers.map((t) => (
            <option key={t.id} value={t.id}>
              {t.display_name || t.name}{t.id === currentTierId ? ' (current)' : ''} — {priceOf(t)}
            </option>
          ))}
        </ModalSelect>
      </ModalField>
      <ModalField label="Billing interval">
        <ModalSelect value={interval} onChange={(e) => setInterval(e.target.value)} disabled={change.isPending}>
          <option value="monthly">Monthly</option>
          <option value="annual">Annual{selected?.annual_price_cents == null ? ' (not available for this plan)' : ''}</option>
        </ModalSelect>
      </ModalField>
    </Modal>
  );
}

// ---- cancel modal ---------------------------------------------------------
export function CancelSubscriptionModal({ open, periodEnd, contractEnd, billingInterval, onClose }: {
  open: boolean;
  periodEnd?: string | null;
  /** End of the 12-month agreement: monthly-billed cancellations keep
   *  billing (and service) through this date, not just the current period. */
  contractEnd?: string | null;
  billingInterval?: string;
  onClose: () => void;
}) {
  const cancel = useCancelSubscription();
  const [reason, setReason] = useState('');

  useEffect(() => { if (open) setReason(''); }, [open]);

  const submit = async () => {
    await cancel.mutateAsync(reason);
    onClose();
  };

  const fmt = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  // Monthly-billed with a contract running past the current period → the
  // agreement governs: billing continues through contract_end.
  const contractual = billingInterval !== 'annual' && !!contractEnd && !!periodEnd &&
    new Date(contractEnd).getTime() > new Date(periodEnd).getTime();
  const description = contractual
    ? `Your plan is a 12-month agreement: monthly billing and service continue until ${fmt(contractEnd!)}, when your subscription ends. You can reactivate any time before then.`
    : `Your plan stays active until ${periodEnd ? fmt(periodEnd) : 'the end of the current billing period'}. You can reactivate any time before then with no interruption.`;

  return (
    <Modal
      open={open}
      onClose={cancel.isPending ? undefined : onClose}
      dismissible={!cancel.isPending}
      size="sm"
      tone="danger"
      icon="octagon-alert"
      eyebrow="Billing"
      title="Cancel subscription"
      description={description}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={cancel.isPending} onClick={submit}>{cancel.isPending ? 'Cancelling…' : contractual ? 'Cancel at end of agreement' : 'Cancel at period end'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={cancel.isPending}>Keep plan</button>}
      footerNote={cancel.isError ? <span style={{ color: 'var(--danger-text)' }}>{(cancel.error as Error).message}</span> : undefined}
    >
      <ModalField label="Reason (optional)" hint="Helps us improve — not required.">
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={3}
          placeholder="Tell us why you're cancelling…"
          style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none', resize: 'vertical' }}
        />
      </ModalField>
    </Modal>
  );
}
