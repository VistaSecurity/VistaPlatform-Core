// Billing → Trials actions: Start trial, and per row Extend · Convert · End
// (owner decision 6, admin-UI data review RC-9 / P14; review of).
//
// billing_trial_tracking is the one trial store and payment_status 'trial' is
// derived from it, so the tenant editor refuses to start or end a trial by
// setting a status and sends the operator here. These are the controls it
// sends them to — without them the refusal pointed at a read-only list.
//
// Every action calls the trial endpoint admin-service already had (each one
// recorded in the platform audit log) and shows the server's own refusal:
// "the tenant's plan is not a trial plan", "this tenant already has a trial",
// "no active trial for this tenant" are things the operator must read.
//
// End trial (owner decision ends the trial exactly as expiry does:
// the tenant moves to the MSP's Free plan, or is suspended when none is
// defined. The dialog says which BEFORE the operator confirms, from GET
// /admin/billing/trials/end-landing — the same query the server runs when it
// ends the trial, not a client-side guess at what "the Free plan" is.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { serverError, useTenants } from '../tenants/queries';

type TrialListing = adminServiceComponents['schemas']['TrialListing'];
type TrialEndLanding = adminServiceComponents['schemas']['TrialEndLanding'];

/** What ending a trial will do, in the operator's words. */
export function endTrialOutcome(landing: TrialEndLanding): string {
  return landing.suspended || !landing.plan_name
    ? 'Suspends the tenant — no Free plan is defined. Its users are signed out and it cannot sign in until it is reactivated or given a plan. Define a plan called Free in Plans & Pricing if ended trials should keep access.'
    : `Moves the tenant to ${landing.plan_name}, the Free plan, with its status active.`;
}

/** Where ending a trial now would land the tenant — the server's own answer. */
function useTrialEndLanding(enabled: boolean) {
  return useQuery({
    queryKey: ['platform', 'billing', 'trials', 'end-landing'],
    enabled,
    staleTime: 0,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/billing/trials/end-landing', {});
      if (error || !data) throw new Error(serverError(error, "Couldn't check which plan the tenant would move to"));
      return data;
    },
  });
}

/** Refresh everything a trial change moves: the Trials list and conversion
 *  (billing) and the tenants' derived payment status (tenants). */
function useTrialMutation<V, R = void>(fn: (v: V) => Promise<R>, done: string | ((r: R) => string)) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: (r) => {
      toast.success(typeof done === 'function' ? done(r) : done);
      void qc.invalidateQueries({ queryKey: ['platform', 'billing'] });
      void qc.invalidateQueries({ queryKey: ['platform', 'tenants'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Trial update failed'),
  });
}

const positiveDays = (s: string) => /^\d+$/.test(s.trim()) && Number(s) > 0;

type RowAction = 'extend' | 'convert' | 'end';

/** Extend · Convert · End for one live trial. */
export function TrialRowActions({ trial }: { trial: Pick<TrialListing, 'tenant_id' | 'tenant_name'> }) {
  const [open, setOpen] = useState<RowAction | null>(null);
  const [days, setDays] = useState('14');
  const path = { params: { path: { tenant_id: trial.tenant_id } } };

  const extend = useTrialMutation(async (additional_days: number) => {
    const { error } = await clients.admin.POST('/admin/billing/trials/tenants/{tenant_id}/extend', { ...path, body: { additional_days } });
    if (error) throw new Error(serverError(error, 'Failed to extend the trial'));
  }, `Extended ${trial.tenant_name}'s trial`);
  const convert = useTrialMutation(async () => {
    const { error } = await clients.admin.POST('/admin/billing/trials/tenants/{tenant_id}/convert', path);
    if (error) throw new Error(serverError(error, 'Failed to convert the trial'));
  }, `${trial.tenant_name} converted to paid`);
  const end = useTrialMutation(async () => {
    const { data, error } = await clients.admin.DELETE('/admin/billing/trials/tenants/{tenant_id}', path);
    if (error) throw new Error(serverError(error, 'Failed to end the trial'));
    return data?.landing;
  }, (l) => !l
    ? `Ended ${trial.tenant_name}'s trial`
    : l.suspended
      ? `Ended ${trial.tenant_name}'s trial — suspended (no Free plan is defined)`
      : `Ended ${trial.tenant_name}'s trial — moved to ${l.plan_name}`);
  const landing = useTrialEndLanding(open === 'end');

  const close = () => setOpen(null);
  const pending = extend.isPending || convert.isPending || end.isPending;
  return (
    <>
      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
        <button className="op-btn ghost sm" onClick={() => setOpen('extend')}>Extend</button>
        <button className="op-btn ghost sm" onClick={() => setOpen('convert')}>Convert</button>
        <button className="op-btn ghost sm" onClick={() => setOpen('end')}>End trial</button>
      </div>
      {open === 'extend' && (
        <Modal
          open
          onClose={close}
          title={`Extend ${trial.tenant_name}'s trial`}
          description="Moves the trial's end date (Ends) out by this many days, counted from that date, or from today if the trial has already locked. The tenant keeps trial access until the new end."
          size="sm"
          primaryLabel="Extend"
          primaryDisabled={!positiveDays(days) || pending}
          primaryLoading={extend.isPending}
          onPrimary={() => extend.mutate(Number(days), { onSuccess: close })}
        >
          <ModalField label="Additional days">
            <input value={days} onChange={(e) => setDays(e.target.value)} inputMode="numeric" style={modalInputStyle} autoFocus />
          </ModalField>
        </Modal>
      )}
      {open === 'convert' && (
        <Modal
          open
          onClose={close}
          title={`Convert ${trial.tenant_name} to paid`}
          description="Marks the trial converted and the tenant active. Use it when the customer has agreed to pay outside a Stripe checkout; a Stripe checkout converts the trial by itself. The plan is unchanged — assign a paid plan from Plans & Pricing if it should change."
          size="sm"
          primaryLabel="Convert"
          primaryDisabled={pending}
          primaryLoading={convert.isPending}
          onPrimary={() => convert.mutate(undefined, { onSuccess: close })}
        />
      )}
      {open === 'end' && (
        <Modal
          open
          onClose={close}
          tone="danger"
          title={`End ${trial.tenant_name}'s trial`}
          description={
            landing.data
              ? `Ends the trial now, as if it had run out. ${endTrialOutcome(landing.data)} The trial is not converted and does not count as a conversion, and the tenant cannot be given another trial.`
              : landing.isError
                ? (landing.error instanceof Error ? landing.error.message : "Couldn't check which plan the tenant would move to")
                : 'Checking which plan the tenant moves to…'
          }
          size="sm"
          primaryLabel="End trial"
          // Not until the dialog can say what will happen.
          primaryDisabled={pending || !landing.data}
          primaryLoading={end.isPending}
          onPrimary={() => end.mutate(undefined, { onSuccess: close })}
        />
      )}
    </>
  );
}

/** Start a trial for a tenant already on a plan marked as a trial. */
export function StartTrialModal({ onClose }: { onClose: () => void }) {
  const tenantsQ = useTenants();
  const [tenantId, setTenantId] = useState('');
  const [q, setQ] = useState('');
  const [days, setDays] = useState('');

  const tenants = useMemo(() => (tenantsQ.data ?? []).filter((t) => t.payment_status !== 'trial'), [tenantsQ.data]);
  const ql = q.trim().toLowerCase();
  const matches = useMemo(
    () => tenants.filter((t) => !ql || t.name.toLowerCase().includes(ql) || t.slug.toLowerCase().includes(ql)).slice(0, 20),
    [tenants, ql],
  );
  const selected = tenants.find((t) => t.id === tenantId);
  const error = !selected ? 'Pick a tenant' : days.trim() && !positiveDays(days) ? 'Days must be a positive number' : null;

  const start = useTrialMutation(async () => {
    const { error: apiError } = await clients.admin.POST('/admin/billing/trials', {
      body: { tenant_id: tenantId, ...(days.trim() ? { duration: Number(days) } : {}) },
    });
    if (apiError) throw new Error(serverError(apiError, 'Failed to start the trial'));
  }, `Started a trial for ${selected?.name ?? 'the tenant'}`);

  return (
    <Modal
      open
      onClose={onClose}
      title="Start trial"
      description="Starts a trial for a tenant whose plan is marked as a trial plan (Plans & Pricing). A tenant that signs up on a trial plan gets one automatically; use this for a tenant you moved onto a trial plan by hand."
      size="md"
      primaryLabel="Start trial"
      primaryDisabled={!!error || start.isPending}
      primaryLoading={start.isPending}
      onPrimary={() => { if (error) { toast.error(error); return; } start.mutate(undefined, { onSuccess: onClose }); }}
    >
      <ModalField label="Tenant">
        <input
          value={selected ? selected.name : q}
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
                {t.name}
                {t.subscription_tier ? <span style={{ color: 'var(--op-t3)' }}> — on {t.subscription_tier}</span> : null}
              </button>
            ))}
          </div>
        )}
      </ModalField>
      <ModalField label="Length in days (optional)">
        <input value={days} onChange={(e) => setDays(e.target.value)} inputMode="numeric" placeholder="The plan's length" style={modalInputStyle} />
        <span style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
          Leave empty for the plan's trial length. A longer length extends the upgrade-prompt phase; one shorter than the plan's full-access plus upgrade-prompt days is refused.
        </span>
      </ModalField>
    </Modal>
  );
}
