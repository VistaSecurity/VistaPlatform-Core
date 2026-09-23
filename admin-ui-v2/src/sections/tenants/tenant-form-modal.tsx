// Edit a tenant. Wired to the typed admin-service client via the mutation
// hooks in ./queries (no hand-rolled calls). Patches
// name/domain/billing_email/payment_status — NOT tier (PUT /admin/tenants/{id}
// ignores subscription_tier; tier change is the separate /tiers/:id/assign flow,
// surfaced as "Assign to tenant…" on a tier's detail in Plans & Pricing → Tiers).
// There is deliberately no create mode: tenants onboard exclusively through
// the self-service signup flow.
//
// Billing email and payment status (with its 'trial' value) are MSP concepts:
// an Enterprise or Core install has no billing and no trials (edition-licensing
// spec §1). Off MSP the modal edits name and domain only — the fields are not
// shown, not required, never sent — and admin-service refuses a payment_status
// write there with 409 as the backstop.
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { useUpdateTenant, type Tenant } from './queries';
import { usePlatformEdition } from '../../lib/edition';

type Props = { tenant: Tenant; onClose: () => void };

const PAYMENT_STATUSES = ['active', 'trial', 'past_due', 'canceled'] as const;
const isEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

export interface TenantFormValues {
  name: string;
  domain: string;
  billingEmail: string;
  paymentStatus: string;
}

/** The form's blocking error, if any. Billing email is required on MSP only. */
export function tenantFormError(v: TenantFormValues, isMsp: boolean): string | null {
  if (!v.name.trim()) return 'Name is required';
  if (isMsp && (!v.billingEmail.trim() || !isEmail(v.billingEmail))) return 'A valid billing email is required';
  return null;
}

/**
 * The partial-update body: only changed fields, and never the billing fields
 * off MSP (admin-service would 409 a payment_status there).
 */
export function tenantUpdateBody(editing: Tenant, v: TenantFormValues, isMsp: boolean): Record<string, string> {
  const body: Record<string, string> = {};
  if (v.name.trim() !== editing.name) body.name = v.name.trim();
  if ((v.domain.trim() || '') !== (editing.domain ?? '')) body.domain = v.domain.trim();
  if (isMsp && v.billingEmail.trim() !== (editing.billing_email ?? '')) body.billing_email = v.billingEmail.trim();
  if (isMsp && v.paymentStatus !== editing.payment_status) body.payment_status = v.paymentStatus;
  return body;
}

export function TenantFormModal({ tenant: editing, onClose }: Props) {
  const updateMut = useUpdateTenant();
  const { isMsp } = usePlatformEdition();

  const [name, setName] = useState(editing.name);
  const [domain, setDomain] = useState(editing.domain ?? '');
  const [billingEmail, setBillingEmail] = useState(editing.billing_email ?? '');
  const [paymentStatus, setPaymentStatus] = useState(editing.payment_status ?? 'trial');

  const error = useMemo(
    () => tenantFormError({ name, domain, billingEmail, paymentStatus }, isMsp),
    [name, domain, billingEmail, paymentStatus, isMsp],
  );

  const submit = () => {
    if (error) { toast.error(error); return; }
    // Partial update — only changed fields. Empty body 400s server-side, so guard it.
    const body = tenantUpdateBody(editing, { name, domain, billingEmail, paymentStatus }, isMsp);
    if (Object.keys(body).length === 0) { toast('No changes to save'); onClose(); return; }
    updateMut.mutate(
      { id: editing.id, body },
      {
        onSuccess: () => { toast.success(`Tenant "${name.trim()}" updated`); onClose(); },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to update tenant'),
      },
    );
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={`Edit ${editing.name}`}
      description={isMsp
        ? 'Tier changes are made from Plans & Pricing → Tiers → open a plan → Assign to tenant…, not here.'
        : "To switch a feature off for this tenant, use the drawer's Entitlements tab."}
      size="md"
      primaryLabel="Save changes"
      onPrimary={submit}
      primaryDisabled={!!error}
      primaryLoading={updateMut.isPending}
      footerNote="Changes are logged to audit."
    >
      <ModalField label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corporation" style={modalInputStyle} autoFocus />
      </ModalField>

      <ModalField label="Domain (optional)">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="acme.com" style={modalInputStyle} />
      </ModalField>

      {isMsp && (
        <ModalField label="Billing email">
          <input value={billingEmail} onChange={(e) => setBillingEmail(e.target.value)} placeholder="billing@acme.com" type="email" style={modalInputStyle} />
        </ModalField>
      )}

      {isMsp && (
        <ModalField label="Payment status">
          <select value={paymentStatus} onChange={(e) => setPaymentStatus(e.target.value)} style={modalInputStyle}>
            {PAYMENT_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </ModalField>
      )}
    </Modal>
  );
}
