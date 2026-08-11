// Policies editing modals — retention policy create / edit (audit-service).
// The contract exposes POST + PUT only (no DELETE) — policies are deactivated
// via is_active rather than removed.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput } from '../../components/ui';
import type { auditServiceComponents as AC } from '@vistasecurity/api-contract';

type RetentionPolicy = AC['schemas']['RetentionPolicy'];

function legacyMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error) return String((error as { error: unknown }).error);
  return fallback;
}

export function RetentionPolicyModal({ policy, open, onClose }: { policy: RetentionPolicy | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = !!policy;
  const [name, setName] = useState(policy?.policy_name ?? '');
  const [eventType, setEventType] = useState(policy?.event_type ?? '');
  const [hotDays, setHotDays] = useState(String(policy?.hot_storage_days ?? 90));
  const [totalDays, setTotalDays] = useState(String(policy?.total_retention_days ?? 365));

  const hot = parseInt(hotDays, 10) || 0;
  const total = parseInt(totalDays, 10) || 0;
  const valid = name.trim().length > 0 && hot > 0 && total >= hot;

  const mutation = useMutation({
    mutationFn: async () => {
      const body = {
        policy_name: name.trim(),
        event_type: eventType.trim() || null,
        hot_storage_days: hot,
        total_retention_days: total,
        is_active: policy?.is_active ?? true,
      };
      if (isEdit) {
        const { error, response } = await clients.audit.PUT('/retention-policies/{id}', { params: { path: { id: policy.id } }, body });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to update the policy'));
      } else {
        const { error, response } = await clients.audit.POST('/retention-policies', { body });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to create the policy'));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'retention-policies'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="archive"
      eyebrow="Policies"
      title={isEdit ? `Edit policy — ${policy.policy_name}` : 'Add retention policy'}
      description="How long audit and event data stays in hot storage, and when it ages out entirely."
      primary={
        <button className="ui-btn sm accent" disabled={!valid || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add policy'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Policy name">
        <ModalInput value={name} data-autofocus placeholder="e.g. Audit logs" onChange={(e) => setName(e.target.value)} />
      </ModalField>
      <ModalField label="Event type" hint="Optional — restricts the policy to one event type; empty applies to all events.">
        <ModalInput value={eventType ?? ''} className="mono" placeholder="e.g. auth.login" onChange={(e) => setEventType(e.target.value)} />
      </ModalField>
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1 }}>
          <ModalField label="Hot storage (days)" hint="Kept immediately queryable.">
            <ModalInput value={hotDays} type="number" min={1} onChange={(e) => setHotDays(e.target.value)} />
          </ModalField>
        </div>
        <div style={{ flex: 1 }}>
          <ModalField label="Total retention (days)" hint="Must be ≥ hot storage.">
            <ModalInput value={totalDays} type="number" min={1} onChange={(e) => setTotalDays(e.target.value)} />
          </ModalField>
        </div>
      </div>
    </Modal>
  );
}
