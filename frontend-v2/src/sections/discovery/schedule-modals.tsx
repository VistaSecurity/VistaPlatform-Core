// Scheduled-scan write surface — create / edit / delete confirmation for the
// Discovery → Scheduled Scans page. Wired through the typed
// device-interrogation-service client: POST /schedules (create),
// PUT /schedules/{id} (edit), DELETE /schedules/{id} (delete). The enable/
// disable toggle and the run-now trigger live on the cards in scans-page.tsx.
//
// Contract note: target_type + target_id are create-only (CreateScheduleRequest
// requires them; UpdateScheduleRequest omits them), so the edit modal does not
// expose them — a schedule's target is fixed once created.
import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useDevices, useIntegrations } from './queries';

type Schedule = deviceInterrogationComponents['schemas']['InterrogationSchedule'];

const TARGET_TYPES = [
  { value: 'device', label: 'Device' },
  { value: 'cloud_integration', label: 'Cloud integration' },
] as const;

function deviceLabel(d: deviceInterrogationComponents['schemas']['Device']): string {
  return d.hostname || d.ip_address || d.vendor || d.device_type || d.id;
}

export function ScheduleFormModal({ schedule, open, onClose }: {
  schedule?: Schedule | null;
  open: boolean;
  onClose: () => void;
}) {
  const isEdit = !!schedule?.id;
  const qc = useQueryClient();
  const devices = useDevices();
  const integrations = useIntegrations();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [cron, setCron] = useState('');
  const [targetType, setTargetType] = useState<string>('device');
  const [targetId, setTargetId] = useState('');
  const [enabled, setEnabled] = useState(true);

  // (Re)hydrate from the target schedule whenever it changes or the modal reopens.
  useEffect(() => {
    setName(schedule?.name ?? '');
    setDescription(schedule?.description ?? '');
    setCron(schedule?.cron_expression ?? '');
    setTargetType(schedule?.target_type || 'device');
    setTargetId(schedule?.target_id ?? '');
    setEnabled(schedule?.is_enabled ?? true);
  }, [schedule, open]);

  const targetValid = isEdit || !!targetId;
  const valid = !!name.trim() && !!cron.trim() && !!targetType && targetValid;

  const save = useMutation({
    mutationFn: async () => {
      if (isEdit) {
        // UpdateScheduleRequest: name / description / cron_expression / is_enabled.
        const { data, error } = await clients.devices.PUT('/schedules/{id}', {
          params: { path: { id: schedule!.id } },
          body: {
            name: name.trim(),
            description: description.trim() || undefined,
            cron_expression: cron.trim(),
            is_enabled: enabled,
          },
        });
        if (error || !data) throw new Error('Failed to update schedule');
        return data;
      }
      // CreateScheduleRequest: name / cron_expression / target_type / target_id (+ description, is_enabled).
      const { data, error } = await clients.devices.POST('/schedules', {
        body: {
          name: name.trim(),
          description: description.trim() || undefined,
          cron_expression: cron.trim(),
          target_type: targetType,
          target_id: targetId,
          is_enabled: enabled,
        },
      });
      if (error || !data) throw new Error('Failed to create schedule');
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'schedules'] });
      onClose();
    },
  });

  const footerErr = save.isError ? (save.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      icon={isEdit ? 'calendar-clock' : 'plus'}
      eyebrow="Discovery · Scheduled Scans"
      title={isEdit ? `Edit schedule — ${schedule?.name ?? ''}` : 'New scheduled scan'}
      description={isEdit
        ? 'Update the name, description, cron cadence, or enabled state. The target is fixed once a schedule is created.'
        : 'A recurring interrogation. Pick a cron cadence and the device or cloud integration it runs against.'}
      primary={
        <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create schedule'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <ModalField label="Name">
        <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Nightly core-switch sweep" />
      </ModalField>
      <ModalField label="Description" hint="Optional — shown in the schedule list.">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this schedule cover?" />
      </ModalField>
      <ModalField label="Cron expression" hint="Standard 5-field cron, e.g. 0 2 * * * (daily at 02:00).">
        <ModalInput value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 2 * * *" className="mono" />
      </ModalField>

      {!isEdit && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
          <ModalField label="Target type">
            <ModalSelect value={targetType} onChange={(e) => { setTargetType(e.target.value); setTargetId(''); }}>
              {TARGET_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label={targetType === 'cloud_integration' ? 'Cloud integration' : 'Device'}>
            <ModalSelect value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              <option value="">Select…</option>
              {targetType === 'cloud_integration'
                ? (integrations.data ?? []).map((i) => <option key={i.id} value={i.id}>{i.integration_name}</option>)
                : (devices.data ?? []).map((d) => <option key={d.id} value={d.id}>{deviceLabel(d)}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      )}

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, marginBottom: 6, cursor: 'pointer' }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>Enabled</span>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>— runs on its cron cadence when on.</span>
      </label>
    </Modal>
  );
}

export function ScheduleDeleteModal({ schedule, open, onClose }: {
  schedule: Schedule | null;
  open: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      if (!schedule) return;
      const { error } = await clients.devices.DELETE('/schedules/{id}', { params: { path: { id: schedule.id } } });
      if (error) throw new Error('Failed to delete schedule');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'schedules'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={del.isPending ? undefined : onClose}
      dismissible={!del.isPending}
      size="sm"
      tone="danger"
      icon="alert-triangle"
      eyebrow="Discovery · Scheduled Scans"
      title={`Delete schedule — ${schedule?.name ?? ''}`}
      description="The schedule stops recurring immediately. Past run history is retained, but the cadence is removed."
      primary={
        <button className="ui-btn" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete schedule'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error instanceof Error ? del.error.message : 'Request failed'}</span> : undefined}
    />
  );
}
