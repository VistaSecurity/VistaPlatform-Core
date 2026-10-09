// Scheduled-scan write surface — create / edit / delete confirmation for the
// Discovery → Scheduled Scans page. Wired through the typed
// device-interrogation-service client: POST /schedules (create),
// PUT /schedules/{id} (edit), DELETE /schedules/{id} (delete). The enable/
// disable toggle and the run-now trigger live on the cards in scans-page.tsx.
//
// Contract note: target_type + target_id are create-only (CreateScheduleRequest
// requires them; UpdateScheduleRequest omits them), so the edit modal does not
// expose them — a schedule's target is fixed once created.
//
// Timing is picked in plain language (every N hours / daily / weekly / monthly,
// a time and a time zone) and compiled to the cron_expression the API stores —
// see schedule-cadence.ts. "Custom (cron expression)" keeps the raw field.
import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { useDevices, useIntegrations } from './queries';
import { serverErrorMessage } from './cloud-modals';
import {
  type Cadence, type Frequency, HOUR_INTERVALS, MAX_DAY_OF_MONTH, WEEKDAY_ORDER, DAY_SHORT,
  cadenceError, defaultCadence, describeCadence, parseCron, timeZoneOptions, toCron,
} from './schedule-cadence';

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
  const [cadence, setCadence] = useState<Cadence>(() => defaultCadence());
  const [targetType, setTargetType] = useState<string>('device');
  const [targetId, setTargetId] = useState('');
  const [enabled, setEnabled] = useState(true);

  // (Re)hydrate from the target schedule whenever it changes or the modal reopens.
  useEffect(() => {
    setName(schedule?.name ?? '');
    setDescription(schedule?.description ?? '');
    setCadence(schedule?.cron_expression ? parseCron(schedule.cron_expression) : defaultCadence());
    setTargetType(schedule?.target_type || 'device');
    setTargetId(schedule?.target_id ?? '');
    setEnabled(schedule?.is_enabled ?? true);
  }, [schedule, open]);

  const targetValid = isEdit || !!targetId;
  const timingError = cadenceError(cadence);
  const cron = toCron(cadence);
  const valid = !!name.trim() && !timingError && !!targetType && targetValid;

  const save = useMutation({
    mutationFn: async () => {
      if (isEdit) {
        // UpdateScheduleRequest: name / description / cron_expression / is_enabled.
        const { data, error } = await clients.devices.PUT('/schedules/{id}', {
          params: { path: { id: schedule!.id } },
          body: {
            name: name.trim(),
            description: description.trim() || undefined,
            cron_expression: cron,
            is_enabled: enabled,
          },
        });
        if (error || !data) throw new Error(serverErrorMessage(error, 'Failed to update schedule'));
        return data;
      }
      // CreateScheduleRequest: name / cron_expression / target_type / target_id (+ description, is_enabled).
      const { data, error } = await clients.devices.POST('/schedules', {
        body: {
          name: name.trim(),
          description: description.trim() || undefined,
          cron_expression: cron,
          target_type: targetType,
          target_id: targetId,
          is_enabled: enabled,
        },
      });
      if (error || !data) throw new Error(serverErrorMessage(error, 'Failed to create schedule'));
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
        ? 'Update the name, description, timing, or enabled state. The target is fixed once a schedule is created.'
        : 'A recurring interrogation. Pick how often it runs and the device or cloud integration it runs against.'}
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
      <CadencePicker value={cadence} onChange={setCadence} error={timingError} />

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
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>— runs on this schedule when on.</span>
      </label>
    </Modal>
  );
}

const FREQUENCIES: { value: Frequency; label: string }[] = [
  { value: 'hourly', label: 'Every few hours' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
  { value: 'custom', label: 'Custom (cron expression)' },
];

const pad2 = (n: number) => String(n).padStart(2, '0');

/** The plain-language timing picker; compiles to cron via toCron(). */
export function CadencePicker({ value: c, onChange, error }: {
  value: Cadence;
  onChange: (c: Cadence) => void;
  error: string | null;
}) {
  const set = (patch: Partial<Cadence>) => onChange({ ...c, ...patch });
  const zones = useMemo(() => timeZoneOptions(c.timeZone), [c.timeZone]);
  const summary = describeCadence(c);

  const changeFrequency = (frequency: Frequency) => {
    // Switching to Custom seeds the field with what the picker had, so a
    // power user starts from a valid expression instead of a blank box.
    if (frequency === 'custom') return onChange({ ...c, frequency, expression: c.frequency === 'custom' ? c.expression : toCron(c) });
    return set({ frequency });
  };
  const toggleDay = (d: number) => set({ weekdays: c.weekdays.includes(d) ? c.weekdays.filter((x) => x !== d) : [...c.weekdays, d] });

  const timeZoneField = (
    <ModalField label="Time zone">
      <ModalSelect value={c.timeZone} onChange={(e) => set({ timeZone: e.target.value })}>
        {c.timeZone === '' && <option value="">UTC (server time)</option>}
        {zones.map((z) => <option key={z} value={z}>{z.replace(/_/g, ' ')}</option>)}
      </ModalSelect>
    </ModalField>
  );

  return (
    <div>
      <ModalField label="Runs">
        <ModalSelect value={c.frequency} onChange={(e) => changeFrequency(e.target.value as Frequency)}>
          {FREQUENCIES.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </ModalSelect>
      </ModalField>

      {c.frequency === 'hourly' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.4fr', gap: '0 14px' }}>
          <ModalField label="Every">
            <ModalSelect value={c.everyHours} onChange={(e) => set({ everyHours: Number(e.target.value) })}>
              {HOUR_INTERVALS.map((h) => <option key={h} value={h}>{h === 1 ? '1 hour' : `${h} hours`}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Minutes past the hour">
            <ModalInput type="number" min={0} max={59} value={c.minute}
              onChange={(e) => set({ minute: Math.min(59, Math.max(0, Math.trunc(Number(e.target.value) || 0))) })} />
          </ModalField>
          {timeZoneField}
        </div>
      )}

      {c.frequency === 'weekly' && (
        // Not a ModalField: that renders a <label>, which would forward every
        // click inside it to the first day button.
        <div style={{ marginBottom: 15 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 6 }}>On</div>
          <div role="group" aria-label="Days of the week" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {WEEKDAY_ORDER.map((d) => {
              const on = c.weekdays.includes(d);
              return (
                <button key={d} type="button" aria-pressed={on} onClick={() => toggleDay(d)}
                  className={`ui-btn sm${on ? ' accent' : ''}`} style={{ minWidth: 48, justifyContent: 'center' }}>
                  {DAY_SHORT[d]}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {(c.frequency === 'daily' || c.frequency === 'weekly' || c.frequency === 'monthly') && (
        <div style={{ display: 'grid', gridTemplateColumns: c.frequency === 'monthly' ? '1fr 1fr 1.4fr' : '1fr 1.4fr', gap: '0 14px' }}>
          {c.frequency === 'monthly' && (
            <ModalField label="Day of the month">
              <ModalSelect value={c.dayOfMonth} onChange={(e) => set({ dayOfMonth: Number(e.target.value) })}>
                {Array.from({ length: MAX_DAY_OF_MONTH }, (_, i) => i + 1).map((d) => <option key={d} value={d}>{d}</option>)}
              </ModalSelect>
            </ModalField>
          )}
          <ModalField label="Time">
            <ModalInput type="time" value={`${pad2(c.hour)}:${pad2(c.minute)}`}
              onChange={(e) => {
                const [h, m] = e.target.value.split(':').map(Number);
                if (Number.isInteger(h) && Number.isInteger(m)) set({ hour: h, minute: m });
              }} />
          </ModalField>
          {timeZoneField}
        </div>
      )}

      {c.frequency === 'custom' && (
        <ModalField label="Cron expression"
          hint="Five fields: minute hour day-of-month month day-of-week, e.g. 0 2 * * 1-5. Times are UTC unless prefixed with CRON_TZ=<zone>.">
          <ModalInput value={c.expression} onChange={(e) => set({ expression: e.target.value })} placeholder="0 2 * * *" className="mono" />
        </ModalField>
      )}

      <div data-testid="schedule-summary" style={{ fontSize: 12, marginTop: -4, marginBottom: 14, color: error ? 'var(--danger-text)' : 'var(--app-t2)' }}>
        {error ?? (summary ? `Runs ${summary.charAt(0).toLowerCase()}${summary.slice(1)}.` : 'Runs on a custom cron schedule.')}
      </div>
    </div>
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
