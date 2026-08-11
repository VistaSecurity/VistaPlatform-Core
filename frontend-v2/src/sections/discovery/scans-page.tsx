import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { PageWrap, queryNote, relTime } from './kit';
import { useSchedules } from './queries';
import { ScheduleFormModal, ScheduleDeleteModal } from './schedule-modals';

type Schedule = deviceInterrogationComponents['schemas']['InterrogationSchedule'];

// Discovery → Scheduled Scans — the mock's `discovery-scans` card grid, live
// from device-interrogation-service /schedules. The toggle drives the real
// enable/disable endpoints.

function nextRun(iso?: string): string {
  if (!iso) return '—';
  const mins = (new Date(iso).getTime() - Date.now()) / 60000;
  if (mins <= 0) return 'due now';
  if (mins < 60) return `in ${Math.round(mins)}m`;
  if (mins < 1440) return `in ${Math.round(mins / 60)}h`;
  return `in ${Math.round(mins / 1440)}d`;
}

export function ScansPage() {
  const q = useSchedules();
  const qc = useQueryClient();
  const schedules = q.data ?? [];

  // Write surfaces: create/edit modal (null target → create), delete confirm.
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [deleting, setDeleting] = useState<Schedule | null>(null);

  const toggle = useMutation({
    mutationFn: async ({ id, enable }: { id: string; enable: boolean }) => {
      const path = enable ? '/schedules/{id}/enable' : '/schedules/{id}/disable';
      const { data, error } = await clients.devices.POST(path, { params: { path: { id } } });
      if (error || !data) throw new Error(`Failed to ${enable ? 'enable' : 'disable'} schedule`);
      return data;
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['discovery', 'schedules'] }),
  });

  // Run now — POST /schedules/{id}/trigger queues an immediate job. Track the
  // in-flight id so only that card's button shows the pending state.
  const trigger = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.devices.POST('/schedules/{id}/trigger', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to trigger schedule');
      return data;
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['discovery', 'schedules'] }),
  });

  const openCreate = () => { setEditing(null); setFormOpen(true); };
  const openEdit = (s: Schedule) => { setEditing(s); setFormOpen(true); };

  const note = queryNote(q, schedules.length === 0, {
    thing: 'scheduled scans',
    emptyTitle: 'No scheduled scans',
    emptyMessage: 'Recurring interrogation schedules appear here once created.',
  });

  return (
    <PageWrap title="Scheduled Scans" count={q.isLoading ? '' : schedules.length}>
      <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
          <button className="ui-btn accent" onClick={openCreate}><Icon name="plus" size={13} />New schedule</button>
        </div>
      </PermissionGate>
      {note ?? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 14 }}>
          {schedules.map((s) => (
            <div key={s.id} className="panel" style={{ padding: 18, display: 'flex', alignItems: 'center', gap: 14 }}>
              <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: s.is_enabled ? 'var(--accent)' : 'var(--app-t3)' }}>
                <Icon name="calendar-clock" size={18} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.name}</div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  <span className="mono">{s.cron_expression}</span>
                  {s.is_enabled && s.next_run_at ? ` · next ${nextRun(s.next_run_at)}` : ''}
                  {` · ${s.target_type === 'cloud_integration' ? 'cloud integration' : 'device'}`}
                </div>
                {(s.last_run_at || s.failure_count > 0) && (
                  <div style={{ fontSize: 10.5, color: s.last_run_status === 'failed' ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 3 }}>
                    {s.last_run_at ? `last run ${relTime(s.last_run_at)}${s.last_run_status ? ` · ${s.last_run_status}` : ''}` : ''}
                    {s.failure_count > 0 ? ` · ${s.failure_count} failures` : ''}
                  </div>
                )}
              </div>
              <PermissionGate
                permission={TENANT_PERMISSIONS.discovery.manage}
                fallback={<span style={{ fontSize: 11, fontWeight: 600, color: s.is_enabled ? 'var(--accent)' : 'var(--app-t3)', flex: 'none' }}>{s.is_enabled ? 'On' : 'Off'}</span>}
              >
                <button
                  onClick={() => toggle.mutate({ id: s.id, enable: !s.is_enabled })}
                  disabled={toggle.isPending}
                  title={s.is_enabled ? 'Disable schedule' : 'Enable schedule'}
                  style={{ width: 38, height: 22, borderRadius: 40, border: 'none', padding: 0, cursor: 'pointer', background: s.is_enabled ? 'var(--accent-gradient)' : 'var(--app-track)', position: 'relative', flex: 'none', opacity: toggle.isPending ? 0.6 : 1 }}
                >
                  <span style={{ position: 'absolute', top: 2, left: s.is_enabled ? 18 : 2, width: 18, height: 18, borderRadius: 50, background: '#fff', transition: 'left .2s' }} />
                </button>
              </PermissionGate>
              <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 'none' }}>
                  <button
                    className="ui-btn sm"
                    onClick={() => trigger.mutate(s.id)}
                    disabled={trigger.isPending && trigger.variables === s.id}
                    title="Run this schedule now"
                  >
                    <Icon name="activity" size={12} />
                    {trigger.isPending && trigger.variables === s.id ? 'Running…' : 'Run now'}
                  </button>
                  <button className="ui-btn sm ghost" onClick={() => openEdit(s)} title="Edit schedule"><Icon name="wrench" size={13} /></button>
                  <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} onClick={() => setDeleting(s)} title="Delete schedule"><Icon name="x" size={13} /></button>
                </div>
              </PermissionGate>
            </div>
          ))}
        </div>
      )}

      <ScheduleFormModal schedule={editing} open={formOpen} onClose={() => setFormOpen(false)} />
      <ScheduleDeleteModal schedule={deleting} open={!!deleting} onClose={() => setDeleting(null)} />
    </PageWrap>
  );
}
