import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime, isCloudSourced, deviceTypeLabel } from './kit';
import { Icon } from '../../components/ui';
import { useDevices } from './queries';
import { DeviceFormModal, DeviceDeleteModal, TestConnectionModal, DiscoverDeviceModal } from './device-modals';

// Discovery → Devices — the mock's `discovery-devices` table, live from
// device-interrogation-service: the network devices registered for
// interrogation (F5 / Palo Alto / Cisco / Fortinet / UniFi …). Adds the write
// surface: add / discover-and-add (toolbar), edit / delete / interrogate /
// test-connection (per row). All writes are gated on discovery.manage.

type Device = deviceInterrogationComponents['schemas']['Device'];

const COLS = [
  { label: 'Device', w: '1.4fr' },
  { label: 'IP', w: '1fr' },
  { label: 'Type', w: '1fr' },
  { label: 'Firmware', w: '1.2fr' },
  { label: 'Last interrogated', w: '140px' },
  { label: 'Connection', w: '110px', align: 'right' as const },
  { label: '', w: '150px', align: 'right' as const },
];

function connColor(status?: string | null): string {
  const s = (status || '').toLowerCase();
  if (s === 'connected') return 'var(--ok)';
  if (s === 'error' || s === 'disconnected') return 'var(--danger)';
  if (s === 'testing') return 'var(--info)';
  return 'var(--app-t3)'; // unknown
}

// Compact icon button for the per-row action cluster.
function RowBtn({ icon, title, onClick, danger, disabled }: { icon: string; title: string; onClick: () => void; danger?: boolean; disabled?: boolean }) {
  return (
    <button
      className="ui-btn sm ghost"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      style={{ flex: 'none', padding: '0 7px', ...(danger ? { color: 'var(--danger-text)' } : null) }}
    >
      <Icon name={icon} size={13} />
    </button>
  );
}

export function DevicesPage() {
  const q = useDevices();
  const qc = useQueryClient();
  const devices = q.data ?? [];

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Device | null>(null);
  const [deleting, setDeleting] = useState<Device | null>(null);
  const [testing, setTesting] = useState<Device | null>(null);
  const [discoverOpen, setDiscoverOpen] = useState(false);

  // Interrogate creates a job, so invalidate both the devices and jobs caches.
  // Track the in-flight device ID so only that row's button shows pending.
  const [interrogatingId, setInterrogatingId] = useState<string | null>(null);
  const interrogate = useMutation({
    mutationFn: async (id: string) => {
      setInterrogatingId(id);
      const { data, error } = await clients.devices.POST('/devices/{id}/interrogate', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to start interrogation');
      return data;
    },
    onSuccess: (result) => {
      const jobId = (result as { job_id?: string }).job_id;
      toast.success(jobId ? `Interrogation started · Job ${jobId.slice(0, 8)}…` : 'Interrogation started');
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to start interrogation');
    },
    onSettled: () => {
      setInterrogatingId(null);
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
    },
  });

  const note = queryNote(q, devices.length === 0, {
    thing: 'devices',
    emptyMessage: 'No network devices are registered for interrogation yet.',
  });

  return (
    <PageWrap title="Devices" count={q.isLoading ? '' : devices.length}>
      {/* Gates below name the permission each route enforces
          (device-interrogation-service/internal/api/router.go): POST /devices and
          /devices/discover-and-create are DiscoveryCreate; PUT /devices/:id is
          DiscoveryUpdate; POST /devices/:id/test-connection is DiscoveryRead;
          /devices/:id/interrogate and DELETE /devices/:id are DiscoveryManage. */}
      <PermissionGate permission={TENANT_PERMISSIONS.discovery.create}>
        <div style={{ display: 'flex', gap: 9, marginBottom: 14 }}>
          <button className="ui-btn accent" onClick={() => { setEditing(null); setFormOpen(true); }}>
            <Icon name="plus" size={13} />Add device
          </button>
          <button className="ui-btn" onClick={() => setDiscoverOpen(true)}>
            <Icon name="radar" size={13} />Discover & add
          </button>
        </div>
      </PermissionGate>

      {note ?? (
        <DTable
          cols={COLS}
          rows={devices}
          rowKey={(d) => d.id}
          render={(d) => {
            const cloud = isCloudSourced(d);
            return (
              <>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <CellMono v={d.hostname || d.management_url || '—'} />
                    {cloud && (
                      <span
                        title="Discovered via cloud API — not a network-reachable device"
                        style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 0.3, textTransform: 'uppercase', padding: '1px 6px', borderRadius: 20, border: '1px solid var(--app-border)', color: 'var(--app-t3)', flex: 'none' }}
                      >
                        Cloud
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {[d.vendor, d.model].filter(Boolean).join(' · ')}
                  </div>
                </div>
                <CellMono v={d.ip_address} c="var(--app-t3)" />
                <CellTxt v={deviceTypeLabel(d.device_type)} />
                <CellTxt v={d.firmware_version} />
                <CellTxt v={d.last_interrogated_at ? relTime(d.last_interrogated_at) : 'never'} c="var(--app-t3)" />
                <span style={{ textAlign: 'right', fontSize: 11.5, fontWeight: 600, color: connColor(d.connection_status) }} title={d.interrogation_error || ''}>
                  {(d.connection_status || 'unknown').replace('_', ' ')}
                </span>
                <span style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                    <RowBtn
                      icon={interrogatingId === d.id ? 'loader' : 'activity'}
                      title={cloud ? 'Not interrogable — discovered via cloud API, no management credentials' : 'Interrogate'}
                      onClick={() => interrogate.mutate(d.id)}
                      disabled={interrogatingId === d.id || cloud}
                    />
                  </PermissionGate>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.read}>
                    <RowBtn
                      icon="plug"
                      title={cloud ? 'Not applicable — discovered via cloud API' : 'Test connection'}
                      onClick={() => setTesting(d)}
                      disabled={cloud}
                    />
                  </PermissionGate>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.update}>
                    <RowBtn icon="wrench" title="Edit device" onClick={() => { setEditing(d); setFormOpen(true); }} />
                  </PermissionGate>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                    <RowBtn icon="x-circle" title="Delete device" danger onClick={() => setDeleting(d)} />
                  </PermissionGate>
                </span>
              </>
            );
          }}
        />
      )}

      <DeviceFormModal open={formOpen} device={editing} onClose={() => { setFormOpen(false); setEditing(null); }} />
      <DeviceDeleteModal open={!!deleting} device={deleting} onClose={() => setDeleting(null)} />
      <TestConnectionModal open={!!testing} device={testing} onClose={() => setTesting(null)} />
      <DiscoverDeviceModal open={discoverOpen} onClose={() => setDiscoverOpen(false)} />
    </PageWrap>
  );
}
