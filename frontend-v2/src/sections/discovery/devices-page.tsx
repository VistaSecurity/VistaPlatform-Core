import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime, isCloudSourced, deviceTypeLabel } from './kit';
import { Icon } from '../../components/ui';
import { useDevices } from './queries';
import { classLabel } from '../inventory/asset-shape';
import { DeviceFormModal, DeviceDeleteModal, TestConnectionModal, DiscoverDeviceModal } from './device-modals';

// Discovery → Devices — now "assets with management configured".
//
// Under ADR-0002 there is no separate device record: sub-task C made a device
// the MANAGEMENT half of an asset (`Device.id` and `Device.asset_id` are the
// same value, and `class` is the asset's class). So this page is a filter of the
// inventory — the assets someone has given the platform credentials for — and
// the rows link to the same asset page every other list links to.
//
// What is genuinely per-device, and why the page stays: management address,
// vendor firmware, the interrogation connection status, and the interrogate /
// test-connection actions. Those belong to the management configuration, not to
// the asset, and there is nowhere else in the product they fit.
//
// Removing management is "unmanage", not "delete": the ASSET survives. Deleting
// an asset is an inventory action and lives on the asset page.

type Device = deviceInterrogationComponents['schemas']['Device'];

const COLS = [
  { label: 'Asset', w: '1.4fr' },
  { label: 'Management address', w: '1fr' },
  { label: 'Class', w: '1fr' },
  { label: 'Interrogator', w: '1fr' },
  { label: 'Firmware', w: '1fr' },
  { label: 'Last interrogated', w: '130px' },
  { label: 'Connection', w: '110px', align: 'right' as const },
  { label: '', w: '206px', align: 'right' as const },
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
  const navigate = useNavigate();
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

  // Clearing the pinned SSH host key. Interrogation fails closed against a key
  // that differs from the pinned one and sends no credential, so a device that
  // was legitimately replaced or rekeyed needs a way back — without one the
  // realistic operator response is to disable host-key checking, which is the
  // control failing open by other means.
  const [repinningId, setRepinningId] = useState<string | null>(null);
  const resetHostKey = useMutation({
    mutationFn: async (id: string) => {
      setRepinningId(id);
      const { data, error } = await clients.devices.DELETE('/devices/{id}/ssh-host-key', { params: { path: { id } } });
      if (error || !data) throw new Error('Failed to clear the pinned SSH host key');
      return data;
    },
    onSuccess: () => {
      toast.success('Pinned SSH host key cleared — the next interrogation will pin the key this device presents');
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : 'Failed to clear the pinned SSH host key');
    },
    onSettled: () => {
      setRepinningId(null);
      void qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
    },
  });

  const note = queryNote(q, devices.length === 0, {
    thing: 'managed assets',
    emptyTitle: 'Nothing is managed yet',
    emptyMessage: 'These are the assets you have given the platform credentials for, so it can log in and read their cryptographic configuration. Add one here, or discover and add it in a single step.',
  });

  return (
    <PageWrap title="Devices" count={q.isLoading ? '' : devices.length}>
      <p style={{ margin: '0 0 14px', fontSize: 13, color: 'var(--app-t3)' }}>
        Assets with management configured — the ones the platform holds credentials for and can interrogate directly. Everything here is also in Inventory; this page is where its management settings live.
      </p>
      {/* Gates below name the permission each route enforces
          (device-interrogation-service/internal/api/router.go): POST /devices and
          /devices/discover-and-create are DiscoveryCreate; PUT /devices/:id is
          DiscoveryUpdate; POST /devices/:id/test-connection is DiscoveryRead;
          /devices/:id/interrogate, DELETE /devices/:id/ssh-host-key and
          DELETE /devices/:id are DiscoveryManage. */}
      <PermissionGate permission={TENANT_PERMISSIONS.discovery.create}>
        <div style={{ display: 'flex', gap: 9, marginBottom: 14 }}>
          <button className="ui-btn accent" onClick={() => { setEditing(null); setFormOpen(true); }}>
            <Icon name="plus" size={13} />Add managed asset
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
                {/* The MANAGEMENT address — where we log in to interrogate it.
                    Distinct from the asset's endpoints, which are what it
                    serves; a switch is managed on one address and serves on
                    others. */}
                <CellMono v={d.ip_address} c="var(--app-t3)" />
                {/* What the thing IS, from the class registry. `device_type` in
                    the next column is which interrogator drives it — the two
                    were conflated under the old four-value `asset_type`. */}
                <CellTxt v={classLabel(d.class)} />
                <CellTxt v={deviceTypeLabel(d.device_type)} />
                <CellTxt v={d.firmware_version} />
                <CellTxt v={d.last_interrogated_at ? relTime(d.last_interrogated_at) : 'never'} c="var(--app-t3)" />
                <span style={{ textAlign: 'right', fontSize: 11.5, fontWeight: 600, color: connColor(d.connection_status) }} title={d.interrogation_error || ''}>
                  {(d.connection_status || 'unknown').replace('_', ' ')}
                </span>
                <span style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
                  <RowBtn
                    icon="external-link"
                    title="Open this asset's page"
                    onClick={() => { void navigate(`/inventory/assets/${d.asset_id || d.id}`); }}
                  />
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
                    <RowBtn icon="wrench" title="Edit management settings" onClick={() => { setEditing(d); setFormOpen(true); }} />
                  </PermissionGate>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                    {/* Only offered once a key is actually pinned: there is
                        nothing to clear before first contact, and a button that
                        does nothing is worse than no button. */}
                    <RowBtn
                      icon={repinningId === d.id ? 'loader' : 'key'}
                      title={
                        d.ssh_host_key_fingerprint
                          ? `Clear the pinned SSH host key (${d.ssh_host_key_fingerprint}). Do this only after a deliberate device replacement or key rotation — if the key changed unexpectedly, change this device's credentials first.`
                          : 'No SSH host key pinned yet — the next interrogation will pin the key this device presents'
                      }
                      onClick={() => resetHostKey.mutate(d.id)}
                      disabled={repinningId === d.id || !d.ssh_host_key_fingerprint}
                    />
                  </PermissionGate>
                  <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                    {/* Unmanage, not delete. This removes the management
                        configuration and its credentials; the ASSET stays in
                        Inventory with everything ever discovered about it. */}
                    <RowBtn icon="unplug" title="Stop managing this asset" danger onClick={() => setDeleting(d)} />
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
