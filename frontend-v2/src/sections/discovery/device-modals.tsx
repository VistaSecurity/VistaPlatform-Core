// Write surface for Discovery → Devices. Restores device CRUD + the live
// device actions (interrogate / test-connection / discover-and-create) the
// read-only rebuild dropped. Wired through the typed device-interrogation
// client; bodies mirror CreateDeviceRequest / UpdateDeviceRequest exactly.
// Composes the shared Modal primitive (same idiom as asset-form-modal.tsx).
import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';

type Device = deviceInterrogationComponents['schemas']['Device'];

// The device types the interrogation service knows how to probe. Free-form on
// the backend, but these are the canonical vendors (see Device.device_type).
const DEVICE_TYPES = ['f5', 'palo_alto', 'cisco', 'fortinet', 'unifi', 'other'];

// ---- Create / edit device ------------------------------------------------
export function DeviceFormModal({ open, device, onClose }: {
  open: boolean;
  /** Present → edit mode (PUT); absent/null → create mode (POST). */
  device?: Device | null;
  onClose: () => void;
}) {
  const isEdit = !!device?.id;
  const qc = useQueryClient();

  const [deviceType, setDeviceType] = useState('f5');
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('');
  const [model, setModel] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [managementUrl, setManagementUrl] = useState('');
  const [serialNumber, setSerialNumber] = useState('');
  const [firmwareVersion, setFirmwareVersion] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tlsInsecure, setTlsInsecure] = useState(false);

  // (Re)hydrate from the target device whenever it changes or the modal reopens.
  useEffect(() => {
    setDeviceType(device?.device_type || 'f5');
    setName(device?.hostname ?? '');
    setVendor(device?.vendor ?? '');
    setModel(device?.model ?? '');
    setIpAddress(device?.ip_address ?? '');
    setManagementUrl(device?.management_url ?? '');
    setSerialNumber(device?.serial_number ?? '');
    setFirmwareVersion(device?.firmware_version ?? '');
    setUsername(device?.username ?? '');
    setPassword(''); // never prefill the (masked) password
    setTlsInsecure(device?.tls_insecure_skip_verify ?? false);
  }, [device, open]);

  // Need a way to reach the device: hostname/IP or a management URL.
  const valid = !!deviceType && !!(name.trim() || ipAddress.trim() || managementUrl.trim());

  const save = useMutation({
    mutationFn: async () => {
      if (isEdit) {
        const body: deviceInterrogationComponents['schemas']['UpdateDeviceRequest'] = {
          vendor: vendor.trim() || undefined,
          model: model.trim() || undefined,
          hostname: name.trim() || undefined,
          ip_address: ipAddress.trim() || undefined,
          management_url: managementUrl.trim() || undefined,
          serial_number: serialNumber.trim() || undefined,
          firmware_version: firmwareVersion.trim() || undefined,
          username: username.trim() || undefined,
          password: password.trim() || undefined,
          tls_insecure_skip_verify: tlsInsecure,
        };
        const { data, error } = await clients.devices.PUT('/devices/{id}', {
          params: { path: { id: device!.id } }, body,
        });
        if (error || !data) throw new Error('Failed to update device');
        return data;
      }
      const body: deviceInterrogationComponents['schemas']['CreateDeviceRequest'] = {
        device_type: deviceType,
        vendor: vendor.trim() || undefined,
        model: model.trim() || undefined,
        hostname: name.trim() || undefined,
        ip_address: ipAddress.trim() || undefined,
        management_url: managementUrl.trim() || undefined,
        serial_number: serialNumber.trim() || undefined,
        firmware_version: firmwareVersion.trim() || undefined,
        username: username.trim() || undefined,
        password: password.trim() || undefined,
        tls_insecure_skip_verify: tlsInsecure,
      };
      const { data, error } = await clients.devices.POST('/devices', { body });
      if (error || !data) throw new Error('Failed to create device');
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      onClose();
    },
  });

  const footerErr = save.isError ? (save.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon={isEdit ? 'server' : 'plus'}
      eyebrow="Discovery"
      title={isEdit ? 'Edit device' : 'Add device'}
      description="A hostname, IP, or management URL is required, plus a device type. Credentials are encrypted at rest."
      primary={
        <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add device'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Device type">
          <ModalSelect data-autofocus value={deviceType} onChange={(e) => setDeviceType(e.target.value)} disabled={isEdit}>
            {DEVICE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Hostname / name"><ModalInput value={name} onChange={(e) => setName(e.target.value)} placeholder="edge-fw-01" /></ModalField>
        <ModalField label="IP address"><ModalInput value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="10.0.0.1" /></ModalField>
        <ModalField label="Management URL"><ModalInput value={managementUrl} onChange={(e) => setManagementUrl(e.target.value)} placeholder="https://10.0.0.1" /></ModalField>
        <ModalField label="Vendor"><ModalInput value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="F5" /></ModalField>
        <ModalField label="Model"><ModalInput value={model} onChange={(e) => setModel(e.target.value)} placeholder="BIG-IP" /></ModalField>
        <ModalField label="Serial number"><ModalInput value={serialNumber} onChange={(e) => setSerialNumber(e.target.value)} placeholder="optional" /></ModalField>
        <ModalField label="Firmware version"><ModalInput value={firmwareVersion} onChange={(e) => setFirmwareVersion(e.target.value)} placeholder="optional" /></ModalField>
        <ModalField label="Username"><ModalInput value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoComplete="off" /></ModalField>
        <ModalField label={isEdit ? 'Password (leave blank to keep)' : 'Password'}>
          <ModalInput type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="new-password" />
        </ModalField>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 12.5, color: 'var(--app-t1)', cursor: 'pointer' }}>
        <input type="checkbox" checked={tlsInsecure} onChange={(e) => setTlsInsecure(e.target.checked)} />
        Skip TLS verification (self-signed management certs)
      </label>
    </Modal>
  );
}

// ---- Delete device (danger confirm) --------------------------------------
export function DeviceDeleteModal({ open, device, onClose }: {
  open: boolean;
  device: Device | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      if (!device) return;
      const { data, error } = await clients.devices.DELETE('/devices/{id}', { params: { path: { id: device.id } } });
      if (error || !data) throw new Error('Failed to delete device');
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      onClose();
    },
  });
  const label = device?.hostname || device?.management_url || device?.ip_address || 'this device';
  return (
    <Modal
      open={open}
      onClose={del.isPending ? undefined : onClose}
      dismissible={!del.isPending}
      size="sm"
      tone="danger"
      icon="x-circle"
      eyebrow="Discovery"
      title="Delete device"
      description={`Remove ${label} from interrogation? This cannot be undone.`}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'transparent' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{(del.error as Error).message}</span> : undefined}
    />
  );
}

// ---- Test connection (result modal) --------------------------------------
// Fires the live test on open; surfaces the ok/fail result inline. The success
// body (DeviceActionAccepted) is an open envelope — show its message/status
// fields when present, else a generic "reachable".
export function TestConnectionModal({ open, device, onClose }: {
  open: boolean;
  device: Device | null;
  onClose: () => void;
}) {
  const test = useMutation({
    mutationFn: async () => {
      if (!device) throw new Error('No device');
      const { data, error } = await clients.devices.POST('/devices/{id}/test-connection', { params: { path: { id: device.id } } });
      if (error || !data) throw new Error('Connection test failed');
      return data as Record<string, unknown>;
    },
  });

  // Re-run the test each time the modal opens for a device.
  useEffect(() => {
    if (open && device) test.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, device?.id]);

  const label = device?.hostname || device?.management_url || device?.ip_address || 'device';
  const result = test.data;
  const ok = test.isSuccess;
  const detail = result
    ? String(result.message ?? result.status ?? result.detail ?? 'Device is reachable.')
    : '';

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="sm"
      tone={ok ? 'green' : test.isError ? 'danger' : 'blue'}
      icon="plug"
      eyebrow="Discovery"
      title={`Test connection · ${label}`}
      primary={<button className="ui-btn accent" onClick={onClose}>Close</button>}
      secondary={<button className="ui-btn" onClick={() => test.mutate()} disabled={test.isPending}>{test.isPending ? 'Testing…' : 'Retry'}</button>}
    >
      <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--app-t2)' }}>
        {test.isPending && <span style={{ color: 'var(--app-t3)' }}>Probing {label}…</span>}
        {ok && <span style={{ color: 'var(--ok)' }}>Connected. {detail}</span>}
        {test.isError && <span style={{ color: 'var(--danger-text)' }}>{(test.error as Error).message}</span>}
      </div>
    </Modal>
  );
}

// ---- Discover & add device -----------------------------------------------
// POST /devices/discover-and-create — body is EXACTLY
// { device_type, management_url, username, password } (all required; confirmed
// from the Go handler). The probe is live device I/O; on success the created
// Device is returned and the devices list is invalidated.
export function DiscoverDeviceModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [deviceType, setDeviceType] = useState('f5');
  const [managementUrl, setManagementUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    if (open) { setDeviceType('f5'); setManagementUrl(''); setUsername(''); setPassword(''); }
  }, [open]);

  const valid = !!deviceType && !!managementUrl.trim() && !!username.trim() && !!password.trim();

  const discover = useMutation({
    mutationFn: async () => {
      const body = {
        device_type: deviceType,
        management_url: managementUrl.trim(),
        username: username.trim(),
        password: password.trim(),
      };
      const { data, error } = await clients.devices.POST('/devices/discover-and-create', {
        // The contract types this body as an empty object; the Go handler reads
        // the four fields above. Cast through the openapi-fetch body slot.
        body: body as unknown as Record<string, never>,
      });
      if (error || !data) throw new Error('Discovery failed — check the URL and credentials.');
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      onClose();
    },
  });

  const footerErr = discover.isError ? (discover.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={discover.isPending ? undefined : onClose}
      dismissible={!discover.isPending}
      size="md"
      tone="blue"
      icon="radar"
      eyebrow="Discovery"
      title="Discover & add device"
      description="Probe a management endpoint with credentials. On success the device is identified and registered for interrogation."
      primary={
        <button className="ui-btn accent" disabled={!valid || discover.isPending} onClick={() => discover.mutate()}>
          {discover.isPending ? 'Probing…' : 'Discover & add'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={discover.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <ModalField label="Device type">
        <ModalSelect data-autofocus value={deviceType} onChange={(e) => setDeviceType(e.target.value)}>
          {DEVICE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Management URL"><ModalInput value={managementUrl} onChange={(e) => setManagementUrl(e.target.value)} placeholder="https://10.0.0.1" /></ModalField>
      <ModalField label="Username"><ModalInput value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoComplete="off" /></ModalField>
      <ModalField label="Password"><ModalInput type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="new-password" /></ModalField>
    </Modal>
  );
}
