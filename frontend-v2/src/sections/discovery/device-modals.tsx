// Write surface for Discovery → Devices. Restores device CRUD + the live
// device actions (interrogate / test-connection / discover-and-create) the
// read-only rebuild dropped. Wired through the typed device-interrogation
// client; bodies mirror CreateDeviceRequest / UpdateDeviceRequest exactly.
// Composes the shared Modal primitive (same idiom as asset-form-modal.tsx).
import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import toast from 'react-hot-toast';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';

type Device = deviceInterrogationComponents['schemas']['Device'];

// The device types the interrogation service knows how to probe. Free-form on
// the backend, but these are the canonical vendors (see Device.device_type).
const DEVICE_TYPES = ['f5', 'palo_alto', 'cisco', 'fortinet', 'unifi', 'other'] as const;
const DISCOVERABLE_DEVICE_TYPES = ['f5', 'palo_alto', 'cisco', 'fortinet', 'unifi'] as const;
type DeviceType = typeof DEVICE_TYPES[number];
type DiscoverableDeviceType = typeof DISCOVERABLE_DEVICE_TYPES[number];

function apiErrorMessage(error: unknown, fallback: string) {
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') return error.message;
  return fallback;
}

export function isValidDeviceHostname(value: string) {
  const hostname = value.trim();
  if (!hostname) return true;
  if (hostname.length > 253 || /\s/.test(hostname)) return false;
  if (hostname.includes(':')) return /^[0-9a-f:]+$/i.test(hostname);
  return hostname.split('.').every((label) => (
    label.length > 0 && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  ));
}

// ---- Create / edit device ------------------------------------------------
export function DeviceFormModal({ open, device, onClose }: {
  open: boolean;
  /** Present → edit mode (PUT); absent/null → create mode (POST). */
  device?: Device | null;
  onClose: () => void;
}) {
  const isEdit = !!device?.id;
  const qc = useQueryClient();
  const navigate = useNavigate();

  const [deviceType, setDeviceType] = useState<DeviceType>('f5');
  const [hostname, setHostname] = useState('');
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
    setDeviceType((device?.device_type || 'f5') as DeviceType);
    setHostname(device?.hostname ?? '');
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
  const hostnameValid = isValidDeviceHostname(hostname);
  const valid = !!deviceType && hostnameValid && !!(hostname.trim() || ipAddress.trim() || managementUrl.trim());

  const save = useMutation({
    mutationFn: async () => {
      if (isEdit) {
        const body: deviceInterrogationComponents['schemas']['UpdateDeviceRequest'] = {
          vendor: vendor.trim() || undefined,
          model: model.trim() || undefined,
          hostname: hostname.trim() || undefined,
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
        if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to update device'));
        return data;
      }
      const body: deviceInterrogationComponents['schemas']['CreateDeviceRequest'] = {
        device_type: deviceType,
        vendor: vendor.trim() || undefined,
        model: model.trim() || undefined,
        hostname: hostname.trim() || undefined,
        ip_address: ipAddress.trim() || undefined,
        management_url: managementUrl.trim() || undefined,
        serial_number: serialNumber.trim() || undefined,
        firmware_version: firmwareVersion.trim() || undefined,
        username: username.trim() || undefined,
        password: password.trim() || undefined,
        tls_insecure_skip_verify: tlsInsecure,
      };
      const { data, error } = await clients.devices.POST('/devices', { body });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to create device'));
      return data;
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      if ('observation_id' in result) {
        void qc.invalidateQueries({ queryKey: ['identity-observations'] });
        void qc.invalidateQueries({ queryKey: ['identity-summary'] });
        void navigate(`/discovery/observations?observation_id=${result.observation_id}`);
        toast.success(result.message ?? 'Management settings were saved with the observation. Resolve its identity to finish adding the device.');
      }
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
          <ModalSelect data-autofocus value={deviceType} onChange={(e) => setDeviceType(e.target.value as DeviceType)} disabled={isEdit}>
            {DEVICE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Hostname">
          <ModalInput value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="edge-fw-01" aria-invalid={!hostnameValid} />
          {!hostnameValid && <span role="alert" style={{ color: 'var(--danger-text)', fontSize: 12 }}>Use a DNS hostname without spaces (for example, edge-fw-01).</span>}
        </ModalField>
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

// ---- Unmanage (danger confirm) -------------------------------------------
//
// The copy says "stop managing", not "delete", because that is what the call
// does: it removes the management configuration and its stored credentials. The
// ASSET survives with every certificate and configuration ever discovered on
// it — deleting an asset is an inventory action and lives on the asset page.
// Saying "delete" here would make an operator think twice about a reversible
// change, or worse, believe they had removed an asset they had not.
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
      if (error || !data) throw new Error('Failed to stop managing this asset');
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
      icon="unplug"
      eyebrow="Discovery"
      title="Stop managing this asset?"
      description={`${label} will no longer be interrogated, and its stored management credentials are removed. The asset itself stays in Inventory with everything already discovered about it — you can manage it again at any time.`}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'transparent' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Removing…' : 'Stop managing'}
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
  const navigate = useNavigate();
  const [deviceType, setDeviceType] = useState<DiscoverableDeviceType>('f5');
  const [managementUrl, setManagementUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tlsInsecure, setTlsInsecure] = useState(false);

  useEffect(() => {
    if (open) { setDeviceType('f5'); setManagementUrl(''); setUsername(''); setPassword(''); setTlsInsecure(false); }
  }, [open]);

  const valid = !!deviceType && !!managementUrl.trim() && !!username.trim() && !!password.trim();

  const discover = useMutation({
    mutationFn: async () => {
      const body = {
        device_type: deviceType,
        management_url: managementUrl.trim(),
        username: username.trim(),
        password: password.trim(),
        tls_insecure_skip_verify: tlsInsecure,
      };
      const { data, error } = await clients.devices.POST('/devices/discover-and-create', {
        body,
      });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Discovery failed. Check the management URL, reachability, and credentials.'));
      return data;
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
      if ('observation_id' in result) {
        void qc.invalidateQueries({ queryKey: ['identity-observations'] });
        void qc.invalidateQueries({ queryKey: ['identity-summary'] });
        void navigate(`/discovery/observations?observation_id=${result.observation_id}`);
        toast.success(result.message ?? 'Management settings were saved with the observation. Resolve its identity to finish adding the device.');
      }
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
      description="Probe a management endpoint with configured credentials. Evidence awaiting identity resolution is retained in Discovery observations."
      primary={
        <button className="ui-btn accent" disabled={!valid || discover.isPending} onClick={() => discover.mutate()}>
          {discover.isPending ? 'Probing…' : 'Discover & add'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={discover.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <ModalField label="Device type">
        <ModalSelect data-autofocus value={deviceType} onChange={(e) => setDeviceType(e.target.value as DiscoverableDeviceType)}>
          {DISCOVERABLE_DEVICE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Management URL"><ModalInput value={managementUrl} onChange={(e) => setManagementUrl(e.target.value)} placeholder="https://10.0.0.1" /></ModalField>
      <ModalField label="Username"><ModalInput value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoComplete="off" /></ModalField>
      <ModalField label="Password"><ModalInput type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="new-password" /></ModalField>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 12.5, color: 'var(--app-t1)', cursor: 'pointer' }}>
        <input type="checkbox" checked={tlsInsecure} onChange={(e) => setTlsInsecure(e.target.checked)} />
        Skip TLS verification (self-signed management certs)
      </label>
    </Modal>
  );
}
