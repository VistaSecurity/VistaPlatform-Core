// Write surface for Discovery → Devices. Device CRUD + the live device actions
// (interrogate / test-connection). Wired through the typed device-interrogation
// client; bodies mirror CreateDeviceRequest / UpdateDeviceRequest /
// DiscoverAndCreateDeviceRequest exactly. Composes the shared Modal primitive
// (same idiom as asset-form-modal.tsx).
//
// Adding a device is ONE flow ( slice A): four fields — device type,
// management address, username, password — and the platform connects,
// identifies the device and fills in vendor, model, serial, firmware, hostname,
// IP and MAC itself. Only when that probe fails does the form expand to the
// remaining fields, with the real reason, so the device can still be added by
// hand. The separate "Discover & add" button and modal it replaced are gone.
import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import toast from 'react-hot-toast';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { deviceTypeLabel } from './kit';

type Device = deviceInterrogationComponents['schemas']['Device'];
type DiscoveryErrorCode = deviceInterrogationComponents['schemas']['DeviceDiscoveryError']['error'];

// The device types the interrogation service knows how to probe. Free-form on
// the backend, but these are the canonical vendors (see Device.device_type).
const DEVICE_TYPES = ['f5', 'palo_alto', 'cisco', 'fortinet', 'unifi', 'other'] as const;
// The types Add device can identify by connecting (each has a vendor identity
// step in shared/deviceinterrogation). 'other' is added by hand.
const PROBE_TYPES: readonly string[] = ['f5', 'palo_alto', 'cisco', 'fortinet', 'unifi'];
type DeviceType = typeof DEVICE_TYPES[number];

// Device types reached over SSH (the Cisco collector). They have no TLS to
// skip, and the backend's skip flag becomes an SSH host-key opt-out for them —
// so the form never offers it for these types and never sends it true
// ( review B1). Mirrors services.IsSSHManagedDeviceType.
const SSH_DEVICE_TYPES: readonly string[] = ['cisco', 'cisco_router', 'cisco_switch', 'cisco_asa'];
export function isSSHManagedDeviceType(deviceType: string | null | undefined): boolean {
  return !!deviceType && SSH_DEVICE_TYPES.includes(deviceType);
}

function apiErrorMessage(error: unknown, fallback: string) {
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') return error.message;
  return fallback;
}

/** A failed probe or connection test: the typed reason and the server's copy for it. */
export class DeviceProbeError extends Error {
  constructor(public readonly code: string | undefined, message: string) {
    super(message);
    this.name = 'DeviceProbeError';
  }
}

function probeError(error: unknown, fallback: string): DeviceProbeError {
  const code = error && typeof error === 'object' && 'error' in error && typeof error.error === 'string' ? error.error : undefined;
  return new DeviceProbeError(code, apiErrorMessage(error, fallback));
}

// Headline per failure reason. The server's message (fixed copy per code, never
// device text) is shown under it; this is what lets an operator tell
// "unreachable" from "wrong password" from "refused by policy" at a glance.
const PROBE_FAILURE_TITLES: Record<DiscoveryErrorCode, string> = {
  connection_failed: "Couldn't reach the device",
  tls_untrusted: "The device's certificate isn't trusted",
  authentication_failed: 'The device rejected the credentials',
  target_disallowed: "That address isn't allowed",
  invalid_target: "That management address isn't valid",
  unsupported_response: 'Something else answered at that address',
  not_supported: "This device type can't be identified automatically",
  host_key_mismatch: 'The SSH host key has changed',
  discovery_failed: "The device's identity couldn't be read",
  credentials_missing: 'No stored credentials to test with',
  rate_limited: 'Too many device connections just now',
  test_throttled: 'This device was tested moments ago',
};

export function probeFailureTitle(code: string | undefined): string {
  const known: string | undefined = code ? PROBE_FAILURE_TITLES[code as DiscoveryErrorCode] : undefined;
  return known ?? "Couldn't identify the device";
}

function isProbeFailure(code: string | undefined): boolean {
  return !!code && code in PROBE_FAILURE_TITLES;
}

// A limit refusal dialled nothing, so it says nothing about the device: the
// form does not fall back to the by-hand fields for it.
function disclosesFields(code: string | undefined): boolean {
  return isProbeFailure(code) && code !== 'rate_limited';
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

function FailurePanel({ error, onRetry, retrying, addByHandHint }: {
  error: DeviceProbeError;
  onRetry?: () => void;
  retrying?: boolean;
  /** Add device only: point an unreachable device at the by-hand fields. */
  addByHandHint?: boolean;
}) {
  return (
    <div role="alert" data-testid="probe-failure" data-code={error.code ?? ''} style={{ margin: '0 0 12px', padding: '10px 12px', borderRadius: 8, border: '1px solid var(--danger)', background: 'var(--danger-bg, transparent)', fontSize: 12.5, lineHeight: 1.5 }}>
      <div style={{ fontWeight: 600, color: 'var(--danger-text)' }}>{probeFailureTitle(error.code)}</div>
      <div style={{ color: 'var(--app-t2)' }}>{error.message}</div>
      {addByHandHint && error.code === 'connection_failed' && (
        <div style={{ color: 'var(--app-t3)', marginTop: 4 }}>If only a deployed agent can reach this device, add it by hand below.</div>
      )}
      {onRetry && (
        <button type="button" className="ui-btn sm" style={{ marginTop: 8 }} onClick={onRetry} disabled={retrying}>
          {retrying ? 'Connecting…' : 'Try connecting again'}
        </button>
      )}
    </div>
  );
}

// ---- Add / edit device ------------------------------------------------------
export function DeviceFormModal({ open, device, onClose }: {
  open: boolean;
  /** Present → edit mode (PUT); absent/null → create mode (probe, then POST on fallback). */
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
  // Create mode only: the remaining fields are revealed when the probe fails
  // (or the operator chooses to enter them by hand).
  const [expanded, setExpanded] = useState(false);

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
    setExpanded(false);
  }, [device, open]);

  const canProbe = !isEdit && PROBE_TYPES.includes(deviceType);
  const isSsh = isSSHManagedDeviceType(deviceType);
  const showAllFields = isEdit || expanded || !canProbe;
  const probing = canProbe && !expanded;

  const hostnameValid = isValidDeviceHostname(hostname);
  // Probe: all four fields. By hand: a way to reach the device (hostname/IP or
  // a management URL) and a type.
  const valid = probing
    ? !!managementUrl.trim() && !!username.trim() && !!password.trim()
    : !!deviceType && hostnameValid && !!(hostname.trim() || ipAddress.trim() || managementUrl.trim());

  const afterCreate = (result: { observation_id?: string; message?: string } | object) => {
    void qc.invalidateQueries({ queryKey: ['discovery', 'devices'] });
    if ('observation_id' in result) {
      void qc.invalidateQueries({ queryKey: ['identity-observations'] });
      void qc.invalidateQueries({ queryKey: ['identity-summary'] });
      void navigate(`/discovery/observations?observation_id=${result.observation_id}`);
      const message = 'message' in result && result.message ? result.message : undefined;
      toast.success(message ?? 'Management settings were saved with the observation. Resolve its identity to finish adding the device.');
    }
    onClose();
  };

  // POST /devices/discover-and-create — connect, identify, create.
  const probe = useMutation({
    mutationFn: async () => {
      const body: deviceInterrogationComponents['schemas']['DiscoverAndCreateDeviceRequest'] = {
        device_type: deviceType as deviceInterrogationComponents['schemas']['DiscoverAndCreateDeviceRequest']['device_type'],
        management_url: managementUrl.trim(),
        username: username.trim(),
        password: password.trim(),
        tls_insecure_skip_verify: isSsh ? false : tlsInsecure,
      };
      const { data, error } = await clients.devices.POST('/devices/discover-and-create', { body });
      if (error || !data) throw probeError(error, "Couldn't connect to the device.");
      return data;
    },
    onSuccess: afterCreate,
    onError: (err) => {
      // A typed probe failure reveals the remaining fields so the device can
      // still be added by hand. Anything else (an identity conflict, a 500) is
      // shown as-is and leaves the form alone.
      if (err instanceof DeviceProbeError && disclosesFields(err.code)) setExpanded(true);
    },
  });

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
          tls_insecure_skip_verify: isSsh ? false : tlsInsecure,
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
        tls_insecure_skip_verify: isSsh ? false : tlsInsecure,
      };
      const { data, error } = await clients.devices.POST('/devices', { body });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to create device'));
      return data;
    },
    onSuccess: afterCreate,
  });

  // A reopened form starts clean: no stale failure from the last attempt.
  useEffect(() => {
    if (open) { probe.reset(); save.reset(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, device?.id]);

  const pending = probe.isPending || save.isPending;
  const probeFailure = probe.error instanceof DeviceProbeError && isProbeFailure(probe.error.code) ? probe.error : null;
  const footerErr = save.error
    ? save.error.message
    : probe.error && !probeFailure ? probe.error.message : null;

  let primaryLabel: string;
  if (isEdit) primaryLabel = save.isPending ? 'Saving…' : 'Save changes';
  else if (probing) primaryLabel = probe.isPending ? 'Connecting…' : 'Add device';
  else if (canProbe) primaryLabel = save.isPending ? 'Saving…' : 'Add without connecting';
  else primaryLabel = save.isPending ? 'Saving…' : 'Add device';

  const description = isEdit
    ? 'A hostname, IP, or management URL is required, plus a device type. Credentials are encrypted at rest.'
    : probing
      ? 'Vista connects with these credentials and fills in the vendor, model, serial number, firmware, hostname and addresses itself. Credentials are encrypted at rest.'
      : canProbe
        ? 'Enter what you know about the device. It is saved without connecting; interrogation uses these credentials later. Credentials are encrypted at rest.'
        : "Vista can't identify this device type by connecting, so enter its details. A hostname, IP, or management URL is required. Credentials are encrypted at rest.";

  return (
    <Modal
      open={open}
      onClose={pending ? undefined : onClose}
      dismissible={!pending}
      size="lg"
      tone="accent"
      icon={isEdit ? 'server' : 'plus'}
      eyebrow="Discovery"
      title={isEdit ? 'Edit device' : 'Add device'}
      description={description}
      primary={
        <button
          className="ui-btn accent"
          data-testid="device-form-primary"
          disabled={!valid || pending}
          onClick={() => (probing ? probe.mutate() : save.mutate())}
        >
          {primaryLabel}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={pending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      {probeFailure && canProbe && (
        <FailurePanel
          error={probeFailure}
          addByHandHint
          onRetry={managementUrl.trim() && username.trim() && password.trim() ? () => probe.mutate() : undefined}
          retrying={probe.isPending}
        />
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Device type">
          <ModalSelect name="device_type" data-autofocus value={deviceType} onChange={(e) => {
            const next = e.target.value as DeviceType;
            setDeviceType(next);
            // A tick made for a TLS device must not ride along to an SSH one.
            if (isSSHManagedDeviceType(next)) setTlsInsecure(false);
            probe.reset();
          }} disabled={isEdit || pending}>
            {DEVICE_TYPES.map((t) => <option key={t} value={t}>{t === 'other' ? 'Other' : deviceTypeLabel(t) ?? t}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label={isSsh && !isEdit ? 'Management address (SSH)' : 'Management URL'}>
          <ModalInput name="management_url" value={managementUrl} onChange={(e) => setManagementUrl(e.target.value)} placeholder={isSsh ? '10.0.0.1 or ssh://10.0.0.1:22' : 'https://10.0.0.1'} disabled={probe.isPending} />
        </ModalField>
        <ModalField label="Username"><ModalInput name="username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoComplete="off" disabled={probe.isPending} /></ModalField>
        <ModalField label={isEdit ? 'Password (leave blank to keep)' : 'Password'}>
          <ModalInput name="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="new-password" disabled={probe.isPending} />
        </ModalField>
        {showAllFields && (
          <>
            <ModalField label="Hostname">
              <ModalInput name="hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="edge-fw-01" aria-invalid={!hostnameValid} />
              {!hostnameValid && <span role="alert" style={{ color: 'var(--danger-text)', fontSize: 12 }}>Use a DNS hostname without spaces (for example, edge-fw-01).</span>}
            </ModalField>
            <ModalField label="IP address"><ModalInput name="ip_address" value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="10.0.0.1" /></ModalField>
            <ModalField label="Vendor"><ModalInput name="vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="F5" /></ModalField>
            <ModalField label="Model"><ModalInput name="model" value={model} onChange={(e) => setModel(e.target.value)} placeholder="BIG-IP" /></ModalField>
            <ModalField label="Serial number"><ModalInput name="serial_number" value={serialNumber} onChange={(e) => setSerialNumber(e.target.value)} placeholder="optional" /></ModalField>
            <ModalField label="Firmware version"><ModalInput name="firmware_version" value={firmwareVersion} onChange={(e) => setFirmwareVersion(e.target.value)} placeholder="optional" /></ModalField>
          </>
        )}
      </div>
      {/* For an SSH device the same flag would skip SSH host-key checking, which
          is not what this label says — so it is never offered for one, when
          adding or when editing (#1492 review B1/NB-7). */}
      {!isSsh && (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, fontSize: 12.5, color: 'var(--app-t1)', cursor: 'pointer' }}>
          <input name="tls_insecure_skip_verify" type="checkbox" checked={tlsInsecure} onChange={(e) => setTlsInsecure(e.target.checked)} disabled={probe.isPending} />
          Skip TLS verification (self-signed management certs)
        </label>
      )}
      {!isEdit && canProbe && (
        <button
          type="button"
          className="ui-btn sm ghost"
          data-testid="device-form-mode-toggle"
          style={{ marginTop: 6, padding: 0 }}
          disabled={pending}
          onClick={() => { setExpanded(!expanded); probe.reset(); }}
        >
          {expanded ? 'Connect and fill in the details automatically' : 'Enter the details by hand instead'}
        </button>
      )}
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
// The server logs in with the stored credentials and reads the device's
// identity; success carries the measured latency and what it read, failure a
// typed reason (the same vocabulary as Add device).
//
// Nothing runs on open. Each test is a real login, and a device whose stored
// password went stale locks its admin account after a few failures (FortiOS
// does) — so a test is always a click, and the server refuses a second one for
// the same device within ten seconds ( review NB-8).
export function TestConnectionModal({ open, device, onClose }: {
  open: boolean;
  device: Device | null;
  onClose: () => void;
}) {
  const test = useMutation({
    mutationFn: async () => {
      if (!device) throw new Error('No device');
      const { data, error } = await clients.devices.POST('/devices/{id}/test-connection', { params: { path: { id: device.id } } });
      if (error || !data) throw probeError(error, 'Connection test failed.');
      return data;
    },
  });

  // A reopened modal starts idle, not showing the last device's result.
  useEffect(() => {
    if (open) test.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, device?.id]);

  const label = device?.hostname || device?.management_url || device?.ip_address || 'device';
  const result = test.data;
  const failure = test.error instanceof DeviceProbeError ? test.error : null;
  const identity = result
    ? [result.identity.vendor, result.identity.model, result.identity.serial_number && `serial ${result.identity.serial_number}`, result.identity.firmware_version]
      .filter(Boolean).join(' · ')
    : '';
  const ran = test.isSuccess || test.isError;

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="sm"
      tone={test.isSuccess ? 'green' : test.isError ? 'danger' : 'blue'}
      icon="plug"
      eyebrow="Discovery"
      title={`Test connection · ${label}`}
      primary={
        <button className="ui-btn accent" data-testid="test-connection-run" onClick={() => test.mutate()} disabled={test.isPending || !device}>
          {test.isPending ? 'Testing…' : ran ? 'Test again' : 'Test'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose}>Close</button>}
    >
      <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--app-t2)' }}>
        {test.isIdle && (
          <span data-testid="test-connection-idle" style={{ color: 'var(--app-t3)' }}>
            Logs in to {label} with its stored credentials and reads what the device is. A wrong stored password counts as a failed login on the device.
          </span>
        )}
        {test.isPending && <span style={{ color: 'var(--app-t3)' }}>Logging in to {label}…</span>}
        {result && (
          <div data-testid="test-connection-success">
            <div style={{ color: 'var(--ok)' }}>Connected and identified the device in {result.latency_ms} ms.</div>
            {identity && <div style={{ color: 'var(--app-t3)' }}>{identity}</div>}
          </div>
        )}
        {test.isError && (failure
          ? <FailurePanel error={failure} />
          : <span style={{ color: 'var(--danger-text)' }}>{test.error.message}</span>)}
      </div>
    </Modal>
  );
}
