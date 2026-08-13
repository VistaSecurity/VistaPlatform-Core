// Sensor write surface for Discovery → Sensors & Agents. Restores the
// register / delete / pending-registration actions the rebuild dropped (old
// web-ui had these in sensors-agents-tab.tsx + sensor-registration-page.tsx).
// Wired through the typed sensor-manager client:
//   POST   /sensors/pending          (register → returns install command)
//   DELETE /sensors/{sensor_id}      (soft-delete a registered sensor)
//   GET    /sensors/pending          (pending registrations list)
//   DELETE /sensors/pending/{key}    (drop a pending registration)
// Composes the shared Modal primitive. queries.ts is shared/off-limits, so the
// pending-registrations query lives here as a local hook.
import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { copyToClipboard } from '../../lib/clipboard';
import { Icon, Modal, ModalField, ModalInput } from '../../components/ui';

// Registration doesn't ask the operator to list NICs — the sensor is configured
// on its own host post-install. It does ask which *kind* of agent (sensor vs
// device interrogation agent); that choice maps to the service-required profile
// via PROFILE_BY_KIND below.

// Loose IPv4/IPv6 sanity check — the service does the authoritative validation;
// this just keeps obviously-bad input from round-tripping.
function looksLikeIp(s: string): boolean {
  const v = s.trim();
  if (!v) return false;
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const m = ipv4.exec(v);
  if (m) return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
  return v.includes(':') && /^[0-9a-fA-F:]+$/.test(v); // permissive IPv6
}

function splitList(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

// ---- Pending registrations: local query (queries.ts is off-limits) --------
export function usePendingSensors() {
  return useQuery({
    queryKey: ['discovery', 'pending-sensors'],
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/sensors/pending', {});
      if (error || !data) throw new Error('Failed to load pending registrations');
      return data.pending_sensors ?? [];
    },
  });
}

// ---- Live registration status: poll until the sensor checks in ------------
// There is no DB link from a registration key to the sensor row it eventually
// creates (the agent proposes its own id at register time), so we correlate the
// two existing tenant endpoints:
//   - key still in GET /sensors/pending  → agent hasn't consumed it yet
//   - key gone + a sensor matches name+ip → registered; last_heartbeat → data flowing
type RegStatusState = 'waiting' | 'registered' | 'connected' | 'expired';

function useRegistrationStatus(
  args: { open: boolean; key: string; name: string; ip: string } | null,
) {
  return useQuery({
    queryKey: ['discovery', 'registration-status', args?.key ?? 'none'],
    enabled: !!args && args.open,
    // Poll every 3s until the sensor is connected (or the code expired).
    refetchInterval: (q) => {
      const s = q.state.data as RegStatusState | undefined;
      return s === 'connected' || s === 'expired' ? false : 3000;
    },
    queryFn: async (): Promise<RegStatusState> => {
      // Still in the pending list? Then the agent hasn't consumed the key yet.
      const pend = await clients.sensors.GET('/sensors/pending', {});
      const rows = (pend.data?.pending_sensors ?? []) as Array<Record<string, unknown>>;
      const mine = rows.find((r) => r['registration_key'] === args!.key);
      if (mine) return mine['status'] === 'expired' ? 'expired' : 'waiting';

      // Key consumed → the sensor exists. Has it reported its first data yet?
      const list = await clients.sensors.GET('/sensors', {});
      const sensors = (list.data?.sensors ?? []) as Array<Record<string, unknown>>;
      const s = sensors.find((x) => x['name'] === args!.name && x['ip_address'] === args!.ip);
      if (s && s['last_heartbeat']) return 'connected';
      return 'registered';
    },
  });
}

function RegistrationStatusBadge({ status }: { status?: RegStatusState }) {
  const map: Record<RegStatusState | 'checking', { dot: string; label: string; pulse: boolean }> = {
    checking:   { dot: 'var(--neutral)', label: 'Checking status…', pulse: true },
    waiting:    { dot: 'var(--warn)', label: 'Not connected — waiting for the sensor to check in…', pulse: true },
    registered: { dot: 'var(--info)', label: 'Registered — waiting for the first data…', pulse: true },
    connected:  { dot: 'var(--ok)', label: 'Connected — receiving data', pulse: false },
    expired:    { dot: 'var(--danger)', label: 'Registration code expired — mint a new one', pulse: false },
  };
  const s = map[status ?? 'checking'];
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', marginBottom: 14 }}>
      <span style={{ width: 9, height: 9, borderRadius: 50, flex: 'none', background: s.dot, animation: s.pulse ? 'vp-reg-pulse 1.4s ease-in-out infinite' : 'none' }} />
      <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>{s.label}</span>
      {status === 'connected' && <Icon name="check" size={13} />}
      <style>{'@keyframes vp-reg-pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.3 } }'}</style>
    </div>
  );
}

// ---- Copy-to-clipboard install-command block ------------------------------
function InstallCommandBlock({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    copyToClipboard(command).then((ok) => {
      if (ok) { setCopied(true); setTimeout(() => setCopied(false), 1600); }
    });
  };
  return (
    <div style={{ position: 'relative' }}>
      <pre
        className="mono"
        style={{ margin: 0, padding: '12px 44px 12px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 160, overflowY: 'auto' }}
      >{command}</pre>
      <button
        className="ui-btn sm ghost"
        onClick={copy}
        title="Copy install command"
        style={{ position: 'absolute', top: 7, right: 7, flex: 'none' }}
      >
        <Icon name={copied ? 'check' : 'download'} size={13} />{copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

// Both install commands are built client-side from window.location.origin so
// they carry the control-plane URL the operator is actually looking at. The
// installer needs `--url` / `-Url` to know where to register — the server-side
// command string omitted it, which left the installer falling back to its
// built-in default. Profile is no longer surfaced (the installer defaults it).
// install-sensor.sh / install-sensor.ps1 ship next to the sensor binary in the
// release package, so the command invokes the local script (`./` / `.\`).
function buildInstallCommands(key: string, ip: string, name: string): { linux: string; windows: string } {
  const origin = window.location.origin;
  return {
    linux: `sudo ./install-sensor.sh --url ${origin} --key ${key} --ip ${ip} --name "${name}"`,
    windows: `.\\install-sensor.ps1 -Url ${origin} -Key ${key} -IP ${ip} -Name "${name}"`,
  };
}

// A registration can be for a passive network *sensor* or a command-driven
// *device interrogation agent*. They share the same pending-key mint
// (POST /sensors/pending) but are different binaries with different enrollment:
//   - sensor        → install-sensor.sh / .ps1  (see buildInstallCommands)
//   - device agent  → the standalone `device-agent` binary, enrolled with a
//                     YAML config against device-interrogation-service.
// Profiles map 1:1: sensor → datacenter_host (full-feature default), device
// agent → device_interrogation (the profile the bootstrap endpoint requires;
// sensor-profile keys are rejected by /agents/register).
type AgentKind = 'sensor' | 'device_agent';
const PROFILE_BY_KIND: Record<AgentKind, string> = {
  sensor: 'datacenter_host',
  device_agent: 'device_interrogation',
};
// Tags the old web-ui stamped on device-agent registrations so the fleet table
// and pending list can tell them apart from sensors.
const DEVICE_AGENT_TAGS = ['device_agent', 'device_interrogation'];

function isDeviceAgentProfile(profile?: string): boolean {
  return profile === 'device_interrogation';
}

// The device agent is a separate binary — not install-sensor.sh. It reads a
// YAML config (platform_url + registration_key), auto-enrolls on first start
// (registration_key set, agent_id empty), saves its client cert, and then polls
// outbound-only. Commands below mirror docsv4 partner/deployment/
// device-agent-deployment.md using verified flags (-register/-config) and
// config keys (platform_url/registration_key/poll_interval). The binary is
// downloaded from the platform's device-agent downloads — described as a step
// rather than a one-liner because that endpoint resolves a tenant-scoped,
// auth'd artifact URL, not a raw file.
function buildDeviceAgentCommands(key: string): { linux: string; windows: string } {
  const origin = window.location.origin;
  return {
    linux: [
      `# 1) Download the device-agent binary for this host (linux/amd64) from the`,
      `#    platform, then make it executable:`,
      `chmod +x device-agent`,
      ``,
      `# 2) Write its config:`,
      `cat > device-agent.yaml <<'EOF'`,
      `platform_url: ${origin}`,
      `registration_key: ${key}`,
      `poll_interval: 30s`,
      `EOF`,
      ``,
      `# 3) Enroll, then run:`,
      `./device-agent -register -config device-agent.yaml`,
      `./device-agent -config device-agent.yaml`,
    ].join('\n'),
    windows: [
      `# 1) Download device-agent.exe for this host (windows/amd64) from the`,
      `#    platform.`,
      ``,
      `# 2) Write its config:`,
      `@"`,
      `platform_url: ${origin}`,
      `registration_key: ${key}`,
      `poll_interval: 30s`,
      `"@ | Out-File -FilePath device-agent.yaml -Encoding utf8`,
      ``,
      `# 3) Enroll, then run:`,
      `.\\device-agent.exe -register -config device-agent.yaml`,
      `.\\device-agent.exe -config device-agent.yaml`,
    ].join('\n'),
  };
}

// Read-only registration-code field with a dedicated copy-to-clipboard button —
// the operator pastes just the key into their terminal / installer prompt.
function RegistrationCodeField({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    copyToClipboard(code).then((ok) => {
      if (ok) { setCopied(true); setTimeout(() => setCopied(false), 1600); }
    });
  };
  return (
    <div style={{ display: 'flex', gap: 8 }}>
      <input
        readOnly
        value={code}
        onFocus={(e) => e.currentTarget.select()}
        className="mono"
        style={{ flex: 1, minWidth: 0, height: 38, padding: '0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }}
      />
      <button className="ui-btn" onClick={copy} style={{ flex: 'none', whiteSpace: 'nowrap' }}>
        <Icon name={copied ? 'check' : 'download'} size={13} />{copied ? 'Copied' : 'Copy registration code'}
      </button>
    </div>
  );
}

// ---- Platform CA fingerprint: the operator's second channel ---------------
// An agent enrolling against a privately-signed platform is asked to approve
// the CA it is shown. Anything able to intercept that enrollment could present
// its own CA, so approving without comparing is theater. This panel is the
// other channel: read here, in an authenticated browser session, and compared
// against what the agent prints. Nothing to show when the platform's cert is
// publicly trusted — agents never prompt in that case.
function usePlatformCA(enabled: boolean) {
  return useQuery({
    queryKey: ['discovery', 'platform-ca'],
    enabled,
    // The edge certificate changes only on renewal; the service caches this too.
    staleTime: 5 * 60_000,
    queryFn: async () => {
      const { data, error } = await clients.sensors.GET('/platform-ca', {});
      if (error || !data) throw new Error('Failed to read platform certificate');
      return data;
    },
  });
}

// What the panel should do, as a pure decision — the branch that matters is
// "show nothing" vs "show a fingerprint", and getting it wrong in either
// direction is a real defect: a missing panel silently removes the operator's
// only way to verify, and a spurious one implies an approval step that does not
// exist. Exported for test; see sensor-modals.platform-ca.test.ts.
export type PlatformCADisplay =
  | { kind: 'hidden' }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'fingerprint' };

export function platformCADisplay(args: {
  isPending: boolean;
  isError: boolean;
  data?: { available?: boolean; trusted_by_default?: boolean; reason?: string; fingerprint_sha256?: string } | null;
}): PlatformCADisplay {
  const { isPending, isError, data } = args;
  // Nothing to compare: still loading, the lookup failed, or the platform's
  // certificate is publicly trusted so no agent will ever prompt.
  if (isPending || isError || !data) return { kind: 'hidden' };
  if (data.trusted_by_default) return { kind: 'hidden' };
  if (!data.available || !data.fingerprint_sha256) {
    return {
      kind: 'unavailable',
      reason: data.reason ?? 'Could not read this platform’s certificate.',
    };
  }
  return { kind: 'fingerprint' };
}

function PlatformCAPanel() {
  const { data, isPending, isError } = usePlatformCA(true);
  const [copied, setCopied] = useState(false);
  const decision = platformCADisplay({ isPending, isError, data });

  if (decision.kind === 'hidden' || !data) return null;

  if (decision.kind === 'unavailable') {
    return (
      <ModalField label="Platform CA fingerprint">
        <div style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.55 }}>
          {decision.reason}
          {' '}Read it on the platform host instead:{' '}
          <code className="mono" style={{ fontSize: 11 }}>
            openssl s_client -connect &lt;host&gt;:443 &lt;/dev/null | openssl x509 -noout -fingerprint -sha256
          </code>
        </div>
      </ModalField>
    );
  }

  const copy = () => {
    copyToClipboard(data.fingerprint_sha256 ?? '').then((ok) => {
      if (ok) { setCopied(true); setTimeout(() => setCopied(false), 1600); }
    });
  };

  return (
    <ModalField
      label="Platform CA fingerprint"
      hint="The agent will show this during install and ask you to approve it. Compare the two before accepting."
    >
      <div
        style={{
          border: '1px solid var(--app-border2)', borderRadius: 9,
          background: 'var(--app-panel2)', padding: '10px 12px',
          display: 'flex', flexDirection: 'column', gap: 7,
        }}
      >
        <div className="mono" style={{ fontSize: 12, lineHeight: 1.5, wordBreak: 'break-all', color: 'var(--app-t1)' }}>
          {data.fingerprint_display}
        </div>
        <div style={{ fontSize: 11, color: 'var(--app-t2)', lineHeight: 1.5 }}>
          {data.subject}
          {data.self_signed === false && ' — intermediate CA (this platform does not present its root)'}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="ui-btn" onClick={copy} style={{ flex: 'none', whiteSpace: 'nowrap' }}>
            <Icon name={copied ? 'check' : 'download'} size={13} />{copied ? 'Copied' : 'Copy fingerprint'}
          </button>
        </div>
        <div style={{ fontSize: 11, color: 'var(--app-t2)', lineHeight: 1.5 }}>
          If the agent shows a different fingerprint, stop — do not approve it.
          For unattended installs, pass it as{' '}
          <code className="mono" style={{ fontSize: 11 }}>--ca-fingerprint</code>.
        </div>
      </div>
    </ModalField>
  );
}

// ---- A) Register sensor or device interrogation agent ---------------------
// One button, two agent kinds — restores the old web-ui's unified registration
// dialog. The kind picker drives the profile (datacenter_host vs
// device_interrogation), the copy, and which install instructions the success
// screen shows. Both kinds mint the same pending key via POST /sensors/pending.
export function RegisterSensorModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<AgentKind>('sensor');
  const [name, setName] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [tags, setTags] = useState('');
  const [description, setDescription] = useState('');
  const [result, setResult] = useState<{ kind: AgentKind; key: string; name: string; ip: string; linux: string; windows: string } | null>(null);

  // Reset on (re)open so a closed-then-reopened modal is fresh.
  useEffect(() => {
    if (!open) return;
    setKind('sensor'); setName(''); setIpAddress(''); setTags(''); setDescription(''); setResult(null);
  }, [open]);

  const isDevice = kind === 'device_agent';
  const ipValid = looksLikeIp(ipAddress);
  const valid = !!name.trim() && ipValid;

  const register = useMutation({
    mutationFn: async () => {
      const tagList = splitList(tags);
      // Stamp the device-agent tags so the fleet/pending lists can distinguish
      // the kind; de-dupe against any the operator typed.
      const mergedTags = isDevice ? [...new Set([...DEVICE_AGENT_TAGS, ...tagList])] : tagList;
      const { data, error } = await clients.sensors.POST('/sensors/pending', {
        body: {
          name: name.trim(),
          ip_address: ipAddress.trim(),
          profile: PROFILE_BY_KIND[kind],
          tags: mergedTags.length ? mergedTags : undefined,
          description: description.trim() || undefined,
        },
      });
      if (error || !data) throw new Error(`Failed to register ${isDevice ? 'device agent' : 'sensor'}`);
      const ps = data.pending_sensor;
      const cmds = isDevice
        ? buildDeviceAgentCommands(ps.registration_key)
        : buildInstallCommands(ps.registration_key, ps.ip_address, ps.name);
      return { kind, key: ps.registration_key, name: ps.name, ip: ps.ip_address, linux: cmds.linux, windows: cmds.windows };
    },
    onSuccess: (r) => {
      setResult(r);
      qc.invalidateQueries({ queryKey: ['discovery', 'sensors'] });
      qc.invalidateQueries({ queryKey: ['discovery', 'pending-sensors'] });
    },
  });

  // Live connection status — drives the badge on the success screen. Polls only
  // while the success screen is open; stops once the sensor is connected. This
  // correlation is sensor-specific (matches a row in GET /sensors), so it's
  // skipped for device agents, which enroll via device-interrogation-service.
  const regStatus = useRegistrationStatus(
    result && result.kind === 'sensor' ? { open, key: result.key, name: result.name, ip: result.ip } : null,
  );

  // Success state — hand the operator the registration code + install commands.
  if (result != null) {
    const deviceResult = result.kind === 'device_agent';
    return (
      <Modal
        open={open}
        onClose={onClose}
        size="lg"
        tone="green"
        icon="check"
        eyebrow="Sensors & Agents"
        title={deviceResult ? 'Device agent registered' : 'Sensor registered'}
        description={deviceResult
          ? 'Enroll the device interrogation agent on its host using the registration code below. The code expires — enroll soon. Once enrolled, the agent connects outbound and begins polling for interrogation jobs.'
          : 'Install the sensor on its host using the registration code below. The code expires — install soon. This window updates live as the sensor connects.'}
        primary={<button className="ui-btn accent" onClick={onClose}>Done</button>}
      >
        {!deviceResult && <RegistrationStatusBadge status={regStatus.data} />}
        <ModalField label="Registration code" hint={deviceResult ? 'Paste this into the agent config (registration_key).' : 'Paste this into the installer prompt or pass it to the install script.'}>
          <RegistrationCodeField code={result.key} />
        </ModalField>
        <ModalField label={deviceResult ? 'Enrollment steps — Linux / macOS' : 'Installation command — Linux'} hint="Run on the target host (bash).">
          <InstallCommandBlock command={result.linux} />
        </ModalField>
        <ModalField label={deviceResult ? 'Enrollment steps — Windows' : 'Installation command — Windows'} hint="Run on the target host (PowerShell).">
          <InstallCommandBlock command={result.windows} />
        </ModalField>
        <PlatformCAPanel />
      </Modal>
    );
  }

  const footerErr = register.isError
    ? (register.error as Error).message
    : ipAddress.trim() && !ipValid ? 'Enter a valid IP address' : null;

  return (
    <Modal
      open={open}
      onClose={register.isPending ? undefined : onClose}
      dismissible={!register.isPending}
      size="lg"
      tone="accent"
      icon="plus"
      eyebrow="Sensors & Agents"
      title="Register sensor or agent"
      description="Mint a registration code for a new sensor or device interrogation agent. Name and IP address are required."
      primary={
        <button className="ui-btn accent" disabled={!valid || register.isPending} onClick={() => register.mutate()}>
          {register.isPending ? 'Registering…' : isDevice ? 'Register agent' : 'Register sensor'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={register.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <ModalField label="Registration type">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <KindOption
            active={kind === 'sensor'}
            onClick={() => setKind('sensor')}
            icon="activity"
            title="Network sensor"
            blurb="Passive / PCAP capture sensor."
          />
          <KindOption
            active={kind === 'device_agent'}
            onClick={() => setKind('device_agent')}
            icon="terminal"
            title="Device interrogation agent"
            blurb="Command-driven agent (SSH/SNMP/API) for F5, Palo Alto, Cisco, Fortinet…"
          />
        </div>
      </ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label={isDevice ? 'Agent label' : 'Name'}>
          <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder={isDevice ? 'win-adc-01-agent' : 'sensor-dc01'} />
        </ModalField>
        <ModalField label="IP address" hint={isDevice ? "The agent host's IPv4 address." : undefined}>
          <ModalInput value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="10.0.0.1" />
        </ModalField>
      </div>
      <ModalField label="Tags" hint="Optional. Comma-separated.">
        <ModalInput value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, datacenter-east" />
      </ModalField>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Short description" /></ModalField>
    </Modal>
  );
}

// Radio-style card for the registration-type picker.
function KindOption({ active, onClick, icon, title, blurb }: {
  active: boolean; onClick: () => void; icon: string; title: string; blurb: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      style={{
        display: 'flex', flexDirection: 'column', gap: 4, textAlign: 'left', cursor: 'pointer',
        padding: '11px 12px', borderRadius: 10,
        border: `1px solid ${active ? 'var(--accent)' : 'var(--app-border2)'}`,
        background: active ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'var(--app-panel2)',
        color: 'var(--app-t1)',
      }}
    >
      <span style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12.5, fontWeight: 600 }}>
        <Icon name={icon} size={13} />{title}
      </span>
      <span style={{ fontSize: 10.5, color: 'var(--app-t3)', lineHeight: 1.35 }}>{blurb}</span>
    </button>
  );
}

// ---- B) Delete a registered sensor ----------------------------------------
export function DeleteSensorModal({ open, sensor, onClose }: {
  open: boolean;
  sensor: { id: string; name: string } | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      if (!sensor) throw new Error('No sensor selected');
      const { error, response } = await clients.sensors.DELETE('/sensors/{sensor_id}', {
        params: { path: { sensor_id: sensor.id } },
      });
      if (!response.ok || error) throw new Error('Failed to delete sensor');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'sensors'] });
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
      icon="x-circle"
      eyebrow="Sensors & Agents"
      title="Delete sensor"
      description={sensor ? `Remove "${sensor.name}"? It will stop appearing in the fleet. This can't be undone here.` : 'Remove this sensor?'}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete sensor'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{(del.error as Error).message}</span> : undefined}
    />
  );
}

// ---- B2) Delete a registered discovery agent ------------------------------
// Separate from DeleteSensorModal because it hits a different service and says
// something different: an agent is a binary the operator installed on a host we
// do not control, so removing the row cannot stop it. The copy says so — the
// platform fails the agent's calls closed either way, but an operator who thinks
// "deleted" means "uninstalled" will leave a process running and polling.
export function DeleteAgentModal({ open, agent, onClose }: {
  open: boolean;
  agent: { id: string; name: string } | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      if (!agent) throw new Error('No agent selected');
      const { error, response } = await clients.devices.DELETE('/agents/{id}', {
        params: { path: { id: agent.id } },
      });
      if (!response.ok || error) throw new Error('Failed to delete agent');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'device-agents'] });
      // Deleting an agent re-queues its pending jobs and fails its in-progress
      // ones, so any job view on screen is now stale.
      qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
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
      icon="x-circle"
      eyebrow="Sensors & Agents"
      title="Delete discovery agent"
      description={agent
        ? `Remove "${agent.name}"? Its certificate is revoked and it can no longer claim work — queued jobs return to the pool and any job it was running is marked failed. This does not uninstall the agent: stop and remove the binary on its host separately.`
        : 'Remove this agent?'}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete agent'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{(del.error as Error).message}</span> : undefined}
    />
  );
}

// ---- C) Delete a pending registration -------------------------------------
function DeletePendingModal({ open, pending, onClose }: {
  open: boolean;
  pending: { registration_key: string; name: string } | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      if (!pending) throw new Error('No registration selected');
      const { error, response } = await clients.sensors.DELETE('/sensors/pending/{key}', {
        params: { path: { key: pending.registration_key } },
      });
      if (!response.ok || error) throw new Error('Failed to delete registration');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'pending-sensors'] });
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
      icon="x-circle"
      eyebrow="Pending registration"
      title="Delete registration"
      description={pending ? `Drop the pending registration for "${pending.name}"? Its install command will stop working.` : 'Drop this registration?'}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Deleting…' : 'Delete'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{(del.error as Error).message}</span> : undefined}
    />
  );
}

// Reveal a pending registration's install/enrollment commands in a read-only
// modal. Copy adapts to the agent kind (sensor install vs device-agent enroll).
function ShowPendingCommandModal({ open, pending, onClose }: {
  open: boolean;
  pending: { name: string; linux: string; windows: string; isDevice: boolean } | null;
  onClose: () => void;
}) {
  const device = !!pending?.isDevice;
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      tone="blue"
      icon="terminal"
      eyebrow="Pending registration"
      title={pending ? `${device ? 'Enrollment steps' : 'Install command'} — ${pending.name}` : 'Install command'}
      description={device
        ? 'Run this on the agent host to enroll and connect the device interrogation agent.'
        : 'Run this on the sensor host to install and connect it.'}
      primary={<button className="ui-btn accent" onClick={onClose}>Done</button>}
    >
      {pending && (
        <>
          <ModalField label={device ? 'Enrollment steps — Linux / macOS' : 'Installation command — Linux'} hint="Run on the target host (bash).">
            <InstallCommandBlock command={pending.linux} />
          </ModalField>
          <ModalField label={device ? 'Enrollment steps — Windows' : 'Installation command — Windows'} hint="Run on the target host (PowerShell).">
            <InstallCommandBlock command={pending.windows} />
          </ModalField>
          {/* Same panel as the register modal. This is the dialog an operator
              opens when they come back later, or when the person running the
              install is not the person who generated the code — exactly the
              case where they have no other reference value to compare the
              agent's trust prompt against. Omitting it here would leave the
              prompt to be approved blind, which is the hole it exists to
              close. */}
          <PlatformCAPanel />
        </>
      )}
    </Modal>
  );
}

// ---- Pending registrations subsection (rendered below the main table) -----
// Install commands are rebuilt client-side from the row's key/ip/name (see
// buildInstallCommands) so they carry the live control-plane URL and match the
// register modal — rather than trusting the server's legacy command string.
export function PendingRegistrationsSection() {
  const q = usePendingSensors();
  const pending = q.data ?? [];
  const [toDelete, setToDelete] = useState<{ registration_key: string; name: string } | null>(null);
  const [toShow, setToShow] = useState<{ name: string; linux: string; windows: string; isDevice: boolean } | null>(null);

  if (q.isLoading || q.isError || pending.length === 0) return null; // quiet when empty

  return (
    <div style={{ marginTop: 26 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--app-t1)' }}>Pending registrations</h3>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{pending.length}</span>
      </div>
      <div className="panel" style={{ borderRadius: 14, overflow: 'hidden' }}>
        {pending.map((p, i) => {
          const isDevice = isDeviceAgentProfile(p.profile);
          const cmds = isDevice
            ? buildDeviceAgentCommands(p.registration_key)
            : buildInstallCommands(p.registration_key, p.ip_address, p.name);
          return (
            <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderBottom: i < pending.length - 1 ? '1px solid var(--app-border)' : 'none' }}>
              <span style={{ width: 8, height: 8, borderRadius: 50, flex: 'none', background: 'var(--warn)' }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.name}</div>
                <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {[p.ip_address, p.profile, `key ${p.registration_key}`].filter(Boolean).join(' · ')}
                </div>
              </div>
              <button className="ui-btn sm ghost" title={isDevice ? 'Show enrollment steps' : 'Show install command'} onClick={() => setToShow({ name: p.name, linux: cmds.linux, windows: cmds.windows, isDevice })}>
                <Icon name="terminal" size={13} />{isDevice ? 'Enroll' : 'Command'}
              </button>
              <PermissionGate permission={TENANT_PERMISSIONS.sensors.delete}>
                <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)', flex: 'none' }} title="Delete registration" onClick={() => setToDelete({ registration_key: p.registration_key, name: p.name })}>
                  <Icon name="x" size={13} />
                </button>
              </PermissionGate>
            </div>
          );
        })}
      </div>

      <ShowPendingCommandModal open={!!toShow} pending={toShow} onClose={() => setToShow(null)} />
      <DeletePendingModal open={!!toDelete} pending={toDelete} onClose={() => setToDelete(null)} />
    </div>
  );
}
