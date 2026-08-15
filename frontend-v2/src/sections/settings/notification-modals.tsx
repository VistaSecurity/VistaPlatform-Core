// Notification editing modals — delivery channels (create / edit / delete /
// test) and alert-routing rules (create / edit / delete). Channel config
// fields follow the delivery service's per-type expectations: email →
// recipients[], slack → webhook_url, webhook → url, pagerduty →
// integration_key. Unknown config keys are carried through on edit.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';

type Channel = NC['schemas']['TenantNotificationChannel'];
type Rule = NC['schemas']['TenantNotificationRule'];

function legacyMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error) return String((error as { error: unknown }).error);
  return fallback;
}

const CHANNEL_TYPES: Array<{ value: string; label: string; configKey: 'recipients' | 'webhook_url' | 'url' | 'integration_key'; configLabel: string; hint: string; csv?: boolean }> = [
  { value: 'email', label: 'Email', configKey: 'recipients', configLabel: 'Recipients', hint: 'Comma-separated email addresses.', csv: true },
  { value: 'slack', label: 'Slack', configKey: 'webhook_url', configLabel: 'Webhook URL', hint: 'Incoming-webhook URL for the target channel.' },
  { value: 'webhook', label: 'Generic webhook', configKey: 'url', configLabel: 'URL', hint: 'POST endpoint that receives the alert JSON.' },
  { value: 'pagerduty', label: 'PagerDuty', configKey: 'integration_key', configLabel: 'Integration key', hint: 'Events API v2 routing key for the target service.' },
];

export function ChannelModal({ channel, open, onClose }: { channel: Channel | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = !!channel;
  const [name, setName] = useState(channel?.channel_name ?? '');
  const [type, setType] = useState(channel?.channel_type ?? 'email');
  const [description, setDescription] = useState(channel?.description ?? '');
  const typeDef = CHANNEL_TYPES.find((t) => t.value === type) ?? CHANNEL_TYPES[0];
  const initialCfg = channel?.config?.[typeDef.configKey];
  const [configValue, setConfigValue] = useState(
    Array.isArray(initialCfg) ? initialCfg.join(', ') : typeof initialCfg === 'string' ? initialCfg : '',
  );

  const mutation = useMutation({
    mutationFn: async () => {
      // carry through config keys the form doesn't expose
      const config: Record<string, unknown> = { ...(channel?.config ?? {}) };
      config[typeDef.configKey] = typeDef.csv
        ? configValue.split(',').map((s) => s.trim()).filter(Boolean)
        : configValue.trim();
      if (isEdit) {
        const { error, response } = await clients.notifications.PUT('/tenant/channels/{id}', {
          params: { path: { id: channel.id } },
          body: { channel_name: name.trim(), config, description: description.trim() || undefined },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to update the channel'));
      } else {
        const { error, response } = await clients.notifications.POST('/tenant/channels', {
          body: { channel_name: name.trim(), channel_type: type, config, enabled: true, description: description.trim() || undefined },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to create the channel'));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="plug"
      eyebrow="Integrations"
      title={isEdit ? `Configure — ${channel.channel_name}` : 'Add connection'}
      description={isEdit
        ? 'The connection is authenticated once here, then referenced from routing rules.'
        : 'Authenticate a delivery channel once; routing rules then choose what it receives.'}
      primary={
        <button className="ui-btn sm accent" disabled={!name.trim() || !configValue.trim() || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add connection'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Name" hint="Shown in the connection hub and rule pickers.">
        <ModalInput value={name} data-autofocus placeholder="e.g. #crypto-alerts" onChange={(e) => setName(e.target.value)} />
      </ModalField>
      <ModalField label="Type" hint={isEdit ? 'The transport cannot be changed after creation.' : undefined}>
        <ModalSelect
          value={type}
          disabled={isEdit}
          onChange={(e) => { setType(e.target.value); setConfigValue(''); }}
        >
          {CHANNEL_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label={typeDef.configLabel} hint={typeDef.hint}>
        <ModalInput value={configValue} className="mono" onChange={(e) => setConfigValue(e.target.value)} />
      </ModalField>
      <ModalField label="Description" hint="Optional — shown on the connection card.">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. SOC rotation" />
      </ModalField>
    </Modal>
  );
}

export function ChannelDeleteModal({ channel, open, onClose }: { channel: Channel | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      if (!channel) return;
      const { error, response } = await clients.notifications.DELETE('/tenant/channels/{id}', { params: { path: { id: channel.id } } });
      if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to delete the channel'));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] });
      onClose();
    },
  });
  return (
    <Modal
      open={open} onClose={onClose} size="sm" tone="danger" icon="alert-triangle" eyebrow="Integrations"
      title={`Remove — ${channel?.channel_name ?? ''}`}
      description="Routing rules that referenced this connection stop delivering to it."
      primary={<button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Removing…' : 'Remove connection'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    />
  );
}

const ALERT_SOURCES = ['all', 'audit', 'billing', 'certificates', 'discovery', 'monitoring', 'platform', 'remediation_plans', 'ticketing'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// The backend's frequency vocabulary is immediate | digest_hourly |
// digest_daily | digest_weekly — enforced by the tenant_notification_rules
// valid_frequency CHECK and by digestWindowMinutes() in the rule engine. This
// modal used to send the bare string 'digest', which no backend recognizes:
// the INSERT violated the CHECK and every attempt to create a digest rule
// failed with a 500. digest_window stays supported as a per-rule override of
// the named cadence (digestWindowMinutes honors it when > 0).
export const isDigest = (frequency: string) => frequency.startsWith('digest');

export function RuleModal({ rule, channels, open, onClose }: { rule: Rule | null; channels: Channel[]; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = !!rule;
  const [name, setName] = useState(rule?.rule_name ?? '');
  const [source, setSource] = useState(rule?.alert_source ?? 'all');
  const [severities, setSeverities] = useState<string[]>(rule?.severity_filter ?? []);
  const [channelIds, setChannelIds] = useState<string[]>(rule?.channel_ids ?? []);
  const [frequency, setFrequency] = useState(rule?.frequency ?? 'immediate');
  const [digestWindow, setDigestWindow] = useState(String(rule?.digest_window ?? 60));

  const toggle = (arr: string[], v: string) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

  const mutation = useMutation({
    mutationFn: async () => {
      const common = {
        rule_name: name.trim(),
        alert_type: rule?.alert_type,
        channel_ids: channelIds,
        severity_filter: severities.length ? severities : undefined,
        frequency,
        digest_window: isDigest(frequency) ? Math.max(1, parseInt(digestWindow, 10) || 60) : undefined,
      };
      if (isEdit) {
        const { error, response } = await clients.notifications.PUT('/tenant/rules/{id}', {
          params: { path: { id: rule.id } },
          body: common,
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to update the rule'));
      } else {
        const { error, response } = await clients.notifications.POST('/tenant/rules', {
          body: { ...common, alert_source: source, enabled: true },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to create the rule'));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'notification-rules'] });
      onClose();
    },
  });

  const chip = (label: string, active: boolean, onClick: () => void) => (
    <button key={label} onClick={onClick} className="chip" style={{ borderColor: active ? 'var(--accent)' : undefined, color: active ? 'var(--app-t1)' : undefined, background: active ? 'color-mix(in srgb, var(--accent) 10%, transparent)' : undefined }}>
      {label}
    </button>
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="route"
      eyebrow="Notifications & Alerts"
      title={isEdit ? `Edit rule — ${rule.rule_name}` : 'Add routing rule'}
      description="Match events to configured delivery channels. Channels are authenticated once in Integrations."
      primary={
        <button className="ui-btn sm accent" disabled={!name.trim() || channelIds.length === 0 || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add rule'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Rule name">
        <ModalInput value={name} data-autofocus placeholder="e.g. Critical or High finding" onChange={(e) => setName(e.target.value)} />
      </ModalField>
      <ModalField label="Alert source" hint={isEdit ? 'The source cannot be changed after creation.' : 'Which subsystem the events come from.'}>
        <ModalSelect value={source} disabled={isEdit} onChange={(e) => setSource(e.target.value)}>
          {ALERT_SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Severity filter" hint="Match only these severities; none selected = all severities.">
        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
          {SEVERITIES.map((s) => chip(s, severities.includes(s), () => setSeverities(toggle(severities, s))))}
        </div>
      </ModalField>
      <ModalField label="Deliver to" hint={channels.length ? 'Pick at least one connection.' : 'No connections configured yet — add one in Integrations first.'}>
        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
          {channels.map((c) => chip(c.channel_name, channelIds.includes(c.id), () => setChannelIds(toggle(channelIds, c.id))))}
        </div>
      </ModalField>
      <ModalField label="Frequency">
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <ModalSelect value={frequency} style={{ width: 170 }} onChange={(e) => setFrequency(e.target.value)}>
            <option value="immediate">Immediate</option>
            <option value="digest_hourly">Digest — hourly</option>
            <option value="digest_daily">Digest — daily</option>
            <option value="digest_weekly">Digest — weekly</option>
          </ModalSelect>
          {isDigest(frequency) && (
            <>
              <ModalInput value={digestWindow} type="number" min={1} style={{ width: 90 }} onChange={(e) => setDigestWindow(e.target.value)} />
              <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>minutes per batch (overrides the cadence above)</span>
            </>
          )}
        </div>
      </ModalField>
    </Modal>
  );
}

export function RuleDeleteModal({ rule, open, onClose }: { rule: Rule | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      if (!rule) return;
      const { error, response } = await clients.notifications.DELETE('/tenant/rules/{id}', { params: { path: { id: rule.id } } });
      if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to delete the rule'));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'notification-rules'] });
      onClose();
    },
  });
  return (
    <Modal
      open={open} onClose={onClose} size="sm" tone="danger" icon="alert-triangle" eyebrow="Notifications & Alerts"
      title={`Delete rule — ${rule?.rule_name ?? ''}`}
      description="Events matched by this rule stop being delivered. The channels it pointed at are unaffected."
      primary={<button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Deleting…' : 'Delete rule'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    />
  );
}
