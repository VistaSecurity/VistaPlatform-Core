// Notification editing modals — delivery channels (create / edit / delete /
// test) and alert-routing rules (create / edit / delete). Channel config
// fields follow the delivery service's per-type expectations: email →
// recipients[], slack → webhook_url, webhook → url, pagerduty →
// integration_key. Unknown config keys are carried through on edit.
//
// Credentials never come back from the API — the server masks them (a URL is
// reduced to scheme + host, a key to its last four characters). So editing a
// channel never prefills the secret: the field starts blank with the masked
// form as a placeholder, and blank means "keep the current value". The server
// treats an omitted / blank / still-masked credential as unchanged.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { alertSourceOptions, fetchAlertCatalogSources } from './alert-sources';
import {
  WEBHOOK_AUTH_MODES, applyWebhookOptions, generateSigningSecret, initialWebhookOptions, storedHeaderCount,
  webhookModeOf, webhookOptionsError, type WebhookAuthMode, type WebhookOptions,
} from './webhook-options';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';

type Channel = NC['schemas']['TenantNotificationChannel'];
type Rule = NC['schemas']['TenantNotificationRule'];

function legacyMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error) return String(error.error);
  return fallback;
}

type ChannelTypeDef = { value: string; label: string; configKey: 'recipients' | 'webhook_url' | 'url' | 'integration_key'; configLabel: string; hint: string; csv?: boolean };

/** Email recipients are addresses, not secrets; every other field is a credential. */
export function isSecretChannelField(typeDef: Pick<ChannelTypeDef, 'configKey'>): boolean {
  return typeDef.configKey !== 'recipients';
}

/**
 * The config to PUT/POST. On edit, a blank credential field is left OUT of the
 * body so the server keeps the stored value; carried-through keys (headers,
 * auth) stay in their masked form, which the server also treats as unchanged.
 */
export function buildChannelConfig(
  existing: Record<string, unknown> | null | undefined,
  typeDef: ChannelTypeDef,
  value: string,
  isEdit: boolean,
): Record<string, unknown> {
  const config: Record<string, unknown> = { ...(existing ?? {}) };
  if (isEdit && isSecretChannelField(typeDef) && !value.trim()) {
    delete config[typeDef.configKey];
    return config;
  }
  config[typeDef.configKey] = typeDef.csv
    ? value.split(',').map((s) => s.trim()).filter(Boolean)
    : value.trim();
  return config;
}

const CHANNEL_TYPES: ChannelTypeDef[] = [
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
  const secretField = isSecretChannelField(typeDef);
  const initialCfg = channel?.config?.[typeDef.configKey];
  // A credential arrives masked and is never prefilled: the masked form is only
  // shown as a placeholder so the user can tell which connection this is.
  const maskedCurrent = isEdit && secretField && typeof initialCfg === 'string' ? initialCfg : '';
  const [configValue, setConfigValue] = useState(
    Array.isArray(initialCfg) ? initialCfg.join(', ') : typeof initialCfg === 'string' && !secretField ? initialCfg : '',
  );
  const keepsCurrent = isEdit && secretField;

  // Generic-webhook only: how Vista authenticates to the receiver, and the HMAC
  // signing secret. See webhook-options.ts.
  const isWebhook = type === 'webhook';
  const [webhook, setWebhook] = useState<WebhookOptions>(() => initialWebhookOptions(channel?.config));
  const setWebhookField = <K extends keyof WebhookOptions>(k: K, v: WebhookOptions[K]) => setWebhook((p) => ({ ...p, [k]: v }));
  const webhookError = isWebhook ? webhookOptionsError(webhook, channel?.config, isEdit) : null;
  // The signing secret the server generated for a new webhook — shown once.
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async (): Promise<string | null> => {
      // carry through config keys the form doesn't expose
      let config = buildChannelConfig(channel?.config, typeDef, configValue, isEdit);
      if (isWebhook) config = applyWebhookOptions(config, webhook);
      if (isEdit) {
        const { error, response } = await clients.notifications.PUT('/tenant/channels/{id}', {
          params: { path: { id: channel.id } },
          body: { channel_name: name.trim(), config, description: description.trim() || undefined },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to update the channel'));
        return null;
      }
      const { data, error, response } = await clients.notifications.POST('/tenant/channels', {
        body: { channel_name: name.trim(), channel_type: type, config, enabled: true, description: description.trim() || undefined },
      });
      if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to create the channel'));
      return data?.signing_secret ?? null;
    },
    onSuccess: (generatedSecret) => {
      void queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] });
      // A generated signing secret is returned exactly once. Keep the modal open
      // on it rather than closing over the only chance to copy it.
      if (generatedSecret) setCreatedSecret(generatedSecret);
      else onClose();
    },
  });

  if (createdSecret) {
    return <SigningSecretModal secret={createdSecret} open={open} onClose={onClose} />;
  }

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
        <button className="ui-btn sm accent" disabled={!name.trim() || (!configValue.trim() && !keepsCurrent) || webhookError !== null || mutation.isPending} onClick={() => mutation.mutate()}>
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
      <ModalField label={typeDef.configLabel} hint={keepsCurrent ? `${typeDef.hint} Leave blank to keep the current value.` : typeDef.hint}>
        <ModalInput
          value={configValue}
          className="mono"
          placeholder={keepsCurrent && maskedCurrent ? `${maskedCurrent} (unchanged)` : undefined}
          autoComplete="off"
          onChange={(e) => setConfigValue(e.target.value)}
        />
      </ModalField>
      {isWebhook && (
        <WebhookFields
          value={webhook}
          onChange={setWebhookField}
          existing={channel?.config}
          isEdit={isEdit}
          error={webhookError}
        />
      )}
      <ModalField label="Description" hint="Optional — shown on the connection card.">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. SOC rotation" />
      </ModalField>
    </Modal>
  );
}

/** Authentication + signing fields of a generic webhook connection. */
function WebhookFields({ value, onChange, existing, isEdit, error }: {
  value: WebhookOptions;
  onChange: <K extends keyof WebhookOptions>(k: K, v: WebhookOptions[K]) => void;
  existing: Record<string, unknown> | null | undefined;
  isEdit: boolean;
  error: string | null;
}) {
  const sameMode = isEdit && webhookModeOf(existing) === value.mode;
  const keep = (label: string) => (sameMode ? `${label} Leave blank to keep the current value.`.trim() : label);
  const maskedAuth = (key: 'token' | 'username' | 'password'): string | undefined => {
    const auth = existing?.auth;
    const v = auth && typeof auth === 'object' ? (auth as Record<string, unknown>)[key] : undefined;
    return sameMode && typeof v === 'string' ? `${v} (unchanged)` : undefined;
  };
  const extraHeaders = storedHeaderCount(existing) > 1;
  const hasSecret = isEdit && typeof existing?.webhook_secret === 'string' && existing.webhook_secret !== '';
  return (
    <>
      <ModalField label="Authentication" hint="How the receiver knows the request came from Vista. Credentials are write-only.">
        <ModalSelect value={value.mode} onChange={(e) => onChange('mode', e.target.value as WebhookAuthMode)}>
          {WEBHOOK_AUTH_MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
        </ModalSelect>
      </ModalField>
      {value.mode === 'bearer' && (
        <ModalField label="Bearer token" hint={keep('Sent as "Authorization: Bearer …".')}>
          <ModalInput value={value.token} className="mono" autoComplete="off" placeholder={maskedAuth('token')} onChange={(e) => onChange('token', e.target.value)} />
        </ModalField>
      )}
      {value.mode === 'basic' && (
        <>
          <ModalField label="Username" hint={keep('HTTP basic authentication.')}>
            <ModalInput value={value.username} className="mono" autoComplete="off" placeholder={maskedAuth('username')} onChange={(e) => onChange('username', e.target.value)} />
          </ModalField>
          <ModalField label="Password" hint={keep('')}>
            <ModalInput value={value.password} type="password" className="mono" autoComplete="new-password" placeholder={maskedAuth('password')} onChange={(e) => onChange('password', e.target.value)} />
          </ModalField>
        </>
      )}
      {value.mode === 'header' && (
        <>
          <ModalField label="Header name" hint="e.g. X-Api-Key">
            <ModalInput value={value.headerName} className="mono" autoComplete="off" onChange={(e) => onChange('headerName', e.target.value)} />
          </ModalField>
          <ModalField label="Header value" hint={keep(extraHeaders ? 'Saving replaces this connection\'s other custom headers with this one.' : '')}>
            <ModalInput value={value.headerValue} className="mono" autoComplete="off" onChange={(e) => onChange('headerValue', e.target.value)} />
          </ModalField>
        </>
      )}
      <ModalField
        label="Signing secret"
        hint={isEdit
          ? `Every delivery carries an HMAC-SHA256 signature (X-Vista-Signature) computed with this secret. ${hasSecret ? 'Leave blank to keep the current secret; enter a new one to rotate it.' : 'This connection has no signing secret yet — enter one to start signing.'}`
          : 'Every delivery carries an HMAC-SHA256 signature (X-Vista-Signature). Leave blank and Vista generates a secret, shown once after you save.'}
      >
        <div style={{ display: 'flex', gap: 6 }}>
          <ModalInput
            value={value.signingSecret}
            className="mono"
            autoComplete="off"
            placeholder={hasSecret ? `${String(existing?.webhook_secret)} (unchanged)` : undefined}
            onChange={(e) => onChange('signingSecret', e.target.value)}
          />
          <button type="button" className="ui-btn sm" onClick={() => onChange('signingSecret', generateSigningSecret())}>Generate</button>
        </div>
      </ModalField>
      {error && <div role="alert" style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>{error}</div>}
    </>
  );
}

/** One-time display of the signing secret the server generated for a new webhook. */
function SigningSecretModal({ secret, open, onClose }: { secret: string; open: boolean; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="lock"
      eyebrow="Integrations"
      title="Save your signing secret"
      description="Vista signs every delivery to this webhook with HMAC-SHA256. This is the only time the secret is shown — copy it into your receiver now. You can rotate it later by entering a new one."
      primary={<button className="ui-btn sm accent" onClick={onClose}>Done</button>}
      secondary={
        <button
          className="ui-btn sm"
          onClick={() => {
            void navigator.clipboard?.writeText(secret).then(() => setCopied(true), () => setCopied(false));
          }}
        >
          {copied ? 'Copied' : 'Copy secret'}
        </button>
      }
    >
      <ModalField label="Signing secret">
        <ModalInput value={secret} readOnly className="mono" data-testid="signing-secret" onFocus={(e) => e.currentTarget.select()} />
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
      void queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] });
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

// B-33: the "Alert source" dropdown below is generated from the alert
// registry rather than hand-maintained — see alert-sources.ts.
function useAlertSources(current: string): string[] {
  const catalogQ = useQuery({
    queryKey: ['settings', 'alert-catalog'],
    queryFn: fetchAlertCatalogSources,
    staleTime: 5 * 60 * 1000,
  });
  return alertSourceOptions(catalogQ.data ?? [], current);
}

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
  const alertSources = useAlertSources(source);
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
      void queryClient.invalidateQueries({ queryKey: ['settings', 'notification-rules'] });
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
          {alertSources.map((s) => <option key={s} value={s}>{s}</option>)}
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
      void queryClient.invalidateQueries({ queryKey: ['settings', 'notification-rules'] });
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
