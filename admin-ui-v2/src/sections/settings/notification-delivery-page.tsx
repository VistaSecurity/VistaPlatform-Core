// VISTA Operations — Settings ▸ Notification Delivery. ONE page, three vertically
// stacked panels (NOT tab navigation): Channels (CRUD + per-row Test), Rules (CRUD),
// and a read-only Recent deliveries table. All wired to notification-service
// /platform/* via the typed @vistasecurity/api-contract client (clients.notifications).
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Send, Filter, BellRing, Plus, Pencil, Trash2, FlaskConical, AlertTriangle } from 'lucide-react';
import { StatusTag, relTime } from '../../components/ui/primitives';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import {
  usePlatformChannels, useChannelMutations, usePlatformRules, useRuleMutations, usePlatformHistory, errMsg,
  type PlatformChannel, type PlatformRule, type CreateChannelRequest, type UpdateChannelRequest,
  type CreateRuleRequest, type UpdateRuleRequest,
} from './settings-notifications-queries';

/* ============================== Channels ================================= */

interface ChannelForm {
  channel_name: string;
  channel_type: string;
  enabled: boolean;
  description: string;
  config: string; // raw JSON text
}

const CHANNEL_TYPES = ['email', 'slack', 'webhook', 'pagerduty', 'sms'];

const DEFAULT_CHANNEL_FORM: ChannelForm = {
  channel_name: '', channel_type: 'email', enabled: true, description: '', config: '{}',
};

function parseConfig(text: string): { [key: string]: unknown } | null {
  const t = text.trim();
  if (!t) return {};
  try {
    const v = JSON.parse(t);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as { [key: string]: unknown }) : null;
  } catch {
    return null;
  }
}

function ChannelModal({ channel, onClose, mut }: { channel: PlatformChannel | null; onClose: () => void; mut: ReturnType<typeof useChannelMutations> }) {
  const editing = !!channel;
  const [form, setForm] = useState<ChannelForm>(() => channel ? {
    channel_name: channel.channel_name,
    channel_type: channel.channel_type,
    enabled: channel.enabled,
    description: channel.description ?? '',
    config: JSON.stringify(channel.config ?? {}, null, 2),
  } : DEFAULT_CHANNEL_FORM);
  const set = <K extends keyof ChannelForm>(k: K, v: ChannelForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const cfg = parseConfig(form.config);
  const invalid = !form.channel_name.trim() || cfg === null;

  const save = () => {
    if (cfg === null) return;
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Channel updated' : 'Channel created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    if (editing) {
      const body: UpdateChannelRequest = {
        channel_name: form.channel_name.trim(),
        config: cfg,
        enabled: form.enabled,
        description: form.description.trim(),
      };
      mut.update.mutate({ id: channel!.id, body }, opts);
    } else {
      const body: CreateChannelRequest = {
        channel_name: form.channel_name.trim(),
        channel_type: form.channel_type,
        config: cfg,
        enabled: form.enabled,
        description: form.description.trim(),
      };
      mut.create.mutate(body, opts);
    }
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit channel — ${channel!.channel_name}` : 'New notification channel'}
      size="lg"
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Name"><input value={form.channel_name} onChange={(e) => set('channel_name', e.target.value)} placeholder="e.g. Ops Slack" style={modalInputStyle} /></ModalField>
        <ModalField label="Type">
          <select value={form.channel_type} onChange={(e) => set('channel_type', e.target.value)} disabled={editing} style={modalInputStyle}>
            {CHANNEL_TYPES.map((o) => <option key={o} value={o}>{o}</option>)}
            {editing && !CHANNEL_TYPES.includes(form.channel_type) && <option value={form.channel_type}>{form.channel_type}</option>}
          </select>
        </ModalField>
      </div>
      <ModalField label="Description (optional)"><input value={form.description} onChange={(e) => set('description', e.target.value)} placeholder="What this channel is for" style={modalInputStyle} /></ModalField>
      <ModalField label="Config (JSON)">
        <textarea
          value={form.config}
          onChange={(e) => set('config', e.target.value)}
          placeholder='{ "webhook_url": "https://…" }'
          rows={5}
          style={{ ...modalInputStyle, height: 'auto', padding: '8px 11px', resize: 'vertical', fontFamily: 'var(--font-mono, monospace)', borderColor: cfg === null ? 'var(--danger)' : 'var(--op-border2)' }}
        />
      </ModalField>
      {cfg === null && <div style={{ fontSize: 11.5, color: 'var(--danger)' }}>Config must be a valid JSON object.</div>}
      <ModalField label="Status">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />Enabled
        </label>
      </ModalField>
    </Modal>
  );
}

type ChannelModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; channel: PlatformChannel };

function ChannelsPanel() {
  const { data, isLoading, isError, refetch } = usePlatformChannels();
  const mut = useChannelMutations();
  const [modal, setModal] = useState<ChannelModalState>({ kind: 'closed' });
  const list = data ?? [];

  const remove = (c: PlatformChannel) => {
    if (!window.confirm(`Delete channel "${c.channel_name}"?`)) return;
    mut.remove.mutate(c.id, { onSuccess: () => toast.success('Channel deleted'), onError: (e) => toast.error(errMsg(e)) });
  };
  const test = (c: PlatformChannel) => {
    mut.test.mutate(c.id, { onSuccess: () => toast.success('Test dispatched'), onError: (e) => toast.error(errMsg(e, 'Test failed')) });
  };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
        <Send size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Notification channels</span>
        <div style={{ flex: 1 }} />
        <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />New channel</button>
      </div>
      <table className="op-table">
        <thead><tr><th>Channel</th><th>Type</th><th>Last test</th><th>Last used</th><th>Enabled</th><th /></tr></thead>
        <tbody>
          {list.map((c) => (
            <tr key={c.id}>
              <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{c.channel_name}</td>
              <td className="t-muted">{c.channel_type}</td>
              <td className="t-muted">{c.test_status ? <StatusTag status={c.test_status === 'success' ? 'active' : c.test_status} /> : '—'}</td>
              <td className="t-muted mono" style={{ fontSize: 11 }}>{c.last_used_at ? relTime(c.last_used_at) : '—'}</td>
              <td><StatusTag status={c.enabled ? 'active' : 'canceled'} /></td>
              <td><div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                <button className="op-btn sm" disabled={mut.test.isPending} onClick={() => test(c)}><FlaskConical size={13} />Test</button>
                <button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', channel: c })}><Pencil size={13} /></button>
                <button className="op-btn icon sm" title="Delete" disabled={mut.remove.isPending} onClick={() => remove(c)}><Trash2 size={13} /></button>
              </div></td>
            </tr>
          ))}
          {isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading channels…</td></tr>}
          {isError && !isLoading && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load channels. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
          {!isLoading && !isError && list.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No channels configured.</td></tr>}
        </tbody>
      </table>

      {modal.kind !== 'closed' && (
        <ChannelModal channel={modal.kind === 'edit' ? modal.channel : null} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}

/* =============================== Rules =================================== */

interface RuleForm {
  rule_name: string;
  alert_source: string;
  alert_type: string;
  channel_ids: string;     // comma-separated
  severity_filter: string; // comma-separated
  frequency: string;
  priority: number;
  enabled: boolean;
}

// Values MUST match the backend CHECK constraint on
// (tenant|platform)_notification_rules.frequency.
const FREQUENCY_OPTIONS: { value: string; label: string }[] = [
  { value: 'immediate', label: 'Immediate' },
  { value: 'digest_hourly', label: 'Hourly digest' },
  { value: 'digest_daily', label: 'Daily digest' },
  { value: 'digest_weekly', label: 'Weekly digest' },
];

const DEFAULT_RULE_FORM: RuleForm = {
  rule_name: '', alert_source: '', alert_type: '', channel_ids: '', severity_filter: '', frequency: 'immediate', priority: 0, enabled: true,
};

function splitCsv(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

function RuleModal({ rule, channels, onClose, mut }: { rule: PlatformRule | null; channels: PlatformChannel[]; onClose: () => void; mut: ReturnType<typeof useRuleMutations> }) {
  const editing = !!rule;
  const [form, setForm] = useState<RuleForm>(() => rule ? {
    rule_name: rule.rule_name,
    alert_source: rule.alert_source,
    alert_type: rule.alert_type ?? '',
    channel_ids: (rule.channel_ids ?? []).join(', '),
    severity_filter: (rule.severity_filter ?? []).join(', '),
    frequency: rule.frequency,
    priority: rule.priority,
    enabled: rule.enabled,
  } : DEFAULT_RULE_FORM);
  const set = <K extends keyof RuleForm>(k: K, v: RuleForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const channelIds = splitCsv(form.channel_ids);
  const invalid = !form.rule_name.trim() || !form.alert_source.trim() || channelIds.length === 0;

  const save = () => {
    const opts = {
      onSuccess: () => { toast.success(editing ? 'Rule updated' : 'Rule created'); onClose(); },
      onError: (e: unknown) => toast.error(errMsg(e)),
    };
    const severity = splitCsv(form.severity_filter);
    if (editing) {
      const body: UpdateRuleRequest = {
        rule_name: form.rule_name.trim(),
        alert_type: form.alert_type.trim(),
        channel_ids: channelIds,
        severity_filter: severity,
        frequency: form.frequency,
        enabled: form.enabled,
        priority: form.priority,
      };
      mut.update.mutate({ id: rule!.id, body }, opts);
    } else {
      const body: CreateRuleRequest = {
        rule_name: form.rule_name.trim(),
        alert_source: form.alert_source.trim(),
        alert_type: form.alert_type.trim() || undefined,
        channel_ids: channelIds,
        severity_filter: severity,
        frequency: form.frequency,
        enabled: form.enabled,
        priority: form.priority,
      };
      mut.create.mutate(body, opts);
    }
  };

  return (
    <Modal
      open onClose={onClose}
      title={editing ? `Edit rule — ${rule!.rule_name}` : 'New routing rule'}
      description={channels.length > 0 ? `Channel IDs reference configured channels. Available: ${channels.map((c) => `${c.channel_name} (${c.id.slice(0, 8)}…)`).join(', ')}` : 'Configure a channel first, then reference its ID here.'}
      size="lg"
      footerNote="Platform-admin · audited"
      primaryLabel={editing ? 'Save' : 'Create'} onPrimary={save}
      primaryLoading={mut.create.isPending || mut.update.isPending} primaryDisabled={invalid}
    >
      <ModalField label="Rule name"><input value={form.rule_name} onChange={(e) => set('rule_name', e.target.value)} placeholder="e.g. Critical alerts → PagerDuty" style={modalInputStyle} /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <ModalField label="Alert source"><input value={form.alert_source} onChange={(e) => set('alert_source', e.target.value)} disabled={editing} placeholder="e.g. compliance" style={modalInputStyle} /></ModalField>
        <ModalField label="Alert type (optional)"><input value={form.alert_type} onChange={(e) => set('alert_type', e.target.value)} placeholder="all types if blank" style={modalInputStyle} /></ModalField>
      </div>
      <ModalField label="Channel IDs (comma-separated)"><input value={form.channel_ids} onChange={(e) => set('channel_ids', e.target.value)} placeholder="uuid, uuid" style={modalInputStyle} /></ModalField>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 100px', gap: 12 }}>
        <ModalField label="Severity filter (csv)"><input value={form.severity_filter} onChange={(e) => set('severity_filter', e.target.value)} placeholder="critical, high" style={modalInputStyle} /></ModalField>
        <ModalField label="Frequency">
          <select value={form.frequency} onChange={(e) => set('frequency', e.target.value)} style={modalInputStyle}>
            {FREQUENCY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            {!FREQUENCY_OPTIONS.some((o) => o.value === form.frequency) && <option value={form.frequency}>{form.frequency}</option>}
          </select>
        </ModalField>
        <ModalField label="Priority"><input type="number" value={form.priority} onChange={(e) => set('priority', parseInt(e.target.value) || 0)} style={modalInputStyle} /></ModalField>
      </div>
      <ModalField label="Status">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />Enabled
        </label>
      </ModalField>
    </Modal>
  );
}

type RuleModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; rule: PlatformRule };

function RulesPanel({ channels }: { channels: PlatformChannel[] }) {
  const { data, isLoading, isError, refetch } = usePlatformRules();
  const mut = useRuleMutations();
  const [modal, setModal] = useState<RuleModalState>({ kind: 'closed' });
  const list = data ?? [];

  const remove = (r: PlatformRule) => {
    if (!window.confirm(`Delete rule "${r.rule_name}"?`)) return;
    mut.remove.mutate(r.id, { onSuccess: () => toast.success('Rule deleted'), onError: (e) => toast.error(errMsg(e)) });
  };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
        <Filter size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Routing rules</span>
        <div style={{ flex: 1 }} />
        <button className="op-btn primary sm" onClick={() => setModal({ kind: 'create' })}><Plus size={14} />New rule</button>
      </div>
      <table className="op-table">
        <thead><tr><th>Rule</th><th>Source</th><th>Severity filter</th><th>Frequency</th><th className="num">Priority</th><th>Enabled</th><th /></tr></thead>
        <tbody>
          {list.map((r) => (
            <tr key={r.id}>
              <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{r.rule_name}</td>
              <td className="t-muted">{r.alert_source}{r.alert_type ? ` · ${r.alert_type}` : ''}</td>
              <td className="t-muted">{(r.severity_filter ?? []).join(', ') || 'all'}</td>
              <td className="t-muted">{r.frequency}</td>
              <td className="num t-muted">{r.priority}</td>
              <td><StatusTag status={r.enabled ? 'active' : 'canceled'} /></td>
              <td><div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                <button className="op-btn icon sm" title="Edit" onClick={() => setModal({ kind: 'edit', rule: r })}><Pencil size={13} /></button>
                <button className="op-btn icon sm" title="Delete" disabled={mut.remove.isPending} onClick={() => remove(r)}><Trash2 size={13} /></button>
              </div></td>
            </tr>
          ))}
          {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading rules…</td></tr>}
          {isError && !isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load rules. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
          {!isLoading && !isError && list.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No rules configured.</td></tr>}
        </tbody>
      </table>

      {modal.kind !== 'closed' && (
        <RuleModal rule={modal.kind === 'edit' ? modal.rule : null} channels={channels} onClose={() => setModal({ kind: 'closed' })} mut={mut} />
      )}
    </div>
  );
}

/* ============================== History ================================= */

function HistoryPanel() {
  const { data, isLoading, isError, refetch } = usePlatformHistory();
  const rows = data ?? [];
  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)' }}>
        <BellRing size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Recent deliveries</span>
      </div>
      <table className="op-table">
        <thead><tr><th>Source</th><th>Type</th><th>Severity</th><th>Message</th><th>Channels</th><th>Status</th><th>When</th></tr></thead>
        <tbody>
          {rows.map((h) => (
            <tr key={h.id}>
              <td style={{ fontWeight: 500, color: 'var(--op-t1)' }}>{h.alert_source}</td>
              <td className="t-muted">{h.alert_type}</td>
              <td><StatusTag status={h.severity} /></td>
              <td className="t-muted" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.message}</td>
              <td className="t-muted">{(h.channels_used ?? []).join(', ') || '—'}</td>
              <td><StatusTag status={h.status} /></td>
              <td className="t-muted mono" style={{ fontSize: 11 }}>{relTime(h.created_at)}</td>
            </tr>
          ))}
          {isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading history…</td></tr>}
          {isError && !isLoading && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Couldn't load history. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></td></tr>}
          {!isLoading && !isError && rows.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>No notifications sent yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

/* =============================== Page =================================== */

export function NotificationDeliveryPage() {
  const channelsQ = usePlatformChannels();
  const channels = channelsQ.data ?? [];
  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 16 }}>
      {channelsQ.isSuccess && channels.length === 0 && (
        <div className="op-panel" style={{ padding: '14px 18px', display: 'flex', alignItems: 'flex-start', gap: 12, borderColor: 'color-mix(in srgb, var(--warn) 35%, transparent)', background: 'color-mix(in srgb, var(--warn) 6%, transparent)' }}>
          <AlertTriangle size={20} style={{ color: 'var(--warn)', flex: 'none', marginTop: 1 }} />
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 13.5, color: 'var(--op-t1)' }}>
              Platform alerts are not being delivered — no notification channels are configured. Alerts from monitoring and audit will be recorded in history but reach no one until a channel and routing rule exist.
            </div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4 }}>Create a channel below, then add a routing rule that targets it.</div>
          </div>
        </div>
      )}
      <ChannelsPanel />
      <RulesPanel channels={channels} />
      <HistoryPanel />
    </div>
  );
}
