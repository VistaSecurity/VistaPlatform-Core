import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { DrawerCloseBtn, DrawerShell, Icon, MetaRow, Modal, Pill, SectionLabel } from '../../components/ui';
import { relTime } from '../settings/kit';

// Remediation → Alerts. The stateful-alerts work surface: lifecycle
// active → acknowledged → snoozed → resolved, with an append-only evidence
// timeline per alert (GET /alerts/:id). Read view is ungated; every mutation
// is behind alerts.manage. Talks to compliance-engine through the typed
// api-contract client (clients.compliance) — see api/openapi/compliance-engine.openapi.yaml.

type Alert = complianceEngineComponents['schemas']['Alert'];
type AlertEvent = complianceEngineComponents['schemas']['AlertEvent'];
// Not pinned as an enum on the wire (the spec documents legacy rows may carry
// other strings) — this union is a UI-local convenience for the tab keys.
type AlertStatus = 'active' | 'acknowledged' | 'snoozed' | 'resolved';

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--ok)', info: 'var(--info)',
};
const STATUS_COLOR: Record<string, string> = {
  active: 'var(--warn-strong)', acknowledged: 'var(--info)', snoozed: 'var(--neutral)', resolved: 'var(--ok)',
};
const EVENT_META: Record<string, { icon: string; label: string }> = {
  opened: { icon: 'bell', label: 'Opened' },
  severity_changed: { icon: 'trending-up', label: 'Severity changed' },
  acknowledged: { icon: 'check', label: 'Acknowledged' },
  snoozed: { icon: 'clock', label: 'Snoozed' },
  unsnoozed: { icon: 'play', label: 'Unsnoozed' },
  ticket_linked: { icon: 'ticket', label: 'Ticket linked' },
  resolved: { icon: 'check-check', label: 'Resolved' },
};

type Tab = AlertStatus | 'all';
const TABS: { key: Tab; label: string }[] = [
  { key: 'active', label: 'Active' },
  { key: 'acknowledged', label: 'Acknowledged' },
  { key: 'snoozed', label: 'Snoozed' },
  { key: 'resolved', label: 'Resolved' },
  { key: 'all', label: 'All' },
];
const EMPTY_MESSAGE: Record<Tab, string> = {
  active: 'No active alerts — all clear.',
  acknowledged: 'No acknowledged alerts.',
  snoozed: 'No snoozed alerts.',
  resolved: 'No resolved alerts yet.',
  all: 'No alerts yet. Alerts raised by the platform land here.',
};

const SNOOZE_PICKS: { label: string; days: number }[] = [
  { label: '1 day', days: 1 }, { label: '3 days', days: 3 },
  { label: '1 week', days: 7 }, { label: '2 weeks', days: 14 },
];

const GRID = '86px 1.7fr 1.1fr 1.1fr 112px 92px 148px';

export function AlertsPage() {
  const qc = useQueryClient();
  // ?alert=<id> deep-links straight into the detail drawer (e.g. the ticket
  // drawer's "View alert" link). The drawer fetches by id, so the alert opens
  // regardless of which status tab it currently lives under.
  const [searchParams] = useSearchParams();
  const [tab, setTab] = useState<Tab>('active');
  const [severity, setSeverity] = useState('all');
  const [detailId, setDetailId] = useState<string | null>(searchParams.get('alert'));
  const [snoozeTarget, setSnoozeTarget] = useState<Alert | null>(null);
  const [resolveTarget, setResolveTarget] = useState<Alert | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const statsQ = useQuery({
    queryKey: ['alerts', 'stats'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/alerts/stats', {});
      if (error || !data) throw new Error(error?.error ?? 'Failed to load alert stats');
      return data;
    },
  });
  const listQ = useQuery({
    queryKey: ['alerts', 'list', tab, severity],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/alerts', {
        params: {
          query: {
            status: tab === 'all' ? undefined : tab,
            severity: severity === 'all' ? undefined : severity,
          },
        },
      });
      if (error || !data) throw new Error(error?.error ?? 'Failed to load alerts');
      return data.alerts;
    },
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ['alerts'] });
  const onError = (e: unknown) => setActionError(e instanceof Error ? e.message : 'Action failed');
  const onOk = () => { setActionError(null); invalidate(); };

  const ack = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.compliance.POST('/alerts/{id}/acknowledge', { params: { path: { id } } });
      if (error || !data) throw new Error(error?.error ?? 'Failed to acknowledge alert');
      return data.alert;
    },
    onSuccess: onOk, onError,
  });
  const unsnooze = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.compliance.POST('/alerts/{id}/unsnooze', { params: { path: { id } } });
      if (error || !data) throw new Error(error?.error ?? 'Failed to unsnooze alert');
      return data.alert;
    },
    onSuccess: onOk, onError,
  });
  const ticket = useMutation({
    mutationFn: async (id: string) => {
      const { data, error, response } = await clients.compliance.POST('/alerts/{id}/ticket', { params: { path: { id } } });
      if (!response.ok || error || !data) throw new Error(error?.error ?? 'Failed to create ticket');
      return data.ticket;
    },
    onSuccess: onOk, onError,
  });

  const rows = listQ.data ?? [];
  const stats = statsQ.data;

  const card = (label: string, val: number | undefined, color: string | null) => (
    <div key={label} className="panel" style={{ padding: '13px 16px', flex: 1, minWidth: 120 }}>
      <div className="eyebrow-app">{label}</div>
      <div className="mono" style={{ fontSize: 24, fontWeight: 700, color: color || 'var(--app-t1)', marginTop: 6 }}>
        {statsQ.isLoading || val == null ? '…' : val}
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', gap: 12, padding: '16px 26px 8px', flexWrap: 'wrap' }}>
        {card('Active', stats?.active, 'var(--warn-strong)')}
        {card('Acknowledged', stats?.acknowledged, 'var(--info)')}
        {card('Snoozed', stats?.snoozed, null)}
        {card('Critical open', stats?.critical, 'var(--danger)')}
        {card('High open', stats?.high, 'var(--warn-strong)')}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 26px 12px', flexWrap: 'wrap' }}>
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className="ui-btn sm"
            style={{
              height: 28, fontSize: 12,
              borderColor: tab === t.key ? 'var(--accent)' : 'var(--app-border)',
              color: tab === t.key ? 'var(--accent)' : 'var(--app-t2)',
              fontWeight: tab === t.key ? 700 : 500,
            }}
          >
            {t.label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          title="Filter by severity"
          style={{ height: 28, padding: '0 8px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', cursor: 'pointer' }}
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{rows.length} alerts</span>
      </div>

      {actionError && (
        <div style={{ margin: '0 26px 10px', padding: '8px 12px', borderRadius: 9, border: '1px solid color-mix(in srgb, var(--danger) 40%, transparent)', background: 'color-mix(in srgb, var(--danger) 8%, transparent)', fontSize: 12, color: 'var(--danger-text)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="alert-triangle" size={13} />{actionError}
          <button onClick={() => setActionError(null)} style={{ marginLeft: 'auto', border: 'none', background: 'none', color: 'inherit', cursor: 'pointer', padding: 0 }}><Icon name="x" size={13} /></button>
        </div>
      )}

      <div className="panel" style={{ flex: 1, minHeight: 0, margin: '0 26px 22px', overflow: 'auto', borderRadius: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', height: 36, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
          {['Severity', 'Alert', 'Subject', 'Source', 'Status', 'Last activity', ''].map((h, i) => <span key={i} className="eyebrow-app">{h}</span>)}
        </div>
        {listQ.isError ? (
          <Empty icon="alert-triangle" title="Couldn't load alerts" message={listQ.error instanceof Error ? listQ.error.message : 'Request failed'} />
        ) : listQ.isLoading ? (
          <Empty icon="loader" title="Loading…" message="Fetching alerts." />
        ) : rows.length === 0 ? (
          <Empty icon={tab === 'active' ? 'check' : 'bell'} title={tab === 'active' ? 'All clear' : 'Nothing here'} message={EMPTY_MESSAGE[tab]} />
        ) : (
          rows.map((a) => (
            <div key={a.id} onClick={() => setDetailId(a.id)} className="row-hover" style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 16px', minHeight: 48, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
              <Pill color={SEV_COLOR[a.severity] || 'var(--app-t2)'} style={{ fontSize: 10.5, justifySelf: 'start' }}>{a.severity}</Pill>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.title}</div>
                {a.message && <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.message}</div>}
              </div>
              <span style={{ fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.subject_label || '—'}</span>
              <div style={{ minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 11, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.source}</div>
                <div className="mono" style={{ fontSize: 10, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.alert_type}</div>
              </div>
              <div>
                <Pill color={STATUS_COLOR[a.status] || 'var(--app-t2)'} tone="outline" style={{ fontSize: 10.5 }}>{a.status}</Pill>
                {a.status === 'snoozed' && a.snoozed_until && (
                  <div className="mono" style={{ fontSize: 9.5, color: 'var(--app-t3)', marginTop: 3 }}>until {a.snoozed_until.slice(0, 10)}</div>
                )}
              </div>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{relTime(a.last_event_at)}</span>
              <div onClick={(e) => e.stopPropagation()} style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                {a.ticket_id && (
                  <Link to="/remediation/queue" title="A ticket is linked — open the work queue" onClick={(e) => e.stopPropagation()} style={{ textDecoration: 'none' }}>
                    <Pill color="var(--info)" style={{ fontSize: 10, cursor: 'pointer' }}><Icon name="ticket" size={11} />ticket</Pill>
                  </Link>
                )}
                <PermissionGate permission={TENANT_PERMISSIONS.alerts.manage}>
                  {(a.status === 'active' || a.status === 'snoozed') && (
                    <RowBtn icon="check" title="Acknowledge" onClick={() => ack.mutate(a.id)} disabled={ack.isPending} />
                  )}
                  {(a.status === 'active' || a.status === 'acknowledged') && (
                    <RowBtn icon="clock" title="Snooze" onClick={() => setSnoozeTarget(a)} />
                  )}
                  {a.status === 'snoozed' && (
                    <RowBtn icon="play" title="Unsnooze" onClick={() => unsnooze.mutate(a.id)} disabled={unsnooze.isPending} />
                  )}
                  {a.status !== 'resolved' && (
                    <RowBtn icon="check-check" title="Resolve" onClick={() => setResolveTarget(a)} />
                  )}
                  {!a.ticket_id && (
                    <RowBtn icon="ticket" title="Create ticket" onClick={() => ticket.mutate(a.id)} disabled={ticket.isPending} />
                  )}
                </PermissionGate>
              </div>
            </div>
          ))
        )}
      </div>

      {snoozeTarget && (
        <SnoozeModal
          alert={snoozeTarget}
          onClose={() => setSnoozeTarget(null)}
          onDone={() => { setSnoozeTarget(null); onOk(); }}
          onError={onError}
        />
      )}
      {resolveTarget && (
        <ResolveModal
          alert={resolveTarget}
          onClose={() => setResolveTarget(null)}
          onDone={() => { setResolveTarget(null); onOk(); }}
          onError={onError}
        />
      )}
      {detailId && <AlertDetailDrawer id={detailId} onClose={() => setDetailId(null)} />}
    </div>
  );
}

function RowBtn({ icon, title, onClick, disabled }: { icon: string; title: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="ui-btn ghost"
      style={{ width: 26, height: 26, padding: 0, justifyContent: 'center', opacity: disabled ? 0.5 : 1 }}
    >
      <Icon name={icon} size={13} />
    </button>
  );
}

function SnoozeModal({ alert, onClose, onDone, onError }: { alert: Alert; onClose: () => void; onDone: () => void; onError: (e: unknown) => void }) {
  const [days, setDays] = useState(1);
  const [reason, setReason] = useState('');
  const snooze = useMutation({
    mutationFn: async () => {
      const until = new Date(Date.now() + days * 86400000).toISOString();
      const trimmed = reason.trim();
      const { data, error } = await clients.compliance.POST('/alerts/{id}/snooze', {
        params: { path: { id: alert.id } },
        body: trimmed ? { until, reason: trimmed } : { until },
      });
      if (error || !data) throw new Error(error?.error ?? 'Failed to snooze alert');
    },
    onSuccess: onDone,
    onError: (e) => { onError(e); onClose(); },
  });
  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      icon="clock"
      eyebrow="Snooze alert"
      title={alert.title}
      description="Mute this alert for a while. It returns to Active when the snooze expires."
      primary={
        <button className="ui-btn accent" disabled={snooze.isPending} onClick={() => snooze.mutate()}>
          {snooze.isPending ? 'Snoozing…' : 'Snooze'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        {SNOOZE_PICKS.map((p) => (
          <button
            key={p.days}
            onClick={() => setDays(p.days)}
            className="ui-btn sm"
            style={{
              borderColor: days === p.days ? 'var(--accent)' : 'var(--app-border)',
              color: days === p.days ? 'var(--accent)' : 'var(--app-t2)',
              fontWeight: days === p.days ? 700 : 500,
            }}
          >
            {p.label}
          </button>
        ))}
      </div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={3}
        placeholder="Reason (optional)"
        style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5, marginBottom: 4 }}
      />
    </Modal>
  );
}

function ResolveModal({ alert, onClose, onDone, onError }: { alert: Alert; onClose: () => void; onDone: () => void; onError: (e: unknown) => void }) {
  const [note, setNote] = useState('');
  const resolve = useMutation({
    mutationFn: async () => {
      const trimmed = note.trim();
      const { data, error } = await clients.compliance.POST('/alerts/{id}/resolve', {
        params: { path: { id: alert.id } },
        body: trimmed ? { note: trimmed } : {},
      });
      if (error || !data) throw new Error(error?.error ?? 'Failed to resolve alert');
    },
    onSuccess: onDone,
    onError: (e) => { onError(e); onClose(); },
  });
  return (
    <Modal
      open
      onClose={onClose}
      size="sm"
      tone="green"
      icon="check-check"
      eyebrow="Resolve alert"
      title={alert.title}
      description="Close this alert out. The evidence timeline records who resolved it and when."
      primary={
        <button className="ui-btn accent" disabled={resolve.isPending} onClick={() => resolve.mutate()}>
          {resolve.isPending ? 'Resolving…' : 'Resolve'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose}>Cancel</button>}
    >
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        rows={3}
        placeholder="Resolution note (optional)"
        style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5, marginBottom: 4 }}
      />
    </Modal>
  );
}

function actorLabel(ev: AlertEvent): string {
  if (ev.actor_type === 'system') return 'system';
  return ev.actor_id ? ev.actor_id.slice(0, 8) : 'user';
}

function EventDetails({ ev }: { ev: AlertEvent }) {
  const d = ev.details || {};
  if (ev.event_type === 'severity_changed') {
    const from = (d.from ?? d.old_severity ?? d.old) as string | undefined;
    const to = (d.to ?? d.new_severity ?? d.new) as string | undefined;
    if (from || to) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t2)' }}>
          <Pill color={SEV_COLOR[String(from)] || 'var(--app-t2)'} style={{ fontSize: 10 }}>{from ?? '?'}</Pill>
          <Icon name="arrow-right" size={11} style={{ color: 'var(--app-t3)' }} />
          <Pill color={SEV_COLOR[String(to)] || 'var(--app-t2)'} style={{ fontSize: 10 }}>{to ?? '?'}</Pill>
        </span>
      );
    }
  }
  if (ev.event_type === 'snoozed') {
    const until = typeof d.until === 'string' ? new Date(d.until).toLocaleString() : null;
    const reason = typeof d.reason === 'string' && d.reason ? d.reason : null;
    if (until || reason) {
      return (
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>
          {until && <>Until <span className="mono" style={{ fontSize: 11.5 }}>{until}</span></>}
          {until && reason && ' — '}
          {reason}
        </span>
      );
    }
  }
  if (ev.event_type === 'resolved') {
    const note = typeof d.note === 'string' && d.note ? d.note : null;
    const observation = d.observation ?? d.resolution_observation;
    return (
      <span style={{ display: 'block' }}>
        {note && <span style={{ display: 'block', fontSize: 12, color: 'var(--app-t2)' }}>{note}</span>}
        {observation != null && (
          <span style={{ display: 'block', marginTop: note ? 6 : 0 }}>
            <span className="eyebrow-app" style={{ display: 'block', marginBottom: 4 }}>Resolution observation</span>
            <code className="mono" style={{ display: 'block', padding: '8px 10px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)', fontSize: 10.5, color: 'var(--app-t2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {JSON.stringify(observation, null, 2)}
            </code>
          </span>
        )}
      </span>
    );
  }
  if (ev.event_type === 'ticket_linked' && typeof d.ticket_id === 'string') {
    return <span className="mono" style={{ fontSize: 11, color: 'var(--info)' }}>{d.ticket_id}</span>;
  }
  // Fallback: surface any unmodeled details rather than hiding evidence.
  if (Object.keys(d).length > 0) {
    return (
      <code className="mono" style={{ display: 'block', padding: '6px 9px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)', fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
        {JSON.stringify(d, null, 2)}
      </code>
    );
  }
  return null;
}

function AlertDetailDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detailQ = useQuery({
    queryKey: ['alerts', 'detail', id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/alerts/{id}', { params: { path: { id } } });
      if (error || !data) throw new Error(error?.error ?? 'Failed to load the alert');
      return data;
    },
  });
  const a = detailQ.data?.alert;
  const events = detailQ.data?.events ?? [];

  return (
    <DrawerShell onClose={onClose} width={520}>
      {detailQ.isLoading || !a ? (
        <div style={{ padding: '60px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
          <Icon name={detailQ.isError ? 'alert-triangle' : 'loader'} size={26} style={{ opacity: 0.6 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>
            {detailQ.isError ? "Couldn't load the alert" : 'Loading…'}
          </div>
          {detailQ.isError && (
            <div style={{ fontSize: 12.5, marginTop: 4 }}>{detailQ.error instanceof Error ? detailQ.error.message : 'Request failed'}</div>
          )}
        </div>
      ) : (
        <>
          <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${SEV_COLOR[a.severity] || 'var(--neutral)'} 12%, transparent)`, color: SEV_COLOR[a.severity] || 'var(--app-t2)' }}>
                <Icon name="bell" size={16} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="eyebrow-app">{a.alert_type} · {a.source}</div>
                <h2 style={{ margin: '4px 0 6px', fontSize: 16.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25 }}>{a.title}</h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                  <Pill color={STATUS_COLOR[a.status] || 'var(--app-t2)'} style={{ fontSize: 10.5 }}>{a.status}</Pill>
                  <Pill color={SEV_COLOR[a.severity] || 'var(--app-t2)'} style={{ fontSize: 10.5 }}>{a.severity}</Pill>
                  {a.resolution && <Pill color="var(--app-t2)" tone="outline" style={{ fontSize: 10.5 }}>{a.resolution === 'auto' ? 'auto-resolved' : 'resolved manually'}</Pill>}
                </div>
              </div>
              <DrawerCloseBtn onClose={onClose} />
            </div>
          </div>

          <div style={{ flex: 1, padding: '4px 22px 30px' }}>
            {a.message && (
              <>
                <SectionLabel icon="file-text">Message</SectionLabel>
                <p style={{ margin: '4px 0 0', fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)', whiteSpace: 'pre-wrap' }}>{a.message}</p>
              </>
            )}

            <SectionLabel icon="circle-alert">Details</SectionLabel>
            <MetaRow k="Subject" v={a.subject_label || a.subject_id} />
            {a.subject_type && <MetaRow k="Subject type" v={a.subject_type} />}
            <MetaRow k="First raised" v={new Date(a.first_raised_at).toLocaleString()} mono />
            <MetaRow k="Last activity" v={`${relTime(a.last_event_at)} · ${new Date(a.last_event_at).toLocaleString()}`} mono />
            {a.acknowledged_at && <MetaRow k="Acknowledged" v={`${a.acknowledged_by ? a.acknowledged_by.slice(0, 8) + ' · ' : ''}${new Date(a.acknowledged_at).toLocaleString()}`} mono />}
            {a.status === 'snoozed' && a.snoozed_until && <MetaRow k="Snoozed until" v={new Date(a.snoozed_until).toLocaleString()} mono />}
            {a.status === 'snoozed' && a.snooze_reason && <MetaRow k="Snooze reason" v={a.snooze_reason} />}
            {a.resolved_at && <MetaRow k="Resolved" v={`${a.resolved_by ? a.resolved_by.slice(0, 8) + ' · ' : ''}${new Date(a.resolved_at).toLocaleString()}`} mono />}
            {a.resolution_note && <MetaRow k="Resolution note" v={a.resolution_note} />}
            {a.ticket_id && (
              <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)', display: 'flex', justifyContent: 'space-between', gap: 16 }}>
                <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Ticket</span>
                <Link to="/remediation/queue" className="mono" style={{ fontSize: 12, color: 'var(--info)', textDecoration: 'none' }}>
                  open the queue <Icon name="arrow-up-right" size={11} />
                </Link>
              </div>
            )}
            {a.resolution === 'auto' && a.resolution_observation != null && (
              <>
                <SectionLabel icon="binary">Resolution observation</SectionLabel>
                <code className="mono" style={{ display: 'block', padding: '8px 10px', borderRadius: 8, background: 'var(--app-panel2)', border: '1px solid var(--app-border)', fontSize: 10.5, color: 'var(--app-t2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {JSON.stringify(a.resolution_observation, null, 2)}
                </code>
              </>
            )}

            <SectionLabel icon="history">Evidence timeline ({events.length})</SectionLabel>
            {events.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No events recorded.</div>
            ) : (
              <div style={{ position: 'relative', paddingLeft: 34, marginTop: 6 }}>
                <div style={{ position: 'absolute', left: 11, top: 10, bottom: 10, width: 1, background: 'var(--app-border2)' }} />
                {events.map((ev) => {
                  const meta = EVENT_META[ev.event_type] || { icon: 'circle-dot', label: ev.event_type.replace(/_/g, ' ') };
                  return (
                    <div key={ev.id} style={{ position: 'relative', padding: '9px 0' }}>
                      <span style={{ position: 'absolute', left: -34, top: 9, width: 22, height: 22, borderRadius: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border2)', color: ev.event_type === 'resolved' ? 'var(--ok)' : ev.event_type === 'opened' ? 'var(--warn-strong)' : 'var(--app-t2)' }}>
                        <Icon name={meta.icon} size={11} />
                      </span>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{meta.label}</span>
                        <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>by {actorLabel(ev)}</span>
                        <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginLeft: 'auto' }} title={new Date(ev.created_at).toLocaleString()}>
                          {relTime(ev.created_at)} · {new Date(ev.created_at).toLocaleString()}
                        </span>
                      </div>
                      <div style={{ marginTop: 3 }}><EventDetails ev={ev} /></div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </DrawerShell>
  );
}

function Empty({ icon, title, message }: { icon: string; title: string; message: string }) {
  return (
    <div style={{ padding: '60px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ opacity: 0.6 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
