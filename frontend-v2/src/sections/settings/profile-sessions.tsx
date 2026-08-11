// My Profile · Sessions & Devices + Connected Accounts — wired to the
// now-contracted auth-service endpoints: /auth/sessions (list + revoke),
// /auth/connections (list + set-primary), /auth/sso/unlink. The current session
// has no contract marker, so the most-recently-used row (the list is ordered
// most-recent-first, and loading this page bumps the current session to the top)
// is treated as "This device" and excluded from "revoke others".
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { authServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, Modal } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, StateNote, relTime, GREEN, AMBER } from './kit';
import type { SettingsNavItem } from './nav';

type Session = authServiceComponents['schemas']['Session'];
type Connection = authServiceComponents['schemas']['Connection'];

function dateStr(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
}

function deviceLabel(ua: string | null): string {
  if (!ua) return 'Unknown device';
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android'
    : /iPhone|iPad|iOS/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return `${browser} · ${os}`;
}

// ---- Sessions & Devices ---------------------------------------------------
export function ProfileSessionsPage({ meta }: { meta: SettingsNavItem }) {
  const qc = useQueryClient();
  const [confirmOthers, setConfirmOthers] = useState(false);
  const [confirmOne, setConfirmOne] = useState<Session | null>(null);

  const q = useQuery({
    queryKey: ['settings', 'sessions'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/auth/sessions', {});
      if (error || !data) throw new Error('Failed to load sessions');
      return (data.sessions ?? []).filter((s) => !s.is_revoked);
    },
  });

  const revoke = useMutation({
    mutationFn: async (ids: string[]) => {
      for (const id of ids) {
        const { error, response } = await clients.auth.DELETE('/auth/sessions/{id}', { params: { path: { id } } });
        if (!response.ok || error) throw new Error('Failed to revoke a session');
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'sessions'] }),
    onSettled: () => { setConfirmOthers(false); setConfirmOne(null); },
  });

  const sessions = q.data ?? [];
  // Most-recently-used first → the current device. (No contract marker exists.)
  const currentId = sessions[0]?.id;
  const others = sessions.slice(1);

  const cols = [
    { label: 'Device' }, { label: 'IP address', w: '150px' },
    { label: 'Last active', w: '130px' }, { label: 'Signed in', w: '120px' }, { label: '', w: '96px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="My Profile" title="Sessions & Devices" job={meta.job}
      actions={
        others.length > 0
          ? <button className="ui-btn" style={{ color: 'var(--danger-text)' }} onClick={() => setConfirmOthers(true)} disabled={revoke.isPending}><Icon name="log-out" size={14} />Revoke other sessions</button>
          : undefined
      }
    >
      {q.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load sessions" message="Your active sessions failed to load." /></SCard>
      ) : q.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading sessions…" message="Fetching your active sessions." /></SCard>
      ) : sessions.length === 0 ? (
        <SCard><StateNote icon="monitor-smartphone" tone="var(--app-t3)" title="No active sessions" message="You have no other active sessions." /></SCard>
      ) : (
        <STable cols={cols}>
          {sessions.map((s, i) => {
            const isCurrent = s.id === currentId;
            return (
              <STableRow
                key={s.id}
                first={i === 0}
                cols={cols}
                cells={[
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon name="monitor-smartphone" size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{deviceLabel(s.user_agent)}</span>
                    {isCurrent && <STag color={GREEN}>This device</STag>}
                  </span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{s.created_from_ip || '—'}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{relTime(s.last_used_at)}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{dateStr(s.created_at)}</span>,
                  isCurrent
                    ? <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>Current</span>
                    : <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Revoke this session" onClick={() => setConfirmOne(s)} disabled={revoke.isPending}><Icon name="x" size={13} />Revoke</button>,
                ]}
              />
            );
          })}
        </STable>
      )}

      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>
        Each row is an active sign-in. Revoking a session signs that device out immediately. “This device” is your current session.
      </p>

      <Modal
        open={confirmOthers} onClose={revoke.isPending ? undefined : () => setConfirmOthers(false)} dismissible={!revoke.isPending}
        size="sm" tone="danger" icon="log-out" eyebrow="Sessions" title="Revoke other sessions?"
        description={`Signs out ${others.length} other ${others.length === 1 ? 'device' : 'devices'}. This device stays signed in.`}
        primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={revoke.isPending} onClick={() => revoke.mutate(others.map((s) => s.id))}>{revoke.isPending ? 'Revoking…' : 'Revoke others'}</button>}
        secondary={<button className="ui-btn" onClick={() => setConfirmOthers(false)} disabled={revoke.isPending}>Cancel</button>}
        footerNote={revoke.isError ? <span style={{ color: 'var(--danger-text)' }}>{(revoke.error as Error).message}</span> : undefined}
      />
      <Modal
        open={!!confirmOne} onClose={revoke.isPending ? undefined : () => setConfirmOne(null)} dismissible={!revoke.isPending}
        size="sm" tone="danger" icon="log-out" eyebrow="Sessions" title="Revoke this session?"
        description={confirmOne ? `Signs out ${deviceLabel(confirmOne.user_agent)}${confirmOne.created_from_ip ? ` (${confirmOne.created_from_ip})` : ''}.` : ''}
        primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={revoke.isPending} onClick={() => confirmOne && revoke.mutate([confirmOne.id])}>{revoke.isPending ? 'Revoking…' : 'Revoke'}</button>}
        secondary={<button className="ui-btn" onClick={() => setConfirmOne(null)} disabled={revoke.isPending}>Cancel</button>}
        footerNote={revoke.isError ? <span style={{ color: 'var(--danger-text)' }}>{(revoke.error as Error).message}</span> : undefined}
      />
    </SPage>
  );
}

// ---- Connected Accounts ---------------------------------------------------
function connLabel(c: Connection): string {
  if (c.auth_type === 'password' || c.auth_type === 'local') return 'Password';
  return c.external_email || `${c.auth_type} account`;
}
function isSso(c: Connection): boolean {
  return !!c.sso_provider_id && c.auth_type !== 'password' && c.auth_type !== 'local';
}

export function ProfileConnectedPage({ meta }: { meta: SettingsNavItem }) {
  const qc = useQueryClient();
  const [confirmUnlink, setConfirmUnlink] = useState<Connection | null>(null);

  const q = useQuery({
    queryKey: ['settings', 'connections'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/auth/connections', {});
      if (error || !data) throw new Error('Failed to load connections');
      return data.connections ?? [];
    },
  });

  const setPrimary = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.auth.PUT('/auth/connections/{id}/primary', { params: { path: { id } } });
      if (!response.ok || error) throw new Error('Failed to set primary');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'connections'] }),
  });

  const unlink = useMutation({
    mutationFn: async (c: Connection) => {
      if (!c.sso_provider_id) throw new Error('Not an unlinkable connection');
      const { error, response } = await clients.auth.DELETE('/auth/sso/unlink', { body: { provider_id: c.sso_provider_id } });
      if (!response.ok || error) throw new Error('Failed to unlink');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'connections'] }),
    onSettled: () => setConfirmUnlink(null),
  });

  const connections = q.data ?? [];
  const err = setPrimary.error instanceof Error ? setPrimary.error.message : null;

  return (
    <SPage eyebrow="My Profile" title="Connected Accounts" job={meta.job}>
      <SSection>
        {q.isError ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load connections" message="Your linked accounts failed to load." /></SCard>
        ) : q.isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading connections…" message="Fetching your linked authentication methods." /></SCard>
        ) : connections.length === 0 ? (
          <SCard><StateNote icon="link-2" tone="var(--app-t3)" title="No connections" message="No authentication methods are linked to your account." /></SCard>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {connections.map((c) => (
              <SCard key={c.id} pad={16} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
                  <Icon name={isSso(c) ? 'fingerprint' : 'lock'} size={17} />
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{connLabel(c)}</span>
                    {c.is_primary && <STag color={GREEN}>Primary</STag>}
                    {isSso(c) ? <STag>SSO</STag> : <STag color={AMBER}>Password</STag>}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
                    {c.external_email ? `${c.external_email} · ` : ''}{c.last_used_at ? `last used ${relTime(c.last_used_at)}` : 'never used'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flex: 'none' }}>
                  {!c.is_primary && (
                    <button className="ui-btn sm" onClick={() => setPrimary.mutate(c.id)} disabled={setPrimary.isPending}>Make primary</button>
                  )}
                  {isSso(c) && !c.is_primary && (
                    <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Unlink" onClick={() => setConfirmUnlink(c)} disabled={unlink.isPending}><Icon name="x" size={13} />Unlink</button>
                  )}
                </div>
              </SCard>
            ))}
          </div>
        )}
        {err && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 10 }}>{err}</div>}
      </SSection>

      <SSection title="Link a provider">
        <SCard style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Icon name="link-2" size={18} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.55 }}>
            Linking a new SSO provider runs through the single sign-on flow, which is being finished now
            (tracked in <span className="mono">#625</span>). Once it lands, you’ll be able to link providers here.
          </div>
        </SCard>
      </SSection>

      <Modal
        open={!!confirmUnlink} onClose={unlink.isPending ? undefined : () => setConfirmUnlink(null)} dismissible={!unlink.isPending}
        size="sm" tone="danger" icon="link-2" eyebrow="Connected accounts" title="Unlink this provider?"
        description={confirmUnlink ? `${connLabel(confirmUnlink)} will no longer be able to sign in to your account.` : ''}
        primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={unlink.isPending} onClick={() => confirmUnlink && unlink.mutate(confirmUnlink)}>{unlink.isPending ? 'Unlinking…' : 'Unlink'}</button>}
        secondary={<button className="ui-btn" onClick={() => setConfirmUnlink(null)} disabled={unlink.isPending}>Cancel</button>}
        footerNote={unlink.isError ? <span style={{ color: 'var(--danger-text)' }}>{(unlink.error as Error).message}</span> : undefined}
      />
    </SPage>
  );
}
