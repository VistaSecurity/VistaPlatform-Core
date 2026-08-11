// VISTA Operations — topbar notification bell. Platform in-app inbox backed by
// notification-service /platform/notifications via the typed api-contract
// client (clients.notifications — cookie auth + platform CSRF wired there).
// Unread badge polls every 60s; the panel refetches on open.
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Bell, CheckCheck } from 'lucide-react';
import type { notificationServiceComponents } from '@vistasecurity/api-contract';
import { Tag, relTime } from '../components/ui/primitives';
import { clients } from '../lib/clients';

export type PlatformInAppNotification = notificationServiceComponents['schemas']['PlatformInAppNotification'];

const INBOX_KEY = ['platform', 'notif', 'inbox'] as const;

function usePlatformInbox() {
  return useQuery({
    queryKey: INBOX_KEY,
    queryFn: async (): Promise<PlatformInAppNotification[]> => {
      const { data, error } = await clients.notifications.GET('/platform/notifications', {});
      if (error) throw new Error('Failed to load notifications');
      return data?.notifications ?? [];
    },
    refetchInterval: 60 * 1000,
    staleTime: 30 * 1000,
  });
}

export function NotificationBell() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const { data, isLoading, isError, refetch } = usePlatformInbox();
  const invalidate = () => qc.invalidateQueries({ queryKey: INBOX_KEY });

  const markRead = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.notifications.PUT('/platform/notifications/{id}/read', { params: { path: { id } } });
      if (error) throw new Error('Mark read failed');
    },
    onSuccess: invalidate,
  });
  const markAllRead = useMutation({
    mutationFn: async () => {
      const { error } = await clients.notifications.PUT('/platform/notifications/read-all', {});
      if (error) throw new Error('Mark all read failed');
    },
    onSuccess: invalidate,
  });

  const list = data ?? [];
  const unread = list.filter((n) => !n.read_at).length;
  const recent = list.slice(0, 10);

  const toggle = () =>
    setOpen((o) => {
      const next = !o;
      if (next) void refetch();
      return next;
    });

  return (
    <div style={{ position: 'relative' }}>
      <button className="op-btn icon" title="Notifications" onClick={toggle} style={{ position: 'relative' }}>
        <Bell size={16} />
        {unread > 0 && (
          <span style={{ position: 'absolute', top: -4, right: -4, minWidth: 16, height: 16, padding: '0 4px', borderRadius: 9, background: 'var(--op-accent)', color: '#0A0A0A', fontSize: 9.5, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1, boxShadow: '0 0 0 2px var(--op-bg2)' }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 40 }} />
          <div style={{ position: 'absolute', top: 40, right: 0, width: 360, background: 'var(--op-panel)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-md)', boxShadow: 'var(--op-shadow)', zIndex: 41, overflow: 'hidden', animation: 'opPop .14s ease both' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '11px 13px', borderBottom: '1px solid var(--op-border)' }}>
              <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 13.5, color: 'var(--op-t1)', flex: 1 }}>Notifications</span>
              {unread > 0 && (
                <button className="op-btn ghost sm" disabled={markAllRead.isPending} onClick={() => markAllRead.mutate()}>
                  <CheckCheck size={13} />Mark all read
                </button>
              )}
            </div>
            <div style={{ maxHeight: 380, overflowY: 'auto', padding: 6 }}>
              {isLoading && <div style={{ padding: '28px 12px', textAlign: 'center', fontSize: 12.5, color: 'var(--op-t3)' }}>Loading notifications…</div>}
              {isError && !isLoading && <div style={{ padding: '28px 12px', textAlign: 'center', fontSize: 12.5, color: 'var(--op-t3)' }}>Couldn't load notifications.</div>}
              {!isLoading && !isError && recent.length === 0 && (
                <div style={{ padding: '28px 12px', textAlign: 'center', fontSize: 12.5, color: 'var(--op-t3)' }}>No notifications yet</div>
              )}
              {recent.map((n) => {
                const isUnread = !n.read_at;
                return (
                  <button
                    key={n.id}
                    className="row-hover"
                    onClick={() => { if (isUnread && !markRead.isPending) markRead.mutate(n.id); }}
                    style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 3, width: '100%', padding: '9px 12px 9px 22px', border: 'none', background: isUnread ? 'var(--op-accent-soft)' : 'transparent', borderRadius: 'var(--r-sm)', cursor: isUnread ? 'pointer' : 'default', textAlign: 'left', marginBottom: 1 }}
                  >
                    {isUnread && <span style={{ position: 'absolute', left: 9, top: 15, width: 6, height: 6, borderRadius: 6, background: 'var(--op-accent)' }} />}
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 12.5, fontWeight: isUnread ? 700 : 500, color: 'var(--op-t1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.title}</span>
                      <span className="mono" style={{ fontSize: 10, color: 'var(--op-t3)', flex: 'none' }}>{relTime(n.created_at)}</span>
                    </span>
                    <span style={{ fontSize: 11.5, color: 'var(--op-t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.message}</span>
                    <span style={{ marginTop: 2 }}><Tag style={{ fontSize: 10, padding: '1px 7px' }}>{n.type}</Tag></span>
                  </button>
                );
              })}
            </div>
            <button
              className="row-hover"
              onClick={() => { setOpen(false); navigate('/settings/notifications'); }}
              style={{ display: 'block', width: '100%', padding: '10px 13px', border: 'none', borderTop: '1px solid var(--op-border)', background: 'transparent', cursor: 'pointer', textAlign: 'left', fontSize: 12, fontWeight: 600, color: 'var(--op-accent-text)', fontFamily: 'var(--font-body)' }}
            >
              Notification delivery →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
