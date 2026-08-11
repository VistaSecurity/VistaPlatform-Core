// Topbar notification bell — live in-app notifications from notification-service.
// Polls the tenant feed every 60s, badges the unread count (capped at 9+), and
// opens a popover (same panel styling as the ProfileChip menu in app-shell) with
// the 10 most recent items. Row click marks the item read; the header offers
// "Mark all read"; the footer deep-links to Settings → Delivery History.
//
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Bell } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { STag, relTime, RED, AMBER, GREEN } from '../sections/settings/kit';
import type { notificationServiceComponents as NC } from '@vistasecurity/api-contract';

type InAppNotification = NC['schemas']['InAppNotification'];

const QK = ['notifications', 'in-app'];

/** Tone per notification type (alert / discovery / compliance / system / billing / security / other). */
const TYPE_TONE: Record<string, string> = {
  alert: RED, security: RED, compliance: AMBER, discovery: 'var(--info)', billing: GREEN,
};

function useInAppNotifications() {
  return useQuery({
    queryKey: QK,
    queryFn: async () => {
      // Gate on response.ok — empty-body errors surface as falsy `error` in
      // openapi-fetch (same guard as the settings pages).
      const { data, response } = await clients.notifications.GET('/tenant/notifications', {});
      if (!response.ok) throw new Error('Failed to load notifications');
      return data?.notifications ?? [];
    },
    refetchInterval: 60_000,
  });
}

function NotificationRow({ n, onRead }: { n: InAppNotification; onRead: (id: string) => void }) {
  const unread = !n.read_at;
  const tone = TYPE_TONE[(n.type || '').toLowerCase()] ?? 'var(--app-t2)';
  return (
    <button
      onClick={() => { if (unread) onRead(n.id); }}
      className="nav-sub"
      title={unread ? 'Mark as read' : undefined}
      style={{
        display: 'flex', gap: 10, width: '100%', padding: '9px 10px', border: 'none',
        background: unread ? 'color-mix(in srgb, var(--accent) 7%, transparent)' : 'transparent',
        cursor: unread ? 'pointer' : 'default', borderRadius: 8, textAlign: 'left', fontFamily: 'var(--font-body)',
      }}
    >
      <span style={{ width: 7, height: 7, borderRadius: 50, marginTop: 5, flex: 'none', background: unread ? 'var(--accent)' : 'transparent' }} />
      <span style={{ minWidth: 0, flex: 1 }}>
        <span style={{ display: 'block', fontSize: 12.5, fontWeight: unread ? 700 : 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{n.title}</span>
        <span style={{ display: 'block', fontSize: 11.5, color: 'var(--app-t3)', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{n.message}</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 4 }}>
          <STag color={tone}>{n.type}</STag>
          <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{relTime(n.created_at)}</span>
        </span>
      </span>
    </button>
  );
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const { data, refetch } = useInAppNotifications();

  // Fresh list every time the panel opens (on top of the 60s poll).
  useEffect(() => { if (open) refetch(); }, [open, refetch]);

  const items = data ?? [];
  const unread = items.filter((n) => !n.read_at).length;
  const recent = items.slice(0, 10);

  const markRead = useMutation({
    mutationFn: async (id: string) => {
      const { response } = await clients.notifications.PUT('/tenant/notifications/{id}/read', { params: { path: { id } } });
      if (!response.ok) throw new Error('Failed to mark the notification read');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: QK }),
  });
  const markAllRead = useMutation({
    mutationFn: async () => {
      const { response } = await clients.notifications.PUT('/tenant/notifications/read-all', {});
      if (!response.ok) throw new Error('Failed to mark all notifications read');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: QK }),
  });

  return (
    <div style={{ position: 'relative' }}>
      <button className="ui-btn ghost" title="Notifications" onClick={() => setOpen((v) => !v)} style={{ position: 'relative' }}>
        <Bell size={16} />
        {unread > 0 && (
          <span style={{
            position: 'absolute', top: 2, right: 2, minWidth: 15, height: 15, padding: '0 3px',
            borderRadius: 8, background: RED, color: '#fff', fontSize: 9.5, fontWeight: 700,
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1,
            border: '1px solid var(--app-bg)',
          }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 79 }} />
          <div style={{ position: 'absolute', right: 0, top: 'calc(100% + 6px)', width: 360, zIndex: 80, background: 'var(--app-panel)', border: '1px solid var(--app-border2)', borderRadius: 14, boxShadow: 'var(--app-shadow)', padding: 7, animation: 'popIn .15s ease both' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 10px 9px', borderBottom: '1px solid var(--app-border)', marginBottom: 5 }}>
              <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>Notifications</span>
              <button
                className="ui-btn sm ghost"
                disabled={unread === 0 || markAllRead.isPending}
                onClick={() => markAllRead.mutate()}
              >
                {markAllRead.isPending ? 'Marking…' : 'Mark all read'}
              </button>
            </div>

            {recent.length === 0 ? (
              <div style={{ padding: '22px 10px', textAlign: 'center', fontSize: 12, color: 'var(--app-t3)' }}>No notifications yet</div>
            ) : (
              <div style={{ maxHeight: 380, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
                {recent.map((n) => <NotificationRow key={n.id} n={n} onRead={(id) => markRead.mutate(id)} />)}
              </div>
            )}

            <div style={{ borderTop: '1px solid var(--app-border)', marginTop: 5, paddingTop: 5 }}>
              <Link
                to="/remediation/alerts"
                onClick={() => setOpen(false)}
                className="nav-sub"
                style={{ display: 'block', padding: '8px 10px', borderRadius: 8, textDecoration: 'none', fontSize: 12.5, fontWeight: 600, color: 'var(--accent)' }}
              >
                View alerts →
              </Link>
              <Link
                to="/settings/notification-history"
                onClick={() => setOpen(false)}
                className="nav-sub"
                style={{ display: 'block', padding: '8px 10px', borderRadius: 8, textDecoration: 'none', fontSize: 12.5, fontWeight: 600, color: 'var(--accent)' }}
              >
                View delivery history →
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
