import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { DrawerCloseBtn, DrawerShell, Icon, MetaRow, Pill, SectionLabel } from '../../components/ui';
import { CATEGORY_ICON, PRIORITY_COLOR, SLA_META, STATUS_COLOR, dueDays, slaState, type Ticket } from './meta';
import { safeHttpUrl } from '../../lib/url';

// Ticket detail drawer — fields, linked items, comments, and a status advance.
// Status changes go through PUT /tickets/{id} (the unified ticketing API).

const NEXT_STATUS: Record<string, { to: string; label: string }> = {
  open: { to: 'in_progress', label: 'Start work' },
  in_progress: { to: 'resolved', label: 'Mark resolved' },
  resolved: { to: 'closed', label: 'Close ticket' },
};

export function TicketDrawer({ ticket, onClose }: { ticket: Ticket; onClose: () => void }) {
  const qc = useQueryClient();
  const t = ticket;
  const sla = slaState(t);
  const d = dueDays(t);

  const commentsQ = useQuery({
    queryKey: ['remediation', 'ticket-comments', t.id],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/tickets/{id}/comments', { params: { path: { id: t.id } } });
      if (error || !data) throw new Error('Failed to load comments');
      return data.comments ?? [];
    },
  });

  const advance = useMutation({
    mutationFn: async (to: string) => {
      const { error } = await clients.compliance.PUT('/tickets/{id}', {
        params: { path: { id: t.id } },
        body: { status: to },
      });
      if (error) throw new Error('Failed to update ticket');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['remediation'] }),
  });

  const [comment, setComment] = useState('');
  const postComment = useMutation({
    mutationFn: async (content: string) => {
      const { data, error, response } = await clients.compliance.POST('/tickets/{id}/comments', {
        params: { path: { id: t.id } },
        body: { content },
      });
      if (!response.ok || error || !data) throw new Error('Failed to post comment');
      return data;
    },
    onSuccess: () => {
      setComment('');
      qc.invalidateQueries({ queryKey: ['remediation', 'ticket-comments', t.id] });
    },
  });

  const next = NEXT_STATUS[t.status];
  const comments = commentsQ.data ?? [];

  return (
    <DrawerShell onClose={onClose} width={480}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${PRIORITY_COLOR[t.priority] || 'var(--neutral)'} 12%, transparent)`, color: PRIORITY_COLOR[t.priority] || 'var(--app-t2)' }}>
            <Icon name={CATEGORY_ICON[t.category] || 'wrench'} size={16} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">{t.category} ticket</div>
            <h2 style={{ margin: '4px 0 6px', fontSize: 16.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25 }}>{t.title}</h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              <Pill color={STATUS_COLOR[t.status] || 'var(--app-t2)'} style={{ fontSize: 10.5 }}>{t.status.replace('_', ' ')}</Pill>
              <Pill color={PRIORITY_COLOR[t.priority] || 'var(--app-t2)'} style={{ fontSize: 10.5 }}>{t.priority}</Pill>
              {sla !== 'none' && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600, color: SLA_META[sla].color }}>
                  <span style={{ width: 6, height: 6, borderRadius: 50, background: SLA_META[sla].color }} />
                  {SLA_META[sla].label}{d != null && (d < 0 ? ` · ${-d}d late` : ` · ${d}d left`)}
                </span>
              )}
            </div>
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        {next && (
          <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
            <button
              onClick={() => advance.mutate(next.to)}
              disabled={advance.isPending}
              className="ui-btn accent"
              style={{ width: '100%', justifyContent: 'center', marginTop: 14, height: 32, fontSize: 12.5, opacity: advance.isPending ? 0.6 : 1 }}
            >
              <Icon name="check" size={14} />{advance.isPending ? 'Updating…' : next.label}
            </button>
          </PermissionGate>
        )}
        {advance.isError && <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--danger-text)' }}>Couldn't update the ticket — try again.</div>}
      </div>

      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        {t.description && (
          <>
            <SectionLabel icon="file-text">Description</SectionLabel>
            <p style={{ margin: '4px 0 0', fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)', whiteSpace: 'pre-wrap' }}>{t.description}</p>
          </>
        )}

        <SectionLabel icon="circle-alert">Details</SectionLabel>
        <MetaRow k="Due" v={t.due_date ? t.due_date.slice(0, 10) : 'no due date'} mono />
        <MetaRow k="Assigned to" v={t.assigned_to as string} />
        <MetaRow k="Source" v={t.source} />
        <MetaRow k="Created" v={(t.created_at as string)?.slice(0, 10)} mono />
        <MetaRow k="Updated" v={(t.updated_at as string)?.slice(0, 10)} mono />
        {(t.tags?.length ?? 0) > 0 && (
          <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)', display: 'flex', gap: 5, flexWrap: 'wrap' }}>
            {t.tags!.map((tag) => <span key={tag} className="mono" style={{ fontSize: 11, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 6, padding: '2px 7px' }}>{tag}</span>)}
          </div>
        )}

        {(t.alert_id || t.asset_id || t.certificate_id || t.finding_id || t.crypto_implementation_id || t.external_ticket_url) && (
          <>
            <SectionLabel icon="link">Linked</SectionLabel>
            {t.alert_id && (
              <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)', display: 'flex', justifyContent: 'space-between', gap: 16 }}>
                <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Alert</span>
                <Link to={`/remediation/alerts?alert=${t.alert_id}`} onClick={onClose} className="mono" style={{ fontSize: 12, color: 'var(--info)', textDecoration: 'none' }}>
                  View alert <Icon name="arrow-up-right" size={11} />
                </Link>
              </div>
            )}
            <MetaRow k="Asset" v={t.asset_id ? 'linked' : null} />
            <MetaRow k="Certificate" v={t.certificate_id ? 'linked' : null} />
            <MetaRow k="Finding" v={t.finding_id ? 'linked' : null} />
            <MetaRow k="Crypto config" v={t.crypto_implementation_id ? 'linked' : null} />
            {t.external_ticket_url && (() => {
              const href = safeHttpUrl(t.external_ticket_url); // only http(s); blocks javascript:/data: (#603)
              const label = `${t.external_ticket_system || 'ticket'} · ${t.external_ticket_id || 'open'}`;
              return (
                <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)', display: 'flex', justifyContent: 'space-between', gap: 16 }}>
                  <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>External</span>
                  {href ? (
                    <a href={href} target="_blank" rel="noreferrer noopener" className="mono" style={{ fontSize: 12, color: 'var(--info)', textDecoration: 'none' }}>
                      {label} <Icon name="arrow-up-right" size={11} />
                    </a>
                  ) : (
                    <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }} title="Link hidden — not a valid http(s) URL">{label}</span>
                  )}
                </div>
              );
            })()}
          </>
        )}

        <SectionLabel icon="activity">Comments ({commentsQ.isLoading ? '…' : comments.length})</SectionLabel>
        {commentsQ.isLoading ? (
          <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>Loading comments…</div>
        ) : comments.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No comments yet.</div>
        ) : (
          comments.map((c) => (
            <div key={c.id} style={{ padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 12.5, color: 'var(--app-t1)', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{c.content}</div>
              <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                {!c.author_id && (
                  <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 0.4, color: 'var(--app-t3)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 5, padding: '1px 5px' }}>SYSTEM</span>
                )}
                {(c.created_at as string)?.slice(0, 16).replace('T', ' ')}
              </div>
            </div>
          ))
        )}

        <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
          <div style={{ marginTop: 12 }}>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              placeholder="Add a comment…"
              disabled={postComment.isPending}
              onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && comment.trim()) postComment.mutate(comment.trim()); }}
              style={{ width: '100%', padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, outline: 'none', resize: 'vertical', lineHeight: 1.5 }}
            />
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginTop: 7 }}>
              <span style={{ fontSize: 10.5, color: postComment.isError ? 'var(--danger-text)' : 'var(--app-t3)' }}>
                {postComment.isError ? "Couldn't post — try again." : '⌘/Ctrl + Enter to post'}
              </span>
              <button
                className="ui-btn sm accent"
                disabled={!comment.trim() || postComment.isPending}
                onClick={() => postComment.mutate(comment.trim())}
                style={{ opacity: !comment.trim() || postComment.isPending ? 0.6 : 1 }}
              >
                <Icon name="activity" size={13} />{postComment.isPending ? 'Posting…' : 'Comment'}
              </button>
            </div>
          </div>
        </PermissionGate>
      </div>
    </DrawerShell>
  );
}
