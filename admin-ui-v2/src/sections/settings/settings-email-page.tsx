// Platform Settings — email delivery config (and a home for future platform-wide
// settings that didn't fit the v1 admin-ui's ad-hoc settings-page layout).
// The Email tab is the primary target: it wires the platform SMTP config that
// drives user invitations, password resets, and the onboarding flow.
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Mail, CheckCircle, XCircle, Send } from 'lucide-react';
import { clients } from '../../lib/clients';

// ── types ─────────────────────────────────────────────────────────────────────

interface EmailConfig {
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_password: string;      // always '' from GET; send '' to preserve stored value
  smtp_password_set: boolean; // read-only indicator
  from_email: string;
  from_name: string;
}

const EMPTY_EMAIL: EmailConfig = {
  smtp_host: '', smtp_port: '587', smtp_username: '',
  smtp_password: '', smtp_password_set: false,
  from_email: '', from_name: '',
};

// ── queries ───────────────────────────────────────────────────────────────────

function useEmailConfig() {
  return useQuery({
    queryKey: ['platform', 'settings', 'email'],
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/settings', {});
      if (error || !data) throw new Error('Failed to load settings');
      return (data as any).email_config as EmailConfig | undefined;
    },
    staleTime: 60_000,
  });
}

function useSaveEmailConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (cfg: EmailConfig) => {
      const { error } = await clients.admin.PUT('/admin/settings', {
        body: { email_config: cfg } as any,
      });
      if (error) throw new Error((error as any)?.error ?? 'Save failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'settings', 'email'] }),
  });
}

function useSendTestEmail() {
  return useMutation({
    mutationFn: async (to: string) => {
      const { error } = await clients.admin.POST('/admin/settings/test-email', {
        body: { to },
      });
      if (error) throw new Error((error as any)?.error ?? 'Send failed');
    },
  });
}

// ── field helpers ─────────────────────────────────────────────────────────────

function Field({
  label, value, onChange, type = 'text', placeholder, hint,
}: {
  label: string; value: string; onChange: (v: string) => void;
  type?: string; placeholder?: string; hint?: string;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--op-t2)', letterSpacing: '.03em' }}>{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={type === 'password' ? 'new-password' : 'off'}
        style={{
          background: 'var(--op-input-bg, rgba(255,255,255,.05))', border: '1px solid var(--op-border)',
          borderRadius: 'var(--r-btn)', padding: '7px 10px', color: 'var(--op-t1)', fontSize: 13,
          outline: 'none', width: '100%', boxSizing: 'border-box',
        }}
      />
      {hint && <span style={{ fontSize: 11, color: 'var(--op-t3)' }}>{hint}</span>}
    </div>
  );
}

// ── toast ─────────────────────────────────────────────────────────────────────

function Toast({ msg, ok, onDone }: { msg: string; ok: boolean; onDone: () => void }) {
  return (
    <div
      onClick={onDone}
      style={{
        position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
        background: ok ? 'rgba(34,197,94,.15)' : 'rgba(239,68,68,.15)',
        border: `1px solid ${ok ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.4)'}`,
        borderRadius: 'var(--r-btn)', padding: '10px 16px',
        display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
        color: 'var(--op-t1)', fontSize: 13, maxWidth: 360,
      }}
    >
      {ok ? <CheckCircle size={15} color="var(--ok)" /> : <XCircle size={15} color="var(--danger)" />}
      {msg}
    </div>
  );
}

// ── page ──────────────────────────────────────────────────────────────────────

export function SettingsEmailPage() {
  const { data: stored, isLoading } = useEmailConfig();
  const save = useSaveEmailConfig();
  const sendTest = useSendTestEmail();

  const [form, setForm] = useState<EmailConfig | null>(null);
  const [testTo, setTestTo] = useState('');
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  // Initialise form from stored config once loaded (only if user hasn't started editing).
  const current: EmailConfig = form ?? (stored ? { ...EMPTY_EMAIL, ...stored } : EMPTY_EMAIL);
  const set = (patch: Partial<EmailConfig>) => setForm({ ...current, ...patch });

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  };

  const handleSave = async () => {
    try {
      await save.mutateAsync(current);
      setForm(null); // reset dirty state; next render re-reads from server
      showToast('Email settings saved.', true);
    } catch (e: any) {
      showToast(e.message, false);
    }
  };

  const handleTest = async () => {
    if (!testTo) return;
    try {
      await sendTest.mutateAsync(testTo);
      showToast(`Test email sent to ${testTo}`, true);
    } catch (e: any) {
      showToast(e.message, false);
    }
  };

  return (
    <div className="op-fade" style={{ padding: '24px', maxWidth: 780 }}>
      <div className="op-panel" style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--op-border)', paddingBottom: 16 }}>
          <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
            <Mail size={16} style={{ color: 'var(--op-accent)' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>Email Delivery</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>
              SMTP settings used for user invitations, password resets, and onboarding emails.
            </div>
          </div>
          {stored && (
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--ok)' }}>
              <CheckCircle size={13} />
              Configured
            </div>
          )}
        </div>

        {isLoading ? (
          <div style={{ color: 'var(--op-t3)', fontSize: 13 }}>Loading…</div>
        ) : (
          <>
            {/* SMTP connection */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 14 }}>SMTP Connection</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: 12 }}>
                <Field label="SMTP Host" value={current.smtp_host} onChange={(v) => set({ smtp_host: v })} placeholder="smtp.example.com" />
                <Field label="Port" value={current.smtp_port} onChange={(v) => set({ smtp_port: v })} placeholder="587" />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
                <Field label="Username" value={current.smtp_username} onChange={(v) => set({ smtp_username: v })} placeholder="user@example.com" />
                <Field
                  label="Password"
                  type="password"
                  value={current.smtp_password}
                  onChange={(v) => set({ smtp_password: v })}
                  placeholder={current.smtp_password_set ? '••••••••  (leave blank to keep)' : 'Set password'}
                  hint={current.smtp_password_set ? 'A password is stored. Leave blank to keep it.' : undefined}
                />
              </div>
            </div>

            {/* Sender identity */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 14 }}>Sender Identity</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <Field label="From Email" value={current.from_email} onChange={(v) => set({ from_email: v })} placeholder="noreply@yourplatform.com" />
                <Field label="From Name" value={current.from_name} onChange={(v) => set({ from_name: v })} placeholder="Vista" />
              </div>
            </div>

            {/* actions */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 4, borderTop: '1px solid var(--op-border)' }}>
              <button
                className="op-btn"
                onClick={handleSave}
                disabled={save.isPending}
                style={{ minWidth: 100 }}
              >
                {save.isPending ? 'Saving…' : 'Save settings'}
              </button>

              {/* test email */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
                <input
                  type="email"
                  value={testTo}
                  onChange={(e) => setTestTo(e.target.value)}
                  placeholder="Send test to…"
                  style={{
                    background: 'var(--op-input-bg, rgba(255,255,255,.05))', border: '1px solid var(--op-border)',
                    borderRadius: 'var(--r-btn)', padding: '6px 10px', color: 'var(--op-t1)', fontSize: 13,
                    outline: 'none', width: 200,
                  }}
                />
                <button
                  className="op-btn ghost sm"
                  onClick={handleTest}
                  disabled={sendTest.isPending || !testTo}
                  title="Send a test email using the current settings"
                >
                  <Send size={13} />
                  {sendTest.isPending ? 'Sending…' : 'Test'}
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {toast && <Toast msg={toast.msg} ok={toast.ok} onDone={() => setToast(null)} />}
    </div>
  );
}
