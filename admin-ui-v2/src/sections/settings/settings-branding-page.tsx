// Platform Settings — Branding (white-labeling). Ports the v1 admin-ui's
// "Appearance & Design System" surface (stranded by the v2 cutover) onto the
// typed admin client. Lets a platform admin rebrand the whole product:
//   • Product name  → platform_settings.platform_name (PUT /admin/settings)
//   • Header logo   → type=logo        (POST/DELETE /admin/branding)
//   • Login logo    → type=login_logo
//   • Favicon       → type=favicon
// All three assets persist to platform_settings and are served publicly by
// auth-service GET /platform/config (login screen + both UIs read it on load).
// Writes are RBAC-gated server-side (platform.settings); 403s surface as toasts.
import { useRef, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Paintbrush, CheckCircle, XCircle, Upload, Trash2, Image as ImageIcon } from 'lucide-react';
import { clients } from '../../lib/clients';

// ── types ─────────────────────────────────────────────────────────────────────

type AssetType = 'logo' | 'login_logo' | 'favicon';

interface BrandingSettings {
  platform_name: string;
  platform_logo_url?: string;
  platform_login_logo_url?: string;
  platform_favicon_url?: string;
}

const SETTINGS_KEY = ['platform', 'settings', 'branding'] as const;

// ── queries ───────────────────────────────────────────────────────────────────

function useBranding() {
  return useQuery({
    queryKey: SETTINGS_KEY,
    queryFn: async (): Promise<BrandingSettings> => {
      const { data, error } = await clients.admin.GET('/admin/settings', {});
      if (error || !data) throw new Error('Failed to load settings');
      const s = data as Partial<BrandingSettings>;
      return {
        platform_name: s.platform_name ?? '',
        platform_logo_url: s.platform_logo_url,
        platform_login_logo_url: s.platform_login_logo_url,
        platform_favicon_url: s.platform_favicon_url,
      };
    },
    staleTime: 60_000,
  });
}

function useSaveName() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (platform_name: string) => {
      const { error } = await clients.admin.PUT('/admin/settings', {
        body: { platform_name } as Record<string, unknown>,
      });
      if (error) throw new Error((error as { error?: string })?.error ?? 'Save failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SETTINGS_KEY }),
  });
}

function useUploadAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ type, file }: { type: AssetType; file: File }) => {
      const { error, response } = await clients.admin.POST('/admin/branding/upload', {
        body: { type, file: '' } as never,
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('type', type);
          fd.append('file', file);
          return fd;
        },
      });
      if (error || !response.ok) {
        throw new Error((error as { error?: string })?.error ?? 'Upload failed');
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SETTINGS_KEY }),
  });
}

function useDeleteAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (type: AssetType) => {
      const { error } = await clients.admin.DELETE('/admin/branding/{type}', {
        params: { path: { type } },
      });
      if (error) throw new Error((error as { error?: string })?.error ?? 'Remove failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: SETTINGS_KEY }),
  });
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

// ── asset uploader ──────────────────────────────────────────────────────────────

function AssetRow({
  label, hint, specs, url, square, previewBg, canRemove, onUpload, onRemove, busy,
}: {
  type: AssetType; label: string; hint: string; specs: string; url?: string; square?: boolean;
  /** Background the asset actually renders on, so the preview is truthful. */
  previewBg?: string;
  canRemove: boolean; onUpload: (f: File) => void; onRemove: () => void; busy: boolean;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const box = square ? 56 : 64;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '14px 0', borderBottom: '1px solid var(--op-border)' }}>
      <div
        style={{
          width: box, height: box, flex: 'none', borderRadius: 'var(--r-btn)',
          border: '1.5px dashed var(--op-border)', background: previewBg || 'var(--op-input-bg, rgba(255,255,255,.04))',
          display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', color: 'var(--op-t3)',
        }}
      >
        {url
          ? <img src={url} alt={label} style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
          : <ImageIcon size={20} />}
      </div>

      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--op-t1)' }}>{label}</div>
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>{hint}</div>
        <div style={{ fontSize: 11, color: 'var(--op-t2)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--op-accent)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', borderRadius: 4, padding: '1px 5px' }}>Suggested</span>
          <span className="mono">{specs}</span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 'none' }}>
        <input
          ref={fileRef} type="file" accept="image/png,image/jpeg,image/x-icon" style={{ display: 'none' }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) onUpload(f); e.target.value = ''; }}
        />
        <button className="op-btn ghost sm" disabled={busy} onClick={() => fileRef.current?.click()}>
          <Upload size={13} />
          {busy ? 'Uploading…' : url ? 'Change' : 'Upload'}
        </button>
        {url && canRemove && (
          <button className="op-btn ghost sm" disabled={busy} onClick={onRemove} title={`Remove ${label.toLowerCase()}`} style={{ color: 'var(--danger)' }}>
            <Trash2 size={13} />
          </button>
        )}
      </div>
    </div>
  );
}

// ── page ──────────────────────────────────────────────────────────────────────

export function SettingsBrandingPage() {
  const { data, isLoading } = useBranding();
  const saveName = useSaveName();
  const upload = useUploadAsset();
  const remove = useDeleteAsset();

  const [name, setName] = useState<string | null>(null);
  const [pending, setPending] = useState<AssetType | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  };

  const currentName = name ?? data?.platform_name ?? '';
  const nameDirty = name !== null && name.trim() !== (data?.platform_name ?? '');

  const handleSaveName = async () => {
    try {
      await saveName.mutateAsync(currentName.trim());
      setName(null);
      showToast('Product name saved.', true);
    } catch (e) {
      showToast((e as Error).message, false);
    }
  };

  const doUpload = async (type: AssetType, file: File) => {
    // Client-side guardrails mirroring the server (PNG/JPEG/ICO, ≤5MB).
    const allowed = ['image/png', 'image/jpeg', 'image/x-icon', 'image/vnd.microsoft.icon'];
    if (!allowed.includes(file.type)) { showToast('Only PNG, JPEG, or ICO are allowed.', false); return; }
    if (file.size > 5 * 1024 * 1024) { showToast('File too large — max 5MB.', false); return; }
    setPending(type);
    try {
      await upload.mutateAsync({ type, file });
      showToast('Asset uploaded.', true);
    } catch (e) {
      showToast((e as Error).message, false);
    } finally {
      setPending(null);
    }
  };

  const doRemove = async (type: AssetType) => {
    setPending(type);
    try {
      await remove.mutateAsync(type);
      showToast('Asset removed.', true);
    } catch (e) {
      showToast((e as Error).message, false);
    } finally {
      setPending(null);
    }
  };

  return (
    <div className="op-fade" style={{ padding: '24px', maxWidth: 780 }}>
      <div className="op-panel" style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--op-border)', paddingBottom: 16 }}>
          <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
            <Paintbrush size={16} style={{ color: 'var(--op-accent)' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>Branding</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>
              White-label the platform — product name and logos shown across the console and login screen.
            </div>
          </div>
        </div>

        {isLoading ? (
          <div style={{ color: 'var(--op-t3)', fontSize: 13 }}>Loading…</div>
        ) : (
          <>
            {/* product identity */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 14 }}>Product Identity</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--op-t2)', letterSpacing: '.03em' }}>Product name</label>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <input
                    value={currentName}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Vista Platform"
                    style={{
                      background: 'var(--op-input-bg, rgba(255,255,255,.05))', border: '1px solid var(--op-border)',
                      borderRadius: 'var(--r-btn)', padding: '7px 10px', color: 'var(--op-t1)', fontSize: 13,
                      outline: 'none', flex: 1, boxSizing: 'border-box',
                    }}
                  />
                  <button className="op-btn" onClick={handleSaveName} disabled={!nameDirty || saveName.isPending} style={{ minWidth: 90 }}>
                    {saveName.isPending ? 'Saving…' : 'Save name'}
                  </button>
                </div>
                <span style={{ fontSize: 11, color: 'var(--op-t3)' }}>Replaces the wordmark when no logo is set; used on the login screen and in emails.</span>
              </div>
            </div>

            {/* logos */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 6 }}>Logos &amp; Favicon</div>
              <AssetRow
                type="logo" label="Header logo"
                hint="Top-left of the sidebar (shown ~30px). Tenant sidebar is dark in dark mode but white in light mode — use a logo that reads on both, or a transparent PNG."
                specs="Square PNG, 128×128 px (min 64). Transparent background."
                previewBg="#070707"
                url={data?.platform_logo_url} canRemove busy={pending === 'logo'}
                onUpload={(f) => doUpload('logo', f)} onRemove={() => doRemove('logo')}
              />
              <AssetRow
                type="login_logo" label="Login logo"
                hint="Sign-in screen lockup (shown ~38px). Always on a dark background, both themes — design for dark."
                specs="Square PNG, 128×128 px (min 96). Transparent background."
                previewBg="#0A0A0A"
                url={data?.platform_login_logo_url} canRemove busy={pending === 'login_logo'}
                onUpload={(f) => doUpload('login_logo', f)} onRemove={() => doRemove('login_logo')}
              />
              <AssetRow
                type="favicon" label="Favicon" square
                hint="Browser-tab icon. Sits on the browser's own tab background, so keep it square with a transparent or solid fill."
                specs="Square, 48×48 px (or 32×32). PNG or ICO."
                url={data?.platform_favicon_url} canRemove busy={pending === 'favicon'}
                onUpload={(f) => doUpload('favicon', f)} onRemove={() => doRemove('favicon')}
              />
            </div>

            <p style={{ fontSize: 12, color: 'var(--op-t3)', lineHeight: 1.55, margin: 0 }}>
              Changes apply to the console and login screen after the next sign-in or refresh.
              SVG is intentionally not accepted (stored-XSS risk).
            </p>
          </>
        )}
      </div>

      {toast && <Toast msg={toast.msg} ok={toast.ok} onDone={() => setToast(null)} />}
    </div>
  );
}
