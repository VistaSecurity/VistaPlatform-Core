// Platform Settings — AI assistant. The platform half of model-provider
// configuration:
//   • the DEFAULT provider every organization gets when it has none of its own
//     (and the one platform-scope features — the catalogue's "Propose with AI",
//     drafting into the shared framework catalogue — use);
//   • whether organizations may connect their own provider at all;
//   • whether an organization's own endpoint may be on a private address.
//
// A provider set here OVERRIDES the one set at install (the chart's `ai.*`
// values). The page shows both and says which is in effect, because a value
// set in a console should visibly win over one nobody can see from it.
//
// The API key is write-only: the page shows whether one is stored and its last
// four characters, never the key.
import { useState } from 'react';
import { Link } from 'react-router';
import { Sparkles, CheckCircle, XCircle, AlertTriangle, PlugZap, Unplug } from 'lucide-react';
import { usePlatformEdition } from '../../lib/edition';
import {
  formFrom, inEffectSummary, providerKindLabel, requestBody, validateForm,
  useClearPlatformAIProvider, usePlatformAI, useSavePlatformAIProvider,
  useSavePlatformAITenantPolicy, useTestPlatformAIProvider,
  type PlatformAISettings, type PlatformAITestResult, type ProviderForm,
} from './ai-queries';

const inputStyle: React.CSSProperties = {
  background: 'var(--op-input-bg, rgba(255,255,255,.05))', border: '1px solid var(--op-border)',
  borderRadius: 'var(--r-btn)', padding: '7px 10px', color: 'var(--op-t1)', fontSize: 13,
  outline: 'none', width: '100%', boxSizing: 'border-box',
};

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--op-t2)', letterSpacing: '.03em' }}>{label}</label>
      {children}
      {hint && <span style={{ fontSize: 11, color: 'var(--op-t3)', lineHeight: 1.5 }}>{hint}</span>}
    </div>
  );
}

function Switch({ checked, disabled, onChange, label }: { checked: boolean; disabled?: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label style={{ display: 'inline-flex', alignItems: 'center', cursor: disabled ? 'default' : 'pointer', flex: 'none' }}>
      <input type="checkbox" aria-label={label} checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)}
        style={{ position: 'absolute', opacity: 0, width: 0, height: 0 }} />
      <span style={{
        width: 38, height: 22, borderRadius: 22, position: 'relative', transition: 'background .15s',
        background: checked ? 'var(--op-accent, var(--accent))' : 'rgba(255,255,255,.14)', opacity: disabled ? 0.5 : 1,
      }}>
        <span style={{ position: 'absolute', top: 3, left: checked ? 19 : 3, width: 16, height: 16, borderRadius: 16, background: '#fff', transition: 'left .15s' }} />
      </span>
    </label>
  );
}

function SwitchRow({ title, description, warning, checked, disabled, onChange }: {
  title: string; description: React.ReactNode; warning?: string; checked: boolean; disabled?: boolean; onChange: (v: boolean) => void;
}) {
  return (
    <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', padding: '14px 0', borderTop: '1px solid var(--op-border)' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13.5, color: 'var(--op-t1)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 3, lineHeight: 1.5 }}>{description}</div>
        {warning && <div style={{ fontSize: 12, color: 'var(--warn)', marginTop: 6, lineHeight: 1.5 }}>{warning}</div>}
      </div>
      <div style={{ marginTop: 4 }}><Switch label={title} checked={checked} disabled={disabled} onChange={onChange} /></div>
    </div>
  );
}

function PanelHead({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
        <Sparkles size={16} style={{ color: 'var(--op-accent)' }} />
      </div>
      <div>
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>{subtitle}</div>
      </div>
    </div>
  );
}

// Mounted with a key derived from the stored provider, so a save or a clear
// re-opens the form on what is now stored without an effect to copy it in.
function ProviderPanel({ settings, onDone }: { settings: PlatformAISettings; onDone: (msg: string) => void }) {
  const save = useSavePlatformAIProvider();
  const clear = useClearPlatformAIProvider();
  const test = useTestPlatformAIProvider();

  const [form, setForm] = useState<ProviderForm>(() => formFrom(settings));
  const [localError, setLocalError] = useState<string | null>(null);
  const [result, setResult] = useState<PlatformAITestResult | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const hasSavedKey = Boolean(settings.provider?.has_key);
  const kinds = settings.provider_kinds;
  const isCompat = form.kind === 'openai_compat';
  const busy = save.isPending || test.isPending || clear.isPending;
  const summary = inEffectSummary(settings);

  const set = (patch: Partial<ProviderForm>) => {
    setForm((f) => ({ ...f, ...patch }));
    setLocalError(null);
    setResult(null);
  };
  const guard = (run: () => void) => () => {
    const problem = validateForm(form, hasSavedKey, settings.can_store_credentials);
    if (problem) { setLocalError(problem); return; }
    run();
  };
  const serverError =
    (save.isError && save.error.message) || (test.isError && test.error.message) || (clear.isError && clear.error.message) || null;

  return (
    <div className="op-panel" style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PanelHead title="Default model provider" subtitle="Answers for every organization that has not connected its own, and for platform features such as “Propose with AI”." />

      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 12.5, lineHeight: 1.5, color: 'var(--op-t2)' }}>
        {summary.ok
          ? <PlugZap size={15} color="var(--ok)" style={{ flex: 'none', marginTop: 2 }} />
          : <Unplug size={15} color="var(--op-t3)" style={{ flex: 'none', marginTop: 2 }} />}
        <span>{summary.text}</span>
      </div>
      {settings.problem && (
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 12.5, lineHeight: 1.5, color: 'var(--warn)' }}>
          <AlertTriangle size={15} style={{ flex: 'none', marginTop: 2 }} />
          <span>{settings.problem}</span>
        </div>
      )}
      {!settings.can_store_credentials && kinds.length > 0 && (
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 12.5, lineHeight: 1.5, color: 'var(--warn)' }}>
          <AlertTriangle size={15} style={{ flex: 'none', marginTop: 2 }} />
          <span>This deployment has no encryption key (ENCRYPTION_MASTER_KEY), so an API key cannot be stored — here or by an organization. An endpoint that needs no key can still be saved.</span>
        </div>
      )}

      {kinds.length > 0 && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14 }}>
            <Field label="Provider">
              <select value={form.kind} disabled={busy} onChange={(e) => set({ kind: e.target.value })} style={inputStyle}>
                {kinds.map((k) => <option key={k} value={k}>{providerKindLabel(k)}</option>)}
              </select>
            </Field>
            <Field label="Model" hint={isCompat ? 'The model id the endpoint serves.' : 'Leave blank for the provider’s default.'}>
              <input value={form.model} disabled={busy} placeholder={isCompat ? 'Required' : 'Optional'} onChange={(e) => set({ model: e.target.value })} style={inputStyle} autoComplete="off" />
            </Field>
          </div>
          <Field
            label="Base URL"
            hint={isCompat
              ? 'The endpoint’s address, as far as its own documentation writes it — e.g. https://llm.example.com/v1 or http://ollama.models.svc:11434/v1.'
              : 'Leave blank to use Anthropic’s public API.'}
          >
            <input value={form.baseUrl} disabled={busy} placeholder={isCompat ? 'https://…' : 'Optional'} onChange={(e) => set({ baseUrl: e.target.value })} style={inputStyle} autoComplete="off" />
          </Field>
          <Field
            label="API key"
            hint={hasSavedKey
              ? `Leave blank to keep the stored key${settings.provider?.api_key_hint ? ` (ending ${settings.provider.api_key_hint})` : ''}. A changed provider or address needs the key again.`
              : isCompat ? 'Leave blank if the endpoint needs none. Stored encrypted; never shown again.' : 'Stored encrypted; never shown again.'}
          >
            <input type="password" value={form.apiKey} disabled={busy} placeholder={hasSavedKey ? '••••••••' : ''} onChange={(e) => set({ apiKey: e.target.value })} style={inputStyle} autoComplete="new-password" />
          </Field>
          <SwitchRow
            title="This endpoint is on a private network"
            description="Required for a loopback, private or in-cluster address — your own model running beside the platform. Leave it off for a public endpoint: it is what stops a mistyped address from reaching something inside the cluster."
            checked={form.allowPrivate}
            disabled={busy}
            onChange={(allowPrivate) => set({ allowPrivate })}
          />

          {result && (
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 12.5, lineHeight: 1.5, color: result.ok ? 'var(--ok)' : 'var(--warn)' }}>
              {result.ok ? <CheckCircle size={15} style={{ flex: 'none', marginTop: 2 }} /> : <AlertTriangle size={15} style={{ flex: 'none', marginTop: 2 }} />}
              <span>
                {result.ok
                  ? `Connection works — answered as ${result.model_id ?? 'the configured model'}${typeof result.latency_ms === 'number' ? ` in ${result.latency_ms} ms` : ''}.`
                  : (result.message ?? 'The provider did not answer.')}
              </span>
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <button className="op-btn" disabled={busy} onClick={guard(() => save.mutate(requestBody(form, hasSavedKey), { onSuccess: () => onDone('Provider saved.') }))}>
              {save.isPending ? 'Saving…' : 'Save'}
            </button>
            <button className="op-btn ghost" disabled={busy} onClick={guard(() => test.mutate(requestBody(form, hasSavedKey), { onSuccess: setResult }))}>
              {test.isPending ? 'Testing…' : 'Test connection'}
            </button>
            {settings.provider && !confirmClear && (
              <button className="op-btn ghost sm" disabled={busy} style={{ color: 'var(--danger)' }} onClick={() => setConfirmClear(true)}>Clear</button>
            )}
            {settings.provider && confirmClear && (
              <>
                <span style={{ fontSize: 12, color: 'var(--op-t2)' }}>
                  Remove this provider and its stored key?{settings.environment ? ' The one set at install takes over.' : ' Organizations without their own will have none.'}
                </span>
                <button className="op-btn sm" disabled={busy} style={{ background: 'var(--danger)', borderColor: 'var(--danger)', color: '#fff' }}
                  onClick={() => clear.mutate(undefined, { onSuccess: () => onDone('Provider cleared.') })}>
                  {clear.isPending ? 'Clearing…' : 'Clear'}
                </button>
                <button className="op-btn ghost sm" disabled={busy} onClick={() => setConfirmClear(false)}>Cancel</button>
              </>
            )}
            {(localError ?? serverError) && <span style={{ fontSize: 12, color: 'var(--danger)' }}>{localError ?? serverError}</span>}
          </div>
        </>
      )}
    </div>
  );
}

function TenantPolicyPanel({ settings }: { settings: PlatformAISettings }) {
  const save = useSavePlatformAITenantPolicy();
  const { isMsp } = usePlatformEdition();
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const setKey = (body: Parameters<typeof save.mutate>[0]) => {
    save.mutate(body, {
      onSuccess: () => { setToast({ msg: 'Saved.', ok: true }); setTimeout(() => setToast(null), 4000); },
      onError: (e) => { setToast({ msg: e.message, ok: false }); setTimeout(() => setToast(null), 6000); },
    });
  };

  return (
    <div className="op-panel" style={{ padding: '20px 22px' }}>
      <div style={{ paddingBottom: 14 }}>
        <PanelHead title="Organizations’ own providers" subtitle="Whether an organization may connect a provider of its own from its Settings → AI assistant page." />
      </div>
      <SwitchRow
        title="Organizations may connect their own provider"
        description={isMsp
          ? <>When on, an organization whose plan includes it can connect its own provider, which then answers for that organization instead of the default. The plan lever is <Link to="/plans/entitlements" style={{ color: 'var(--op-accent)' }}>Own AI Model Provider</Link> under Plans &amp; Pricing → Entitlements, and it is off in every plan until you turn it on.</>
          : 'When on, an organization can connect its own provider, which then answers for that organization instead of the default. Turn it off to make the default the only provider anyone uses.'}
        warning={settings.tenant_providers_allowed ? undefined : 'Off — every organization uses the default provider (or none). Providers already saved by organizations are kept but not used.'}
        checked={settings.tenant_providers_allowed}
        disabled={save.isPending}
        onChange={(v) => setKey({ tenant_providers_allowed: v })}
      />
      <SwitchRow
        title="Their endpoint may be on a private network"
        description="When off (the default), an organization can only connect a provider at a public address. Turn it on only if organizations should reach a model inside your network or cluster — it lets an organization-supplied address point at private address space."
        warning={settings.tenant_private_endpoints_allowed ? 'On — an address an organization types may reach hosts on your private network.' : undefined}
        checked={settings.tenant_private_endpoints_allowed}
        disabled={save.isPending || !settings.tenant_providers_allowed}
        onChange={(v) => setKey({ tenant_private_endpoints_allowed: v })}
      />
      {toast && (
        <div onClick={() => setToast(null)} style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          background: toast.ok ? 'rgba(34,197,94,.15)' : 'rgba(239,68,68,.15)',
          border: `1px solid ${toast.ok ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.4)'}`,
          borderRadius: 'var(--r-btn)', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 10,
          cursor: 'pointer', color: 'var(--op-t1)', fontSize: 13, maxWidth: 360,
        }}>
          {toast.ok ? <CheckCircle size={15} color="var(--ok)" /> : <XCircle size={15} color="var(--danger)" />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}

export function SettingsAIPage() {
  const { data, isLoading, isError, refetch } = usePlatformAI();
  const [flash, setFlash] = useState<string | null>(null);
  const done = (msg: string) => { setFlash(msg); setTimeout(() => setFlash(null), 4000); };

  return (
    <div className="op-fade" style={{ padding: '24px', maxWidth: 780, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {isError ? (
        <div className="op-panel" style={{ padding: '20px 22px' }}>
          <div style={{ fontSize: 13, color: 'var(--op-t1)', fontWeight: 600 }}>Couldn’t load the AI assistant settings</div>
          <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 4 }}>Nothing has changed. Try again.</div>
          <button className="op-btn ghost sm" style={{ marginTop: 12 }} onClick={() => void refetch()}>Try again</button>
        </div>
      ) : isLoading || !data ? (
        <div className="op-panel" style={{ padding: '20px 22px', color: 'var(--op-t3)', fontSize: 13 }}>Loading…</div>
      ) : (
        <>
          <ProviderPanel key={JSON.stringify(data.provider ?? null)} settings={data} onDone={done} />
          {data.provider_kinds.length > 0 && <TenantPolicyPanel settings={data} />}
        </>
      )}
      {flash && (
        <div onClick={() => setFlash(null)} style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999, background: 'rgba(34,197,94,.15)',
          border: '1px solid rgba(34,197,94,.4)', borderRadius: 'var(--r-btn)', padding: '10px 16px',
          display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', color: 'var(--op-t1)', fontSize: 13, maxWidth: 360,
        }}>
          <CheckCircle size={15} color="var(--ok)" />
          {flash}
        </div>
      )}
    </div>
  );
}
