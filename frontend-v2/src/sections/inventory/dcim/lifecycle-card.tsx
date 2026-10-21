// The asset Hardware tab's Lifecycle card (DCIM gap 4): what the asset cost
// and who sold it, its warranty and support contract, when it went in and came
// out — all DECLARED, by a person here or by an import — and the two computed
// states the server derives from them: the warranty, and the end of support
// (the earlier of the device type's and the platform's, each declared on the
// catalogue or taken from the end-of-life catalogue entry it is linked to).
//
// Three-valued honesty: a field nobody recorded reads "Not recorded", never a
// blank that looks like an answer, and a state with nothing behind it is "Not
// recorded" too — never "Active" or "Supported" by default.
//
// Reads need dcim.read (the tab's gate); Edit needs dcim.manage.
import { useState } from 'react';
import { Icon, ModalField, ModalInput } from '../../../components/ui';
import {
  useAssetHardware, usePatchAssetLifecycle,
  type AssetCommercial, type AssetLifecycle, type CatalogueEOS, type EOSDate, type HardwarePatch,
} from './catalogue-queries';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';

type Tone = 'ok' | 'warn' | 'danger' | 'muted';

const WARRANTY: Record<AssetLifecycle['warranty_state'], { label: string; tone: Tone }> = {
  active: { label: 'Under warranty', tone: 'ok' },
  expiring_90: { label: 'Warranty ends within 90 days', tone: 'warn' },
  expired: { label: 'Warranty expired', tone: 'danger' },
  unknown: { label: 'Warranty not recorded', tone: 'muted' },
};

const EOS: Record<AssetLifecycle['eos_state'], { label: string; tone: Tone }> = {
  supported: { label: 'Supported', tone: 'ok' },
  eos_within_12m: { label: 'End of support within 12 months', tone: 'warn' },
  past_eos: { label: 'Past end of support', tone: 'danger' },
  unknown: { label: 'End of support not recorded', tone: 'muted' },
};

const TONE: Record<Tone, string> = { ok: 'var(--ok)', warn: 'var(--warn)', danger: 'var(--danger-text)', muted: 'var(--app-t3)' };

/** The warranty badge's words and tone. */
export function warrantyBadge(state: AssetLifecycle['warranty_state']) {
  return WARRANTY[state] ?? WARRANTY.unknown;
}

/** The end-of-support badge's words and tone. */
export function eosBadge(state: AssetLifecycle['eos_state']) {
  return EOS[state] ?? EOS.unknown;
}

/** Where the effective end of support came from, in words; null when there is no date. */
export function eosSourceText(lc: AssetLifecycle): string | null {
  if (!lc.effective_end_of_support) return null;
  const whose = lc.subject === 'platform' ? 'the platform (OS)' : 'the device type';
  const how = lc.source === 'catalogue' ? 'the end-of-life catalogue' : 'declared';
  return `${lc.effective_end_of_support} — ${whose}, ${how}`;
}

/** A cost with its currency; the amount alone when no (valid) currency is recorded. */
export function costText(cost: number | null | undefined, currency: string | null | undefined): string | null {
  if (cost === null || cost === undefined) return null;
  if (currency && /^[A-Z]{3}$/.test(currency)) {
    try {
      return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(cost);
    } catch {
      return `${cost.toFixed(2)} ${currency}`;
    }
  }
  return `${cost.toFixed(2)} (no currency recorded)`;
}

function Badge({ label, tone, testId }: { label: string; tone: Tone; testId: string }) {
  return (
    <span data-testid={testId} data-tone={tone} style={{
      fontSize: 11.5, fontWeight: 600, padding: '2px 8px', borderRadius: 7, color: TONE[tone],
      background: `color-mix(in srgb, ${TONE[tone]} 12%, transparent)`,
    }}>{label}</span>
  );
}

function Row({ k, v, mono }: { k: string; v: string | null | undefined; mono?: boolean }) {
  const has = v !== null && v !== undefined && v !== '';
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '5px 0', fontSize: 12.5 }}>
      <span style={{ color: 'var(--app-t3)' }}>{k}</span>
      <span className={mono && has ? 'mono' : undefined} style={{ color: has ? 'var(--app-t1)' : 'var(--app-t3)', textAlign: 'right' }}>
        {has ? v : 'Not recorded'}
      </span>
    </div>
  );
}

function sourceTag(d: EOSDate): string {
  return d.source === 'catalogue' ? 'from the end-of-life catalogue' : d.source === 'declared' ? 'declared' : '';
}

function EOSRows({ title, eos }: { title: string; eos: CatalogueEOS | null }) {
  if (!eos) return null;
  const line = (label: string, d: EOSDate) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', fontSize: 12.5 }}>
      <span style={{ color: 'var(--app-t3)' }}>{label}</span>
      {d.date
        ? <span><span className="mono" style={{ color: 'var(--app-t1)' }}>{d.date}</span> <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{sourceTag(d)}</span></span>
        : <span style={{ color: 'var(--app-t3)' }}>Not recorded</span>}
    </div>
  );
  return (
    <div data-testid={`eos-${title === 'Device type' ? 'device-type' : 'platform'}`} style={{ marginTop: 8 }}>
      <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--app-t2)', textTransform: 'uppercase', letterSpacing: 0.4 }}>{title}</div>
      {line('End of sale', eos.end_of_sale)}
      {line('End of support', eos.end_of_support)}
      {line('End of life', eos.end_of_life)}
    </div>
  );
}

const FIELDS: { key: keyof AssetCommercial; label: string; kind: 'date' | 'text' | 'money' | 'currency' }[] = [
  { key: 'purchase_date', label: 'Purchase date', kind: 'date' },
  { key: 'purchase_cost', label: 'Purchase cost', kind: 'money' },
  { key: 'purchase_currency', label: 'Currency', kind: 'currency' },
  { key: 'purchase_order', label: 'Purchase order', kind: 'text' },
  { key: 'vendor', label: 'Vendor (seller)', kind: 'text' },
  { key: 'warranty_start', label: 'Warranty start', kind: 'date' },
  { key: 'warranty_end', label: 'Warranty end', kind: 'date' },
  { key: 'support_contract', label: 'Support contract', kind: 'text' },
  { key: 'support_contract_end', label: 'Support contract ends', kind: 'date' },
  { key: 'installed_at', label: 'Installed', kind: 'date' },
  { key: 'decommissioned_at', label: 'Decommissioned', kind: 'date' },
];

type Draft = Record<keyof AssetCommercial, string>;

/** What an older server (no commercial lifecycle) is read as: nothing recorded, every state unknown. */
export const NOT_RECORDED: AssetCommercial = {
  purchase_date: null, warranty_start: null, warranty_end: null, purchase_cost: null, purchase_currency: null, purchase_order: null,
  vendor: null, support_contract: null, support_contract_end: null, installed_at: null, decommissioned_at: null,
};
export const UNKNOWN_LIFECYCLE: AssetLifecycle = { warranty_state: 'unknown', eos_state: 'unknown', effective_end_of_support: null, source: 'none', subject: null };

export function draftOfCommercial(c: AssetCommercial): Draft {
  const out = {} as Draft;
  for (const f of FIELDS) {
    const v = c[f.key];
    out[f.key] = v === null || v === undefined ? '' : f.kind === 'money' ? Number(v).toFixed(2) : String(v);
  }
  return out;
}

/** What the person changed, as the PATCH body ("" clears to null), or a reason it cannot be sent. */
export function commercialChanges(base: Draft, draft: Draft): { body: HardwarePatch | null; error: string | null } {
  const d = (k: keyof AssetCommercial) => draft[k].trim();
  if (d('purchase_cost') && !/^\d{1,12}(\.\d{1,2})?$/.test(d('purchase_cost'))) {
    return { body: null, error: 'Purchase cost is a non-negative amount with at most two decimals.' };
  }
  if (d('purchase_currency') && !/^[A-Za-z]{3}$/.test(d('purchase_currency'))) {
    return { body: null, error: 'Currency is a three-letter ISO 4217 code, such as USD or EUR.' };
  }
  if (d('warranty_start') && d('warranty_end') && d('warranty_end') < d('warranty_start')) {
    return { body: null, error: 'The warranty cannot end before it starts.' };
  }
  if (d('installed_at') && d('decommissioned_at') && d('decommissioned_at') < d('installed_at')) {
    return { body: null, error: 'An asset cannot be decommissioned before it was installed.' };
  }
  const body: Record<string, string | null> = {};
  for (const f of FIELDS) {
    if (d(f.key) !== base[f.key].trim()) body[f.key] = d(f.key) === '' ? null : f.kind === 'currency' ? d(f.key).toUpperCase() : d(f.key);
  }
  return { body: Object.keys(body).length ? body : null, error: null };
}

function anyRecorded(c: AssetCommercial): boolean {
  return FIELDS.some((f) => c[f.key] !== null && c[f.key] !== undefined);
}

export function LifecycleCard({ assetId, canManage }: { assetId: string; canManage: boolean }) {
  const q = useAssetHardware(assetId);
  const patch = usePatchAssetLifecycle(assetId);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const hw = q.data;

  let body: React.ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading the lifecycle…" />;
  else if (q.isError) body = <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  else if (hw && draft) {
    const base = draftOfCommercial(hw.commercial ?? NOT_RECORDED);
    const save = () => {
      const { body: b, error: e } = commercialChanges(base, draft);
      if (e) { setError(e); return; }
      if (!b) { setDraft(null); return; }
      setError(null);
      patch.mutate(b, { onSuccess: () => setDraft(null), onError: (err) => setError(err.message) });
    };
    body = (
      <div data-testid="lifecycle-form">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: '0 14px' }}>
          {FIELDS.map((f) => (
            <ModalField key={f.key} label={f.label}>
              <ModalInput aria-label={f.label} type={f.kind === 'date' ? 'date' : 'text'} inputMode={f.kind === 'money' ? 'decimal' : undefined}
                className={f.kind === 'currency' || f.kind === 'money' ? 'mono' : undefined}
                placeholder={f.kind === 'currency' ? 'USD' : f.kind === 'money' ? '4200.00' : undefined}
                value={draft[f.key]} onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })} />
            </ModalField>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
          <button type="button" className="ui-btn sm" onClick={() => { setDraft(null); setError(null); }} disabled={patch.isPending}>Cancel</button>
          <button type="button" className="ui-btn sm accent" data-testid="lifecycle-save" onClick={save} disabled={patch.isPending}>
            <Icon name="check" size={12} />{patch.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    );
  } else if (hw) {
    const c = hw.commercial ?? NOT_RECORDED;
    const lc = hw.lifecycle ?? UNKNOWN_LIFECYCLE;
    const w = warrantyBadge(lc.warranty_state);
    const e = eosBadge(lc.eos_state);
    const nothing = !anyRecorded(c) && !lc.effective_end_of_support && !hw.device_type_eos && !hw.platform_eos;
    body = (
      <div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <Badge testId="warranty-badge" {...w} />
          <Badge testId="eos-badge" {...e} />
        </div>
        {eosSourceText(lc) && <div data-testid="eos-source" style={{ fontSize: 12, color: 'var(--app-t2)', marginBottom: 6 }}>End of support {eosSourceText(lc)}</div>}
        {nothing ? (
          <PanelEmpty icon="calendar-clock" title="No lifecycle recorded"
            message="Nobody has recorded this asset's purchase, warranty or support contract, and neither its device type nor its platform has an end-of-support date. That says nothing about whether it is covered." />
        ) : (
          <div data-testid="lifecycle-rows" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '0 24px' }}>
            <div>
              <Row k="Purchase date" v={c.purchase_date} mono />
              <Row k="Purchase cost" v={costText(c.purchase_cost, c.purchase_currency)} />
              <Row k="Purchase order" v={c.purchase_order} mono />
              <Row k="Vendor (seller)" v={c.vendor} />
              <Row k="Installed" v={c.installed_at} mono />
              <Row k="Decommissioned" v={c.decommissioned_at} mono />
            </div>
            <div>
              <Row k="Warranty start" v={c.warranty_start} mono />
              <Row k="Warranty end" v={c.warranty_end} mono />
              <Row k="Support contract" v={c.support_contract} />
              <Row k="Support contract ends" v={c.support_contract_end} mono />
              <EOSRows title="Device type" eos={hw.device_type_eos ?? null} />
              <EOSRows title="Platform (OS)" eos={hw.platform_eos ?? null} />
            </div>
          </div>
        )}
      </div>
    );
  }
  return (
    <section data-testid="hardware-lifecycle" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 13px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <Icon name="calendar-clock" size={14} style={{ color: 'var(--accent)' }} />
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>Lifecycle</div>
        <div style={{ flex: 1 }} />
        {canManage && hw && !draft && (
          <button type="button" className="ui-btn sm" data-testid="lifecycle-edit" onClick={() => { setError(null); setDraft(draftOfCommercial(hw.commercial ?? NOT_RECORDED)); }}>
            <Icon name="pencil" size={12} />Edit
          </button>
        )}
      </div>
      {body}
      {error && <div data-testid="lifecycle-error" role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{error}</div>}
    </section>
  );
}
