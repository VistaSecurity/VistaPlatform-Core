// Tenants ▸ (a tenant) ▸ Entitlements (edition-licensing spec PR 2).
//
// What this tab shows depends on the LICENCE, because the two paid editions
// decide a tenant's features differently:
//
//   Enterprise — every tenant gets every feature the licence covers. The one
//                lever is to switch a feature OFF for one tenant (a contractor,
//                a due-diligence tenant). Each licensed feature is a row with a
//                switch; switching off asks for a reason, switching back on
//                returns the tenant to the licence default. Both are audited.
//   MSP        — the tenant's plan decides. The tab shows the plan's
//                composition (read from the tenant's REAL tier id — the drawer
//                used to query tier 0000…, RC-10) and the Plan Exceptions for
//                this tenant.
//   Core       — no paid features; the switch list reads as empty.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { ToggleLeft, ToggleRight } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { usePlatformEdition } from '../../lib/edition';
import {
  type Tenant, type TenantFeature, planLabel, tierIdOf,
  useSetTenantFeature, useTenantFeatures, useTierEntitlements,
} from './queries';
import { PlanExceptionsPanel } from './plan-exceptions';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: '16px 20px', borderTop: '1px solid var(--op-border)' }}>
      <div className="op-eyebrow" style={{ marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '12px 14px', fontSize: 12, color: 'var(--op-t3)', lineHeight: 1.55 }}>
      {children}
    </div>
  );
}

/** Entitlement `included_value` is an untyped JSON value. */
function fmtIncluded(v: unknown, unit?: string): string {
  const dv = (v ?? {}) as { enabled?: boolean; quantity?: number | null; value?: string };
  if (typeof dv.enabled === 'boolean') return dv.enabled ? 'Included' : 'Not included';
  if ('quantity' in dv) return dv.quantity == null ? 'Unlimited' : `${dv.quantity.toLocaleString()}${unit ? ` ${unit}` : ''}`;
  if (typeof dv.value === 'string') return dv.value;
  return '—';
}

export function TenantEntitlementsTab({ tenant }: { tenant: Tenant }) {
  const { license } = usePlatformEdition();
  if (license === 'msp') return <MspEntitlements tenant={tenant} />;
  return <FeatureSwitches tenant={tenant} />;
}

function MspEntitlements({ tenant }: { tenant: Tenant }) {
  const ents = useTierEntitlements(tierIdOf(tenant));
  return (
    <>
      <Section title={`Plan — ${planLabel(tenant)}`}>
        {!tierIdOf(tenant) ? (
          <Note>This tenant is not on a plan.</Note>
        ) : ents.isLoading ? (
          <Note>Loading the plan…</Note>
        ) : ents.isError ? (
          <Note>Couldn't load the plan's entitlements.</Note>
        ) : ents.data && ents.data.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            {ents.data.map((e) => (
              <div key={e.item_id} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: 12.5 }}>
                <span style={{ color: 'var(--op-t3)' }}>{e.item_display_name}</span>
                <span style={{ color: 'var(--op-t1)', fontWeight: 500 }}>{fmtIncluded(e.included_value, e.item_unit)}</span>
              </div>
            ))}
          </div>
        ) : (
          <Note>This plan composes no entitlements.</Note>
        )}
      </Section>
      <Section title="Plan Exceptions">
        <PlanExceptionsPanel tenantId={tenant.id} />
      </Section>
    </>
  );
}

function FeatureSwitches({ tenant }: { tenant: Tenant }) {
  const feats = useTenantFeatures(tenant.id);
  const perms = usePlatformPermissions();
  const canManage = perms.hasPermission(PLATFORM_PERMISSIONS.tenants.manage);

  let body: React.ReactNode;
  if (feats.isLoading) {
    body = (
      <div data-testid="features-loading" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[0, 1, 2].map((i) => <div key={i} style={{ height: 44, borderRadius: 'var(--r-sm)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }} />)}
      </div>
    );
  } else if (feats.isError || !feats.data) {
    body = (
      <Note>
        Couldn't load this tenant's features.{' '}
        <button className="op-btn sm" onClick={() => void feats.refetch()}>Retry</button>
      </Note>
    );
  } else if (feats.data.features.length === 0) {
    body = <Note>No paid features to switch — this install has no licence, so it runs Vista Platform Core.</Note>;
  } else {
    const switchable = feats.data.switchable && canManage;
    body = (
      <>
        <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginBottom: 10, lineHeight: 1.5 }}>
          Every tenant gets every feature the licence covers. Switch one off for this tenant only — for example a
          contractor or due-diligence tenant. Changes are recorded in the audit log.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {feats.data.features.map((f) => (
            <FeatureRow key={f.key} tenantId={tenant.id} feature={f} switchable={switchable} />
          ))}
        </div>
        {!canManage && <div style={{ fontSize: 11, color: 'var(--op-t3)', marginTop: 10 }}>Changing a feature needs the tenants.manage permission.</div>}
      </>
    );
  }
  return <Section title="Licensed features">{body}</Section>;
}

function FeatureRow({ tenantId, feature: f, switchable }: { tenantId: string; feature: TenantFeature; switchable: boolean }) {
  const set = useSetTenantFeature();
  const [asking, setAsking] = useState(false);
  const [reason, setReason] = useState('');

  const switchOn = () => {
    if (!window.confirm(`Switch ${f.display_name} back on for this tenant? It returns to the licence default. This is recorded in the audit log.`)) return;
    set.mutate({ id: tenantId, key: f.key, enabled: true }, {
      onSuccess: () => toast.success(`${f.display_name} switched on`),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
    });
  };
  const switchOff = () => {
    set.mutate({ id: tenantId, key: f.key, enabled: false, reason: reason.trim() }, {
      onSuccess: () => { toast.success(`${f.display_name} switched off`); setAsking(false); setReason(''); },
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
    });
  };

  const offByOther = !f.enabled && !f.switched_off;
  return (
    <div style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '9px 11px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: 'var(--op-t1)', fontWeight: 500 }}>{f.display_name}</div>
          <div style={{ fontSize: 10.5, color: 'var(--op-t3)' }}>
            {f.switched_off ? `Switched off${f.reason ? ` — ${f.reason}` : ''}`
              : offByOther ? 'Off for this tenant by an override set outside this switch'
                : 'On (licence)'}
          </div>
        </div>
        {switchable && !offByOther && (
          f.enabled ? (
            <button className="op-btn sm" disabled={set.isPending || asking} onClick={() => setAsking(true)} aria-label={`Switch ${f.display_name} off`}>
              <ToggleRight size={14} style={{ color: 'var(--op-good)' }} />On
            </button>
          ) : (
            <button className="op-btn sm" disabled={set.isPending} onClick={switchOn} aria-label={`Switch ${f.display_name} on`}>
              <ToggleLeft size={14} />Off
            </button>
          )
        )}
        {!switchable && <span style={{ fontSize: 11.5, color: f.enabled ? 'var(--op-good)' : 'var(--op-t3)', fontWeight: 600 }}>{f.enabled ? 'On' : 'Off'}</span>}
      </div>
      {asking && (
        <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
          <input
            autoFocus
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (required, e.g. contractor tenant)"
            maxLength={500}
            style={{ flex: 1, padding: '6px 9px', borderRadius: 'var(--r-sm)', fontSize: 12, border: '1px solid var(--op-border)', background: 'var(--op-panel)', color: 'var(--op-t1)', outline: 'none' }}
          />
          <button className="op-btn danger sm" disabled={!reason.trim() || set.isPending} onClick={switchOff}>{set.isPending ? 'Saving…' : 'Switch off'}</button>
          <button className="op-btn sm" disabled={set.isPending} onClick={() => { setAsking(false); setReason(''); }}>Cancel</button>
        </div>
      )}
    </div>
  );
}
