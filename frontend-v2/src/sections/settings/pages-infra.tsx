// Settings · infrastructure pages — Asset Lifecycle. Wired to inventory-service
// through the typed client: reads/writes /lifecycle/policy and /settings/drift.
// (Network Segments was retired with its table in DCIM row 1.6: the tenant's
// networks are prefixes in Inventory → Networks. Locations moved to Settings →
// Sites in DCIM row 2.1.)
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { SPage, SSection, SCard, SRow, SInput, SToggle, StateNote, GREEN, AMBER } from './kit';
import type { SettingsNavItem } from './nav';
import { unwrap } from '../../lib/api-result';

type LifecyclePolicy = inventoryComponents['schemas']['AssetLifecyclePolicy'];
type DriftSettings = inventoryComponents['schemas']['DriftSettings'];

// ---- Asset Lifecycle (read + write) ---------------------------------------
export function AssetLifecyclePage({ meta }: { meta: SettingsNavItem }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'lifecycle-policy'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/lifecycle/policy', {});
      if (error || !data) throw new Error('Failed to load the lifecycle policy');
      return data.policy;
    },
  });

  return (
    <SPage eyebrow="Inventory" title="Asset Lifecycle" job={meta.job}>
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the policy" message="The asset-lifecycle policy failed to load." /></SCard>
      ) : isLoading || !data ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading policy…" message="Fetching the asset-lifecycle policy." /></SCard>
      ) : (
        <LifecycleForm key={data.updated_at} policy={data} />
      )}
      <DriftBaselineSection />
    </SPage>
  );
}

// ---- Drift baseline (read + write) ----------------------------------------
//
// On this page rather than one of its own: it is the second time window the
// inventory is judged against, beside staleness, and a settings entry per
// number is how a settings area becomes unnavigable.
//
// Its own query and its own save, because it is a different store — the
// lifecycle policy has a table, this is a key in the tenant's settings document
// — and folding it into the policy payload would put a jsonb setting behind an
// API shape that cannot express "leave the rest of the document alone".
function DriftBaselineSection() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'drift'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/settings/drift', {});
      if (error || !data) throw new Error('Failed to load the drift settings');
      return data.drift;
    },
  });

  if (isError) {
    return (
      <SSection title="Drift baseline" desc="How far back the platform compares against when deciding something is new.">
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the drift baseline" message="The drift settings failed to load." /></SCard>
      </SSection>
    );
  }
  if (isLoading || !data) {
    return (
      <SSection title="Drift baseline" desc="How far back the platform compares against when deciding something is new.">
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading drift settings…" message="Fetching the drift baseline window." /></SCard>
      </SSection>
    );
  }
  return <DriftBaselineForm key={data.baseline_days} settings={data} />;
}

function DriftBaselineForm({ settings }: { settings: DriftSettings }) {
  const qc = useQueryClient();
  const [days, setDays] = useState(String(settings.baseline_days));

  const n = Number(days);
  const valid = Number.isInteger(n) && n >= settings.min_days && n <= settings.max_days;
  const dirty = n !== settings.baseline_days;

  const save = useMutation({
    mutationFn: async () => {
      const data = unwrap(await clients.inventory.PUT('/settings/drift', {
        body: { baseline_days: n },
      }), 'Failed to save the drift baseline', { requireData: true });
      return data.drift;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'drift'] }),
  });

  return (
    <SSection title="Drift baseline" desc="How far back the platform compares against when deciding something is new.">
      <SCard>
        <SRow
          label="Baseline window"
          hint={`Days of history a change is measured against. A device class, protocol, listening port or certificate issuer first seen inside this window is reported as drift; once it has been there for a full window it becomes part of the baseline and the finding closes. ${settings.min_days}–${settings.max_days} days.`}
          last
        >
          <SInput value={days} onChange={setDays} type="number" width={110} />
        </SRow>
      </SCard>
      {!valid && (
        <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 8 }}>
          The baseline window must be a whole number between {settings.min_days} and {settings.max_days} days.
        </div>
      )}
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>
        Nothing is reported as drift until this organization has been observed for a full window — a new tenant is not told that every asset it has is new.
      </div>
      <PermissionGate
        permission={TENANT_PERMISSIONS.settings.update}
        fallback={<p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>You don’t have permission to change the drift baseline.</p>}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
          <button className="ui-btn accent" disabled={!dirty || !valid || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save baseline'}
          </button>
          {save.isError && <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn’t save — try again.</span>}
          {save.isSuccess && !dirty && <span style={{ fontSize: 12, color: GREEN }}>Saved.</span>}
          {dirty && !save.isPending && <span style={{ fontSize: 11.5, color: AMBER }}>Unsaved changes</span>}
        </div>
      </PermissionGate>
    </SSection>
  );
}

function LifecycleForm({ policy }: { policy: LifecyclePolicy }) {
  const qc = useQueryClient();
  const [warningDays, setWarningDays] = useState(String(policy.stale_warning_days));
  const [archivedDays, setArchivedDays] = useState(String(policy.stale_archived_days));
  const [autoArchive, setAutoArchive] = useState(policy.auto_archive_enabled);
  const [notifications, setNotifications] = useState(policy.notifications_enabled);

  const wn = Number(warningDays);
  const an = Number(archivedDays);
  const valid = Number.isInteger(wn) && wn > 0 && Number.isInteger(an) && an > 0 && an > wn;
  const dirty = wn !== policy.stale_warning_days || an !== policy.stale_archived_days
    || autoArchive !== policy.auto_archive_enabled || notifications !== policy.notifications_enabled;

  const save = useMutation({
    mutationFn: async () => {
      const data = unwrap(await clients.inventory.PUT('/lifecycle/policy', {
        body: { stale_warning_days: wn, stale_archived_days: an, auto_archive_enabled: autoArchive, notifications_enabled: notifications },
      }), 'Failed to save the policy', { requireData: true });
      return data.policy;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'lifecycle-policy'] }),
  });

  const canEdit = TENANT_PERMISSIONS.settings.update;

  return (
    <>
      <SSection title="Staleness thresholds" desc="How long an asset can go unseen before it's flagged stale, then archived.">
        <SCard>
          <SRow label="Stale warning" hint="Days since last seen before an asset is flagged as stale.">
            <SInput value={warningDays} onChange={setWarningDays} type="number" width={110} />
          </SRow>
          <SRow label="Auto-archive after" hint="Days since last seen before a stale asset is archived. Must be greater than the warning threshold." last>
            <SInput value={archivedDays} onChange={setArchivedDays} type="number" width={110} />
          </SRow>
        </SCard>
        {!valid && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 8 }}>Both thresholds must be positive, and the archive threshold must exceed the warning threshold.</div>}
      </SSection>

      <SSection title="Automation">
        <SCard>
          <SRow label="Auto-archive stale assets" hint="When on, assets past the archive threshold are archived automatically.">
            <SToggle on={autoArchive} onChange={setAutoArchive} />
          </SRow>
          <SRow label="Stale notifications" hint="Notify when assets cross the stale-warning threshold." last>
            <SToggle on={notifications} onChange={setNotifications} />
          </SRow>
        </SCard>
      </SSection>

      <PermissionGate
        permission={canEdit}
        fallback={<p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>You don’t have permission to change the lifecycle policy.</p>}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
          <button className="ui-btn accent" disabled={!dirty || !valid || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save changes'}
          </button>
          {save.isError && <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn’t save — try again.</span>}
          {save.isSuccess && !dirty && <span style={{ fontSize: 12, color: GREEN }}>Saved.</span>}
          {dirty && !save.isPending && <span style={{ fontSize: 11.5, color: AMBER }}>Unsaved changes</span>}
        </div>
      </PermissionGate>
    </>
  );
}
