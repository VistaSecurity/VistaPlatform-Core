// Settings · infrastructure pages — Locations, Network Segments, Asset
// Lifecycle. Wired to inventory-service through the typed client. Locations and
// Network Segments have full CRUD via the now-contracted write endpoints;
// Asset Lifecycle reads/writes /lifecycle/policy.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, SRow, SInput, SToggle, STable, STableRow, STag, StateNote, GREEN, AMBER } from './kit';
import { LocationModal, NetworkSegmentModal, DeleteInfraModal } from './infra-modals';
import { ImportSpreadsheetModal } from '../discovery/import-modal';
import type { SettingsNavItem } from './nav';

type Location = inventoryComponents['schemas']['Location'];
type NetworkSegment = inventoryComponents['schemas']['NetworkSegment'];
type LifecyclePolicy = inventoryComponents['schemas']['AssetLifecyclePolicy'];

// Compact per-row Edit / Delete actions, gated on settings.update.
function RowActions({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) {
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.settings.update} fallback={<span />}>
      <span style={{ display: 'inline-flex', justifyContent: 'flex-end', gap: 6 }}>
        <button className="ui-btn sm ghost" title="Edit" onClick={(e) => { e.stopPropagation(); onEdit(); }}><Icon name="sliders-horizontal" size={13} /></button>
        <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Delete" onClick={(e) => { e.stopPropagation(); onDelete(); }}><Icon name="x" size={13} /></button>
      </span>
    </PermissionGate>
  );
}

// ---- Locations ------------------------------------------------------------
export function LocationsPage({ meta }: { meta: SettingsNavItem }) {
  const [createOpen, setCreateOpen] = useState(false);
  const [editLoc, setEditLoc] = useState<Location | null>(null);
  const [delLoc, setDelLoc] = useState<Location | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'locations'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/locations', {});
      if (error || !data) throw new Error('Failed to load locations');
      return data.locations ?? [];
    },
  });
  const locations = data ?? [];
  const cols = [
    { label: 'Name' }, { label: 'Type', w: '120px' }, { label: 'Cloud', w: '160px' },
    { label: 'Timezone', w: '140px' }, { label: 'Assets', w: '70px', align: 'right' as const },
    { label: '', w: '88px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="Inventory" title="Locations" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
          <button className="ui-btn sm accent" onClick={() => setCreateOpen(true)}><Icon name="plus" size={14} />New location</button>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load locations" message="The location registry failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading locations…" message="Fetching the location registry." /></SCard>
      ) : locations.length === 0 ? (
        <SCard><StateNote icon="map-pin" tone="var(--app-t3)" title="No locations" message="No locations are defined yet. Create one to organize assets by site or cloud region." /></SCard>
      ) : (
        <STable cols={cols}>
          {locations.map((l: Location, i) => (
            <STableRow key={l.id} first={i === 0} cols={cols} cells={[
              <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>
                <span style={{ fontWeight: 600 }}>{l.name}</span>
                {l.full_path && l.full_path !== l.name && <span style={{ color: 'var(--app-t3)', marginLeft: 6 }}>· {l.full_path}</span>}
              </span>,
              <STag>{l.location_type}</STag>,
              <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{l.cloud_provider ? `${l.cloud_provider}${l.cloud_region ? ` · ${l.cloud_region}` : ''}` : '—'}</span>,
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{l.timezone || '—'}</span>,
              <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{l.asset_count ?? 0}</span>,
              <RowActions onEdit={() => setEditLoc(l)} onDelete={() => setDelLoc(l)} />,
            ]} />
          ))}
        </STable>
      )}

      {(createOpen || editLoc) && <LocationModal open location={editLoc} onClose={() => { setCreateOpen(false); setEditLoc(null); }} />}
      {delLoc && <DeleteInfraModal open kind="location" id={delLoc.id} name={delLoc.name} onClose={() => setDelLoc(null)} />}
    </SPage>
  );
}

// ---- Network Segments -----------------------------------------------------
const SEGMENT_TYPE_LABEL: Record<string, string> = { cidr: 'CIDR', ip_range: 'IP range', domain: 'Domain', cloud_vpc: 'Cloud VPC' };

export function NetworkSegmentsPage({ meta }: { meta: SettingsNavItem }) {
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [editSeg, setEditSeg] = useState<NetworkSegment | null>(null);
  const [delSeg, setDelSeg] = useState<NetworkSegment | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'network-segments'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/network-segments', {});
      if (error || !data) throw new Error('Failed to load network segments');
      return data.network_segments ?? [];
    },
  });
  const segments = data ?? [];
  const cols = [
    { label: 'Name' }, { label: 'Type', w: '100px' }, { label: 'Value' },
    { label: 'Environment', w: '110px' }, { label: 'Location', w: '140px' }, { label: 'Active', w: '64px', align: 'right' as const },
    { label: '', w: '88px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="Inventory" title="Network Segments" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="ui-btn sm" onClick={() => setImportOpen(true)}><Icon name="upload" size={14} />Import</button>
            <button className="ui-btn sm accent" onClick={() => setCreateOpen(true)}><Icon name="plus" size={14} />New segment</button>
          </div>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load network segments" message="The network-segment registry failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading segments…" message="Fetching the network-segment registry." /></SCard>
      ) : segments.length === 0 ? (
        <SCard><StateNote icon="network" tone="var(--app-t3)" title="No network segments" message="No network segments are defined yet. Add one to scope Discovery scans." /></SCard>
      ) : (
        <STable cols={cols}>
          {segments.map((s: NetworkSegment, i) => (
            <STableRow key={s.id} first={i === 0} cols={cols} cells={[
              <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{s.name}</span>,
              <STag>{SEGMENT_TYPE_LABEL[s.segment_type] || s.segment_type}</STag>,
              <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{s.value}</span>,
              <span style={{ fontSize: 12, color: 'var(--app-t2)', textTransform: 'capitalize' }}>{s.environment || '—'}</span>,
              <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{s.location_name || s.location_full_path || '—'}</span>,
              <span style={{ display: 'inline-flex', justifyContent: 'flex-end' }}><STag color={s.is_active ? GREEN : 'var(--app-t3)'}>{s.is_active ? 'Yes' : 'No'}</STag></span>,
              <RowActions onEdit={() => setEditSeg(s)} onDelete={() => setDelSeg(s)} />,
            ]} />
          ))}
        </STable>
      )}

      {(createOpen || editSeg) && <NetworkSegmentModal open segment={editSeg} onClose={() => { setCreateOpen(false); setEditSeg(null); }} />}
      <ImportSpreadsheetModal open={importOpen} lockedTarget="segments" onClose={() => setImportOpen(false)} />
      {delSeg && <DeleteInfraModal open kind="segment" id={delSeg.id} name={delSeg.name} onClose={() => setDelSeg(null)} />}
    </SPage>
  );
}

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
    </SPage>
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
      const { data, error, response } = await clients.inventory.PUT('/lifecycle/policy', {
        body: { stale_warning_days: wn, stale_archived_days: an, auto_archive_enabled: autoArchive, notifications_enabled: notifications },
      });
      if (!response.ok || error || !data) throw new Error('Failed to save the policy');
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
