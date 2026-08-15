// Settings · Integrations + Notifications & Alerts pages — ported from the
// mock's settings/sectionF.jsx. Configured connections = tenant notification
// channels (notification-service, full CRUD + test) + SIEM integrations
// (audit-service, read-only this pass); routing rules = tenant notification
// rules (full CRUD + live enable toggle); alert rules = audit-service alert
// rules (live enable toggle — creation needs the conditions/actions designer).
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useFeature } from '@vistasecurity/primitives/features';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, SDot, SToggle, StateNote, relTime, GREEN, AMBER, RED } from './kit';
import { ChannelModal, ChannelDeleteModal, RuleModal, RuleDeleteModal, isDigest } from './notification-modals';
import { CmdbProfileModal, CmdbDeleteModal, CmdbJobsModal, PLATFORM_LABEL, jobTone, type CMDBProfile } from './cmdb-modals';
import { cmdbProfilesQuery, siemIntegrationsQuery, editionSectionState } from './integrations-queries';
import type { SettingsNavItem } from './nav';
import type { notificationServiceComponents as NC, complianceEngineComponents } from '@vistasecurity/api-contract';

type Channel = NC['schemas']['TenantNotificationChannel'];
type Rule = NC['schemas']['TenantNotificationRule'];
type AlertCatalogEntry = complianceEngineComponents['schemas']['AlertCatalogEntry'];
type AlertCatalogRung = complianceEngineComponents['schemas']['AlertCatalogRung'];
type AlertCatalogPreferenceRung = complianceEngineComponents['schemas']['AlertCatalogPreferenceRung'];

const CHANNEL_CAT: Record<string, string> = {
  email: 'Messaging', slack: 'Messaging', teams: 'Messaging', pagerduty: 'Messaging', webhook: 'Generic webhook',
};
function testTone(status?: string): string {
  const s = (status || '').toLowerCase();
  if (s === 'success' || s === 'ok' || s === 'passed') return GREEN;
  if (s === 'failed' || s === 'error') return RED;
  return AMBER;
}

function useChannels() {
  return useQuery({
    queryKey: ['settings', 'channels'],
    queryFn: async () => {
      // Empty-body error responses surface as a falsy `error` in openapi-fetch
      // ('s history) — gate on response.ok.
      const { data, response } = await clients.notifications.GET('/tenant/channels', {});
      if (!response.ok) throw new Error('Failed to load channels');
      return data ?? [];
    },
  });
}

type ChannelModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; channel: Channel }
  | { kind: 'delete'; channel: Channel };

function ChannelTestButton({ channel }: { channel: Channel }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.notifications.POST('/tenant/channels/{id}/test', { params: { path: { id: channel.id } } });
      if (error || !response.ok) throw new Error('Test failed');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['settings', 'channels'] }),
  });
  return (
    <button
      className="ui-btn sm ghost"
      disabled={mutation.isPending}
      title="Send a test notification through this connection"
      onClick={() => mutation.mutate()}
      style={mutation.isError ? { color: 'var(--danger-text)' } : undefined}
    >
      {mutation.isPending ? 'Testing…' : mutation.isError ? 'Test failed' : mutation.isSuccess ? 'Test sent' : 'Test'}
    </button>
  );
}

type CmdbModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; profile: CMDBProfile }
  | { kind: 'delete'; profile: CMDBProfile }
  | { kind: 'jobs'; profile: CMDBProfile };

function CmdbTestButton({ profile }: { profile: CMDBProfile }) {
  const m = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.inventory.POST('/cmdb/profiles/{id}/test', { params: { path: { id: profile.id } } });
      if (error || !response.ok) throw new Error('Connection failed');
      return data;
    },
    onSuccess: () => toast.success('Connection OK'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Connection failed'),
  });
  return (
    <button className="ui-btn sm ghost" disabled={m.isPending} title="Test the CMDB connection" onClick={() => m.mutate()} style={m.isError ? { color: 'var(--danger-text)' } : undefined}>
      {m.isPending ? 'Testing…' : 'Test'}
    </button>
  );
}

function CmdbSyncButton({ profile }: { profile: CMDBProfile }) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.inventory.POST('/cmdb/profiles/{id}/sync', { params: { path: { id: profile.id } } });
      if (error || !response.ok) throw new Error('Failed to start sync');
    },
    onSuccess: () => {
      toast.success('Sync started');
      qc.invalidateQueries({ queryKey: ['settings', 'cmdb-jobs', profile.id] });
      qc.invalidateQueries({ queryKey: ['settings', 'cmdb-profiles'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Sync failed'),
  });
  return (
    <button className="ui-btn sm ghost" disabled={m.isPending} title="Push inventory to the CMDB now" onClick={() => m.mutate()}>
      {m.isPending ? 'Syncing…' : 'Sync'}
    </button>
  );
}

function CmdbPullButton({ profile }: { profile: CMDBProfile }) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.inventory.POST('/cmdb/profiles/{id}/pull', { params: { path: { id: profile.id } } });
      if (error || !response.ok || !data) {
        // Surface the server's message (e.g. the asset-limit reason on 402)
        // rather than a generic failure.
        const msg = (error as { error?: string } | undefined)?.error;
        throw new Error(msg || 'Pull failed');
      }
      return data;
    },
    onSuccess: (data) => {
      toast.success(`Pulled ${data.created} new asset${data.created === 1 ? '' : 's'} (${data.skipped} already present)`);
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Pull failed'),
  });
  return (
    <button className="ui-btn sm ghost" disabled={m.isPending} title="Pull server inventory from the CMDB into Vista" onClick={() => m.mutate()}>
      {m.isPending ? 'Pulling…' : 'Pull'}
    </button>
  );
}

export function IntegrationsPage({ meta }: { meta: SettingsNavItem }) {
  const [modal, setModal] = useState<ChannelModalState>({ kind: 'closed' });
  const [cmdbModal, setCmdbModal] = useState<CmdbModalState>({ kind: 'closed' });
  // CMDB sync and SIEM export are Enterprise-only routes with no entitlement
  // key to gate on — see integrations-queries.ts. Both are edition-probed: an
  // absent route resolves to `unavailable`, which renders an upgrade card (and
  // drops the Add button) instead of a red failure. Notification channels are
  // Core, so the page itself always renders.
  const cmdbEntitled = useFeature('cmdb_sync');
  const cmdbQ = useQuery(cmdbProfilesQuery(cmdbEntitled));
  const cmdbState = cmdbEntitled ? editionSectionState(cmdbQ) : 'unavailable';
  const cmdbProfiles = cmdbQ.data ?? [];
  const closeCmdb = () => setCmdbModal({ kind: 'closed' });
  const channelsQ = useChannels();
  const siemEntitled = useFeature('siem_export');
  // GET /siem/integrations requires audit.read ( — it required the WRITE
  // permission audit.manage until then, which is why this panel showed "SIEM
  // integrations failed to load" for every role but tenant_admin). Gate the
  // fetch on the permission as well as the entitlement: a role that cannot read
  // the audit surface should see the panel absent, not failing.
  // Not destructured: `const { hasPermission } = usePermissions()` trips
  // @typescript-eslint/unbound-method, and the lint job is a warning ratchet.
  // Same call form as discovery/pcap-page.tsx.
  const siemPermitted = usePermissions().hasPermission(TENANT_PERMISSIONS.audit.read);
  const siemQ = useQuery(siemIntegrationsQuery(siemEntitled && siemPermitted));
  const siemState = siemEntitled && siemPermitted ? editionSectionState(siemQ) : 'unavailable';
  const siemForbidden = siemEntitled && !siemPermitted;

  const siem = siemQ.data ?? [];
  const channels = channelsQ.data ?? [];
  // A Core build has no SIEM route at all, so its absence must not count as a
  // load failure of the (Core) connections list.
  const siemUnavailable = siemState === 'unavailable';
  const siemFailed = siemState === 'error';
  const loading = channelsQ.isLoading || (!siemUnavailable && siemQ.isLoading);
  const failed = channelsQ.isError && (siemFailed || siemUnavailable);
  const partialFail = !failed && (channelsQ.isError || siemFailed);
  const close = () => setModal({ kind: 'closed' });

  const cardShell = (key: string, name: string, cat: string, tone: string, enabled: boolean, detail: string, actions?: React.ReactNode) => (
    <SCard key={key} pad={16}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 12 }}>
        <span style={{ width: 34, height: 34, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--app-t2)' }}>
          <Icon name="plug" size={15} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</div>
          <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{cat}</div>
        </div>
        <span title={enabled ? 'enabled' : 'disabled'} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <SDot color={tone} />
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{detail}</div>
        {actions}
      </div>
    </SCard>
  );

  return (
    <SPage
      eyebrow="Integrations" title="Integrations" job={meta.job} maxWidth={1000}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />Add connection</button>
        </PermissionGate>
      }
    >
      <SSection title="Configured connections" desc="Each connection is authenticated once here, then referenced wherever it's used.">
        {failed ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load connections" message="The connection list failed to load." /></SCard>
        ) : loading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading connections…" message="Fetching configured channels and SIEM integrations." /></SCard>
        ) : siem.length + channels.length === 0 ? (
          <SCard><StateNote icon="plug" tone="var(--app-t3)" title="No connections" message="No channels or SIEM integrations are configured yet — add one to start routing alerts." /></SCard>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(280px,1fr))', gap: 12 }}>
            {siem.map((s) =>
              cardShell(`siem-${s.id}`, s.name, `SIEM · ${s.type}`, s.enabled ? GREEN : AMBER, s.enabled,
                `audit forwarding · ${relTime(s.updated_at)}`),
            )}
            {channels.map((c) =>
              cardShell(`ch-${c.id}`, c.channel_name, CHANNEL_CAT[c.channel_type] ?? c.channel_type,
                c.enabled ? testTone(c.test_status) : AMBER, c.enabled,
                `${c.description || c.channel_type} · ${relTime(c.last_used_at ?? c.updated_at) === '—' ? 'never used' : `used ${relTime(c.last_used_at ?? c.updated_at)}`}`,
                <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
                  <div style={{ display: 'flex', gap: 4, flex: 'none' }}>
                    <ChannelTestButton channel={c} />
                    <button className="ui-btn sm ghost" title="Configure" onClick={() => setModal({ kind: 'edit', channel: c })}><Icon name="settings" size={14} /></button>
                    <button className="ui-btn sm ghost" title="Remove" style={{ color: 'var(--danger-text)' }} onClick={() => setModal({ kind: 'delete', channel: c })}><Icon name="x" size={14} /></button>
                  </div>
                </PermissionGate>,
              ),
            )}
          </div>
        )}
      </SSection>
      {partialFail && (
        <p style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 4 }}>
          <Icon name="alert-triangle" size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />
          {channelsQ.isError ? 'Notification channels failed to load' : 'SIEM integrations failed to load'} — the list above may be incomplete.
        </p>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 4 }}>
        {siemForbidden ? (
          <>
            <Icon name="lock" size={13} style={{ verticalAlign: '-2px', marginRight: 5, color: 'var(--app-t3)' }} />
            SIEM forwarders are not shown — viewing them needs the audit read permission. Ask a Tenant Administrator if you need access.
          </>
        ) : siemUnavailable ? (
          <>
            <Icon name="lock" size={13} style={{ verticalAlign: '-2px', marginRight: 5, color: 'var(--accent)' }} />
            Outbound SIEM forwarding (Splunk, Datadog, Elastic) is an Enterprise feature. Audit events are still recorded and searchable in every edition — only forwarding them to an external SIEM is gated.
          </>
        ) : (
          'SIEM forwarder management (Splunk, Datadog, Elastic) is read-only here for now — connectors are configured via the audit pipeline.'
        )}
      </p>

      <SSection
        title="CMDB / ITSM sync"
        desc="Push your discovered inventory — assets, certificates, keys and crypto configurations — into ServiceNow, Device42, SolarWinds or Oomnitza."
        style={{ marginTop: 22 }}
        action={
          cmdbState === 'unavailable' ? undefined : (
            <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
              <button className="ui-btn sm accent" onClick={() => setCmdbModal({ kind: 'create' })}><Icon name="plus" size={14} />Add CMDB sync</button>
            </PermissionGate>
          )
        }
      >
        {cmdbState === 'unavailable' ? (
          <SCard>
            <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
              message="Bidirectional CMDB / ITSM sync pushes your cryptographic inventory into ServiceNow, Device42, SolarWinds or Oomnitza — and pulls their server inventory back in. The internal CMDB, and every discovery and inventory capability behind it, is included in every edition. Upgrade to Enterprise to connect an external CMDB." />
          </SCard>
        ) : cmdbState === 'error' ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load CMDB profiles" message="The CMDB sync profiles failed to load." /></SCard>
        ) : cmdbQ.isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading CMDB profiles…" message="Fetching configured CMDB sync profiles." /></SCard>
        ) : cmdbProfiles.length === 0 ? (
          <SCard><StateNote icon="plug" tone="var(--app-t3)" title="No CMDB sync configured" message="Connect a CMDB/ITSM platform to push your cryptographic inventory into the tools your IT teams already use." /></SCard>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(300px,1fr))', gap: 12 }}>
            {cmdbProfiles.map((p) => {
              const tone = !p.is_enabled ? AMBER : testTone(p.last_sync_status);
              const last = p.last_sync_at ? `last sync ${relTime(p.last_sync_at)}` : 'never synced';
              return (
                <SCard key={p.id} pad={16}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 12 }}>
                    <span style={{ width: 34, height: 34, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--app-t2)' }}>
                      <Icon name="plug" size={15} />
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{PLATFORM_LABEL[p.platform_type] ?? p.platform_type}</div>
                    </div>
                    <span title={p.is_enabled ? 'enabled' : 'disabled'}><SDot color={tone} /></span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t3)', minWidth: 0 }}>
                      {p.last_sync_status && <STag color={jobTone(p.last_sync_status)}>{p.last_sync_status}</STag>}
                      <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{last}</span>
                    </div>
                    {/* Two gates, because the routes behind these buttons ask
                        for two different permissions (ee/cmdbsync/routes.go):
                        profile CRUD + /test are settings.update, while /sync
                        and /pull are assets.manage — they move inventory, not
                        configuration. One settings.update gate over the whole
                        cluster both 403'd on sync/pull for a role holding only
                        settings.update, and hid sync/pull from security_admin,
                        which holds assets.manage but no settings.update. */}
                    <div style={{ display: 'flex', gap: 4, flex: 'none' }}>
                      <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
                        <CmdbTestButton profile={p} />
                      </PermissionGate>
                      <PermissionGate permission={TENANT_PERMISSIONS.assets.manage}>
                        <CmdbPullButton profile={p} />
                        <CmdbSyncButton profile={p} />
                      </PermissionGate>
                      <button className="ui-btn sm ghost" title="Sync history" onClick={() => setCmdbModal({ kind: 'jobs', profile: p })}><Icon name="history" size={14} /></button>
                      <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
                        <button className="ui-btn sm ghost" title="Configure" onClick={() => setCmdbModal({ kind: 'edit', profile: p })}><Icon name="settings" size={14} /></button>
                        <button className="ui-btn sm ghost" title="Remove" style={{ color: 'var(--danger-text)' }} onClick={() => setCmdbModal({ kind: 'delete', profile: p })}><Icon name="x" size={14} /></button>
                      </PermissionGate>
                    </div>
                  </div>
                </SCard>
              );
            })}
          </div>
        )}
      </SSection>

      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <ChannelModal key={modal.kind === 'edit' ? modal.channel.id : 'new'} channel={modal.kind === 'edit' ? modal.channel : null} open onClose={close} />
      )}
      {modal.kind === 'delete' && <ChannelDeleteModal channel={modal.channel} open onClose={close} />}

      {(cmdbModal.kind === 'create' || cmdbModal.kind === 'edit') && (
        <CmdbProfileModal key={cmdbModal.kind === 'edit' ? cmdbModal.profile.id : 'new'} profile={cmdbModal.kind === 'edit' ? cmdbModal.profile : null} open onClose={closeCmdb} />
      )}
      {cmdbModal.kind === 'delete' && <CmdbDeleteModal profile={cmdbModal.profile} open onClose={closeCmdb} />}
      {cmdbModal.kind === 'jobs' && <CmdbJobsModal profile={cmdbModal.profile} open onClose={closeCmdb} />}
    </SPage>
  );
}

type RuleModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; rule: Rule }
  | { kind: 'delete'; rule: Rule };

function RuleEnableToggle({ rule }: { rule: Rule }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      const { error, response } = await clients.notifications.PUT('/tenant/rules/{id}', {
        params: { path: { id: rule.id } },
        body: { enabled },
      });
      if (error || !response.ok) throw new Error('Failed to update the rule');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['settings', 'notification-rules'] }),
  });
  return <SToggle key={`${rule.id}-${rule.enabled}`} on={rule.enabled} onChange={(v) => mutation.mutate(v)} />;
}

export function RoutingRulesPage({ meta }: { meta: SettingsNavItem }) {
  const [modal, setModal] = useState<RuleModalState>({ kind: 'closed' });
  const channelsQ = useChannels();
  const rulesQ = useQuery({
    queryKey: ['settings', 'notification-rules'],
    queryFn: async () => {
      const { data, response } = await clients.notifications.GET('/tenant/rules', {});
      if (!response.ok) throw new Error('Failed to load routing rules');
      return data ?? [];
    },
  });

  const channels = channelsQ.data ?? [];
  const channelName = (id: string) => channels.find((c) => c.id === id)?.channel_name ?? id.slice(0, 8);
  const rules = rulesQ.data ?? [];
  const close = () => setModal({ kind: 'closed' });
  const cols = [
    { label: 'When', w: '1.6fr' }, { label: 'Deliver to', w: '1fr' }, { label: 'Frequency', w: '130px' },
    { label: 'On', w: '60px', align: 'right' as const }, { label: '', w: '90px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="Notifications & Alerts" title="Routing Rules" job={meta.job} maxWidth={1000}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />Add rule</button>
        </PermissionGate>
      }
    >
      {rulesQ.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load routing rules" message="The routing rule list failed to load." /></SCard>
      ) : rulesQ.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading routing rules…" message="Fetching the tenant's alert routing." /></SCard>
      ) : rules.length === 0 ? (
        <SCard><StateNote icon="route" tone="var(--app-t3)" title="No routing rules" message="No alert routing rules are configured yet — add one to start delivering alerts." /></SCard>
      ) : (
        <STable cols={cols}>
          {rules.map((r, i) => (
            <STableRow
              key={r.id}
              first={i === 0}
              cols={cols}
              cells={[
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 500 }}>{r.rule_name}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
                    {[r.alert_source, r.alert_type, r.severity_filter?.join('/')].filter(Boolean).join(' · ')}
                  </div>
                </div>,
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t2)', minWidth: 0 }}>
                  <Icon name="send" size={13} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                  <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {(r.channel_ids ?? []).map(channelName).join(', ') || '—'}
                  </span>
                </span>,
                <STag>{isDigest(r.frequency ?? '') ? `Digest${r.digest_window ? ` · ${r.digest_window}m` : ''}` : 'Immediate'}</STag>,
                <PermissionGate permission={TENANT_PERMISSIONS.settings.update} fallback={<span style={{ display: 'inline-flex', justifyContent: 'flex-end' }}><SDot color={r.enabled ? GREEN : 'var(--app-t3)'} /></span>}>
                  <span style={{ display: 'inline-flex', justifyContent: 'flex-end' }}><RuleEnableToggle rule={r} /></span>
                </PermissionGate>,
                <PermissionGate permission={TENANT_PERMISSIONS.settings.update}>
                  <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                    <button className="ui-btn sm ghost" title="Edit rule" onClick={() => setModal({ kind: 'edit', rule: r })}><Icon name="settings" size={14} /></button>
                    <button className="ui-btn sm ghost" title="Delete rule" style={{ color: 'var(--danger-text)' }} onClick={() => setModal({ kind: 'delete', rule: r })}><Icon name="x" size={14} /></button>
                  </div>
                </PermissionGate>,
              ]}
            />
          ))}
        </STable>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 13 }}>
        Channels are configured once in <strong style={{ color: 'var(--app-t2)' }}>Integrations</strong>; rules here only choose which channel receives what.
      </p>

      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <RuleModal key={modal.kind === 'edit' ? modal.rule.id : 'new'} rule={modal.kind === 'edit' ? modal.rule : null} channels={channels} open onClose={close} />
      )}
      {modal.kind === 'delete' && <RuleDeleteModal rule={modal.rule} open onClose={close} />}
    </SPage>
  );
}

const SEVERITY_TONE: Record<string, string> = { critical: RED, high: 'var(--warn-strong)', medium: AMBER, low: 'var(--info)', info: 'var(--neutral)' };

type AlertRule = import('@vistasecurity/api-contract').auditServiceComponents['schemas']['AlertRule'];

function AlertRuleToggle({ rule }: { rule: AlertRule }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (on: boolean) => {
      // The backend's update overwrites every column from the body (no partial
      // merge — filed as a backend issue), so send the full rule back.
      const { error, response } = await clients.audit.PUT('/alert-rules/{id}', {
        params: { path: { id: rule.id } },
        body: {
          name: rule.name, description: rule.description, rule_type: rule.rule_type,
          severity: rule.severity, conditions: rule.conditions, actions: rule.actions,
          is_enabled: on,
        },
      });
      if (error || !response.ok) throw new Error('Failed to update the alert rule');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['settings', 'alert-rules'] }),
  });
  return <SToggle key={`${rule.id}-${rule.is_enabled}`} on={rule.is_enabled} onChange={(v) => mutation.mutate(v)} />;
}

// --- Alert catalog (compliance-engine registry types) ----------------------

const CATALOG_QK = ['settings', 'alert-catalog'];

/** "certificate_expiring" → "Certificate expiring" */
function catalogName(id: string): string {
  const s = id.replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function rungSourceLabel(source: string): string {
  if (source === 'baseline') return 'Product default';
  if (source === 'preference') return 'Your setting';
  if (source.startsWith('policy:')) return source.slice('policy:'.length);
  return source;
}

function useCatalogUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { id: string; enabled: boolean; preference_rung?: AlertCatalogPreferenceRung | null }) => {
      const { data, error } = await clients.compliance.PUT('/alert-catalog/{type}', {
        params: { path: { type: vars.id } },
        body: { enabled: vars.enabled, preference_rung: vars.preference_rung },
      });
      if (error || !data) throw new Error(error?.error ?? 'Failed to update the alert type');
      return data;
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to update the alert type'),
    onSettled: () => queryClient.invalidateQueries({ queryKey: CATALOG_QK }),
  });
}

function RungChip({ rung }: { rung: AlertCatalogRung }) {
  const tone = SEVERITY_TONE[(rung.severity || '').toLowerCase()] ?? 'var(--app-t3)';
  const isPolicy = rung.source.startsWith('policy:');
  const label = rungSourceLabel(rung.source);
  return (
    <span title={`${label} · ${rung.severity}${isPolicy ? ' · required by an activated policy' : ''}`} style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 3, minWidth: 0 }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 9px', borderRadius: 40, fontSize: 11, fontWeight: 700, color: tone, background: `color-mix(in srgb, ${tone} 13%, transparent)`, whiteSpace: 'nowrap' }}>
        {rung.days}d
        {isPolicy && <Icon name="lock" size={10} style={{ opacity: 0.85 }} />}
      </span>
      <span style={{ fontSize: 9.5, color: 'var(--app-t3)', maxWidth: 92, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
    </span>
  );
}

function CertRungEditor({ entry }: { entry: AlertCatalogEntry }) {
  const [open, setOpen] = useState(false);
  const [days, setDays] = useState(String(entry.preference_rung?.days ?? entry.baseline_days ?? 60));
  const mutation = useCatalogUpdate();
  const save = () => {
    const n = Number(days);
    if (!Number.isInteger(n) || n < 1 || n > 3650) {
      toast.error('Warning rung must be between 1 and 3650 days');
      return;
    }
    mutation.mutate(
      { id: entry.id, enabled: entry.enabled, preference_rung: { days: n } },
      { onSuccess: () => setOpen(false) },
    );
  };
  const reset = () => {
    mutation.mutate(
      { id: entry.id, enabled: entry.enabled, preference_rung: null },
      { onSuccess: () => setOpen(false) },
    );
  };
  if (!open) {
    return (
      <button className="ui-btn sm ghost" onClick={() => setOpen(true)}>
        <Icon name="settings" size={13} />Edit warning rung
      </button>
    );
  }
  return (
    <div style={{ marginTop: 10, padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border)', background: 'var(--app-panel2)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: 'var(--app-t2)', fontWeight: 600 }}>Warn me at</span>
        <input
          type="number" min={1} max={3650} value={days} onChange={(e) => setDays(e.target.value)}
          style={{ width: 84, height: 32, padding: '0 10px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }}
        />
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>days before expiry</span>
        <div style={{ display: 'flex', gap: 6, marginLeft: 'auto' }}>
          <button className="ui-btn sm accent" disabled={mutation.isPending} onClick={save}>{mutation.isPending ? 'Saving…' : 'Save'}</button>
          <button className="ui-btn sm ghost" disabled={mutation.isPending} onClick={reset} title="Remove your rung and fall back to the product default">Reset to default</button>
          <button className="ui-btn sm ghost" onClick={() => setOpen(false)}>Cancel</button>
        </div>
      </div>
      <p style={{ margin: '8px 0 0', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
        Replaces the 60-day product default. Policy rungs from activated frameworks are always added on top.
      </p>
    </div>
  );
}

function CatalogCard({ entry }: { entry: AlertCatalogEntry }) {
  const mutation = useCatalogUpdate();
  const planned = entry.status === 'planned';
  const fixedSeverity = (entry.default_severity || '').toLowerCase();
  const derivedSeverity = fixedSeverity === 'from-control' || fixedSeverity === 'from-threshold';
  const tone = planned
    ? 'var(--app-t3)'
    : entry.severity_model === 'ladder'
      ? SEVERITY_TONE[(entry.ladder?.[entry.ladder.length - 1]?.severity ?? entry.baseline_severity ?? '').toLowerCase()] ?? 'var(--accent)'
      : SEVERITY_TONE[fixedSeverity] ?? 'var(--app-t3)';

  const toggle = (
    <SToggle
      key={`${entry.id}-${entry.enabled}`}
      on={entry.enabled}
      onChange={(v) => mutation.mutate({ id: entry.id, enabled: v, preference_rung: entry.preference_rung ?? null })}
    />
  );

  return (
    <SCard pad={16} style={planned ? { opacity: 0.55 } : undefined}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
        <span style={{ width: 32, height: 32, borderRadius: 8, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${tone} 11%, transparent)`, color: tone }}>
          <Icon name={entry.kind === 'policy' ? 'shield' : 'bell-ring'} size={15} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{catalogName(entry.id)}</span>
            <STag>{entry.kind === 'policy' ? 'Policy-driven' : 'Operational'}</STag>
            {planned && <STag color={AMBER}>Detector coming soon</STag>}
            {entry.severity_model === 'fixed' && !derivedSeverity && entry.default_severity && (
              <STag color={SEVERITY_TONE[fixedSeverity] ?? 'var(--app-t3)'}>{entry.default_severity}</STag>
            )}
            {entry.severity_model === 'fixed' && derivedSeverity && (
              <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>
                severity from {fixedSeverity === 'from-control' ? 'control' : 'threshold'}
              </span>
            )}
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3, lineHeight: 1.5 }}>{entry.description}</div>
          {entry.severity_model === 'ladder' && (entry.ladder?.length ?? 0) > 0 && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
              {entry.ladder!.map((rung, i) => <RungChip key={`${rung.source}-${rung.days}-${i}`} rung={rung} />)}
            </div>
          )}
          {entry.auto_resolve && (
            <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 8, fontStyle: 'italic' }}>
              Auto-resolves when: {entry.auto_resolve}
            </div>
          )}
          {!planned && entry.id === 'certificate_expiring' && (
            <PermissionGate permission={TENANT_PERMISSIONS.alerts.manage}>
              <div style={{ marginTop: 8 }}><CertRungEditor entry={entry} /></div>
            </PermissionGate>
          )}
        </div>
        <div style={{ flex: 'none', paddingTop: 2 }}>
          {planned ? (
            <span style={{ pointerEvents: 'none', opacity: 0.45, display: 'inline-flex' }}><SToggle on={entry.enabled} /></span>
          ) : (
            <PermissionGate permission={TENANT_PERMISSIONS.alerts.manage} fallback={<SDot color={entry.enabled ? GREEN : 'var(--app-t3)'} />}>
              {toggle}
            </PermissionGate>
          )}
        </div>
      </div>
    </SCard>
  );
}

function AlertCatalogSection() {
  const { data, isLoading, isError } = useQuery({
    queryKey: CATALOG_QK,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/alert-catalog', {});
      if (error || !data) throw new Error(error?.error ?? 'Failed to load the alert catalog');
      return data.catalog;
    },
  });
  const catalog = data ?? [];

  return (
    <SSection
      title="Alert catalog"
      desc="What the platform raises alerts for. Activated compliance policies add trigger rungs; disabling a type keeps policy-required rungs active (you can silence notifications via routing rules, but posture stays visible)."
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the alert catalog" message="The alert catalog failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading alert catalog…" message="Fetching the platform's alert types." /></SCard>
      ) : catalog.length === 0 ? (
        <SCard><StateNote icon="bell-ring" tone="var(--app-t3)" title="No alert types" message="The alert catalog is empty." /></SCard>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {catalog.map((entry) => <CatalogCard key={entry.id} entry={entry} />)}
        </div>
      )}
    </SSection>
  );
}

export function AlertRulesPage({ meta }: { meta: SettingsNavItem }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'alert-rules'],
    queryFn: async () => {
      const { data, error } = await clients.audit.GET('/alert-rules', {});
      if (error || !data) throw new Error('Failed to load alert rules');
      return data.rules ?? [];
    },
  });
  const rules = data ?? [];

  return (
    <SPage eyebrow="Notifications & Alerts" title="Alert Rules" job={meta.job} maxWidth={1000}>
      <AlertCatalogSection />
      <SSection title="Audit alert rules" desc="Event-based rules evaluated by the audit pipeline — conditions and actions are tuned per rule." style={{ marginTop: 22 }}>
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load alert rules" message="The alert rule list failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading alert rules…" message="Fetching the tenant's alert rules." /></SCard>
      ) : rules.length === 0 ? (
        <SCard><StateNote icon="bell-ring" tone="var(--app-t3)" title="No alert rules" message="No event-based alert rules are defined yet." /></SCard>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {rules.map((r) => {
            const tone = SEVERITY_TONE[(r.severity || '').toLowerCase()] ?? 'var(--app-t3)';
            return (
              <SCard key={r.id} pad={16} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <span style={{ width: 32, height: 32, borderRadius: 8, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${tone} 11%, transparent)`, color: tone }}>
                  <Icon name="bell-ring" size={15} />
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{r.name}</div>
                  <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {r.description || `${r.rule_type} · ${r.severity}`}
                  </div>
                </div>
                <STag color={tone}>{r.severity}</STag>
                {/* audit.manage, not settings.update: this toggle PUTs
                    /audit-service/alert-rules/:id, which audit-service gates on
                    PermissionAuditManage (#1374). */}
                <PermissionGate permission={TENANT_PERMISSIONS.audit.manage} fallback={<SDot color={r.is_enabled ? GREEN : 'var(--app-t3)'} />}>
                  <AlertRuleToggle rule={r} />
                </PermissionGate>
              </SCard>
            );
          })}
        </div>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 13 }}>
        Authoring new alert rules (conditions and actions) gets its own designer in a later pass; enable/disable is live.
      </p>
      </SSection>
    </SPage>
  );
}
