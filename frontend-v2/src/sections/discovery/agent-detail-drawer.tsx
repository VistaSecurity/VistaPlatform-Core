// Discovery agent detail, and the settings surface that makes an agent
// manageable without logging into its host.
//
// Agents had no drawer at all: the fleet table could show one and delete one,
// and everything else about it was a file on somebody's server.

import { useState } from 'react';
import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Icon, DrawerShell, DrawerCloseBtn, MetaRow, SectionLabel, Pill } from '../../components/ui';
import { relTime, sensorOnline } from './kit';
import { hostInventorySummary, addressTooltip, profileLabel } from './agent-fleet';
import { useDeviceAgents } from './queries';
import { SettingsPanel } from './settings-panel';
import { useAgentConfig, useAgentConfigHistory, useSaveAgentConfig, useRequestAgentRestart } from './agent-config-queries';
import { ConfigHistorySection } from './config-history';
import type { SettingValue } from './agent-config';

// The row shape the fleet query returns, rather than a hand-written interface:
// a local copy would drift from the generated contract silently.
export type DeviceAgentRow = NonNullable<ReturnType<typeof useDeviceAgents>['data']>[number];

type TabKey = 'overview' | 'settings';

const TABS: { key: TabKey; label: string; icon: string }[] = [
  { key: 'overview', label: 'Overview', icon: 'info' },
  { key: 'settings', label: 'Settings', icon: 'settings' },
];

export function AgentDetailDrawer({ agent, onClose }: { agent: DeviceAgentRow; onClose: () => void }) {
  const [tab, setTab] = useState<TabKey>('overview');
  const on = sensorOnline(agent.status, agent.last_heartbeat);
  const name = agent.name || `agent-${agent.id.slice(0, 8)}`;

  return (
    <DrawerShell onClose={onClose} width={560}>
      <div style={{ padding: '18px 22px 0', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${on ? 'var(--ok)' : 'var(--danger)'} 12%, transparent)`, color: on ? 'var(--ok)' : 'var(--danger)' }}>
            <Icon name="server-cog" size={16} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">Discovery agent</div>
            <h2 style={{ margin: '4px 0 6px', fontSize: 16.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25, wordBreak: 'break-word' }}>{name}</h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              <Pill color={on ? 'var(--ok)' : agent.status === 'pending' ? 'var(--warn)' : 'var(--danger)'} style={{ fontSize: 10.5 }}>
                {(agent.status || 'unknown').replace('_', ' ')}
              </Pill>
              {agent.version && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>v{agent.version}</span>}
            </div>
          </div>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        <div style={{ display: 'flex', gap: 4, marginTop: 16 }}>
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', border: 'none', background: 'transparent', cursor: 'pointer',
                fontSize: 12.5, fontWeight: 600, color: tab === t.key ? 'var(--app-t1)' : 'var(--app-t3)',
                borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent', marginBottom: -1,
              }}
            >
              <Icon name={t.icon} size={13} />{t.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        {tab === 'overview' && <AgentOverview agent={agent} />}
        {tab === 'settings' && <AgentSettings agent={agent} />}
      </div>
    </DrawerShell>
  );
}

function AgentOverview({ agent }: { agent: DeviceAgentRow }) {
  return (
    <div style={{ marginTop: 4 }}>
      <SectionLabel icon="info">Summary</SectionLabel>
      <MetaRow k="Platform" v={agent.platform || '—'} />
      <MetaRow k="Profile" v={profileLabel(agent.profile) || '—'} />
      <MetaRow k="Version" v={agent.version ? `v${agent.version}` : '—'} />
      <MetaRow k="Address" v={agent.ip_address || '—'} title={addressTooltip(agent) || undefined} />
      <MetaRow k="Last heartbeat" v={relTime(agent.last_heartbeat)} />
      {/* What the agent learned about its OWN host, which no job count can
          say — a host inventory is not work anybody queued. */}
      <MetaRow k="Host inventory" v={hostInventorySummary(agent) || 'Never reported'} />
    </div>
  );
}

function AgentSettings({ agent }: { agent: DeviceAgentRow }) {
  // Not destructured: the hook's methods read `this`, and relationships-tab.tsx
  // records that destructuring them trips.
  const canEdit = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const q = useAgentConfig(agent.id);
  const save = useSaveAgentConfig(agent.id);
  // Fetched only once the section is opened: a drawer somebody glances at
  // should not query an audit table.
  const [historyOpen, setHistoryOpen] = useState(false);
  const history = useAgentConfigHistory(agent.id, historyOpen);

  if (q.isLoading) {
    return <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '10px 0' }}>Loading settings…</div>;
  }
  if (q.isError || !q.data) {
    return (
      <div style={{ fontSize: 12, color: 'var(--danger-text)', padding: '10px 0' }}>
        Couldn't load this agent's settings.
      </div>
    );
  }

  return (
    <>
      <SettingsPanel
        settings={q.data.settings}
        status={q.data.status}
        version={q.data.version}
        scope="device"
        canEdit={canEdit}
        saving={save.isPending}
        save={(values: Record<string, SettingValue>, confirmed: boolean) => save.mutateAsync({ values, confirmed })}
      />
      {!canEdit && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 12 }}>
          You can view these settings but not change them. Changing them needs the Update sensors permission.
        </div>
      )}
      {canEdit && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 14, lineHeight: 1.6 }}>
          These settings are managed here, not on the agent's host. A local edit to the agent's
          config file is overwritten at its next check-in.
        </div>
      )}
      <RestartSection agentId={agent.id} />
      <ConfigHistorySection
        changes={history.data}
        isLoading={history.isLoading}
        isError={history.isError}
        onOpen={() => setHistoryOpen(true)}
      />
    </>
  );
}

// ---- Restart ---------------------------------------------------------------
//
// Gated on sensors.manage, not sensors.update: this is disruptive, and
// disruptive is the side of that line where manage lives. Configuration is the
// other side.
function RestartSection({ agentId }: { agentId: string }) {
  const canRestart = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.manage);
  const restart = useRequestAgentRestart(agentId);
  const [confirming, setConfirming] = useState(false);

  if (!canRestart) return null;

  return (
    <div style={{ marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--app-border)' }}>
      <SectionLabel icon="refresh">Restart</SectionLabel>
      <div style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.6, margin: '6px 0 10px' }}>
        Settings marked “takes effect on restart” are adopted when the agent restarts.
      </div>

      {!confirming && (
        <button className="ui-btn sm ghost" disabled={restart.isPending} onClick={() => setConfirming(true)}>
          <Icon name="refresh" size={13} />Restart agent
        </button>
      )}

      {confirming && (
        <div style={{ padding: 12, border: '1px solid var(--warn)', borderLeft: '3px solid var(--warn)', borderRadius: 0 }}>
          {/* The caveat BEFORE the click, not after it: an agent that nothing
              supervises stops rather than restarting. That is the one way this
              disappoints, and an operator should meet it while they can still
              change their mind. */}
          <div style={{ fontSize: 11.5, color: 'var(--app-t2)', lineHeight: 1.6, marginBottom: 8 }}>
            The agent exits and its service manager starts it again. If this agent was launched by
            hand rather than installed as a service, it will stop instead of restarting.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="ui-btn sm"
              disabled={restart.isPending}
              onClick={() => { setConfirming(false); restart.mutate(); }}
            >
              {restart.isPending ? 'Requesting…' : 'Restart it'}
            </button>
            <button className="ui-btn sm ghost" disabled={restart.isPending} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {restart.isSuccess && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginTop: 10, lineHeight: 1.6 }}>
          Requested. {restart.data.note}
        </div>
      )}
      {restart.isError && (
        <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 10 }}>
          {restart.error instanceof Error ? restart.error.message : 'Could not request a restart'}
        </div>
      )}
    </div>
  );
}
