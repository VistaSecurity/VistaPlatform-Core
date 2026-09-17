// Fleet defaults for discovery agents: the settings every agent
// inherits unless it carries its own override.
//
// Changing one here moves every inheriting agent at its next check-in, with
// nothing to push and nothing to restart — and deliberately does NOT move an
// agent that overrides that setting, which is the whole point of an override.

import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Modal } from '../../components/ui';
import { SettingsPanel } from './settings-panel';
import { useAgentFleetDefaults, useSaveAgentFleetDefaults } from './agent-config-queries';
import type { SettingValue } from './agent-config';

export function AgentFleetDefaultsModal({ onClose }: { onClose: () => void }) {
  const canEdit = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const q = useAgentFleetDefaults(true);
  const save = useSaveAgentFleetDefaults();

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      icon="settings"
      eyebrow="Discovery agents"
      title="Agent fleet defaults"
    >
      <div style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.6, marginBottom: 10 }}>
        These apply to every discovery agent that has no setting of its own. An agent with an
        override keeps it.
      </div>

      {q.isLoading && <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading defaults…</div>}
      {q.isError && (
        <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn't load the fleet defaults.</div>
      )}

      {q.data && (
        <SettingsPanel
          settings={q.data.settings}
          scope="fleet"
          canEdit={canEdit}
          saving={save.isPending}
          save={(values: Record<string, SettingValue>, confirmed: boolean) => save.mutateAsync({ values, confirmed })}
        />
      )}

      {q.data && !canEdit && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 12 }}>
          Changing fleet defaults needs the Update sensors permission.
        </div>
      )}
    </Modal>
  );
}
