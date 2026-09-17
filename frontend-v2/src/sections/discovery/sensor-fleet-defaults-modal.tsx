// Fleet defaults for sensors: the settings every sensor inherits unless
// it carries its own override.

import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Modal } from '../../components/ui';
import { SettingsPanel } from './settings-panel';
import { useSensorFleetDefaults, useSaveSensorFleetDefaults } from './sensor-config-queries';
import type { SettingValue } from './agent-config';

export function SensorFleetDefaultsModal({ onClose }: { onClose: () => void }) {
  const canEdit = usePermissions().hasPermission(TENANT_PERMISSIONS.sensors.update);
  const q = useSensorFleetDefaults(true);
  const save = useSaveSensorFleetDefaults();

  return (
    <Modal open onClose={onClose} size="lg" icon="settings" eyebrow="Sensors" title="Sensor fleet defaults">
      <div style={{ fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.6, marginBottom: 10 }}>
        These apply to every sensor that has no setting of its own. A sensor with an override keeps
        it. Host observation and DNS decoding take effect when a sensor restarts.
      </div>

      {q.isLoading && <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading defaults…</div>}
      {q.isError && (
        <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn't load the sensor fleet defaults.</div>
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
