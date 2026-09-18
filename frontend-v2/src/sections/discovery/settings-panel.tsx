// The settings form for a sensor or agent, and for a tenant's fleet defaults
//
//
// It renders whatever the API returns. The registry — which settings exist,
// their bounds, their descriptions, whether one needs confirming — lives on the
// platform, and a second copy here would be free to drift from it. So a setting
// added to the platform appears here with no frontend change, and one this
// build has never heard of still renders correctly.

import { useMemo, useState } from 'react';
import { Icon, SectionLabel } from '../../components/ui';
import {
  awaitingRestart,
  changedKeys,
  confirmationsNeeded,
  failureFor,
  hasDeviceOverrides,
  originNote,
  overridesToSend,
  settingLabel,
  settingUnit,
  stateNote,
  versionNote,
  type ConfigStatus,
  type Setting,
  type SettingValue,
  type VersionInfo,
} from './agent-config';
import { NeedsConfirmation, saveResultFrom, type SaveResult } from './agent-config-queries';

const TONE: Record<string, string> = {
  ok: 'var(--ok)',
  warn: 'var(--warn)',
  danger: 'var(--danger-text)',
  muted: 'var(--app-t3)',
};

export function SettingsPanel({
  settings,
  status,
  version,
  scope,
  canEdit,
  save,
  saving,
}: {
  settings: Setting[];
  status?: ConfigStatus;
  /** What the device runs versus what this release ships. Absent for fleet
   *  defaults, which describe no single device. */
  version?: VersionInfo;
  /** 'device' shows convergence state and the revert control; 'fleet' does not
   *  — fleet defaults are not something a device reports on. */
  scope: 'device' | 'fleet';
  canEdit: boolean;
  save: (values: Record<string, SettingValue>, confirmed: boolean) => Promise<SaveResult>;
  saving: boolean;
}) {
  const [edited, setEdited] = useState<Record<string, SettingValue>>({});
  const [result, setResult] = useState<SaveResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<{ key: string; confirm: string }[] | null>(null);

  const dirty = useMemo(() => changedKeys(settings, edited), [settings, edited]);
  const note = stateNote(status);

  const set = (key: string, value: SettingValue) => {
    setResult(null);
    setError(null);
    setConfirming(null);
    setEdited((e) => ({ ...e, [key]: value }));
  };

  const submit = async (confirmed: boolean) => {
    setError(null);
    try {
      const out = await save(overridesToSend(settings, edited, scope), confirmed);
      setResult(saveResultFrom(out));
      setEdited({});
      setConfirming(null);
    } catch (e) {
      if (e instanceof NeedsConfirmation) {
        // The server decides this, not the form. Asking it and then showing
        // what it names keeps one source of truth for what a setting collects.
        setConfirming(e.required.needsConfirming);
        return;
      }
      setError(e instanceof Error ? e.message : 'Could not save the settings');
    }
  };

  const onSave = () => {
    const needed = confirmationsNeeded(settings, edited);
    if (needed.length > 0) {
      setConfirming(needed.map((s) => ({ key: s.key, confirm: s.confirm as string })));
      return;
    }
    void submit(false);
  };

  return (
    <div style={{ marginTop: 4 }}>
      {scope === 'device' && (
        <>
          <SectionLabel icon="activity">Status</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '6px 0 4px' }}>
            <span style={{ width: 8, height: 8, borderRadius: 50, background: TONE[note.tone] }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{note.label}</span>
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.55 }}>{note.detail}</div>

          {/* Version visibility: what it runs, what this release ships, and
              whether that differs. The platform does NOT upgrade it — the
              wording says so, because a badge reading "update available" with
              no button invites the question. */}
          {(() => {
            const v = versionNote(version);
            if (!v) return null;
            return (
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: TONE[v.tone] }}>{v.label}</span>
                <span style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.55 }}>{v.detail}</span>
              </div>
            );
          })()}
        </>
      )}

      <div style={{ margin: scope === 'device' ? '20px 0 0' : 0 }}>
        <SectionLabel icon="settings">{scope === 'fleet' ? 'Fleet defaults' : 'Settings'}</SectionLabel>
      </div>

      {settings.length === 0 && (
        <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '8px 0' }}>No settings reported.</div>
      )}

      {settings.map((s) => {
        const value = edited[s.key] ?? s.value;
        const failure = scope === 'device' ? failureFor(status, s.key) : undefined;
        const waiting = scope === 'device' && awaitingRestart(status, s.key);
        const unit = settingUnit(s.key);
        return (
          <div key={s.key} style={{ padding: '11px 0', borderBottom: '1px solid var(--app-border)' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{settingLabel(s.key)}</div>
                <div style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.5, marginTop: 2 }}>{s.description}</div>
                <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 4 }}>
                  {originNote(s.origin)}
                  {s.apply === 'restart' && ' · takes effect on restart'}
                </div>
                {failure && (
                  <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 5 }}>
                    <Icon name="alert-triangle" size={11} /> {failure}
                  </div>
                )}
                {waiting && !failure && (
                  <div style={{ fontSize: 11, color: 'var(--warn)', marginTop: 5 }}>
                    Accepted — adopted when the device restarts.
                  </div>
                )}
              </div>
              <div style={{ flex: 'none' }}>
                <SettingControl setting={s} value={value} unit={unit} disabled={!canEdit || saving} onChange={(v) => set(s.key, v)} />
              </div>
            </div>
          </div>
        );
      })}

      {confirming && (
        <div style={{ marginTop: 14, padding: 12, border: '1px solid var(--warn)', borderRadius: 0, borderLeft: '3px solid var(--warn)' }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 6 }}>Confirm this change</div>
          {confirming.map((c) => (
            <div key={c.key} style={{ fontSize: 11.5, color: 'var(--app-t2)', lineHeight: 1.6, marginBottom: 6 }}>
              <strong>{settingLabel(c.key)}:</strong> {c.confirm}
            </div>
          ))}
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="ui-btn sm" disabled={saving} onClick={() => void submit(true)}>
              Yes, turn it on
            </button>
            <button className="ui-btn sm ghost" disabled={saving} onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 12, fontSize: 11.5, color: 'var(--danger-text)' }}>{error}</div>
      )}

      {result && (
        <div style={{ marginTop: 12, fontSize: 11.5, color: 'var(--app-t2)', lineHeight: 1.6 }}>
          {result.changed.length === 0 ? (
            <div>Nothing changed.</div>
          ) : (
            <div>Saved: {result.changed.join('; ')}</div>
          )}
          {/* Shown because the platform adjusted a value the operator typed.
              The device has always done this silently in its own log. */}
          {result.adjusted.map((a) => (
            <div key={a} style={{ color: 'var(--warn)' }}>{a}</div>
          ))}
          {result.needs_restart.length > 0 && (
            <div style={{ color: 'var(--warn)' }}>
              Takes effect on restart: {result.needs_restart.map(settingLabel).join(', ')}
            </div>
          )}
        </div>
      )}

      {canEdit && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14 }}>
          <button className="ui-btn sm" disabled={dirty.length === 0 || saving} onClick={onSave}>
            {saving ? 'Saving…' : `Save${dirty.length > 0 ? ` (${dirty.length})` : ''}`}
          </button>
          {scope === 'device' && hasDeviceOverrides(settings) && (
            <button
              className="ui-btn sm ghost"
              disabled={saving}
              title="Remove this device's overrides and follow the fleet defaults"
              onClick={() => { setEdited({}); void save({}, false).then((out) => setResult(saveResultFrom(out))).catch((e) => setError(e instanceof Error ? e.message : 'Could not revert')); }}
            >
              Revert to fleet defaults
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function SettingControl({
  setting,
  value,
  unit,
  disabled,
  onChange,
}: {
  setting: Setting;
  value: SettingValue;
  unit: 'seconds' | 'minutes' | null;
  disabled: boolean;
  onChange: (v: SettingValue) => void;
}) {
  if (setting.kind === 'bool') {
    return (
      <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: disabled ? 'default' : 'pointer' }}>
        <input type="checkbox" checked={value === true} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
        {value === true ? 'On' : 'Off'}
      </label>
    );
  }
  if (setting.kind === 'enum') {
    return (
      <select
        className="ui-input sm"
        value={String(value)}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        style={{ minWidth: 110 }}
      >
        {(setting.allowed ?? []).map((a) => (
          <option key={a} value={a}>{a}</option>
        ))}
      </select>
    );
  }
  // Int. The unit is shown rather than converted: the platform stores seconds
  // where the key says seconds, and converting in the form is how a value
  // becomes 60× wrong in one direction.
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <input
        className="ui-input sm mono"
        type="number"
        value={Number(value)}
        min={setting.min}
        max={setting.max}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{ width: 96, textAlign: 'right' }}
      />
      {unit && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{unit}</span>}
    </div>
  );
}
