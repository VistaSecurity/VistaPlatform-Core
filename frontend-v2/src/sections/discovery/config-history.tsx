// The change history for one sensor or agent.
//
// This exists because the Reachability check found agent_config_audit being
// written on every save and read by nothing. A write-only audit table is the
// orphaned layer this project's framework forbids, and here it was carrying an
// obligation: the sensor's DNS decoder is manageable at all only because the
// owner's decision paired it with a recorded confirmation. A record nobody can
// read does not discharge that.
//
// Collapsed by default. An operator opening a device's settings wants the
// settings; the history is what they want on the day something is on and
// nobody remembers turning it on.

import { useState } from 'react';
import { Icon, SectionLabel } from '../../components/ui';
import { relTime } from './kit';
import { settingLabel } from './agent-config';
import type { ConfigChange } from './agent-config-queries';

function renderValue(v: unknown): string {
  if (v === undefined) return '—';
  if (v === null) return 'cleared';
  if (typeof v === 'boolean') return v ? 'on' : 'off';
  if (typeof v === 'number' || typeof v === 'string') return String(v);
  // A settings value is a bool, an int or a string; anything else means the
  // registry grew a shape this has not been taught. Say so rather than printing
  // "[object Object]" at somebody auditing a change.
  return JSON.stringify(v);
}

/** One line per setting that actually moved. The keys come from the server so
 *  no two clients disagree about what "changed" means. */
function ChangeRow({ change }: { change: ConfigChange }) {
  return (
    <li style={{ padding: '8px 0', borderTop: '1px solid var(--app-border)', listStyle: 'none' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11.5, color: 'var(--app-t2)', fontWeight: 600 }}>
          {change.scope === 'fleet' ? 'Fleet defaults' : 'This device'}
        </span>
        <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{relTime(change.changed_at)}</span>
      </div>
      {change.keys.length === 0 ? (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 3 }}>No setting changed value.</div>
      ) : (
        <div style={{ marginTop: 3 }}>
          {change.keys.map((k) => (
            <div key={k} style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>
              {settingLabel(k)}:{' '}
              <span className="mono" style={{ color: 'var(--app-t3)' }}>{renderValue(change.values_before[k])}</span>
              {' → '}
              <span className="mono" style={{ color: 'var(--app-t1)' }}>{renderValue(change.values_after[k])}</span>
            </div>
          ))}
        </div>
      )}
    </li>
  );
}

export function ConfigHistorySection({
  changes,
  isLoading,
  isError,
  onOpen,
}: {
  changes: ConfigChange[] | undefined;
  isLoading: boolean;
  isError: boolean;
  /** Called the first time the section is opened, so the history is not
   *  fetched for every drawer a user merely glances at. */
  onOpen: () => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div style={{ marginTop: 18 }}>
      <button
        onClick={() => {
          if (!open) onOpen();
          setOpen(!open);
        }}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, border: 'none', background: 'transparent',
          cursor: 'pointer', padding: 0, color: 'var(--app-t2)', fontSize: 12, fontWeight: 600,
        }}
      >
        <Icon name={open ? 'chevron-down' : 'chevron-right'} size={13} />
        Change history
      </button>
      {open && (
        <div style={{ marginTop: 8 }}>
          <SectionLabel icon="history">Who changed what</SectionLabel>
          {isLoading && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Loading…</div>}
          {isError && (
            <div style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>Couldn't load the change history.</div>
          )}
          {!isLoading && !isError && (changes ?? []).length === 0 && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
              Nothing has been changed from the console yet.
            </div>
          )}
          <ul style={{ margin: '4px 0 0', padding: 0 }}>
            {(changes ?? []).map((c, i) => (
              <ChangeRow key={`${c.changed_at}-${i}`} change={c} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
