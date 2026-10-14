// VISTA Operations — Maintenance › About & Updates › Update confirmation.
//
// Opening the dialog runs pre-flight for the target version (spinner, then the
// check list in plain language). It says what will happen, and the Update
// button stays disabled until (a) pre-flight has no failing check and (b) the
// operator has typed the version. Warnings — image pins in the values, a
// single-node cluster, no recent backup — are shown and allow the update.
// "I have my own backup" skips the run's backup step (spec D4); the run
// records that the operator chose it.
import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Loader2, XCircle, type LucideIcon } from 'lucide-react';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import {
  PreflightFailedError,
  RunInProgressError,
  usePreflight,
  useRunMutations,
  type PreflightCheck,
  type PreflightResult,
} from './maintenance-queries';

/** Plain-language names of the pre-flight checks. */
export const CHECK_LABEL: Record<PreflightCheck['name'], string> = {
  capabilities: 'Managed by Helm',
  version: 'Version available',
  signature: 'Chart signature',
  value_overrides: 'Image pins in your values',
  single_node: 'Cluster size',
  schema: 'Database schema',
  no_run_in_progress: 'No other maintenance running',
  recent_backup: 'Recent backup',
};

const CHECK_META: Record<PreflightCheck['status'], { icon: LucideIcon; color: string; label: string }> = {
  pass: { icon: CheckCircle2, color: 'var(--ok)', label: 'Pass' },
  warn: { icon: AlertTriangle, color: 'var(--warn)', label: 'Warning' },
  fail: { icon: XCircle, color: 'var(--danger)', label: 'Blocks the update' },
};

export type DialogPhase = 'checking' | 'preflight-error' | 'blocked' | 'confirm' | 'ready' | 'starting';

export interface DialogInput {
  preflight: { isLoading: boolean; isError: boolean; data?: PreflightResult };
  /** A 422 from POST /updates carries a fresher pre-flight; it wins. */
  rejected?: PreflightResult;
  version: string;
  typed: string;
  starting: boolean;
}

/**
 * The dialog's state (pure, for tests): what it shows and whether Update is
 * enabled. Update needs a pre-flight with no failing check AND the version
 * typed exactly; warnings never block.
 */
export function dialogState(i: DialogInput): { phase: DialogPhase; result?: PreflightResult; canUpdate: boolean } {
  const result = i.rejected ?? i.preflight.data;
  if (i.starting) return { phase: 'starting', result, canUpdate: false };
  if (!result && i.preflight.isLoading) return { phase: 'checking', canUpdate: false };
  if (!result) return { phase: 'preflight-error', canUpdate: false };
  if (!result.ok || result.checks.some((c) => c.status === 'fail')) return { phase: 'blocked', result, canUpdate: false };
  if (i.typed.trim() !== i.version) return { phase: 'confirm', result, canUpdate: false };
  return { phase: 'ready', result, canUpdate: true };
}

function CheckRow({ check }: { check: PreflightCheck }) {
  const meta = CHECK_META[check.status];
  const Icon = meta.icon;
  return (
    <li data-testid="preflight-check" data-check={check.name} data-status={check.status} style={{ listStyle: 'none', display: 'flex', gap: 9, padding: '7px 0', borderBottom: '1px solid var(--op-border)' }}>
      <Icon size={15} style={{ color: meta.color, flex: 'none', marginTop: 1 }} aria-label={meta.label} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--op-t1)' }}>{CHECK_LABEL[check.name] ?? check.name}</div>
        <div style={{ fontSize: 12, color: 'var(--op-t3)', lineHeight: 1.5, wordBreak: 'break-word' }}>{check.detail}</div>
      </div>
    </li>
  );
}

export function UpdateDialog({ version, currentVersion, onClose, onStarted }: {
  version: string;
  currentVersion?: string;
  onClose: () => void;
  /** The run started: the caller navigates to its progress page. */
  onStarted: (runId: string) => void;
}) {
  const preflight = usePreflight(version);
  const { update } = useRunMutations();
  const [typed, setTyped] = useState('');
  const [ownBackup, setOwnBackup] = useState(false);
  const rejected = update.error instanceof PreflightFailedError ? update.error.preflight : undefined;
  const st = dialogState({ preflight, rejected, version, typed, starting: update.isPending });
  const startError = update.error instanceof RunInProgressError ? update.error.message
    : update.error && !(update.error instanceof PreflightFailedError) ? update.error.message : null;

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={`Update to Vista Platform ${version}`}
      description={currentVersion ? `From ${currentVersion}. Pre-flight checks this install first; nothing changes until you press Update.` : 'Pre-flight checks this install first; nothing changes until you press Update.'}
      tone="accent"
      footerNote="Platform-admin · audited"
      primaryLabel={`Update to ${version}`}
      primaryLoadingLabel="Starting…"
      primaryLoading={update.isPending}
      primaryDisabled={!st.canUpdate}
      onPrimary={() => {
        if (!st.canUpdate) return;
        update.mutate({ version, skip_backup: ownBackup }, { onSuccess: (r) => onStarted(r.run.id) });
      }}
      dirty={typed !== '' || ownBackup}
    >
      <div data-testid="update-dialog" data-phase={st.phase}>
        <ModalField label="Pre-flight">
          {st.phase === 'checking' && (
            <div data-testid="preflight-loading" style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5, color: 'var(--op-t3)' }}>
              <Loader2 size={14} className="spin" /> Checking this install — this can take up to a minute while the chart’s signature is verified…
            </div>
          )}
          {st.phase === 'preflight-error' && (
            <div data-testid="preflight-error" role="alert" style={{ fontSize: 12.5, color: 'var(--danger)' }}>
              Pre-flight could not run. {preflight.error?.message ?? ''}
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => { void preflight.refetch(); }}>Retry</button>
            </div>
          )}
          {st.result && (
            <ul data-testid="preflight-checks" style={{ margin: 0, padding: 0 }}>
              {st.result.checks.map((c) => <CheckRow key={c.name} check={c} />)}
            </ul>
          )}
          {st.phase === 'blocked' && (
            <div data-testid="preflight-blocked" role="alert" style={{ fontSize: 12, color: 'var(--danger)', marginTop: 6 }}>
              Fix the checks marked as blocking, then open this dialog again.
            </div>
          )}
        </ModalField>

        <ModalField label="What will happen">
          <ol data-testid="update-plan" style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--op-t2)', lineHeight: 1.7 }}>
            <li data-testid="plan-backup">{ownBackup ? <s>Back up the database first</s> : 'Back up the database first (database only — download it from Backups afterwards).'}{ownBackup && ' — skipped: you have your own backup.'}</li>
            <li>Verify the chart’s signature against the Vista Security release identity.</li>
            <li>Apply the new database schema, then restart every service on {version}.</li>
            <li>Services restarted with the Recreate strategy (such as pcap-processor and sensor-manager) are briefly unavailable; the console itself restarts too.</li>
            <li>Check that every service reports {version}. If anything fails you can roll back from the progress page.</li>
          </ol>
          <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 6 }}>You do not need to keep this page open — the update runs in the cluster.</div>
        </ModalField>

        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer', margin: '4px 0 10px' }}>
          <input type="checkbox" data-testid="own-backup" checked={ownBackup} onChange={(e) => setOwnBackup(e.target.checked)} />
          I have my own backup — skip the backup step
        </label>

        <ModalField label={`Type ${version} to confirm`}>
          <input
            aria-label="Type the version to confirm"
            data-testid="confirm-version"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={version}
            autoComplete="off"
            spellCheck={false}
            style={modalInputStyle}
            disabled={st.phase === 'checking' || st.phase === 'blocked' || st.phase === 'preflight-error'}
          />
        </ModalField>
        {startError && <div role="alert" data-testid="update-start-error" style={{ fontSize: 12, color: 'var(--danger)' }}>{startError}</div>}
      </div>
    </Modal>
  );
}
