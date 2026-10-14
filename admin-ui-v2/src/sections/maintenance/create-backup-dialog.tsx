// VISTA Operations — Maintenance › Backups › Create backup.
//
// Contents: the database, always. Optionally the encryption keys and install
// secrets (spec platform-maintenance.md D2) — without the encryption master
// key a restored database holds credentials nothing can decrypt, but a file
// holding that key is as sensitive as the cluster itself, so the service then
// encrypts the whole bundle under a passphrase the operator chooses here.
// The passphrase is never stored: it is the only way to open the file.
import { useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { MIN_BACKUP_PASSPHRASE, type CreateBackupRequest } from './maintenance-queries';

export interface CreateBackupForm {
  includeSecrets: boolean;
  passphrase: string;
  confirm: string;
}

export const EMPTY_BACKUP_FORM: CreateBackupForm = { includeSecrets: false, passphrase: '', confirm: '' };

/**
 * Why the form cannot be submitted, or null. Mirrors the service's rule
 * (backups.CreateOptions.Validate): a passphrase of at least 12 characters
 * when the secrets are included — plus the confirmation, which only the
 * console can check.
 */
export function createBackupFormError(f: CreateBackupForm): string | null {
  if (!f.includeSecrets) return null;
  if (!f.passphrase) return 'Enter a passphrase to encrypt the backup.';
  if ([...f.passphrase].length < MIN_BACKUP_PASSPHRASE) return `The passphrase must be at least ${MIN_BACKUP_PASSPHRASE} characters.`;
  if (f.passphrase !== f.confirm) return 'The two passphrases do not match.';
  return null;
}

/** The request body for a valid form. A passphrase is sent only with the secrets. */
export function createBackupRequest(f: CreateBackupForm): CreateBackupRequest {
  return f.includeSecrets ? { include_secrets: true, passphrase: f.passphrase } : { include_secrets: false };
}

export function CreateBackupDialog({ onClose, onCreate, pending, error }: {
  onClose: () => void;
  onCreate: (body: CreateBackupRequest) => void;
  pending: boolean;
  /** The service's refusal, shown inline. */
  error: string | null;
}) {
  const [form, setForm] = useState<CreateBackupForm>(EMPTY_BACKUP_FORM);
  const set = <K extends keyof CreateBackupForm>(k: K, v: CreateBackupForm[K]) => setForm((p) => ({ ...p, [k]: v }));
  const formError = createBackupFormError(form);
  // Show the rule only once the operator has typed something.
  const showFormError = form.includeSecrets && (form.passphrase !== '' || form.confirm !== '') ? formError : null;

  return (
    <Modal
      open
      onClose={onClose}
      title="Create backup"
      description="Backs up the Vista Platform database to backup storage, as a file you can download. The platform keeps running while it does."
      footerNote="Platform-admin · audited"
      primaryLabel="Create backup"
      primaryLoadingLabel="Starting…"
      onPrimary={() => { if (!formError) onCreate(createBackupRequest(form)); }}
      primaryDisabled={formError !== null}
      primaryLoading={pending}
      dirty={form.passphrase !== '' || form.confirm !== ''}
    >
      <ModalField label="Contents">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)' }}>
          <input type="checkbox" checked disabled aria-label="Database" /> Database (always included)
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)', cursor: 'pointer', marginTop: 6 }}>
          <input
            type="checkbox"
            data-testid="include-secrets"
            checked={form.includeSecrets}
            onChange={(e) => setForm({ includeSecrets: e.target.checked, passphrase: '', confirm: '' })}
          />
          Include encryption keys and install secrets
        </label>
      </ModalField>

      {form.includeSecrets && (
        <>
          <div data-testid="secrets-warning" style={{ display: 'flex', gap: 9, fontSize: 12, lineHeight: 1.55, color: 'var(--op-t2)', background: 'color-mix(in srgb, var(--warn) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--warn) 30%, transparent)', borderRadius: 'var(--r-sm)', padding: '10px 12px' }}>
            <AlertTriangle size={15} style={{ color: 'var(--warn)', flex: 'none', marginTop: 1 }} />
            <span>
              The backup will contain this install’s encryption master key, JWT signing key and install identity. With them,
              a restored platform can read the credentials it stores — and so can anyone holding the file. It is encrypted
              with the passphrase below. <strong>The passphrase is not stored anywhere: it is the only way to open the file.</strong>{' '}
              If you lose it, the backup cannot be restored.
            </span>
          </div>
          <ModalField label={`Passphrase (at least ${MIN_BACKUP_PASSPHRASE} characters)`}>
            <input
              type="password"
              aria-label="Passphrase"
              autoComplete="new-password"
              value={form.passphrase}
              onChange={(e) => set('passphrase', e.target.value)}
              style={modalInputStyle}
            />
          </ModalField>
          <ModalField label="Confirm passphrase">
            <input
              type="password"
              aria-label="Confirm passphrase"
              autoComplete="new-password"
              value={form.confirm}
              onChange={(e) => set('confirm', e.target.value)}
              style={modalInputStyle}
            />
          </ModalField>
        </>
      )}
      {showFormError && <div role="alert" data-testid="form-error" style={{ fontSize: 11.5, color: 'var(--danger)' }}>{showFormError}</div>}
      {error && <div role="alert" data-testid="create-error" style={{ fontSize: 12, color: 'var(--danger)' }}>{error}</div>}
    </Modal>
  );
}
