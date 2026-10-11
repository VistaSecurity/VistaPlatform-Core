// Settings → Policies → Trusted CAs (slice 1).
//
// The home of every certificate-authority trust decision this organisation has
// made. Trust is decided CENTRALLY by the platform for the tenant — not by the
// root store of whichever sensor happened to look — so this page is the one
// place that says what "trusted" means here: public roots by default (the
// embedded bundle, shown read-only), overridden by the decisions in the table.
//
// Reading is `assets.read` (nav entry): anyone who can see the inventory can see
// the rules its trust column is decided by. Every WRITE control — Add CA,
// Change decision, Remove — sits behind `certificates.trust`, so a viewer sees
// the table and cannot change it. The server enforces the same permission; a
// 403 that still gets through (a role changed mid-session) is said in words
// inside the dialog, not as a generic failure.
import { useMemo, useRef, useState, type ChangeEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { useAuth } from '@vistasecurity/primitives/auth';
import { Icon, Modal, ModalField } from '../../components/ui';
import { useTenantUsers } from '../findings/queries';
import {
  TRUST_NOTE_MAX,
  TrustWriteError,
  caName,
  createTrustAnchor,
  deleteTrustAnchor,
  invalidateTrust,
  pemProblem,
  shortFingerprint,
  updateTrustAnchor,
  usePublicRoots,
  useTrustAnchors,
  type TrustAnchor,
  type TrustDecision,
} from '../inventory/trust-anchors';
import { SCard, SPage, SSection, STable, STableRow, STag, StateNote, relTime, type STableCol } from './kit';
import type { SettingsNavItem } from './nav';

const COLS: STableCol[] = [
  { label: 'CA', w: '2fr' },
  { label: 'Decision', w: '104px' },
  { label: 'Decided', w: '1.2fr' },
  { label: 'Note', w: '1.3fr' },
  { label: 'Affected', w: '1.1fr' },
  { label: '', w: '150px', align: 'right' },
];

const DECISION_TONE: Record<TrustDecision, string> = { trusted: 'var(--ok)', distrusted: 'var(--danger)' };
const DECISION_LABEL: Record<TrustDecision, string> = { trusted: 'Trusted', distrusted: 'Distrusted' };

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export function affectedSentence(a: Pick<TrustAnchor, 'affected_certificates' | 'affected_assets'>): string {
  return `${plural(a.affected_certificates ?? 0, 'certificate', 'certificates')} on ${plural(a.affected_assets ?? 0, 'asset', 'assets')}`;
}

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function TrustedCAsPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const anchorsQ = useTrustAnchors();
  const [adding, setAdding] = useState(false);
  const [changing, setChanging] = useState<TrustAnchor | null>(null);
  const [removing, setRemoving] = useState<TrustAnchor | null>(null);
  const [highlight, setHighlight] = useState<string | null>(null);
  const anchors = anchorsQ.data ?? [];
  const members = useDeciderNames();

  const point = (id: string) => {
    setHighlight(id);
    // Next frame: the row may only now be rendered (a fresh add).
    requestAnimationFrame(() => document.querySelector(`[data-anchor-row="${id}"]`)?.scrollIntoView?.({ block: 'center', behavior: 'smooth' }));
  };

  return (
    <SPage
      eyebrow={meta.section ?? 'Settings'}
      title={meta.label}
      job={meta.job}
      maxWidth={1060}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.certificates.trust}>
          <button className="ui-btn sm accent" onClick={() => setAdding(true)}>
            <Icon name="plus" size={14} />Add CA
          </button>
        </PermissionGate>
      }
    >
      <p style={{ margin: '0 0 18px', fontSize: 12.5, lineHeight: 1.6, color: 'var(--app-t2)', maxWidth: 760 }}>
        Vista Platform decides whether a certificate is trusted centrally, for your whole organisation — not from the
        trust store of whichever sensor happened to see it. Certificates that chain to a <strong>public root</strong> are
        trusted by default. A decision recorded here overrides that: trust your own internal certificate authorities, or
        distrust one — public or private — that your organisation no longer accepts.
      </p>

      <PublicRootsGroup />

      <SSection title="Your decisions" desc="Every certificate chaining to a CA below is evaluated against your decision.">
        {anchorsQ.isError ? (
          <SCard>
            <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load trust decisions" message={errorText(anchorsQ.error, 'The request failed.')} />
            <div style={{ textAlign: 'center', marginTop: -36, paddingBottom: 24 }}>
              <button className="ui-btn sm" onClick={() => void anchorsQ.refetch()}><Icon name="refresh-cw" size={13} />Retry</button>
            </div>
          </SCard>
        ) : anchorsQ.isLoading ? (
          <STable cols={COLS}>
            {[0, 1, 2].map((i) => (
              <STableRow key={i} first={i === 0} cols={COLS} cells={COLS.map((_, j) => <SkeletonBar key={j} />)} />
            ))}
          </STable>
        ) : anchors.length === 0 ? (
          <SCard>
            <StateNote icon="badge-check" tone="var(--app-t3)" title="No CA decisions yet." message="Public roots are trusted by default." />
            <PermissionGate permission={TENANT_PERMISSIONS.certificates.trust}>
              <div style={{ textAlign: 'center', marginTop: -36, paddingBottom: 24 }}>
                <button className="ui-btn sm accent" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add CA</button>
              </div>
            </PermissionGate>
          </SCard>
        ) : (
          <STable cols={COLS}>
            {anchors.map((a, i) => (
              <AnchorRow
                key={a.id}
                anchor={a}
                first={i === 0}
                highlighted={highlight === a.id}
                decidedBy={members(a.decided_by)}
                onChange={() => setChanging(a)}
                onRemove={() => setRemoving(a)}
              />
            ))}
          </STable>
        )}
      </SSection>

      {adding && (
        <AddCaModal
          anchors={anchors}
          onClose={() => setAdding(false)}
          onAdded={(a) => { setAdding(false); point(a.id); }}
          onShowExisting={(id) => { setAdding(false); point(id); }}
        />
      )}
      {changing && <ChangeDecisionModal anchor={changing} onClose={() => setChanging(null)} onSaved={(a) => { setChanging(null); point(a.id); }} />}
      {removing && <RemoveDecisionModal anchor={removing} onClose={() => setRemoving(null)} />}
    </SPage>
  );
}

function SkeletonBar() {
  return <span aria-hidden style={{ display: 'block', height: 10, width: '70%', borderRadius: 6, background: 'var(--app-track)', opacity: 0.7 }} />;
}

/** decided_by is a user id; show the member's name when the viewer can list members. */
function useDeciderNames(): (id: string | undefined) => string | null {
  const { tenant } = useAuth();
  const perms = usePermissions();
  const canList = perms.hasPermission(TENANT_PERMISSIONS.users.read);
  const members = useTenantUsers(canList ? tenant?.id : undefined);
  return (id) => {
    if (!id) return null;
    const u = (members.data ?? []).find((m) => m.id === id);
    if (u) return [u.first_name, u.last_name].filter(Boolean).join(' ') || u.email;
    // Not "unknown": without users.read the list is not ours to read, and a
    // member who left is genuinely no longer in it.
    return canList && !members.isLoading ? 'a former member' : 'a member';
  };
}

function PublicRootsGroup() {
  const q = usePublicRoots();
  const line = q.data
    ? `Public roots · Mozilla bundle ${q.data.version} · ${plural(q.data.root_count, 'root', 'roots')} · trusted by default`
    : q.isError
      ? "Public roots · couldn't load the bundle details · trusted by default"
      : 'Public roots · loading…';
  return (
    <SSection title="Public roots">
      <SCard pad={16} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Icon name="shield-check" size={17} style={{ color: 'var(--ok)', flex: 'none' }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div data-testid="public-roots" style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{line}</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
            The same bundle for every organisation, refreshed with each release{q.data?.source ? ` (${q.data.source})` : ''}. To stop trusting one public root, add it here as distrusted.
          </div>
        </div>
        <STag color="var(--app-t2)">Read-only</STag>
      </SCard>
    </SSection>
  );
}

function AnchorRow({ anchor: a, first, highlighted, decidedBy, onChange, onRemove }: {
  anchor: TrustAnchor; first: boolean; highlighted: boolean; decidedBy: string | null; onChange: () => void; onRemove: () => void;
}) {
  const fp = a.certificate?.fingerprint_sha256;
  const [copied, setCopied] = useState(false);
  const copy = () => {
    if (!fp || !navigator.clipboard) return;
    void navigator.clipboard.writeText(fp).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  };
  return (
    <div data-anchor-row={a.id} data-highlighted={highlighted ? 'true' : undefined}>
      <STableRow
        first={first}
        cols={COLS}
        style={highlighted ? { background: 'color-mix(in srgb, var(--accent) 9%, transparent)' } : undefined}
        cells={[
          <div key="ca" style={{ minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.certificate?.subject_dn}>
              {caName(a.certificate)}
            </div>
            <button
              type="button"
              onClick={copy}
              title={fp ? `SHA-256 ${fp} — click to copy` : undefined}
              className="mono"
              style={{ border: 'none', background: 'none', padding: 0, cursor: fp ? 'copy' : 'default', fontSize: 10.5, color: 'var(--app-t3)', display: 'inline-flex', alignItems: 'center', gap: 4 }}
            >
              {shortFingerprint(fp)}{fp && <Icon name={copied ? 'check' : 'copy'} size={10} />}
            </button>
          </div>,
          <STag key="d" color={DECISION_TONE[a.decision]}>{DECISION_LABEL[a.decision]}</STag>,
          <div key="by" style={{ fontSize: 12, color: 'var(--app-t2)' }} title={a.decided_at}>
            {decidedBy ? <>{decidedBy}<br /></> : null}
            <span style={{ color: 'var(--app-t3)' }}>{relTime(a.decided_at)}</span>
          </div>,
          <div key="n" style={{ fontSize: 12, color: a.note ? 'var(--app-t2)' : 'var(--app-t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.note}>{a.note ?? '—'}</div>,
          <div key="aff" style={{ fontSize: 12, color: 'var(--app-t2)' }}>{affectedSentence(a)}</div>,
          <PermissionGate key="act" permission={TENANT_PERMISSIONS.certificates.trust}>
            <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
              <button className="ui-btn sm" onClick={onChange}>Change decision</button>
              <button className="ui-btn sm ghost" onClick={onRemove} aria-label={`Remove decision for ${caName(a.certificate)}`} title="Remove decision">
                <Icon name="trash-2" size={13} />Remove
              </button>
            </div>
          </PermissionGate>,
        ]}
      />
    </div>
  );
}

function DecisionPicker({ value, onChange }: { value: TrustDecision; onChange: (d: TrustDecision) => void }) {
  return (
    <div role="radiogroup" aria-label="Decision" style={{ display: 'flex', gap: 8 }}>
      {(['trusted', 'distrusted'] as const).map((d) => (
        <button
          key={d}
          type="button"
          role="radio"
          aria-checked={value === d}
          onClick={() => onChange(d)}
          style={{
            flex: 1, padding: '8px 0', borderRadius: 8, fontSize: 12.5, fontWeight: 600, cursor: 'pointer',
            background: value === d ? `color-mix(in srgb, ${DECISION_TONE[d]} 14%, transparent)` : 'var(--app-panel2)',
            color: value === d ? DECISION_TONE[d] : 'var(--app-t2)',
            border: `1px solid ${value === d ? DECISION_TONE[d] : 'var(--app-border2)'}`,
          }}
        >
          {DECISION_LABEL[d]}
        </button>
      ))}
    </div>
  );
}

const TEXTAREA_STYLE = {
  width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)',
  color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' as const, lineHeight: 1.45,
};

function NoteField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <ModalField label="Note" hint={`Optional — why, a ticket, an owner. ${value.length}/${TRUST_NOTE_MAX}`}>
      <textarea aria-label="Note" value={value} maxLength={TRUST_NOTE_MAX} rows={2} onChange={(e) => onChange(e.target.value)} style={TEXTAREA_STYLE} />
    </ModalField>
  );
}

/** The decision this paste collides with, when it can be named from the server's 409 text. */
function existingFrom(anchors: TrustAnchor[], message: string): TrustAnchor | null {
  const m = message.toLowerCase();
  return anchors.find((a) => {
    const names = [a.id, a.certificate_id, a.certificate?.fingerprint_sha256, a.certificate?.common_name, caName(a.certificate)];
    return names.some((n) => typeof n === 'string' && n.length > 2 && n !== '—' && m.includes(n.toLowerCase()));
  }) ?? null;
}

export function AddCaModal({ anchors, onClose, onAdded, onShowExisting }: {
  anchors: TrustAnchor[]; onClose: () => void; onAdded: (a: TrustAnchor) => void; onShowExisting: (id: string) => void;
}) {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [pem, setPem] = useState('');
  const [decision, setDecision] = useState<TrustDecision>('trusted');
  const [note, setNote] = useState('');
  const [touched, setTouched] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const problem = pemProblem(pem);

  const create = useMutation({
    mutationFn: () => createTrustAnchor({ certificate_pem: pem.trim(), decision, note: note.trim() || undefined }),
    onSuccess: (a) => {
      invalidateTrust(qc);
      toast.success(`${decision === 'trusted' ? 'Trusted' : 'Distrusted'} ${caName(a.certificate)}`);
      onAdded(a);
    },
  });

  const conflict = create.error instanceof TrustWriteError && create.error.status === 409 ? create.error : null;
  const existing = useMemo(() => (conflict ? existingFrom(anchors, conflict.message) : null), [conflict, anchors]);

  // Read client-side as TEXT into the same textarea — the request carries PEM,
  // never a binary upload. A DER file reads as garbage and fails the PEM check.
  const pick = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = '';
    if (!f) return;
    setFileError(null);
    const reader = new FileReader();
    reader.onload = () => { setPem(typeof reader.result === 'string' ? reader.result : ''); setTouched(true); create.reset(); };
    reader.onerror = () => setFileError(`Couldn't read ${f.name}.`);
    reader.readAsText(f);
  };

  const footer = create.isError
    ? (
      <span style={{ color: 'var(--danger-text)' }}>
        {errorText(create.error, 'Request failed')}
        {conflict && existing && (
          <> {' '}<button type="button" className="ui-btn sm ghost" style={{ height: 22, padding: '0 6px' }} onClick={() => onShowExisting(existing.id)}>Show existing decision</button></>
        )}
      </span>
    )
    : touched && problem ? <span style={{ color: 'var(--danger-text)' }}>{problem}</span>
      : fileError ? <span style={{ color: 'var(--danger-text)' }}>{fileError}</span>
        : 'PEM (.pem/.crt/.cer). With a chain, the decision applies to the last certificate.';

  return (
    <Modal
      open
      onClose={create.isPending ? undefined : onClose}
      dismissible={!create.isPending}
      icon="badge-check"
      eyebrow="Policies · Trusted CAs"
      title="Add a CA decision"
      description="Paste the certificate authority's certificate, or choose a file. It is stored in your inventory and every certificate that chains to it is re-evaluated."
      primary={
        <button className="ui-btn sm accent" disabled={!!problem || create.isPending} onClick={() => { setTouched(true); create.mutate(); }}>
          {create.isPending ? 'Saving…' : decision === 'trusted' ? 'Trust this CA' : 'Distrust this CA'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose} disabled={create.isPending}>Cancel</button>}
      footerNote={footer}
    >
      <ModalField label="CA certificate (PEM)">
        <textarea
          aria-label="CA certificate (PEM)"
          data-autofocus
          value={pem}
          onChange={(e) => { setPem(e.target.value); setTouched(true); create.reset(); }}
          rows={7}
          spellCheck={false}
          placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
          className="mono"
          style={{ ...TEXTAREA_STYLE, fontSize: 11.5 }}
        />
      </ModalField>
      <div style={{ margin: '-6px 0 14px' }}>
        <input ref={fileRef} type="file" accept=".pem,.crt,.cer" hidden aria-label="Choose a certificate file" onChange={pick} />
        <button type="button" className="ui-btn sm" onClick={() => fileRef.current?.click()}><Icon name="file-up" size={13} />Choose a file…</button>
      </div>
      <ModalField label="Decision">
        <DecisionPicker value={decision} onChange={setDecision} />
      </ModalField>
      <NoteField value={note} onChange={setNote} />
    </Modal>
  );
}

function CaSummary({ anchor }: { anchor: TrustAnchor }) {
  return (
    <div className="panel" style={{ padding: 12, borderRadius: 10, marginBottom: 14, display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', wordBreak: 'break-all' }}>{anchor.certificate?.subject_dn || caName(anchor.certificate)}</div>
      <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', wordBreak: 'break-all' }}>SHA-256 {anchor.certificate?.fingerprint_sha256 || '—'}</div>
      <div style={{ fontSize: 12, color: 'var(--app-t2)' }}>Affects {affectedSentence(anchor)}.</div>
    </div>
  );
}

export function ChangeDecisionModal({ anchor, onClose, onSaved }: { anchor: TrustAnchor; onClose: () => void; onSaved: (a: TrustAnchor) => void }) {
  const qc = useQueryClient();
  // The common reason to open this is to flip the decision, so it starts flipped.
  const [decision, setDecision] = useState<TrustDecision>(anchor.decision === 'trusted' ? 'distrusted' : 'trusted');
  const [note, setNote] = useState(anchor.note ?? '');
  const save = useMutation({
    mutationFn: () => updateTrustAnchor(anchor.id, { decision, note: note.trim() }),
    onSuccess: (a) => {
      invalidateTrust(qc);
      toast.success(`${caName(anchor.certificate)} is now ${DECISION_LABEL[a.decision ?? decision].toLowerCase()}`);
      onSaved(a);
    },
  });
  return (
    <Modal
      open
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      tone={decision === 'distrusted' ? 'danger' : 'accent'}
      icon={decision === 'distrusted' ? 'shield-x' : 'shield-check'}
      eyebrow="Policies · Trusted CAs"
      title={`Change decision — ${caName(anchor.certificate)}`}
      description={decision === 'trusted'
        ? `Trusting ${caName(anchor.certificate)} marks every certificate that chains to it as trusted by your organisation.`
        : `Distrusting ${caName(anchor.certificate)} marks every certificate that chains to it as distrusted, even if it is a public root.`}
      primary={<button className="ui-btn sm accent" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save decision'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{errorText(save.error, 'Request failed')}</span> : undefined}
    >
      <CaSummary anchor={anchor} />
      <ModalField label="Decision"><DecisionPicker value={decision} onChange={setDecision} /></ModalField>
      <NoteField value={note} onChange={setNote} />
    </Modal>
  );
}

export function RemoveDecisionModal({ anchor, onClose }: { anchor: TrustAnchor; onClose: () => void }) {
  const qc = useQueryClient();
  const name = caName(anchor.certificate);
  const remove = useMutation({
    mutationFn: () => deleteTrustAnchor(anchor.id),
    onSuccess: () => {
      invalidateTrust(qc);
      toast.success(`Removed the decision for ${name}`);
      onClose();
    },
  });
  return (
    <Modal
      open
      size="sm"
      tone="danger"
      icon="alert-triangle"
      onClose={remove.isPending ? undefined : onClose}
      dismissible={!remove.isPending}
      eyebrow="Policies · Trusted CAs"
      title={`Remove decision — ${name}`}
      description={`The CA stays in your inventory. Certificates that chain to it (${affectedSentence(anchor)}) return to Untrusted CA — or to Public CA if it is a public root.`}
      primary={
        <button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={remove.isPending} onClick={() => remove.mutate()}>
          {remove.isPending ? 'Removing…' : 'Remove decision'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose} disabled={remove.isPending}>Cancel</button>}
      footerNote={remove.isError ? <span style={{ color: 'var(--danger-text)' }}>{errorText(remove.error, 'Request failed')}</span> : undefined}
    />
  );
}
