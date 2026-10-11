// The certificate drawer's Trust pieces ( slice 1): the header chip, the
// "Trust" rows in Trust & revocation, and — on a CA certificate — the Trust /
// Distrust / Remove decision action. The action writes the same store as
// Settings → Policies → Trusted CAs, through the same helpers, so a decision
// made here appears there and flips the chip on every certificate chaining to
// this CA once the server's synchronous re-evaluation returns.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { MetaRow, Modal, ModalField } from '../../components/ui';
import { TRUST_TONE_COLOR, trustPresentation } from './trust-status';
import {
  TRUST_NOTE_MAX,
  caName,
  createTrustAnchor,
  deleteTrustAnchor,
  invalidateTrust,
  updateTrustAnchor,
  useTrustAnchors,
  type TrustAnchor,
  type TrustDecision,
} from './trust-anchors';

type Certificate = inventoryComponents['schemas']['Certificate'];

export function CertTrustChip({ status }: { status: string | null | undefined }) {
  const p = trustPresentation(status);
  const c = TRUST_TONE_COLOR[p.tone];
  return (
    <span
      data-testid="cert-trust-chip"
      title={p.explanation}
      style={{ fontSize: 11, fontWeight: 600, color: c, background: `color-mix(in srgb, ${c} 11%, transparent)`, borderRadius: 40, padding: '2px 9px', whiteSpace: 'nowrap' }}
    >
      {p.label}
    </span>
  );
}

/** Names the certificate the trust status was decided on, from the chain already loaded. */
export function trustAnchorName(cert: Pick<Certificate, 'id' | 'trust_anchor_certificate_id'>, chain: Certificate[]): string | null {
  const id = cert.trust_anchor_certificate_id;
  if (!id) return null;
  if (id === cert.id) return 'this certificate';
  const hit = chain.find((l) => l.id === id);
  return hit ? caName(hit) : id;
}

/** The rows at the top of the drawer's Trust & revocation section. */
export function CertTrustRows({ cert, chain }: { cert: Certificate; chain: Certificate[] }) {
  const p = trustPresentation(cert.trust_status);
  const anchor = trustAnchorName(cert, chain);
  return (
    <>
      <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
          <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Trust</span>
          <CertTrustChip status={cert.trust_status} />
        </div>
        <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginTop: 4, lineHeight: 1.5 }}>{p.explanation}</div>
      </div>
      {anchor && <MetaRow k="Chain ends at" v={anchor} mono title={cert.trust_anchor_certificate_id} />}
      {cert.trust_evaluated_at && <MetaRow k="Trust evaluated" v={cert.trust_evaluated_at.slice(0, 10)} mono />}
      {cert.is_ca_certificate === true && <CertTrustAction cert={cert} />}
    </>
  );
}

type Intent = { kind: 'decide'; decision: TrustDecision } | { kind: 'remove' };

/** Trust / Distrust / Remove decision for a CA certificate. */
export function CertTrustAction({ cert }: { cert: Certificate }) {
  const anchorsQ = useTrustAnchors(cert.is_ca_certificate === true);
  const [intent, setIntent] = useState<Intent | null>(null);
  const existing = (anchorsQ.data ?? []).find((a) => a.certificate_id === cert.id) ?? null;
  const decided = existing?.decision;

  return (
    <PermissionGate permission={TENANT_PERMISSIONS.certificates.trust}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
        {anchorsQ.isLoading ? (
          <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading trust decision…</span>
        ) : (
          <>
            {decided !== 'trusted' && (
              <button className="ui-btn sm accent" onClick={() => setIntent({ kind: 'decide', decision: 'trusted' })}>Trust this CA</button>
            )}
            {decided !== 'distrusted' && (
              <button className="ui-btn sm" onClick={() => setIntent({ kind: 'decide', decision: 'distrusted' })}>Distrust this CA</button>
            )}
            {existing && (
              <button className="ui-btn sm ghost" onClick={() => setIntent({ kind: 'remove' })}>Remove decision</button>
            )}
          </>
        )}
      </div>
      {intent && <TrustConfirm cert={cert} existing={existing} intent={intent} onClose={() => setIntent(null)} />}
    </PermissionGate>
  );
}

function TrustConfirm({ cert, existing, intent, onClose }: { cert: Certificate; existing: TrustAnchor | null; intent: Intent; onClose: () => void }) {
  const qc = useQueryClient();
  const name = caName(cert);
  const [note, setNote] = useState(existing?.note ?? '');
  const write = useMutation({
    mutationFn: async () => {
      if (intent.kind === 'remove') {
        if (existing) await deleteTrustAnchor(existing.id);
        return;
      }
      const trimmed = note.trim();
      if (existing) await updateTrustAnchor(existing.id, { decision: intent.decision, note: trimmed });
      else await createTrustAnchor({ certificate_id: cert.id, decision: intent.decision, note: trimmed || undefined });
    },
    onSuccess: () => {
      invalidateTrust(qc);
      toast.success(intent.kind === 'remove' ? `Removed the decision for ${name}` : `${intent.decision === 'trusted' ? 'Trusted' : 'Distrusted'} ${name}`);
      onClose();
    },
  });

  const remove = intent.kind === 'remove';
  const trust = intent.kind === 'decide' && intent.decision === 'trusted';
  const title = remove ? `Remove decision — ${name}` : trust ? `Trust ${name}?` : `Distrust ${name}?`;
  const description = remove
    ? `The CA stays in your inventory. Certificates that chain to ${name} return to Untrusted CA — or to Public CA if it is a public root.`
    : trust
      ? `Trusting ${name} marks every certificate that chains to it as trusted by your organisation.`
      : `Distrusting ${name} marks every certificate that chains to it as distrusted by your organisation.`;
  const label = remove ? 'Remove decision' : trust ? 'Trust this CA' : 'Distrust this CA';

  return (
    <Modal
      open
      size="sm"
      tone={trust ? 'accent' : 'danger'}
      icon={remove ? 'alert-triangle' : trust ? 'shield-check' : 'shield-x'}
      eyebrow="Certificate trust"
      title={title}
      description={description}
      onClose={write.isPending ? undefined : onClose}
      dismissible={!write.isPending}
      primary={
        <button className={trust ? 'ui-btn sm accent' : 'ui-btn sm'} style={trust ? undefined : { borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={write.isPending} onClick={() => write.mutate()}>
          {write.isPending ? 'Saving…' : label}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose} disabled={write.isPending}>Cancel</button>}
      footerNote={write.isError ? <span style={{ color: 'var(--danger-text)' }}>{write.error instanceof Error ? write.error.message : 'Request failed'}</span> : undefined}
    >
      {!remove && (
        <ModalField label="Note" hint={`Optional — why, a ticket, an owner. ${note.length}/${TRUST_NOTE_MAX}`}>
          <textarea
            aria-label="Note"
            value={note}
            maxLength={TRUST_NOTE_MAX}
            rows={2}
            onChange={(e) => setNote(e.target.value)}
            style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
          />
        </ModalField>
      )}
    </Modal>
  );
}
