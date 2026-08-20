// Artifact detail slide-out — full metadata (hash, signature, provenance,
// compliance-attestation layers) plus the per-artifact actions: download,
// verify (recompute hash/signature), compare, delete. Reads the live detail
// (GET /cbom/artifacts/:id), seeded by the list row so it paints instantly.
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { Icon } from '../../components/ui';
import { fmtBytes, fmtDateTime, hashVerdict, relTime, Pill } from './kit';
import { artifactName, downloadArtifact, useArtifact, useDeleteArtifact, useVerify, type CBOMArtifact, type Layer, type VerifyResponse } from './queries';

function Row({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '9px 0', borderBottom: '1px solid var(--app-border)' }}>
      <span style={{ fontSize: 11.5, color: 'var(--app-t3)', width: 116, flex: 'none', paddingTop: 1 }}>{label}</span>
      <span className={mono ? 'mono' : undefined} style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1, minWidth: 0, wordBreak: mono ? 'break-all' : 'normal' }}>{children}</span>
    </div>
  );
}

function VerifyResult({ v }: { v: VerifyResponse }) {
  // Three states — see hashVerdict. "Not checked" must not render as a mismatch.
  const hash = hashVerdict(v);
  return (
    <div style={{ marginTop: 11, padding: '11px 13px', borderRadius: 10, background: 'var(--app-panel2)', border: '1px solid var(--app-border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name={hash.icon} size={15} style={{ color: hash.tone }} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: hash.tone }}>{hash.label}</span>
      </div>
      {hash.detail && (
        <div className={hash.state === 'mismatch' ? 'mono' : undefined}
          style={{ fontSize: hash.state === 'mismatch' ? 10.5 : 11.5, color: 'var(--app-t3)', marginTop: 6, wordBreak: 'break-all', lineHeight: 1.5 }}>
          {hash.detail}
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 8, fontSize: 11.5, color: 'var(--app-t2)' }}>
        <Icon name={v.signature_checked ? (v.signature_valid ? 'badge-check' : 'shield-x') : 'shield-off'} size={13}
          style={{ color: v.signature_checked ? (v.signature_valid ? 'var(--ok)' : 'var(--danger)') : 'var(--app-t3)' }} />
        {v.signature_checked
          ? (v.signature_valid ? 'Signature valid' : 'Signature invalid')
          : 'Signature not asserted (unsigned or no verifier wired)'}
        {v.signature_kid && <span className="mono" style={{ color: 'var(--app-t3)' }}>· {v.signature_kid}</span>}
      </div>
    </div>
  );
}

function AttestationLayer({ layer }: { layer: Layer }) {
  return (
    <div style={{ padding: '10px 12px', borderRadius: 9, background: 'var(--app-panel2)', border: '1px solid var(--app-border)', marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <Icon name="shield-check" size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{layer.type.replace(/_/g, ' ')}</span>
        {layer.version && <Pill color="var(--app-t3)">v{layer.version}</Pill>}
      </div>
      {layer.data && Object.keys(layer.data).length > 0 && (
        <pre className="mono" style={{ margin: '8px 0 0', fontSize: 10.5, color: 'var(--app-t2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 140, overflowY: 'auto' }}>
          {JSON.stringify(layer.data, null, 2)}
        </pre>
      )}
    </div>
  );
}

export function ArtifactDrawer({ seed, onClose, onDeleted }: {
  seed: CBOMArtifact;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const nav = useNavigate();
  const detailQ = useArtifact(seed.id);
  const verify = useVerify();
  const del = useDeleteArtifact();
  const [verifyRes, setVerifyRes] = useState<VerifyResponse | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [downloadErr, setDownloadErr] = useState<string | null>(null);
  // Comparison is Enterprise-only (cbom-service/ee/diff). Download and verify
  // are Core; verify simply reports "signature not asserted" on an unsigned
  // (Core-generated) artifact, which is accurate, not a failure.
  const evidenceEntitled = useFeature('cbom_signing');

  const a = detailQ.data ?? seed;
  const layers = a.layers ?? [];
  const signed = !!a.signature_hmac;

  const onDownload = async () => {
    setDownloadErr(null);
    try { await downloadArtifact(a); } catch (e) { setDownloadErr(e instanceof Error ? e.message : 'Download failed'); }
  };

  const onVerify = async () => {
    try { setVerifyRes(await verify.mutateAsync(a.id)); } catch { /* surfaced via verify.isError below */ }
  };

  const onDelete = async () => {
    await del.mutateAsync(a.id);
    onDeleted();
  };

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'var(--app-scrim)', animation: 'scrimIn .18s ease both', display: 'flex', justifyContent: 'flex-end' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 480, maxWidth: '95vw', height: '100%', background: 'var(--app-panel)', borderLeft: '1px solid var(--app-border2)', boxShadow: 'var(--app-shadow)', animation: 'drawerIn .26s cubic-bezier(.2,.8,.2,1) both', display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
        {/* header */}
        <div style={{ padding: '16px 18px 14px', borderBottom: '1px solid var(--app-border)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 11 }}>
            <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--accent) 14%, transparent)', color: 'var(--accent)' }}>
              <Icon name="file-badge" size={19} />
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.08em' }}>CBOM Artifact</div>
              <div style={{ fontSize: 15.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.25 }}>{artifactName(a)}</div>
            </div>
            <button onClick={onClose} title="Close" style={{ flex: 'none', width: 28, height: 28, borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--app-t2)' }}><Icon name="x" size={15} /></button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7, marginTop: 11 }}>
            <Pill icon="crop" color="var(--app-t2)">{a.scope_name_snapshot} · v{a.scope_version}</Pill>
            <Pill icon={a.has_inline_content ? 'database' : 'cloud'} color="var(--app-t2)">{a.has_inline_content ? 'Inline' : 'Object'}</Pill>
            {signed ? <Pill icon="badge-check" color="var(--ok)" bg="color-mix(in srgb, var(--ok) 13%, transparent)">Signed</Pill> : <Pill icon="shield-off" color="var(--app-t3)">Unsigned</Pill>}
            {layers.length > 0 && <Pill icon="shield-check" color="var(--accent)" bg="color-mix(in srgb, var(--accent) 12%, transparent)">Attested</Pill>}
          </div>
        </div>

        {/* actions */}
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--app-border)', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button className="ui-btn sm accent" onClick={onDownload}><Icon name="download" size={13} />CycloneDX</button>
          <button className="ui-btn sm" onClick={onVerify} disabled={verify.isPending}><Icon name="badge-check" size={13} />{verify.isPending ? 'Verifying…' : 'Verify'}</button>
          {evidenceEntitled && (
            <button className="ui-btn sm" onClick={() => nav(`/risk-compliance/cbom/compare?head=${a.id}`)}><Icon name="scale" size={13} />Compare</button>
          )}
          <PermissionGate permission={TENANT_PERMISSIONS.reports.manage}>
            <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)', marginLeft: 'auto' }} onClick={() => setConfirmDel(true)}><Icon name="x" size={13} />Delete</button>
          </PermissionGate>
        </div>

        <div style={{ padding: '6px 18px 18px' }}>
          {downloadErr && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', padding: '9px 0' }}>{downloadErr}</div>}
          {verify.isError && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', padding: '9px 0' }}>Verification request failed.</div>}
          {verifyRes && <VerifyResult v={verifyRes} />}

          {/* SPDX / PDF — wire shape stable, adapters not yet wired server-side. */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, fontSize: 11, color: 'var(--app-t3)' }}>
            <Icon name="clock" size={12} />
            <span>SPDX 2.3 and PDF downloads are coming in a follow-up — CycloneDX 1.6 is the canonical format today.</span>
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="eyebrow-app" style={{ marginBottom: 4 }}>Integrity</div>
            <Row label="Content hash" mono>{a.content_hash}</Row>
            <Row label="Spec" mono>CycloneDX {a.cyclonedx_spec_version}</Row>
            {signed && <Row label="Signature" mono>{a.signature_hmac}</Row>}
            {signed && a.signature_kid && <Row label="Key id" mono>{a.signature_kid}</Row>}
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="eyebrow-app" style={{ marginBottom: 4 }}>Snapshot</div>
            <Row label="Components">{a.component_count.toLocaleString()}</Row>
            <Row label="Size">{fmtBytes(a.size_bytes)}</Row>
            <Row label="Generated">{fmtDateTime(a.generated_at)} <span style={{ color: 'var(--app-t3)' }}>· {relTime(a.generated_at)}</span></Row>
            <Row label="Inventory as of">{fmtDateTime(a.input_data_freshness_at)}</Row>
            {a.provenance?.generator_version && <Row label="Generator" mono>{a.provenance.generator_service} {a.provenance.generator_version}</Row>}
            <Row label="Storage">{a.has_inline_content ? 'Inline (Postgres)' : `Object${a.storage_key ? ` · ${a.storage_key}` : ''}`}</Row>
          </div>

          {layers.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="eyebrow-app" style={{ marginBottom: 8, color: 'var(--accent)' }}>Attestation layers</div>
              {layers.map((l, i) => <AttestationLayer key={i} layer={l} />)}
            </div>
          )}
        </div>

        {/* delete confirm */}
        {confirmDel && (
          <div onClick={() => setConfirmDel(false)} style={{ position: 'absolute', inset: 0, background: 'var(--app-scrim)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 18, zIndex: 5 }}>
            <div onClick={(e) => e.stopPropagation()} className="panel" style={{ padding: 20, maxWidth: 340, borderRadius: 14 }}>
              <div style={{ fontSize: 14.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)' }}>Delete this artifact?</div>
              <p style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.55, margin: '8px 0 16px' }}>
                Soft-delete — the row is retained so comparisons that reference it show “deleted” rather than 404. The content is removed from active queries.
              </p>
              {del.isError && <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginBottom: 10 }}>Delete failed.</div>}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 9 }}>
                <button className="ui-btn sm" onClick={() => setConfirmDel(false)} disabled={del.isPending}>Cancel</button>
                <button className="ui-btn sm" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} onClick={onDelete} disabled={del.isPending}>{del.isPending ? 'Deleting…' : 'Delete'}</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
