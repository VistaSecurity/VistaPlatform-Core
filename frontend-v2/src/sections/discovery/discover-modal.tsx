// Discover Assets wizard — the "scan targets for crypto assets" flow, on the
// contracted inventory-service /discovery/* endpoints (POST /discovery/jobs →
// poll GET /discovery/jobs/{id} → GET .../results). Composes the shared Modal
// primitive.
//
// There is deliberately NO import step. Findings reach inventory server-side:
// cluster-sensor mirrors every job's findings into the same ingestion queue the
// sensors feed, and the pipeline evaluates the tenant's segment auto-approval
// rules. The wizard reports where they landed; it does not decide it.
import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { describeMaterialization, type Materialization } from './discover-summary';

// ─── Finding detail helpers ───────────────────────────────────────────────────

type RawData = Record<string, unknown>;

interface CertInfo {
  subject_dn?: string;
  issuer_dn?: string;
  subject?: string;
  issuer?: string;
  serial_number?: string;
  not_before?: string;
  not_after?: string;
  fingerprint_sha256?: string;
  key_algorithm?: string;
  signature_alg?: string;
  subject_alternative_names?: string[];
  is_self_signed?: boolean;
  chain_order?: number;
  cert_is_ev?: boolean;
  ocsp_status?: string;
}

function fmtDate(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function expiryColor(iso: string | undefined): string {
  if (!iso) return 'var(--app-t3)';
  const days = (new Date(iso).getTime() - Date.now()) / 86_400_000;
  if (days < 0) return 'var(--danger-text)';
  if (days < 30) return 'var(--warn)';
  return 'var(--app-ok)';
}

function cnFrom(dn: string | undefined): string {
  if (!dn) return '—';
  const m = dn.match(/CN=([^,]+)/i);
  return m ? m[1].trim() : dn;
}

function FindingDetail({ f }: { f: DiscoveryFinding }) {
  const raw = (f as unknown as { data?: RawData }).data ?? {};
  const certs = (raw.certificates as CertInfo[] | undefined) ?? [];
  const leaf = certs.find((c) => c.chain_order === 0) ?? certs[0];
  const sans: string[] = leaf?.subject_alternative_names?.slice(0, 6) ?? [];
  const keyInfo = [leaf?.key_algorithm, raw.key_size != null ? `${raw.key_size}-bit` : null].filter(Boolean).join(' ');
  const fingerprint = (leaf?.fingerprint_sha256 as string | undefined) ?? '';

  const [certModalOpen, setCertModalOpen] = useState(false);

  const kv = (label: string, value: React.ReactNode, mono = false) => (
    <div style={{ display: 'flex', gap: 8, padding: '3px 0' }}>
      <span style={{ fontSize: 11, color: 'var(--app-t3)', width: 110, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, color: 'var(--app-t1)', fontFamily: mono ? 'var(--font-mono)' : undefined, wordBreak: 'break-all' }}>{value ?? '—'}</span>
    </div>
  );

  if (!leaf && !raw.cipher_suite) {
    return <div style={{ padding: '8px 0', fontSize: 11, color: 'var(--app-t3)' }}>No detail data returned for this finding.</div>;
  }

  return (
    <>
      {certModalOpen && leaf && (
        <DiscoveryCertModal certs={certs} data={raw} onClose={() => setCertModalOpen(false)} />
      )}
      <div style={{ padding: '10px 0 4px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
        {/* Left: certificate */}
        <div>
          {leaf && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Certificate</div>
                <button
                  onClick={() => setCertModalOpen(true)}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10.5, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px' }}
                >
                  <Icon name="file-badge" size={11} />
                  View full cert
                </button>
              </div>
              {kv('Subject', cnFrom(leaf.subject ?? leaf.subject_dn))}
              {kv('Issuer', cnFrom(leaf.issuer ?? leaf.issuer_dn))}
              {leaf.not_after && kv(
                'Expires',
                <span style={{ color: expiryColor(leaf.not_after) }}>{fmtDate(leaf.not_after)}</span>,
              )}
              {kv('Valid from', fmtDate(leaf.not_before))}
              {leaf.is_self_signed && kv('', <span style={{ color: 'var(--warn)', fontSize: 10 }}>⚠ Self-signed</span>)}
              {leaf.cert_is_ev && kv('', <span style={{ color: 'var(--app-ok)', fontSize: 10 }}>✓ Extended Validation</span>)}
              {leaf.ocsp_status && leaf.ocsp_status !== 'good' && kv('OCSP', <span style={{ color: 'var(--warn)' }}>{leaf.ocsp_status}</span>)}
              {sans.length > 0 && kv('SANs', sans.join(', '))}
              {fingerprint && kv('SHA-256', fingerprint.slice(0, 16) + '…', true)}
            </>
          )}
        </div>
        {/* Right: cipher / TLS */}
        <div>
          <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>Crypto</div>
          {kv('Protocol', [f.protocol, f.protocol_version].filter(Boolean).join(' '))}
          {!!raw.cipher_suite && kv('Cipher suite', raw.cipher_suite as string, true)}
          {!!raw.key_exchange_algorithm && kv('Key exchange', raw.key_exchange_algorithm as string)}
          {keyInfo && kv('Key', keyInfo)}
          {!!raw.hash_algorithm && kv('Hash', raw.hash_algorithm as string)}
          {leaf?.signature_alg && kv('Signature', leaf.signature_alg)}
          {(raw.supported_tls_versions as string[] | undefined)?.length ? kv('Supported TLS', (raw.supported_tls_versions as string[]).join(', ')) : null}
        </div>
      </div>
    </>
  );
}

// ─── Discovery cert preview modal ────────────────────────────────────────────
// Renders a full certificate detail view from raw finding data (no API lookup
// needed — all fields come from the TLS prober's certInfoToMap output).

interface RawCert {
  subject?: string;
  issuer?: string;
  serial_number?: string;
  not_before?: string;
  not_after?: string;
  subject_alternative_names?: string[];
  key_usage?: string[];
  extended_key_usage?: string[];
  public_key_algorithm?: string;
  public_key_size?: number;
  signature_algorithm?: string;
  is_self_signed?: boolean;
  is_ca?: boolean;
  is_ca_certificate?: boolean;
  chain_order?: number;
  certificate_pem?: string;
  fingerprint_sha256?: string;
  fingerprint_sha1?: string;
  certificate_state?: string;
}

function DiscoveryCertModal({ certs, data, onClose }: {
  certs: RawCert[];
  data: RawData;
  onClose: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  // Sort leaf → intermediates → root
  const sorted = [...certs].sort((a, b) => (a.chain_order ?? 0) - (b.chain_order ?? 0));
  const leaf = sorted[0];

  const expDays = leaf?.not_after
    ? Math.round((new Date(leaf.not_after).getTime() - Date.now()) / 86_400_000)
    : null;
  const expColor = expDays == null ? 'var(--app-t2)' : expDays < 0 ? 'var(--danger)' : expDays < 30 ? 'var(--warn)' : 'var(--ok)';

  const [copied, setCopied] = useState(false);
  const copyPem = () => {
    if (leaf?.certificate_pem) {
      navigator.clipboard.writeText(leaf.certificate_pem).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  // Row helper
  const row = (label: string, value: React.ReactNode, mono = false) =>
    value == null || value === '' ? null : (
      <div style={{ display: 'flex', gap: 12, padding: '7px 0', borderBottom: '1px solid var(--app-border)' }}>
        <span style={{ fontSize: 12, color: 'var(--app-t3)', width: 130, flexShrink: 0 }}>{label}</span>
        <span style={{ fontSize: 12, color: 'var(--app-t1)', fontFamily: mono ? 'var(--font-mono)' : undefined, wordBreak: 'break-all', lineHeight: 1.5 }}>{value}</span>
      </div>
    );

  const section = (title: string, icon: string) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7, margin: '18px 0 6px', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={12} />
      <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>{title}</span>
    </div>
  );

  return createPortal(
    /* Overlay — rendered at document.body to escape the discover modal's stacking context */
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width: 560, maxHeight: '85vh', background: 'var(--app-panel)', border: '1px solid var(--app-border2)', borderRadius: 14, display: 'flex', flexDirection: 'column', boxShadow: '0 24px 80px rgba(0,0,0,0.5)' }}
      >
        {/* Header */}
        <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 36, height: 36, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)' }}>
            <Icon name="file-badge" size={18} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 3 }}>Certificate preview</div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 600, color: 'var(--app-t1)', wordBreak: 'break-all', lineHeight: 1.3 }}>
              {cnFrom(leaf?.subject)}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5, flexWrap: 'wrap' }}>
              {leaf?.certificate_state && (
                <span style={{ fontSize: 11, fontWeight: 600, color: leaf.certificate_state === 'active' ? 'var(--ok)' : 'var(--danger)', background: leaf.certificate_state === 'active' ? 'color-mix(in srgb, var(--ok) 11%, transparent)' : 'color-mix(in srgb, var(--danger) 11%, transparent)', borderRadius: 40, padding: '2px 9px', textTransform: 'capitalize' }}>
                  {leaf.certificate_state}
                </span>
              )}
              {expDays != null && (
                <span className="mono" style={{ fontSize: 11.5, color: expColor }}>
                  {expDays < 0 ? `expired ${-expDays}d ago` : `expires in ${expDays}d`}
                </span>
              )}
              {leaf?.is_self_signed && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn-strong) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>self-signed</span>}
              {data.cert_is_ev === true && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--ok)', background: 'color-mix(in srgb, var(--ok) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>EV</span>}
            </div>
          </div>
          <button onClick={onClose} style={{ flex: 'none', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--app-t3)', padding: 4, borderRadius: 6, marginTop: -2 }}>
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Body */}
        <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', padding: '4px 22px 24px' }}>

          {section('Identity', 'file-badge')}
          {row('Subject', leaf?.subject, true)}
          {row('Issuer', leaf?.issuer, true)}
          {row('Serial number', leaf?.serial_number, true)}
          {(leaf?.subject_alternative_names?.length ?? 0) > 0 && (
            <div style={{ padding: '7px 0', borderBottom: '1px solid var(--app-border)' }}>
              <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 6 }}>Subject alternative names</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {leaf!.subject_alternative_names!.map((s) => (
                  <span key={s} className="mono" style={{ fontSize: 11, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 6, padding: '2px 7px' }}>{s}</span>
                ))}
              </div>
            </div>
          )}

          {section('Validity', 'clock')}
          {row('Not before', leaf?.not_before ? fmtDate(leaf.not_before) + ' · ' + leaf.not_before?.slice(0, 10) : null, true)}
          {row('Not after', leaf?.not_after ? (
            <span style={{ color: expColor }}>{fmtDate(leaf.not_after)} · {leaf.not_after?.slice(0, 10)}</span>
          ) : null)}

          {section('Key & signature', 'key-round')}
          {row('Public key', leaf?.public_key_algorithm ? `${leaf.public_key_algorithm} · ${leaf.public_key_size ?? '?'}-bit` : null, true)}
          {row('Signature', leaf?.signature_algorithm, true)}
          {row('Key usage', leaf?.key_usage?.join(', '))}
          {row('Extended usage', leaf?.extended_key_usage?.join(', '))}

          {section('Trust & revocation', 'shield-check')}
          {row('OCSP', (data.ocsp_status as string) || null)}
          {row('OCSP detail', (data.ocsp_detail as string) || null)}
          {data.cert_has_sct != null && row('CT logged (SCT)', data.cert_has_sct ? 'yes' : 'no')}
          {data.cert_known_bad_ca === true && row('Known-bad CA', <span style={{ color: 'var(--danger)' }}>yes — do not trust</span>)}
          {row('Is CA', leaf?.is_ca ? 'yes' : leaf?.is_ca === false ? 'no' : null)}

          {/* Chain */}
          {sorted.length > 1 && (
            <>
              {section('Certificate chain', 'link')}
              <div style={{ padding: '6px 0' }}>
                {sorted.map((c, i) => {
                  const label = cnFrom(c.subject) || '—';
                  const role = i === 0 ? 'leaf' : c.is_self_signed ? 'root' : 'intermediate';
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0 5px ' + (i * 16) + 'px' }}>
                      {i > 0 && <span style={{ color: 'var(--app-t3)', fontSize: 11 }}>↳</span>}
                      <Icon name={c.is_ca_certificate ? 'shield-check' : 'file-badge'} size={13} style={{ color: i === 0 ? 'var(--accent)' : 'var(--app-t3)', flexShrink: 0 }} />
                      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                      <span style={{ fontSize: 10, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: '.08em', flexShrink: 0 }}>{role}</span>
                    </div>
                  );
                })}
              </div>
            </>
          )}

          {section('Fingerprints', 'fingerprint')}
          {row('SHA-256', leaf?.fingerprint_sha256, true)}
          {row('SHA-1', leaf?.fingerprint_sha1, true)}

          {/* PEM */}
          {leaf?.certificate_pem && (
            <>
              {section('PEM', 'code')}
              <div style={{ position: 'relative' }}>
                <pre style={{ background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 8, padding: '10px 12px', fontSize: 10, color: 'var(--app-t2)', overflowX: 'auto', maxHeight: 140, margin: 0, lineHeight: 1.5 }}>
                  {leaf.certificate_pem}
                </pre>
                <button
                  onClick={copyPem}
                  style={{ position: 'absolute', top: 6, right: 6, display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '3px 8px', background: 'var(--app-panel)', border: '1px solid var(--app-border2)', borderRadius: 6, cursor: 'pointer', color: copied ? 'var(--ok)' : 'var(--app-t2)' }}
                >
                  <Icon name={copied ? 'check' : 'copy'} size={11} />
                  {copied ? 'Copied' : 'Copy PEM'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  , document.body);
}

type DiscoveryFinding = inventoryComponents['schemas']['DiscoveryFinding'];

const PROTOCOLS = ['TLS', 'SSH'];
const EXEC_MODES: { value: string; label: string }[] = [
  { value: 'auto', label: 'Auto — platform decides' },
  { value: 'cloud', label: 'Cloud — platform sensor' },
  { value: 'sensors', label: 'Sensors — tenant-deployed' },
];

// Reports where a job's findings went. The wording is built by
// describeMaterialization (pure, unit-tested) — see discover-summary.ts for why
// the two numbers are reported separately.
function MaterializationSummary({ count, m }: { count: number; m?: Materialization }) {
  const tones: Record<string, string> = {
    neutral: 'var(--app-t2)',
    ok: 'var(--app-ok)',
    warn: 'var(--warn)',
    muted: 'var(--app-t3)',
  };
  const summary = describeMaterialization(count, m);
  return (
    <div style={{ fontSize: 12.5, marginBottom: 10 }}>
      <div>
        {summary.parts.map((part, i) => (
          <span key={i}>
            {i > 0 && <span style={{ color: 'var(--app-t3)' }}> · </span>}
            <span style={{ color: tones[part.tone] }}>{part.text}</span>
          </span>
        ))}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 4 }}>{summary.note}</div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 4 }}>
        Click any row to inspect certificate and cipher details.
      </div>
    </div>
  );
}

const TERMINAL = ['completed', 'success', 'failed', 'error', 'cancelled'];

type Phase = 'configure' | 'running' | 'results';

export function DiscoverAssetsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [phase, setPhase] = useState<Phase>('configure');
  const [jobId, setJobId] = useState<string | null>(null);
  const [expandedSet, setExpandedSet] = useState<Set<number>>(new Set());

  const toggleExpand = (i: number) =>
    setExpandedSet((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      return next;
    });

  // form
  const [targets, setTargets] = useState('');
  const [protocols, setProtocols] = useState<string[]>(['TLS']);
  const [ports, setPorts] = useState('443, 22');
  const [execMode, setExecMode] = useState('auto');

  // Reset to a clean wizard whenever it (re)opens.
  useEffect(() => {
    if (open) {
      setPhase('configure');
      setJobId(null);
      setExpandedSet(new Set());
      setTargets('');
      setProtocols(['TLS']);
      setPorts('443, 22');
      setExecMode('auto');
    }
  }, [open]);

  const targetList = targets.split(/[\n,]/).map((t) => t.trim()).filter(Boolean);
  const portList = ports.split(',').map((p) => parseInt(p.trim(), 10)).filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
  const canStart = targetList.length > 0 && targetList.length <= 1000 && protocols.length > 0;

  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.inventory.POST('/discovery/jobs', {
        body: { targets: targetList, protocols, ports: portList, execution_mode: execMode },
      });
      if (error || !data) throw new Error('Failed to start discovery');
      return data.job;
    },
    onSuccess: (job) => {
      setJobId(job.id);
      setPhase('running');
      qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
    },
  });

  // Poll job status while running.
  const jobQ = useQuery({
    queryKey: ['discovery', 'job', jobId],
    enabled: open && phase === 'running' && !!jobId,
    refetchInterval: 3000,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs/{id}', { params: { path: { id: jobId! } } });
      if (error || !data) throw new Error('Failed to load job status');
      return data;
    },
  });
  const status = (jobQ.data?.status || '').toLowerCase();
  useEffect(() => {
    if (phase === 'running' && status && TERMINAL.includes(status)) setPhase('results');
  }, [status, phase]);

  // Fetch findings once the job finishes. Ingestion is asynchronous, so keep
  // polling while the queue still holds rows the pipeline hasn't dispositioned —
  // that is what lets the split below settle without the user doing anything.
  const resultsQ = useQuery({
    queryKey: ['discovery', 'job-results', jobId],
    enabled: open && phase === 'results' && !!jobId,
    refetchInterval: (q) => (q.state.data?.materialization?.awaiting_processing ? 3000 : false),
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/discovery/jobs/{id}/results', { params: { path: { id: jobId! } } });
      if (error || !data) throw new Error('Failed to load findings');
      qc.invalidateQueries({ queryKey: ['inventory'] });
      return {
        findings: (data.findings ?? []) as DiscoveryFinding[],
        materialization: data.materialization as Materialization | undefined,
      };
    },
  });
  const findings = resultsQ.data?.findings ?? [];
  const materialization = resultsQ.data?.materialization;

  const cancelM = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.POST('/discovery/jobs/{id}/cancel', { params: { path: { id: jobId! } } });
      if (error) throw new Error('Failed to cancel');
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
      onClose();
    },
  });

  const busy = create.isPending || cancelM.isPending;
  const err =
    (create.error as Error | undefined)?.message ||
    (jobQ.error as Error | undefined)?.message ||
    (resultsQ.error as Error | undefined)?.message ||
    null;

  // Footer buttons per phase.
  let primary: React.ReactNode = null;
  let secondary: React.ReactNode = null;
  if (phase === 'configure') {
    primary = (
      <button className="ui-btn accent" disabled={!canStart || create.isPending} onClick={() => create.mutate()}>
        {create.isPending ? 'Starting…' : 'Start discovery'}
      </button>
    );
    secondary = <button className="ui-btn" onClick={onClose} disabled={busy}>Cancel</button>;
  } else if (phase === 'running') {
    secondary = (
      <button className="ui-btn" onClick={() => cancelM.mutate()} disabled={cancelM.isPending}>
        {cancelM.isPending ? 'Cancelling…' : 'Cancel job'}
      </button>
    );
    primary = <button className="ui-btn" onClick={onClose}>Run in background</button>;
  } else {
    // Results is terminal: the findings are already on their way to inventory.
    primary = <button className="ui-btn accent" onClick={onClose}>Done</button>;
    if ((materialization?.pending_approval ?? 0) > 0) {
      secondary = (
        <button className="ui-btn" onClick={() => { onClose(); nav('/discovery/approvals'); }}>
          Go to Approvals
        </button>
      );
    }
  }

  return (
    <Modal
      open={open}
      onClose={busy ? undefined : onClose}
      dismissible={!busy}
      size="lg"
      tone="accent"
      icon="radar"
      eyebrow="Discovery"
      title="Discover assets"
      description="Scan targets for cryptographic assets. Findings flow into your inventory automatically — hosts on an auto-approve network segment are monitored straight away, everything else waits in Approvals."
      primary={primary}
      secondary={secondary}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : undefined}
    >
      {phase === 'configure' && (
        <>
          <ModalField label="Targets" hint="One per line or comma-separated. IPs, CIDRs, or hostnames (max 1000).">
            <textarea
              data-autofocus
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              rows={4}
              spellCheck={false}
              className="mono"
              placeholder={'10.0.0.0/24\nweb-prod-01.example.com\n192.0.2.10'}
              style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
            />
          </ModalField>

          <div style={{ marginBottom: 15 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 8 }}>Protocols</div>
            <div style={{ display: 'flex', gap: 16 }}>
              {PROTOCOLS.map((p) => (
                <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13, color: 'var(--app-t1)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={protocols.includes(p)}
                    onChange={(e) => setProtocols(e.target.checked ? [...protocols, p] : protocols.filter((x) => x !== p))}
                  />
                  {p}
                </label>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
            <ModalField label="Ports" hint="Comma-separated.">
              <ModalInput value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="443, 22, 8443" inputMode="numeric" />
            </ModalField>
            <ModalField label="Execution mode">
              <ModalSelect value={execMode} onChange={(e) => setExecMode(e.target.value)}>
                {EXEC_MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
        </>
      )}

      {phase === 'running' && (
        <div style={{ padding: '24px 4px', textAlign: 'center' }}>
          <div style={{ fontSize: 13, color: 'var(--app-t2)' }}>
            Scanning {targetList.length} target{targetList.length === 1 ? '' : 's'}…
          </div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 8 }}>
            Job {jobId?.slice(0, 8)} · {jobQ.data?.status || 'pending'}
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 10 }}>
            This can take a few minutes. You can run it in the background and check Discovery → Jobs.
          </div>
        </div>
      )}

      {phase === 'results' && (
        <div>
          {resultsQ.isLoading ? (
            <div style={{ padding: '24px 4px', textAlign: 'center', fontSize: 13, color: 'var(--app-t3)' }}>Loading findings…</div>
          ) : findings.length === 0 ? (
            <div style={{ padding: '24px 4px', textAlign: 'center', fontSize: 13, color: 'var(--app-t3)' }}>
              The scan completed but found no cryptographic assets on those targets.
            </div>
          ) : (
            <>
              <MaterializationSummary count={findings.length} m={materialization} />
              <div className="panel" style={{ borderRadius: 10, maxHeight: 320, overflowY: 'auto' }}>
                {findings.slice(0, 50).map((f, i) => {
                  const expanded = expandedSet.has(i);
                  const hasDetail = !!(f as unknown as { data?: RawData }).data;
                  return (
                    <div key={i} style={{ borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                      {/* Summary row */}
                      <div
                        onClick={() => hasDetail && toggleExpand(i)}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                          cursor: hasDetail ? 'pointer' : 'default',
                          background: expanded ? 'var(--app-panel3)' : undefined,
                        }}
                      >
                        {/* Expand chevron */}
                        <span style={{
                          fontSize: 9, color: hasDetail ? 'var(--app-t3)' : 'transparent', flexShrink: 0,
                          transform: expanded ? 'rotate(90deg)' : undefined, display: 'inline-block', transition: 'transform 0.15s',
                        }}>▶</span>
                        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {(f as unknown as { resolved_ip?: string }).resolved_ip
                            ? `${f.hostname || (f as unknown as { resolved_ip?: string }).resolved_ip}:${f.port ?? ''}`
                            : `${f.hostname || f.ip_address || 'unknown'}${f.port != null ? `:${f.port}` : ''}`}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--app-t3)', flexShrink: 0 }}>
                          {[f.protocol, f.protocol_version].filter(Boolean).join(' ') || '—'}
                        </span>
                        {f.cipher_suite && (
                          <span className="mono" style={{ fontSize: 10, color: 'var(--app-t3)', flexShrink: 0, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {f.cipher_suite}
                          </span>
                        )}
                      </div>
                      {/* Detail panel */}
                      {expanded && (
                        <div style={{ padding: '0 12px 10px 30px', background: 'var(--app-panel3)', borderTop: '1px solid var(--app-border)' }}>
                          <FindingDetail f={f} />
                        </div>
                      )}
                    </div>
                  );
                })}
                {findings.length > 50 && (
                  <div style={{ padding: '8px 12px', fontSize: 11, color: 'var(--app-t3)', borderTop: '1px solid var(--app-border)' }}>
                    + {findings.length - 50} more
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

    </Modal>
  );
}
