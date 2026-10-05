// A discovery finding's certificate and cipher detail, and the full
// certificate preview it opens — shared by the Discover Assets wizard and the
// Discovery Jobs detail (results by host), so both read a finding the same
// way. Extracted unchanged from discover-modal.tsx ( WP4b).
import { useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { Icon } from '../../components/ui';

type DiscoveryFinding = inventoryComponents['schemas']['DiscoveryFinding'];

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

// The TLS prober records the NAME of the known-bad CA it matched in the chain
// (cert_known_bad_ca), not a boolean, so comparing against `true` hid the
// warning for every real hit. A boolean `true` is still what findings stored by
// older versions carry: warn for those too, just without a name to show. Absent,
// null, false and blank all mean no known-bad CA was seen.
function readKnownBadCA(v: unknown): { name: string | null } | null {
  if (typeof v === 'string') {
    const name = v.trim();
    return name ? { name } : null;
  }
  return v === true ? { name: null } : null;
}

export function FindingDetail({ f }: { f: DiscoveryFinding }) {
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

  const knownBadCA = readKnownBadCA(data.cert_known_bad_ca);

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
          {knownBadCA && row('Known-bad CA', <span style={{ color: 'var(--danger)' }}>{knownBadCA.name ?? 'yes'} — do not trust</span>)}
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
