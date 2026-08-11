import { useQuery } from '@tanstack/react-query';
import type { Asset, inventoryComponents } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { DrawerCloseBtn as CloseBtn, DrawerShell, Icon, MetaRow, RiskChip, RiskGauge, SectionLabel, levelFromScore } from '../../components/ui';
import { DeleteAssetButton, RestoreAssetButton, ScanAssetButton } from './bulk-actions';

export type CryptoConfig = inventoryComponents['schemas']['CryptoImplementation'];
export type Certificate = inventoryComponents['schemas']['Certificate'];
export type Key = inventoryComponents['schemas']['Key'];
export type KeyImplementation = inventoryComponents['schemas']['KeyImplementation'];
export type OpenAsset = (assetId: string, seed?: Partial<Asset>) => void;
export type OpenConfig = (config: CryptoConfig) => void;
export type OpenCert = (certId: string) => void;
export type OpenKey = (keyId: string) => void;

// Drawer furniture (DrawerShell / MetaRow / SectionLabel / CloseBtn) lives in
// components/ui/drawer.tsx — shared across sections.

// ---- config drawer ------------------------------------------------------
// Base layer of the inventory drill-down. Its header carries an "open asset"
// button → onOpenAsset, which the page stacks ON TOP of this drawer.
export function ConfigDrawer({ config, onOpenAsset, onOpenCert, onClose, active = true, depth = 0 }: {
  config: CryptoConfig; onOpenAsset?: OpenAsset; onOpenCert?: OpenCert; onClose: () => void; active?: boolean; depth?: number;
}) {
  const c = config as Record<string, unknown> & CryptoConfig;
  const level = (c.risk_level as string) || levelFromScore(typeof c.risk_score === 'number' ? c.risk_score : 0);
  const assetId = c.asset_id as string | undefined;
  const certId = c.certificate_id as string | undefined;
  return (
    <DrawerShell onClose={onClose} width={460} active={active} depth={depth}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <RiskChip level={level} size={28} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">Crypto configuration</div>
            <h2 style={{ margin: '4px 0 2px', fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.15 }}>{c.protocol as string} · {c.protocol_version as string}</h2>
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', wordBreak: 'break-all' }}>{c.cipher_suite as string}</div>
          </div>
          <CloseBtn onClose={onClose} />
        </div>
        {assetId && onOpenAsset && (
          <button
            onClick={() => onOpenAsset(assetId, { hostname: c.asset_hostname as string, ip_address: c.asset_ip_address as string, asset_type: c.asset_type as string, environment: c.asset_environment as string })}
            className="row-hover"
            style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', marginTop: 14, padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}
          >
            <Icon name="server" size={14} style={{ color: 'var(--accent)', flex: 'none' }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--app-t3)' }}>Open asset</div>
              <div className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{(c.asset_hostname as string) || 'View asset details'}</div>
            </div>
            <Icon name="chevron-right" size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          </button>
        )}
      </div>
      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        <SectionLabel icon="lock">Cryptography</SectionLabel>
        <MetaRow k="Protocol" v={`${c.protocol ?? ''} ${c.protocol_version ?? ''}`.trim()} />
        <MetaRow k="Cipher suite" v={c.cipher_suite as string} mono />
        <MetaRow k="Key exchange" v={c.key_exchange_algorithm as string} mono />
        <MetaRow k="Signature" v={c.signature_algorithm as string} mono />
        <MetaRow k="Symmetric" v={c.symmetric_encryption as string} mono />
        <MetaRow k="Hash" v={c.hash_algorithm as string} mono />
        <MetaRow k="Key size" v={c.key_size ? `${c.key_size}-bit` : null} mono />
        <SectionLabel icon="server">Where</SectionLabel>
        <MetaRow k="Asset" v={c.asset_hostname as string} />
        <MetaRow k="IP" v={c.asset_ip_address as string} mono />
        <MetaRow k="Environment" v={c.asset_environment as string} />
        {certId && onOpenCert ? (
          <button onClick={() => onOpenCert(certId)} className="row-hover" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', padding: '8px 0', border: 'none', borderBottom: '1px solid var(--app-border)', background: 'transparent', cursor: 'pointer', gap: 16, textAlign: 'left' }}>
            <span style={{ fontSize: 12.5, color: 'var(--app-t3)', flex: 'none' }}>Certificate</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--accent)', fontWeight: 600 }}>
              <Icon name="file-badge" size={13} />View certificate<Icon name="chevron-right" size={13} />
            </span>
          </button>
        ) : (
          <MetaRow k="Certificate" v={certId ? 'present' : '—'} />
        )}
        <SectionLabel icon="activity">Assessment</SectionLabel>
        <MetaRow k="Risk score" v={typeof c.risk_score === 'number' ? c.risk_score : null} mono />
        <MetaRow k="Risk level" v={level} />
        <MetaRow k="Discovery" v={c.discovery_method as string} />
        <MetaRow k="Last verified" v={(c.last_verified_at as string)?.slice(0, 10)} mono />
      </div>
    </DrawerShell>
  );
}

// ---- asset drawer -------------------------------------------------------
// Fetches the full asset detail by id (`{ asset }` envelope) plus its crypto
// configs; `seed` paints the header instantly while the detail loads.
export function AssetDrawer({ assetId, seed, onOpenConfig, onClose, onEdit, active = true, depth = 0 }: {
  assetId: string; seed?: Partial<Asset>; onOpenConfig: OpenConfig; onClose: () => void; onEdit?: (asset: Asset) => void; active?: boolean; depth?: number;
}) {
  const detailQ = useQuery({
    queryKey: ['asset-detail', assetId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets/{id}', { params: { path: { id: assetId } } });
      if (error || !data) throw new Error('Failed to load asset');
      return data.asset;
    },
  });
  const configsQ = useQuery({
    queryKey: ['asset-configs', assetId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-configurations', { params: { query: { asset_id: assetId, page: 1, page_size: 100 } } });
      if (error || !data) throw new Error('Failed to load configs');
      return data.crypto_implementations ?? [];
    },
  });
  const a = ((detailQ.data ?? seed ?? {}) as Record<string, unknown> & Partial<Asset>);
  const risk = typeof a.risk_score === 'number' ? a.risk_score : 0;
  const riskLevel = (a.risk_level as string) || levelFromScore(risk);
  const configs = configsQ.data ?? [];
  const tags = Array.isArray(a.tags) ? (a.tags as string[]) : [];

  return (
    <DrawerShell onClose={onClose} width={500} active={active} depth={depth}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', gap: 14, alignItems: 'center', minWidth: 0 }}>
            <RiskGauge score={risk} level={riskLevel} size={68} label="" stroke={6} />
            <div style={{ minWidth: 0 }}>
              <div className="eyebrow-app">{(a.asset_type as string) || 'asset'}</div>
              <h2 className="mono" style={{ margin: '4px 0 2px', fontSize: 16, fontWeight: 600, color: 'var(--app-t1)', wordBreak: 'break-all', lineHeight: 1.2 }}>{(a.hostname as string) || '—'}</h2>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{(a.ip_address as string) || ''}{a.port ? ':' + a.port : ''}</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 'none' }}>
            {detailQ.data && (a.deleted_at || a.asset_status === 'archived') && (
              <RestoreAssetButton assetId={assetId} onDone={onClose} />
            )}
            {detailQ.data && !a.deleted_at && a.asset_status !== 'archived' && (
              <ScanAssetButton assetId={assetId} />
            )}
            {onEdit && detailQ.data && (
              <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
                <button onClick={() => onEdit(detailQ.data!)} className="ui-btn sm" title="Edit asset" style={{ height: 28, padding: '0 9px' }}>
                  <Icon name="sliders-horizontal" size={13} />Edit
                </button>
              </PermissionGate>
            )}
            {detailQ.data && !a.deleted_at && (
              <DeleteAssetButton assetId={assetId} hostname={a.hostname as string} onDone={onClose} />
            )}
            <CloseBtn onClose={onClose} />
          </div>
        </div>
        {tags.length > 0 && (
          <div style={{ display: 'flex', gap: 6, marginTop: 12, flexWrap: 'wrap' }}>
            {tags.slice(0, 8).map((t) => <span key={t} style={{ fontSize: 11, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn-strong) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>{t}</span>)}
          </div>
        )}
      </div>
      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        <SectionLabel icon="key-round">Cryptographic configurations ({configsQ.isLoading ? '…' : configs.length})</SectionLabel>
        {configsQ.isLoading ? (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>Loading configurations…</div>
        ) : configs.length === 0 ? (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>No crypto configurations on this asset.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {configs.map((cfg) => {
              const c = cfg as Record<string, unknown> & CryptoConfig;
              const lvl = (c.risk_level as string) || levelFromScore(typeof c.risk_score === 'number' ? c.risk_score : 0);
              return (
                <button key={c.id as string} onClick={() => onOpenConfig(cfg)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '9px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 8, textAlign: 'left' }}>
                  <RiskChip level={lvl} size={22} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{c.protocol as string} · {c.protocol_version as string}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.cipher_suite as string}</div>
                  </div>
                  <Icon name="chevron-right" size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
                </button>
              );
            })}
          </div>
        )}

        <SectionLabel icon="circle-alert">Asset details</SectionLabel>
        <MetaRow k="Service" v={[a.service_name, a.service_version].filter(Boolean).join(' ') as string} />
        <MetaRow k="Operating system" v={a.operating_system as string} />
        <MetaRow k="Environment" v={a.environment as string} />
        <MetaRow k="Business unit" v={a.business_unit as string} />
        <MetaRow k="Owner" v={a.owner_email as string} />
        <MetaRow k="Network segment" v={(a.network_segment_name as string) || (a.network_segment_id as string)} />
        <MetaRow k="Cloud" v={(a.cloud_provider as string) ? `${a.cloud_provider}${a.region ? ' · ' + a.region : ''}` : 'on-prem'} />
        <MetaRow k="Location" v={[a.site, a.region, a.zone].filter(Boolean).join(' / ') as string} />
        <MetaRow k="Status" v={a.asset_status as string} />
        <MetaRow k="Ownership" v={a.asset_ownership as string} />
        <MetaRow k="Last seen" v={(a.last_seen_at as string)?.slice(0, 10)} mono />
        <MetaRow k="Discovery" v={a.discovery_method as string} />
        <MetaRow k="Risk score" v={risk} mono />
      </div>
    </DrawerShell>
  );
}

// ---- certificate drawer ---------------------------------------------------
// Top layer of the drill-down: config → certificate. Fetches the full cert
// (`{ certificate }` envelope) plus its issuer chain (flat [leaf..root]).
function dnPart(dn: string | undefined, key: string): string | null {
  if (!dn) return null;
  const m = dn.match(new RegExp(`(?:^|,)\\s*${key}=([^,]+)`));
  return m ? m[1] : null;
}
function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000);
}

export function CertDrawer({ certId, onClose, active = true, depth = 0 }: {
  certId: string; onClose: () => void; active?: boolean; depth?: number;
}) {
  const certQ = useQuery({
    queryKey: ['cert-detail', certId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/certificates/{id}', { params: { path: { id: certId } } });
      if (error || !data) throw new Error('Failed to load certificate');
      return data.certificate;
    },
  });
  const chainQ = useQuery({
    queryKey: ['cert-chain', certId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/certificates/{id}/chain', { params: { path: { id: certId } } });
      if (error || !data) throw new Error('Failed to load chain');
      return data;
    },
  });
  const cert = certQ.data;
  const c = (cert ?? {}) as Record<string, unknown> & Partial<Certificate>;
  const chain = (chainQ.data?.chain ?? []) as Certificate[];
  const chainComplete = chainQ.data?.is_complete === true;
  const expDays = daysUntil(c.not_after as string);
  const expTone = expDays == null ? 'var(--app-t2)' : expDays < 0 ? 'var(--danger)' : expDays < 90 ? 'var(--warn-strong)' : 'var(--ok)';
  const state = (c.certificate_state as string) || '';
  const stateTone = state === 'active' ? 'var(--ok)' : state === 'revoked' || state === 'expired' ? 'var(--danger)' : 'var(--warn)';
  const sans = (c.subject_alternative_names as string[] | undefined) ?? [];

  return (
    <DrawerShell onClose={onClose} width={480} active={active} depth={depth}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)' }}>
            <Icon name="file-badge" size={17} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">Certificate</div>
            <h2 className="mono" style={{ margin: '4px 0 2px', fontSize: 15.5, fontWeight: 600, color: 'var(--app-t1)', wordBreak: 'break-all', lineHeight: 1.25 }}>
              {certQ.isLoading ? 'Loading…' : (c.common_name as string) || dnPart(c.subject_dn as string, 'CN') || '—'}
            </h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
              {state && <span style={{ fontSize: 11, fontWeight: 600, color: stateTone, background: `color-mix(in srgb, ${stateTone} 11%, transparent)`, borderRadius: 40, padding: '2px 9px', textTransform: 'capitalize' }}>{state}</span>}
              {expDays != null && <span className="mono" style={{ fontSize: 11.5, color: expTone }}>{expDays < 0 ? `expired ${-expDays}d ago` : `expires in ${expDays}d`}</span>}
              {c.is_self_signed === true && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn-strong) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>self-signed</span>}
              {c.is_ev === true && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--ok)', background: 'color-mix(in srgb, var(--ok) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>EV</span>}
            </div>
          </div>
          <CloseBtn onClose={onClose} />
        </div>
      </div>

      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        {certQ.isError ? (
          <div style={{ padding: '32px 0', textAlign: 'center', fontSize: 12.5, color: 'var(--app-t3)' }}>Couldn't load this certificate.</div>
        ) : (
          <>
            <SectionLabel icon="file-badge">Identity</SectionLabel>
            <MetaRow k="Common name" v={c.common_name as string} mono />
            <MetaRow k="Subject" v={c.subject_dn as string} mono />
            <MetaRow k="Issuer" v={dnPart(c.issuer_dn as string, 'CN') || (c.issuer_dn as string)} mono />
            <MetaRow k="Serial" v={c.serial_number as string} mono />
            {sans.length > 0 && (
              <div style={{ padding: '8px 0', borderBottom: '1px solid var(--app-border)' }}>
                <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 6 }}>Subject alternative names</div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  {sans.map((s) => <span key={s} className="mono" style={{ fontSize: 11, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 6, padding: '2px 7px' }}>{s}</span>)}
                </div>
              </div>
            )}

            <SectionLabel icon="clock">Validity</SectionLabel>
            <MetaRow k="Not before" v={(c.not_before as string)?.slice(0, 10)} mono />
            <MetaRow k="Not after" v={(c.not_after as string)?.slice(0, 10)} mono />
            <MetaRow k="Days remaining" v={expDays != null ? String(expDays) : null} mono />

            <SectionLabel icon="key-round">Key &amp; signature</SectionLabel>
            <MetaRow k="Public key" v={c.public_key_algorithm ? `${c.public_key_algorithm} · ${c.public_key_size ?? '?'}-bit` : null} mono />
            <MetaRow k="Signature" v={c.signature_algorithm as string} mono />
            <MetaRow k="Key usage" v={(c.key_usage as string[] | undefined)?.join(', ')} />
            <MetaRow k="Extended usage" v={(c.extended_key_usage as string[] | undefined)?.join(', ')} />

            <SectionLabel icon="link">Issuer chain</SectionLabel>
            {chainQ.isLoading ? (
              <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>Loading chain…</div>
            ) : chain.length === 0 ? (
              <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>No chain recorded.</div>
            ) : (
              <div style={{ padding: '6px 0' }}>
                {chain.map((link, i) => {
                  const l = link as Record<string, unknown> & Certificate;
                  const label = (l.common_name as string) || dnPart(l.subject_dn as string, 'CN') || (l.subject_dn as string);
                  const role = i === 0 ? 'leaf' : l.is_self_signed ? 'root' : 'intermediate';
                  return (
                    <div key={l.id as string} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0 5px ' + i * 18 + 'px' }}>
                      {i > 0 && <span style={{ color: 'var(--app-t3)', fontSize: 11 }}>↳</span>}
                      <Icon name={l.is_ca_certificate ? 'shield-check' : 'file-badge'} size={13} style={{ color: i === 0 ? 'var(--accent)' : 'var(--app-t3)', flex: 'none' }} />
                      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
                      <span style={{ fontSize: 10, color: 'var(--app-t3)', flex: 'none', textTransform: 'uppercase', letterSpacing: '.08em' }}>{role}</span>
                    </div>
                  );
                })}
                {!chainComplete && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 6, fontSize: 11.5, color: 'var(--warn)' }}>
                    <Icon name="alert-triangle" size={12} />Chain incomplete — issuer not in inventory.
                  </div>
                )}
              </div>
            )}

            <SectionLabel icon="activity">Trust &amp; revocation</SectionLabel>
            <MetaRow k="State" v={state} />
            <MetaRow k="OCSP" v={c.ocsp_status as string} />
            <MetaRow k="SCT (CT logged)" v={c.has_sct == null ? null : c.has_sct ? 'yes' : 'no'} />
            <MetaRow k="Known-bad CA" v={(c.known_bad_ca as string) || 'no'} />
            <MetaRow k="Deployments" v={typeof c.deployment_count === 'number' ? c.deployment_count : null} mono />

            <SectionLabel icon="lock">Fingerprints</SectionLabel>
            <MetaRow k="SHA-256" v={c.fingerprint_sha256 as string} mono />
            <MetaRow k="SHA-1" v={c.fingerprint_sha1 as string} mono />
          </>
        )}
      </div>
    </DrawerShell>
  );
}

// ---- key drawer ---------------------------------------------------------
// Keys-lens drill-down. Shows the key's metadata, then the crypto
// configurations that reference it (via implementation_keys). Each
// implementation row → onOpenAsset, which the page stacks ON TOP of this drawer
// — mirroring the cert→asset path the owner asked for.
const KEY_STATE_TONE: Record<string, string> = {
  active: 'var(--ok)',
  'pre-activation': 'var(--app-t3)',
  suspended: 'var(--warn)',
  deactivated: 'var(--warn-strong)',
  compromised: 'var(--danger)',
  destroyed: 'var(--danger)',
};

export function KeyDrawer({ keyId, onOpenAsset, onClose, active = true, depth = 0 }: {
  keyId: string; onOpenAsset?: OpenAsset; onClose: () => void; active?: boolean; depth?: number;
}) {
  const keyQ = useQuery({
    queryKey: ['key-detail', keyId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/keys/{id}', { params: { path: { id: keyId } } });
      if (error || !data) throw new Error('Failed to load key');
      return data.key;
    },
  });
  const implsQ = useQuery({
    queryKey: ['key-implementations', keyId],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/keys/{id}/implementations', { params: { path: { id: keyId } } });
      if (error || !data) throw new Error('Failed to load key usage');
      return data.implementations ?? [];
    },
  });
  const k = (keyQ.data ?? {}) as Record<string, unknown> & Partial<Key>;
  const impls = (implsQ.data ?? []) as KeyImplementation[];
  const state = (k.state as string) || '';
  const stateTone = KEY_STATE_TONE[state] || 'var(--app-t2)';
  const expDays = daysUntil(k.expires_at as string);
  const expTone = expDays == null ? 'var(--app-t2)' : expDays < 0 ? 'var(--danger)' : expDays < 90 ? 'var(--warn-strong)' : 'var(--ok)';
  const sizeLabel = k.size_bits ? `${k.size_bits}-bit` : (k.curve as string) || '';
  const title = [k.key_type as string, sizeLabel].filter(Boolean).join(' · ') || (k.material_type as string) || 'Key';

  return (
    <DrawerShell onClose={onClose} width={480} active={active} depth={depth}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flex: 'none', width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)' }}>
            <Icon name="key-round" size={17} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">Cryptographic key</div>
            <h2 style={{ margin: '4px 0 2px', fontSize: 15.5, fontWeight: 600, color: 'var(--app-t1)', lineHeight: 1.25 }}>
              {keyQ.isLoading ? 'Loading…' : title}
            </h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
              {state && <span style={{ fontSize: 11, fontWeight: 600, color: stateTone, background: `color-mix(in srgb, ${stateTone} 11%, transparent)`, borderRadius: 40, padding: '2px 9px', textTransform: 'capitalize' }}>{state}</span>}
              {k.material_type != null && <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--app-t2)', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', borderRadius: 40, padding: '2px 9px' }}>{k.material_type as string}</span>}
              {expDays != null && <span className="mono" style={{ fontSize: 11.5, color: expTone }}>{expDays < 0 ? `expired ${-expDays}d ago` : `expires in ${expDays}d`}</span>}
            </div>
          </div>
          <CloseBtn onClose={onClose} />
        </div>
      </div>

      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        {keyQ.isError ? (
          <div style={{ padding: '32px 0', textAlign: 'center', fontSize: 12.5, color: 'var(--app-t3)' }}>Couldn't load this key.</div>
        ) : (
          <>
            <SectionLabel icon="key-round">Identity</SectionLabel>
            <MetaRow k="Key type" v={k.key_type as string} />
            <MetaRow k="Material type" v={k.material_type as string} />
            <MetaRow k="Format" v={k.format as string} />
            <MetaRow k="Key usage" v={(k.key_usage as string[] | undefined)?.join(', ')} />
            <MetaRow k="Fingerprint" v={k.public_fingerprint as string} mono />
            <MetaRow k="JWK thumbprint" v={k.jwk_thumbprint as string} mono />

            <SectionLabel icon="lock">Key &amp; algorithm</SectionLabel>
            <MetaRow k="Size" v={k.size_bits ? `${k.size_bits}-bit` : null} mono />
            <MetaRow k="Curve" v={k.curve as string} mono />
            <MetaRow k="Algorithm" v={k.algorithm_ref as string} mono />
            <MetaRow k="Secured by" v={k.secured_by as string} />

            <SectionLabel icon="clock">Lifecycle</SectionLabel>
            <MetaRow k="State" v={state} />
            <MetaRow k="State reason" v={k.state_reason as string} />
            <MetaRow k="Created" v={(k.created_at as string)?.slice(0, 10)} mono />
            <MetaRow k="Activated" v={(k.activation_date as string)?.slice(0, 10)} mono />
            <MetaRow k="Rotated" v={(k.rotated_at as string)?.slice(0, 10)} mono />
            <MetaRow k="Expires" v={(k.expires_at as string)?.slice(0, 10)} mono />

            <SectionLabel icon="server">Used by ({implsQ.isLoading ? '…' : impls.length})</SectionLabel>
            {implsQ.isLoading ? (
              <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>Loading usage…</div>
            ) : impls.length === 0 ? (
              <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0' }}>Not linked to any asset. This key is in inventory but no discovered configuration references it.</div>
            ) : (
              <div style={{ padding: '4px 0' }}>
                {impls.map((im) => (
                  <button
                    key={im.implementation_id}
                    onClick={() => onOpenAsset?.(im.asset_id, { hostname: im.asset_hostname ?? undefined })}
                    disabled={!onOpenAsset}
                    className="row-hover"
                    style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: '8px 10px', border: '1px solid var(--app-border)', borderRadius: 8, background: 'var(--app-panel2)', cursor: onOpenAsset ? 'pointer' : 'default', textAlign: 'left', marginBottom: 6 }}
                  >
                    <Icon name="server" size={13} style={{ flex: 'none', color: 'var(--app-t3)' }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{im.asset_hostname || im.asset_id}</div>
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{[im.protocol, im.protocol_version].filter(Boolean).join(' ')}</div>
                    </div>
                    {onOpenAsset && <Icon name="chevron-right" size={14} style={{ flex: 'none', color: 'var(--app-t3)' }} />}
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </DrawerShell>
  );
}
