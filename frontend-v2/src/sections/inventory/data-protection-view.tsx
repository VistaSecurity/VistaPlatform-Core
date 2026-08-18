// Data Protection lens — rows + detail drawer + the query hook.
// Derivations live in ./data-protection.ts (pure, unit-tested); this file is
// presentation only.
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { DrawerCloseBtn as CloseBtn, DrawerShell, Icon, MetaRow, RiskChip, SectionLabel, riskColor, type RiskLevel } from '../../components/ui';
import {
  atRestState, protectionRung, rungColor, rowRiskLevel, RUNG_META,
  encryptionTypeLabel, orText, originLabel, resourceTypeLabel,
  type AtRestState, type CryptoApplication, type ResourceTypeParam,
} from './data-protection';

export const DP_GRID = '22px minmax(0,1.8fr) 116px 132px 150px minmax(0,1fr) 96px';

// The endpoint is in the generated contract, so the call is fully typed —
// no local path/response shapes. `risk_at_least` is a BAND LABEL ("High"), not
// a score: the server matches that band and everything above it, which keeps
// the threshold arithmetic on the one side that owns the bands.
export function useCryptoApplications(
  enabled: boolean,
  opts: { page: number; pageSize: number; search: string; resourceType?: ResourceTypeParam; determined?: boolean; riskAtLeast?: RiskLevel },
) {
  const { page, pageSize, search, resourceType, determined, riskAtLeast } = opts;
  return useQuery({
    queryKey: ['inventory', 'crypto-applications', page, pageSize, search, resourceType ?? '', determined ?? '', riskAtLeast ?? ''],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-applications', {
        params: {
          query: {
            encryption_context: 'at_rest' as const,
            limit: pageSize,
            offset: (page - 1) * pageSize,
            ...(search ? { search } : {}),
            ...(resourceType ? { resource_type: resourceType } : {}),
            ...(determined === undefined ? {} : { determined }),
            ...(riskAtLeast === undefined ? {} : { risk_at_least: riskAtLeast }),
          },
        },
      });
      if (error || !data) throw new Error('Failed to load at-rest encryption posture');
      return data;
    },
    enabled,
    placeholderData: keepPreviousData,
  });
}

// ---- three-state badge ----------------------------------------------------
// The whole point of the lens: encrypted / not encrypted / NOT ASSESSED are
// three distinct renders. "Not assessed" is deliberately neutral and dashed —
// it must never be mistaken for either verdict.
const STATE_LABEL: Record<AtRestState, string> = {
  encrypted: 'Encrypted',
  unencrypted: 'Not encrypted',
  'not-assessed': 'Not assessed',
};
const STATE_ICON: Record<AtRestState, string> = {
  encrypted: 'shield-check',
  unencrypted: 'shield-x',
  'not-assessed': 'circle-help',
};

export function EncryptionStateBadge({ app, size = 11 }: { app: CryptoApplication; size?: number }) {
  const state = atRestState(app);
  const rung = protectionRung(app);
  // Tone comes from the LADDER, not from the bit: an SSE-S3 bucket reads
  // "Encrypted" in the Medium tone, a customer-KMS bucket in the Low tone, so
  // two green ticks can never imply equivalent protection.
  const tone = state === 'not-assessed' ? 'var(--neutral)' : rungColor(rung);
  return (
    <span
      title={state === 'not-assessed' ? RUNG_META['not-assessed'].detail : RUNG_META[rung].detail}
      style={{
        fontSize: size, fontWeight: 600, color: tone, justifySelf: 'start',
        background: state === 'not-assessed' ? 'transparent' : `color-mix(in srgb, ${tone} 11%, transparent)`,
        border: state === 'not-assessed' ? `1px dashed color-mix(in srgb, ${tone} 55%, transparent)` : '1px solid transparent',
        borderRadius: 40, padding: '2px 9px', display: 'inline-flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap', cursor: 'help',
      }}
    >
      <Icon name={STATE_ICON[state]} size={size} />{STATE_LABEL[state]}
    </span>
  );
}

// ---- custody ladder -------------------------------------------------------
// Three rungs: unencrypted → provider-managed key → customer-managed key.
// The meter makes the rung visible at a glance; the label names it.
export function CustodyLadder({ app }: { app: CryptoApplication }) {
  const rung = protectionRung(app);
  const meta = RUNG_META[rung];
  const tone = rung === 'not-assessed' ? 'var(--neutral)' : rungColor(rung);
  return (
    <span title={meta.detail} style={{ display: 'inline-flex', alignItems: 'center', gap: 7, minWidth: 0, cursor: 'help' }}>
      <span aria-hidden style={{ display: 'inline-flex', gap: 2, flex: 'none' }}>
        {[1, 2, 3].map((i) => (
          <span key={i} style={{ width: 9, height: 6, borderRadius: 2, background: i <= meta.filled ? tone : 'var(--app-track)' }} />
        ))}
      </span>
      <span style={{ fontSize: 11.5, color: rung === 'not-assessed' ? 'var(--app-t3)' : 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
        {meta.label}
      </span>
    </span>
  );
}

// ---- row ------------------------------------------------------------------
export function DataProtectionRow({ app, onClick }: { app: CryptoApplication; onClick: () => void }) {
  const level = rowRiskLevel(app);
  return (
    <div
      className="row-hover"
      onClick={onClick}
      style={{ display: 'grid', gridTemplateColumns: DP_GRID, gap: 12, padding: '0 16px', minHeight: 48, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}
    >
      <RiskChip level={level} size={22} />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {orText(app.resource_name, '—')}
        </div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {orText(app.resource_identifier, '')}
        </div>
      </div>
      <span style={{ fontSize: 12.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{resourceTypeLabel(app.resource_type)}</span>
      <EncryptionStateBadge app={app} />
      <CustodyLadder app={app} />
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{originLabel(app)}</span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{verifiedLabel(app.last_verified_at)}</span>
    </div>
  );
}

export function verifiedLabel(iso?: string | null): string {
  if (!iso) return 'never';
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (!Number.isFinite(d)) return '—';
  return d < 1 ? 'today' : `${d}d ago`;
}

// ---- drawer ---------------------------------------------------------------
export function DataProtectionDrawer({ app, onClose, onOpenAsset, active = true, depth = 0 }: {
  app: CryptoApplication; onClose: () => void; onOpenAsset?: (assetId: string) => void; active?: boolean; depth?: number;
}) {
  const level = rowRiskLevel(app);
  const state = atRestState(app);
  const rung = protectionRung(app);
  return (
    <DrawerShell onClose={onClose} width={470} active={active} depth={depth}>
      <div style={{ padding: '18px 22px 16px', borderBottom: '1px solid var(--app-border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <RiskChip level={level} size={28} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app">{resourceTypeLabel(app.resource_type)} · at rest</div>
            <h2 style={{ margin: '4px 0 2px', fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', lineHeight: 1.15, wordBreak: 'break-word' }}>
              {orText(app.resource_name, 'Resource')}
            </h2>
            <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', wordBreak: 'break-all' }}>{orText(app.resource_identifier, '')}</div>
          </div>
          <CloseBtn onClose={onClose} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
          <EncryptionStateBadge app={app} size={12} />
          <CustodyLadder app={app} />
        </div>
        {state === 'not-assessed' && (
          <div style={{ marginTop: 12, padding: '9px 12px', borderRadius: 10, border: '1px solid color-mix(in srgb, var(--warn) 35%, transparent)', background: 'color-mix(in srgb, var(--warn) 8%, transparent)', fontSize: 12, color: 'var(--app-t1)', lineHeight: 1.45 }}>
            Discovery could not read this resource’s encryption setting — most often the discovery credential lacks the permission to read it. <strong>This is not a finding of “encrypted”.</strong> Re-run the cloud discovery once the credential can read the resource’s encryption configuration.
          </div>
        )}
      </div>
      <div style={{ flex: 1, padding: '4px 22px 30px' }}>
        <SectionLabel icon="lock">At-rest encryption</SectionLabel>
        <MetaRow k="Assessment" v={state === 'not-assessed' ? 'Could not determine' : state === 'encrypted' ? 'Encrypted' : 'Not encrypted'} />
        <MetaRow k="Key custody" v={RUNG_META[rung].label} />
        <MetaRow k="Encryption type" v={state === 'not-assessed' ? null : encryptionTypeLabel(app.encryption_type)} mono />
        <MetaRow k="Algorithm" v={app.algorithm} mono />
        <MetaRow k="KMS key" v={app.kms_key_id} mono />
        {app.bucket_key_enabled != null && <MetaRow k="Bucket key" v={app.bucket_key_enabled ? 'enabled' : 'disabled'} />}
        {(!!app.engine || !!app.engine_version) && (
          <MetaRow k="Engine" v={[app.engine, app.engine_version].filter(Boolean).join(' ')} mono />
        )}

        <SectionLabel icon="cloud">Where</SectionLabel>
        <MetaRow k="Provider" v={app.cloud_provider} />
        <MetaRow k="Region" v={app.cloud_region} mono />
        <MetaRow k="Identifier" v={app.resource_identifier} mono />

        <SectionLabel icon="activity">Assessment</SectionLabel>
        <MetaRow k="Risk level" v={level} />
        <MetaRow
          k="Risk score"
          v={typeof app.risk_score === 'number' && app.risk_score > 0 ? app.risk_score : 'not assessed'}
        />
        <MetaRow k="Last verified" v={app.last_verified_at ? new Date(app.last_verified_at).toLocaleString() : 'never'} />
        <div style={{ marginTop: 10, fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
          <span style={{ color: riskColor(level), fontWeight: 600 }}>{level}</span> — {RUNG_META[rung].detail}
        </div>

        {app.asset_id && onOpenAsset && (
          <button
            onClick={() => onOpenAsset(app.asset_id as string)}
            className="row-hover"
            style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', marginTop: 18, padding: '9px 11px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}
          >
            <Icon name="server" size={14} style={{ color: 'var(--accent)', flex: 'none' }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--app-t3)' }}>Open asset</div>
              <div className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{orText(app.resource_name, 'View asset details')}</div>
            </div>
            <Icon name="chevron-right" size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          </button>
        )}
      </div>
    </DrawerShell>
  );
}
