// The asset page (ADR-0006 D3) — `/inventory/assets/:id[/:tab]`.
//
// Reached from any list row, from the drawer's "Open full page", from the
// command palette, from Findings and from Discovery → Devices. The drawer keeps
// its role as the peek from a list; this is the thing you send someone a link
// to.
//
// Every tab implements all five states the spec asks for: default, empty,
// loading, error, success. The empties are written per tab on purpose — "no
// endpoints observed" and "not assessed" are different facts about an asset and
// a shared "nothing here" would flatten them into one.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { Asset } from '@vistasecurity/api-contract';
import { parseSeverity, severityRank } from '@vistasecurity/primitives/ratings';
import { Icon, MetaRow, RiskGauge, RiskChip, SectionLabel } from '../../components/ui';
import { ASSET_TABS, DEFAULT_ASSET_TAB, assetTabPath, findAssetTab, type AssetTab } from './asset-tabs';
import { AssetMergeModal } from '../discovery/asset-merge-modal';
import { IdentityStatus } from './identity-status';
import { ProvisionalIdentityPanel } from './provisional-identity-panel';
import {
  useAsset, useAssetClassHistory, useAssetConfigs, useAssetEndpoints, useAssetHistory, useAssetIdentifiers,
  CLASS_CHANGE_SOURCE_LABELS,
  type AssetClassChange, type AssetEndpoint, type AssetHistoryEntry, type AssetIdentifier,
} from './asset-queries';
import {
  assetRisk, attr, classIcon, classLabel, confidenceLabel, identifierKindLabel,
  operatingSystem, primaryAddressPort, relativeSeen, sourceKindLabel, stripMask,
  type AssetLike,
} from './asset-shape';
import { ATTRIBUTE_SCHEMAS, type AssetClassKey } from '@vistasecurity/primitives/assets';
import {
  SOFTWARE_PAGE_SIZE, installSourceLabel, productIdentifier, statusTone, useAssetSoftware,
  type SoftwareSort,
} from './software-queries';
// The lifecycle and vulnerability columns (workstream 3.8). The states ride on
// the software list itself, so the tab is still ONE request — fifty installs
// would otherwise be fifty subject-filtered calls to compliance-engine.
import { eolCell, installFindingsHref, vulnerabilityCell } from './software-state';
import { ConfigDrawer, type CryptoConfig, type OpenConfig } from './drawers';
import { AssetFormModal } from './asset-form-modal';
// The Findings tab reads the compliance-engine per-asset route and the findings
// vocabulary from the Risk & Compliance section, rather than restating either.
import { useAssetFindings } from '../findings/queries';
import { findingCitation, isOpenWf, sevLevel, type ComplianceFinding } from '../findings/model';
import { AssessmentLimitNotice } from '../findings/assessment-limit';
import { CryptoRiskChip } from './crypto-risk-presentation';
import { RelationshipsTab } from './relationships-tab';

// ------------------------------------------------------------------ states --

function Loading({ label }: { label: string }) {
  return (
    <div data-testid="tab-loading" style={{ padding: '10px 0' }}>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} style={{ height: 13, borderRadius: 6, background: 'var(--app-panel2)', marginBottom: 9, width: `${88 - i * 13}%` }} />
      ))}
      <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{label}</span>
    </div>
  );
}

function ErrorCard({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div data-testid="tab-error" style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '13px 15px', borderRadius: 12, border: '1px solid var(--danger)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)' }}>
      <Icon name="alert-triangle" size={16} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>Couldn't load this</div>
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 3 }}>{message}</div>
      </div>
      {onRetry && <button className="ui-btn sm" onClick={onRetry}><Icon name="refresh-cw" size={12} />Retry</button>}
    </div>
  );
}

function Empty({ icon, title, message, action }: {
  icon: string; title: string; message: string; action?: { label: string; to: string };
}) {
  return (
    <div data-testid="tab-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: '42px 20px', textAlign: 'center' }}>
      <Icon name={icon} size={24} style={{ color: 'var(--app-t3)' }} />
      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 480, lineHeight: 1.6 }}>{message}</div>
      {action && <Link to={action.to} className="ui-btn sm" style={{ marginTop: 4, textDecoration: 'none' }}>{action.label}</Link>}
    </div>
  );
}

function PhasePlaceholder({ tab }: { tab: AssetTab }) {
  return (
    <div data-testid="tab-placeholder" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 9, padding: '46px 20px', textAlign: 'center' }}>
      <Icon name={tab.icon} size={26} style={{ color: 'var(--accent)' }} />
      <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>{tab.label} arrives in {tab.placeholder?.phase}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 520, lineHeight: 1.6 }}>{tab.placeholder?.message}</div>
    </div>
  );
}

// ---------------------------------------------------------------- overview --

function IdentifierRow({ ident }: { ident: AssetIdentifier }) {
  const conf = confidenceLabel(ident.confidence);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,150px) minmax(0,1.6fr) minmax(0,1fr) 96px 92px', gap: 12, alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--app-border)' }}>
      <span style={{ fontSize: 12, color: 'var(--app-t2)', fontWeight: 600 }}>{identifierKindLabel(ident.kind)}</span>
      <span className="mono" title={ident.value} style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ident.value}</span>
      <span
        style={{ fontSize: 11.5, color: 'var(--app-t3)' }}
        title={
          ident.source_ref
            ? `${sourceKindLabel(ident.source_kind)} · ${ident.source_ref}`
            : sourceKindLabel(ident.source_kind)
        }
      >
        {sourceKindLabel(ident.source_kind) || '—'}
      </span>
      {/* An ABSENT confidence is not a low one. It renders as a dash, and the
          tooltip says which it is, because a "0%" here would read as "we are
          certain this is wrong". */}
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }} title={conf ? `Confidence ${conf}` : 'No confidence recorded for this identifier'}>{conf || '—'}</span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }} title={ident.last_seen_at ?? undefined}>{relativeSeen(ident.last_seen_at) || '—'}</span>
    </div>
  );
}

/**
 * The one finding that explains an asset's score.
 *
 * `assets.risk_score` is MAX over the asset's open risk-feeding findings
 * (ADR-0005 D4), so exactly one of them is the reason the number is what it is.
 * Showing a score without it leaves the user with a number and no next step —
 * they have to open a tab, scan a list and work out which row the gauge came
 * from.
 *
 * Ties break on the worst severity and then on the summary, so the same set of
 * findings always names the same one: a "why" that changed on every reload
 * would read as the asset changing.
 *
 * A finding whose kind feeds no risk (hygiene, compliance) can never be the
 * answer, because it never moved the score. Its score is 0 and the filter below
 * excludes it — which is the same rule the server's rollup applies, stated here
 * for the one thing this component does with it.
 *
 * Exported for the unit test.
 */
export function topRiskFinding(findings: ComplianceFinding[]): ComplianceFinding | null {
  const open = findings.filter((f) => isOpenWf(f) && (f.score ?? 0) > 0);
  if (open.length === 0) return null;
  return open.reduce((best, f) => {
    const ds = (f.score ?? 0) - (best.score ?? 0);
    if (ds !== 0) return ds > 0 ? f : best;
    const currentSeverity = parseSeverity(f.severity);
    const bestSeverity = parseSeverity(best.severity);
    const dr = (currentSeverity ? severityRank(currentSeverity) ?? 0 : 0)
      - (bestSeverity ? severityRank(bestSeverity) ?? 0 : 0);
    if (dr !== 0) return dr > 0 ? f : best;
    return f.summary < best.summary ? f : best;
  });
}

/**
 * The coverage sentence, in words rather than an array.
 *
 * Three states, and the third is the one the product exists to tell apart:
 * assessed and scored, assessed and clean, and NOT ASSESSED. `risk_assessed_by`
 * is the only thing that separates the last two — score 0 with producers named
 * is a clean bill of health, score 0 with an empty array is nobody having
 * looked — so this never renders an empty list as anything but "Not assessed".
 *
 * Exported for the unit test.
 */
export function assessedBySentence(assessedBy: string[]): string {
  if (assessedBy.length === 0) return 'Not assessed';
  return `Assessed by ${assessedBy.join(', ')}`;
}

/**
 * The anchor a finding carries on the Findings tab, and the link that lands on
 * it.
 *
 * ONE helper for both ends. The Overview tab's "why" is a link into a list, and
 * a link into a list that does not say WHICH row it meant leaves the user
 * scanning for the finding the gauge came from — exactly the work the "why"
 * exists to save. An anchor spelled separately at each end stops matching the
 * day either spelling changes, and nothing says so: the browser simply does not
 * scroll, and the page looks fine.
 *
 * Exported for the unit test that pins the two ends together.
 */
export function findingAnchor(findingID: string): string {
  return `finding-${findingID}`;
}

/** The Overview "why" link: the Findings tab, with that finding selected. */
export function findingLinkTo(assetID: string, findingID: string): string {
  return `${assetTabPath(assetID, 'findings')}#${findingAnchor(findingID)}`;
}

/** The finding a `#finding-…` hash names, or '' for any other hash. */
export function selectedFindingID(hash: string): string {
  const prefix = `#${findingAnchor('')}`;
  return hash.startsWith(prefix) ? hash.slice(prefix.length) : '';
}

function OverviewTab({ asset }: { asset: Asset }) {
  const identifiers = (asset.identifiers ?? []) as AssetIdentifier[];
  const risk = assetRisk(asset);
  // The "why" behind the gauge. Loading or failing quietly leaves the gauge
  // alone: the score is on the asset itself and does not depend on this call,
  // and an error card beside a valid number would suggest the number is wrong.
  const findingsQ = useAssetFindings(asset.id);
  const why = useMemo(() => topRiskFinding(findingsQ.data ?? []), [findingsQ.data]);
  const schema = ATTRIBUTE_SCHEMAS[(asset.class_key ?? '') as AssetClassKey];
  const declared = Object.keys(schema?.properties ?? {});
  const attributes = declared
    .map((name) => ({ name, value: attr(asset, name), description: schema?.properties[name]?.description }))
    .filter((r) => r.value !== '');
  const tags = asset.tags && typeof asset.tags === 'object' ? Object.entries(asset.tags as Record<string, unknown>) : [];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.35fr) minmax(0,1fr)', gap: 26, alignItems: 'start' }}>
      <div>
        <SectionLabel icon="fingerprint">Identity</SectionLabel>
        <IdentityStatus asset={asset} />
        {/* The provisional panel REPLACES the bare evidence link for a
            provisional item: the link is still there, inside the panel, next to
            the explanation that makes it worth following. Rendering both would
            put two "Inspect discovery evidence" links a line apart. */}
        {asset.identity_status === 'provisional'
          ? <ProvisionalIdentityPanel assetID={asset.id} />
          : asset.id && <Link to={`/discovery/observations?asset_id=${asset.id}`}>Inspect discovery evidence</Link>}
        <MetaRow k="Class" v={
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Icon name={classIcon(asset.class_key)} size={13} style={{ color: 'var(--app-t3)' }} />
            {classLabel(asset.class_key) || '—'}
            {asset.class_source_kind && (
              <span style={{ fontWeight: 400, color: 'var(--app-t3)' }}>
                · {sourceKindLabel(asset.class_source_kind)}
                {/* `!= null`, not `!== undefined`: JSON carries an absent
                    confidence as `null`, which `!== undefined` lets through to
                    render a stray space. `confidenceLabel` already answers ''
                    for both, so this only decides the separator. */}
                {asset.class_confidence != null ? ` ${confidenceLabel(asset.class_confidence)}` : ''}
              </span>
            )}
          </span>
        } title={asset.class_source_ref ? `Classified by ${asset.class_source_ref}` : undefined} />
        <MetaRow k="Class path" v={asset.class_path} mono />
        <MetaRow k="Display name" v={asset.display_name} />

        <SectionLabel icon="scan-barcode">Identifiers ({identifiers.length})</SectionLabel>
        {identifiers.length === 0 ? (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', padding: '8px 0', lineHeight: 1.55 }}>
            No identifiers are recorded for this asset. Legacy records may have incomplete identity evidence. Inspect discovery evidence to see what was collected and how it was linked.
          </div>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,150px) minmax(0,1.6fr) minmax(0,1fr) 96px 92px', gap: 12, padding: '0 0 5px' }}>
              <span className="eyebrow-app">Kind</span>
              <span className="eyebrow-app">Value</span>
              <span className="eyebrow-app">Source</span>
              <span className="eyebrow-app">Confidence</span>
              <span className="eyebrow-app">Last seen</span>
            </div>
            {identifiers.map((i, n) => <IdentifierRow key={i.id ?? `${i.kind}-${i.value}-${n}`} ident={i} />)}
          </div>
        )}

        {attributes.length > 0 && (
          <>
            <SectionLabel icon="list">{classLabel(asset.class_key)} attributes</SectionLabel>
            {attributes.map((a) => <MetaRow key={a.name} k={humanAttr(a.name)} v={a.value} title={a.description} />)}
          </>
        )}
      </div>

      <div>
        <SectionLabel icon="gauge">Risk</SectionLabel>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '4px 0 10px' }}>
          <RiskGauge score={risk.score} level={risk.level} size={62} label="" stroke={6} />
          <div style={{ minWidth: 0 }}>
            {risk.assessed ? (
              <>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{risk.level}</div>
                <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>score {risk.score}</div>
                {/* The WHY. One finding, the one the MAX came from, linked to the
                    tab that lists the rest — so the gauge is a starting point
                    rather than a verdict with no working. */}
                {why && (
                  <Link
                    to={findingLinkTo(asset.id, why.id)}
                    style={{ display: 'block', fontSize: 11.5, color: 'var(--accent)', marginTop: 4, lineHeight: 1.5, maxWidth: 280, textDecoration: 'none' }}
                    title={`${why.producer} · severity ${why.severity} · score ${why.score}`}
                  >
                    {why.summary}
                  </Link>
                )}
                {!why && risk.score === 0 && (
                  <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 4, lineHeight: 1.5, maxWidth: 280 }}>
                    Nothing open is feeding this score.
                  </div>
                )}
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>
                  {risk.assessedBy.length > 0
                    ? assessedBySentence(risk.assessedBy)
                    : 'Assessed by an unnamed producer'}
                </div>
              </>
            ) : (
              // The load-bearing state. An unassessed asset is NOT a low-risk
              // one, and a grey gauge with "0" beside it would say the opposite
              // of what we know — which is nothing.
              <>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t2)' }}>Not assessed</div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3, lineHeight: 1.5, maxWidth: 260 }}>
                  No producer has evaluated this asset. That is not the same as “no risk found” — nothing has looked yet.
                </div>
              </>
            )}
          </div>
        </div>
        <AssessmentLimitNotice findings={findingsQ.data ?? []} assetContext />

        <SectionLabel icon="building-2">Context</SectionLabel>
        <MetaRow k="Environment" v={asset.environment} />
        <MetaRow k="Business unit" v={asset.business_unit} />
        <MetaRow k="Support group" v={asset.support_group} />
        <MetaRow k="Owner" v={asset.owner_email} />
        <MetaRow k="Location" v={[asset.site, asset.region, asset.zone].filter(Boolean).join(' / ')} />
        <MetaRow k="Network segment" v={asset.network_segment_name} />
        <MetaRow k="Description" v={asset.description} />

        <SectionLabel icon="activity">Status</SectionLabel>
        <MetaRow k="Lifecycle" v={asset.asset_status} />
        <MetaRow k="Staleness" v={asset.stale_status} />
        <MetaRow k="Ownership" v={asset.asset_ownership} />
        <MetaRow k="Discovery" v={asset.discovery_method} />
        <MetaRow k="First discovered" v={asset.first_discovered_at?.slice(0, 10)} mono />
        <MetaRow k="Last seen" v={relativeSeen(asset.last_seen_at)} mono title={asset.last_seen_at ?? undefined} />

        {tags.length > 0 && (
          <>
            <SectionLabel icon="tags">Tags</SectionLabel>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {tags.map(([k, v]) => (
                <span key={k} className="mono" style={{ fontSize: 11, color: 'var(--warn-strong)', background: 'color-mix(in srgb, var(--warn-strong) 11%, transparent)', borderRadius: 40, padding: '2px 9px' }}>
                  {k}{tagValue(v)}
                </span>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/** A tag's value, when it has a printable one. A JSONB tag map can hold an
 *  object; `String(...)` would render it as "[object Object]", which says less
 *  than the bare key does. */
function tagValue(v: unknown): string {
  if (typeof v === 'string') return v === '' ? '' : `=${v}`;
  if (typeof v === 'number' || typeof v === 'boolean') return `=${String(v)}`;
  return '';
}

function humanAttr(name: string): string {
  const words = name.split('_');
  const head = words[0] === 'os' || words[0] === 'cpu' || words[0] === 'ip'
    ? words[0].toUpperCase()
    : words[0].charAt(0).toUpperCase() + words[0].slice(1);
  return [head, ...words.slice(1)].join(' ');
}

// ------------------------------------------------------------ merged-into --

/**
 * The survivor this asset was merged into, or null.
 *
 * A merge ARCHIVES the losing record rather than deleting it — "the tombstone
 * points at the survivor" — so its page still resolves, and without this it
 * resolves to a page that looks like an ordinary archived asset with no
 * endpoints, no configurations and no explanation. Every link anyone ever sent
 * to it still works and now says nothing true.
 *
 * `merged_into` is the contract's own field: "present ONLY on an asset a merge
 * archived; absent on every other asset", and the read answers 200 with it
 * rather than 404 precisely so a stale link can be followed rather than dead-end.
 *
 * `assets.metadata.merged_into` is read as a FALLBACK, not as the source. The
 * merge service has written the pointer there since before the column was
 * projected, so rows archived by an older build carry it in metadata and
 * nowhere else — and the whole value of the banner is for the links that were
 * sent before anyone thought about it. The two never disagree: the same
 * transaction writes both.
 */
export function mergedIntoId(asset: AssetLike & { merged_into?: string | null; metadata?: unknown }): string | null {
  const field = asset.merged_into;
  if (typeof field === 'string' && field.trim() !== '') return field.trim();
  const meta = asset.metadata;
  if (!meta || typeof meta !== 'object') return null;
  const v = (meta as Record<string, unknown>).merged_into;
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

function MergedIntoBanner({ survivorId }: { survivorId: string }) {
  // The survivor's own read names it. A banner that said "Merged into
  // 8f3c…-…" would be a link the reader has to follow to find out whether it
  // is the thing they were looking for.
  const survivor = useAsset(survivorId);
  const name = survivor.data
    ? (survivor.data.display_name || survivor.data.hostname || primaryAddressPort(survivor.data) || survivorId)
    : survivorId;
  return (
    <div
      data-testid="merged-into-banner"
      style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '0 26px 4px', padding: '9px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--accent) 35%, transparent)', background: 'color-mix(in srgb, var(--accent) 8%, transparent)' }}
    >
      <Icon name="git-merge" size={15} style={{ color: 'var(--accent)', flexShrink: 0 }} />
      <span style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1 }}>
        This record was merged into another asset and archived. Everything discovered here now lives on{' '}
        <Link to={`/inventory/assets/${survivorId}`} style={{ color: 'var(--accent)', fontWeight: 600 }}>{name}</Link>.
      </span>
      <Link to={`/inventory/assets/${survivorId}`} className="ui-btn sm" style={{ textDecoration: 'none', flex: 'none' }}>
        Open it<Icon name="chevron-right" size={13} />
      </Link>
    </div>
  );
}

// --------------------------------------------------------------- endpoints --

function EndpointsTab({ asset }: { asset: Asset }) {
  const q = useAssetEndpoints(asset.id, (asset.endpoints ?? null) as AssetEndpoint[] | null);
  const rows = q.data ?? [];
  if (q.isError) return <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  if (q.isLoading) return <Loading label="Loading endpoints…" />;
  if (rows.length === 0) {
    return (
      <Empty
        icon="ethernet-port"
        title="No endpoints observed"
        message="An asset may genuinely have none — an object store or a declared service has nothing to connect to. If you expected one, an active scan will record what this asset exposes."
        action={{ label: 'Go to Active Scan', to: '/discovery/active-scan' }}
      />
    );
  }
  const GRID = 'minmax(0,1.3fr) 64px 72px minmax(0,1.1fr) 128px 88px 92px';
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, padding: '0 0 6px' }}>
        <span className="eyebrow-app">Address</span>
        <span className="eyebrow-app">Port</span>
        <span className="eyebrow-app">Transport</span>
        <span className="eyebrow-app">Service</span>
        <span className="eyebrow-app">Exposure</span>
        <span className="eyebrow-app">Status</span>
        <span className="eyebrow-app">Last seen</span>
      </div>
      {rows.map((e) => (
        <div key={e.id} style={{ display: 'grid', gridTemplateColumns: GRID, gap: 12, alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--app-border)' }}>
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {stripMask(e.address) || e.fqdn || '—'}
          </span>
          {/* Absent, not zero. `port` is omitted for an at-rest or declared
              endpoint, and the "AT-REST" sentinel the port-as-asset model
              needed is retired — so there is nothing to print. */}
          <span className="mono" style={{ fontSize: 12, color: e.port ? 'var(--app-t1)' : 'var(--app-t3)' }} title={e.port ? undefined : 'This endpoint has no port — it is at rest or declared'}>
            {e.port ?? '—'}
          </span>
          <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{e.transport === 'none' ? '—' : e.transport}</span>
          <span style={{ fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={serviceTitle(e)}>
            {[e.service_name, e.service_version].filter(Boolean).join(' ') || '—'}
            {e.service_identification_method && (
              <span style={{ color: 'var(--app-t3)' }}> · {confidenceWord(e)}</span>
            )}
          </span>
          {/* Three-valued, and the third state renders NOTHING — see
              exposureChip. An endpoint nobody measured the binding of must not
              be shown asserting one. */}
          <span style={{ fontSize: 11, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {(() => {
              const chip = exposureChip(e);
              if (!chip) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
              return (
                <span
                  title={chip.title}
                  style={{
                    padding: '1px 6px',
                    borderRadius: 4,
                    border: '1px solid var(--app-border)',
                    color: chip.tone === 'warn' ? 'var(--warn)' : 'var(--app-t3)',
                  }}
                >
                  {chip.label}
                </span>
              );
            })()}
          </span>
          <span style={{ fontSize: 11.5, color: e.status === 'active' ? 'var(--ok)' : e.status === 'closed' ? 'var(--app-t3)' : 'var(--warn)' }}>{e.status}</span>
          <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }} title={e.last_seen_at}>{relativeSeen(e.last_seen_at) || '—'}</span>
        </div>
      ))}
    </div>
  );
}

const METHOD_TITLE: Record<string, string> = {
  banner: 'The service announced itself in its banner.',
  ja3s: 'Matched on the TLS handshake fingerprint, not on anything the service said.',
  port_heuristic: 'Inferred from the port number alone. The port is the only evidence, so treat the name as a guess.',
  http_header: 'Read from an HTTP response header.',
  manual: 'Entered by a user, not discovered.',
};
const CONFIDENCE_WORD: Record<string, string> = { high: 'confirmed', medium: 'likely', low: 'best guess' };
function confidenceWord(e: AssetEndpoint): string {
  if (e.service_identification_method === 'manual') return 'set manually';
  return CONFIDENCE_WORD[(e.service_confidence ?? '').toLowerCase()] ?? (e.service_identification_method ?? '');
}
function serviceTitle(e: AssetEndpoint): string | undefined {
  return METHOD_TITLE[e.service_identification_method ?? ''] ?? undefined;
}

/**
 * The exposure chip, and its third state is "say nothing".
 *
 * `bound_local` is three-valued and ABSENT is a real answer: nobody established
 * the binding. That is every endpoint a network scan found — a scan cannot
 * establish it even in principle, it only sees what answers — so rendering
 * absence as "reachable" would have the great majority of the inventory
 * asserting an exposure nobody measured, which is the fabrication this column
 * exists to avoid.
 *
 * Only a host's own view of its sockets (the agent's host inventory) reports
 * either boolean, and `false` there IS a measurement: the service is exposed to
 * the network. That is why `false` gets a chip and nil does not, rather than
 * both collapsing into the same blank.
 *
 * Exported for the unit test, like assetFindingRows above it.
 */
export function exposureChip(e: Pick<AssetEndpoint, 'bound_local'>): { label: string; tone: 'quiet' | 'warn'; title: string } | null {
  if (e.bound_local === true) {
    return {
      label: 'bound to localhost',
      tone: 'quiet',
      title: 'The host reported this socket bound to a loopback address, so nothing outside the machine can reach it. Only the host itself can establish this — a network scan never sees these.',
    };
  }
  if (e.bound_local === false) {
    return {
      label: 'reachable',
      tone: 'warn',
      title: 'The host reported this socket bound to a non-loopback address: it is exposed to the network. This is a measurement, not an assumption.',
    };
  }
  // Undefined AND null both land here. Nobody established the binding.
  return null;
}

// ------------------------------------------------------------ cryptography --

/**
 * Every discovery method that contributed to a configuration, primary first.
 * `discovery_methods` is the full provenance (a passive glimpse and the active
 * probe that completed it are ONE row carrying both); rows written before it
 * was recorded fall back to the single `discovery_method`.
 */
export function configProvenance(c: Pick<CryptoConfig, 'discovery_method' | 'discovery_methods'>): string[] {
  const methods = Array.isArray(c.discovery_methods) ? c.discovery_methods.filter((m) => typeof m === 'string' && m !== '') : [];
  if (methods.length > 0) return methods;
  return c.discovery_method ? [c.discovery_method] : [];
}

function ProvenanceChips({ methods }: { methods: string[] }) {
  if (methods.length === 0) return null;
  return (
    <span
      className="mono"
      title={`Observed by: ${methods.join(', ')}`}
      style={{ display: 'inline-flex', gap: 4, flex: 'none', fontSize: 10, color: 'var(--app-t3)' }}
    >
      {methods.map((m) => (
        <span key={m} style={{ padding: '1px 6px', borderRadius: 999, border: '1px solid var(--app-border)' }}>{m.replace(/_/g, ' ')}</span>
      ))}
    </span>
  );
}

function CryptographyTab({ asset, onOpenConfig }: { asset: Asset; onOpenConfig: OpenConfig }) {
  const q = useAssetConfigs(asset.id);
  const configs = q.data ?? [];
  if (q.isError) return <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  if (q.isLoading) return <Loading label="Loading cryptographic configurations…" />;
  if (configs.length === 0) {
    return (
      <Empty
        icon="key-round"
        title="No cryptographic configurations"
        message="Nothing cryptographic has been observed on this asset. That is not a clean bill of health — it means no sensor or scan has measured a handshake here yet."
        action={{ label: 'Go to Active Scan', to: '/discovery/active-scan' }}
      />
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      {configs.map((cfg) => {
        const c = cfg as Record<string, unknown> & CryptoConfig;
        return (
          <button
            key={c.id as string}
            onClick={() => onOpenConfig(cfg as CryptoConfig)}
            className="row-hover"
            style={{ display: 'flex', alignItems: 'center', gap: 11, width: '100%', padding: '10px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 8, textAlign: 'left' }}
          >
            <CryptoRiskChip config={c} size={22} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{c.protocol as string} · {c.protocol_version as string}</div>
              <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.cipher_suite as string}</div>
            </div>
            <ProvenanceChips methods={configProvenance(c)} />
            <Icon name="chevron-right" size={15} style={{ color: 'var(--app-t3)', flex: 'none' }} />
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------- findings --

function FindingsTab({ asset }: { asset: Asset }) {
  const findingsQ = useAssetFindings(asset.id);
  const risk = assetRisk(asset);
  // The finding the Overview tab's "why" named, if the user arrived that way.
  // The browser cannot do this for us: the list is rendered after the query
  // resolves, so the element the hash names does not exist at navigation time.
  const selected = selectedFindingID(useLocation().hash);
  const selectedRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    selectedRef.current?.scrollIntoView({ block: 'center' });
  }, [selected, findingsQ.data]);
  const findings: ComplianceFinding[] = useMemo(() => findingsQ.data ?? [], [findingsQ.data]);
  const producers = useMemo(
    () => [...new Set(findings.map((f) => f.producer))].sort(),
    [findings],
  );
  // Which producers have EVALUATED this asset, as opposed to which have
  // reported something about it. The two lists are different and the gap
  // between them is the useful part: a producer that assessed and found nothing
  // belongs in the first and not the second, and a producer in neither has not
  // looked at all.
  const silent = useMemo(
    () => risk.assessedBy.filter((p) => !producers.includes(p)),
    [risk.assessedBy, producers],
  );

  if (findingsQ.isError) {
    return <ErrorCard message={findingsQ.error instanceof Error ? findingsQ.error.message : 'Request failed'} onRetry={() => { void findingsQ.refetch(); }} />;
  }
  if (findingsQ.isLoading) return <Loading label="Loading findings…" />;

  // Which producers have actually said something about THIS asset, and which
  // have looked and said nothing. Naming both is the difference between
  // "nothing is wrong here" and "nobody has looked", and this tab used to be
  // able to say only the first.
  //
  // The crypto "risk factors" that used to be synthesised here from the asset's
  // own configurations are gone: the `crypto` producer writes real
  // `weak_configuration`, `weak_certificate` and `pqc_vulnerable` findings now
  // (workstream 3.2), so they arrive through the same route as every other
  // producer's and are counted, ticketed and assigned like them. Keeping the
  // synthesised rows beside the real ones would show the same judgement twice.
  const producerNote = (
    <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 12, lineHeight: 1.55 }}>
      Open findings on this asset and on everything under it — its endpoints, the certificates and
      cryptographic configurations at those endpoints, its software.
      {producers.length > 0 && <> Reported by: {producers.join(', ')}.</>}
      {silent.length > 0 && <> Assessed with nothing to report by: {silent.join(', ')}.</>}
      {' '}
      <Link to="/risk-compliance/findings" style={{ color: 'var(--accent)' }}>Risk &amp; Compliance → Findings</Link>{' '}
      has findings for the whole organization.
    </div>
  );

  if (findings.length === 0) {
    // Two different nothings, told apart by `risk_assessed_by`. Before that
    // field existed the UI could only guess, and it guessed the pessimistic one
    // for both — which denied a genuinely clean asset its clean bill of health.
    return (
      <div>
        {producerNote}
        {risk.assessed ? (
          <Empty
            icon="shield-check"
            title="No open findings"
            message={`Nothing is outstanding on this asset. ${assessedBySentence(risk.assessedBy)}.`}
          />
        ) : (
          <Empty
            icon="circle-help"
            title="Not assessed"
            message="No producer has evaluated this asset, so there are no findings to show — and no clean bill of health either. Run an active scan, or wait for a sensor to observe it."
            action={{ label: 'Go to Active Scan', to: '/discovery/active-scan' }}
          />
        )}
      </div>
    );
  }

  return (
    <div>
      {producerNote}
      <AssessmentLimitNotice findings={findings} assetContext />
      {findings.map((f) => (
        <div
          key={f.id}
          id={findingAnchor(f.id)}
          ref={f.id === selected ? selectedRef : undefined}
          style={{
            display: 'flex', alignItems: 'flex-start', gap: 11, width: '100%', padding: '10px 8px',
            borderBottom: '1px solid var(--app-border)', textAlign: 'left',
            // The selected row is MARKED, not just scrolled to: scrolling alone
            // puts the row somewhere on screen and leaves the user guessing
            // which of the rows now in view was the one the score came from.
            ...(f.id === selected
              ? { background: 'var(--app-hover)', boxShadow: 'inset 2px 0 0 0 var(--accent)' }
              : {}),
          }}
        >
          <RiskChip level={sevLevel(f.severity)} size={22} title={`${sevLevel(f.severity)} · ${f.producer}`} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{f.summary}</div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 2 }}>
              {f.producer} · {f.subject_label || SUBJECT_NOUN[f.subject_type] || f.subject_type}
              {/*
                The citation. A finding the platform derived from a catalogue —
                an end-of-life date, a CVE — has to say where that came from, or
                the user has no way to check it and no way to dispute it. Absent
                for the `compliance` producer, which cites a control rather than
                a URL. `rel` is not optional on a target=_blank link to a
                third-party page.
              */}
              {(() => {
                const cite = findingCitation(f);
                if (!cite) return null;
                return (
                  <>
                    {' · '}
                    <a
                      href={cite.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: 'var(--accent)' }}
                    >
                      {cite.label}
                    </a>
                  </>
                );
              })()}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * The noun for a finding's subject, when it has no label of its own.
 *
 * One entry per `subject_types` value in `standards/findings-registry.yaml`, and
 * `subject-noun.test.ts` fails if the registry gains a type this map has not.
 * A missing entry is not a blank: the row falls back to the raw
 * `subject_type`, so `pqc_vulnerable` on a key read "crypto · key" and
 * `orphan_relationship` read "hygiene · relationship" — the vocabulary leaking
 * onto the page, which is how both went unnoticed after their subject paths
 * were added to findings.AssetSubjects.
 *
 * `control` and `framework` are listed for completeness. findings.AssetSubjects
 * deliberately has no path from an asset to either, so a finding on one cannot
 * reach this tab today; the noun costs nothing and stops the guard from having
 * to carve out exceptions that would hide a real omission.
 */
export const SUBJECT_NOUN: Record<string, string> = {
  asset: 'this asset',
  endpoint: 'an endpoint',
  certificate: 'a certificate',
  key: 'a cryptographic key',
  crypto_configuration: 'a cryptographic configuration',
  software_install: 'installed software',
  relationship: 'a relationship to another asset',
  control: 'a compliance control',
  framework: 'a compliance framework',
};

// ----------------------------------------------------------------- history --

function HistoryTab({ asset }: { asset: Asset }) {
  const q = useAssetHistory(asset.id);
  const rows = q.data ?? [];
  return (
    <div>
      <ClassHistoryPanel asset={asset} />
      <div style={{ fontSize: 12, fontWeight: 700, color: "var(--app-t2)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 6 }}>All changes</div>
      {q.isError
        ? <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />
        : q.isLoading
          ? <Loading label="Loading history…" />
          : rows.length === 0
            ? <Empty icon="history" title="No history yet" message="Changes to this asset — reclassification, context edits, merges and approvals — are recorded here as they happen." />
            : rows.map((h) => <HistoryRow key={h.id} entry={h} />)}
    </div>
  );
}

/**
 * Class history — every class this asset has held, and who decided.
 *
 * It sits above the general change log because it answers the question people
 * actually arrive with. A class is an INPUT to most of the platform: producers
 * pick which findings apply by it, approval rules match on it, compliance
 * measurements scope by it. When it moves, everything written before the move
 * was written about a different thing — and until this panel there was nothing
 * anywhere that said it had moved.
 *
 * An EMPTY list is not "it has always been what it is". It means no recorded
 * change, which for an asset created before the record existed is a different
 * claim entirely; the empty state says so rather than showing a tidy timeline.
 */
function ClassHistoryPanel({ asset }: { asset: Asset }) {
  const q = useAssetClassHistory(asset.id);
  const rows = q.data ?? [];
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: "var(--app-t2)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 6 }}>Class history</div>
      {q.isError
        ? <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />
        : q.isLoading
          ? <Loading label="Loading class history…" />
          : rows.length === 0
            ? <Empty
                icon="shapes"
                title="No recorded class change"
                message="Nothing has been recorded for this asset's class. That is not the same as never having changed — an asset created before this record existed has no entry here."
              />
            : rows.map((c) => <ClassChangeRow key={c.id} change={c} />)}
    </div>
  );
}

/**
 * The label if the catalogue has one, else the raw key, else nothing.
 *
 * Not `label ?? key`: a class the catalogue does not know gets an EMPTY label,
 * not an absent one, and nullish coalescing would render the blank instead of
 * falling back to the key the reader can at least look up. Written out rather
 * than as `a || b` so the eslint ratchet does not have to take that on trust.
 */
function classText(label: string | undefined, key: string | undefined): string {
  if (label !== undefined && label !== '') return label;
  if (key !== undefined && key !== '') return key;
  return '';
}

function ClassChangeRow({ change }: { change: AssetClassChange }) {
  const from = classText(change.from_class_label, change.from_class_key);
  const to = classText(change.to_class_label, change.to_class_key);
  const evidence = change.evidence && typeof change.evidence === 'object'
    ? Object.entries(change.evidence)
    : [];
  return (
    <div style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
      <div style={{ width: 110, flex: 'none' }}>
        <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }} title={change.created_at}>{relativeSeen(change.created_at) || '—'}</div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 600 }}>
          {/* The creation row has no previous class. Rendering "— → Printer"
              would read as a change from nothing; "Classified as Printer" is
              what actually happened. */}
          {from ? `${from} → ${to}` : `Classified as ${to}`}
        </div>
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
          {CLASS_CHANGE_SOURCE_LABELS[change.source] ?? change.source}
          {/* Absent actor means NO PERSON — a machine did it — never "person
              unknown", so the row says the mechanism rather than a shrug. */}
          {change.actor_user_id ? ` · by ${change.actor_user_id}` : ''}
        </div>
        {evidence.length > 0 && (
          <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 4, wordBreak: 'break-word' }}>
            {evidence.slice(0, 6).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(' · ')}
            {evidence.length > 6 ? ` · +${evidence.length - 6} more` : ''}
          </div>
        )}
      </div>
    </div>
  );
}

function HistoryRow({ entry }: { entry: AssetHistoryEntry }) {
  const changes = entry.changes && typeof entry.changes === 'object' ? Object.entries(entry.changes) : [];
  return (
    <div style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--app-border)' }}>
      <div style={{ width: 110, flex: 'none' }}>
        <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }} title={entry.created_at}>{relativeSeen(entry.created_at) || '—'}</div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 600 }}>{entry.action.replace(/_/g, ' ')}</div>
        {/* The actor. `actor_user_id` is not populated by the context writer
            yet (carried note in the phase-1 spec), so the SOURCE is what we can
            name honestly — and naming the source beats inventing a person. */}
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
          {entry.actor_user_id ? `by ${entry.actor_user_id}` : `source: ${entry.source || 'unknown'}`}
        </div>
        {changes.length > 0 && (
          <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 4, wordBreak: 'break-word' }}>
            {changes.slice(0, 6).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(' · ')}
            {changes.length > 6 ? ` · +${changes.length - 6} more` : ''}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- software --

/**
 * The Software tab (workstream 2.6b) — what is installed on this asset.
 *
 * Two honesty rules shape it, and both come straight from the model:
 *
 *  - An EMPTY list is not "no software". It means nothing has enumerated
 *    software here. The empty state says that in those words and points at the
 *    upload, rather than showing a clean table that reads as a clean bill of
 *    health. Same distinction `risk_assessed_by` draws for risk and the
 *    `unclassified` bucket draws for PQC.
 *  - REMOVED rows are shown, muted, not hidden. A removed install is a product
 *    a later document did not list; its row is kept precisely so "this was here
 *    last month" stays answerable. The status filter is there for the reader
 *    who wants only what is present now.
 */
function SoftwareTab({ asset }: { asset: Asset }) {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [sort, setSort] = useState<SoftwareSort>('name');
  const [page, setPage] = useState(0);
  const q = useAssetSoftware(asset.id, { q: search, status, sort, page });

  const rows = q.data?.rows ?? [];
  const total = q.data?.total ?? 0;

  if (q.isError) {
    return <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  }
  // A filtered-to-nothing result is NOT the never-enumerated empty state. Only
  // an unfiltered, zero-row answer means nobody has looked.
  const neverEnumerated = !q.isLoading && total === 0 && search === '' && status === '';

  return (
    <div data-testid="software-tab">
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
        <input
          className="ui-input"
          style={{ flex: 1, minWidth: 190 }}
          placeholder="Search name, vendor, purl or CPE…"
          value={search}
          data-testid="software-search"
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
        />
        <select className="ui-input" value={status} data-testid="software-status" onChange={(e) => { setStatus(e.target.value); setPage(0); }}>
          <option value="">All statuses</option>
          <option value="active">Present now</option>
          <option value="stale">Stale</option>
          <option value="removed">No longer listed</option>
        </select>
        <select className="ui-input" value={sort} data-testid="software-sort" onChange={(e) => { setSort(e.target.value as SoftwareSort); setPage(0); }}>
          <option value="name">Name</option>
          <option value="version">Version</option>
          <option value="vendor">Vendor</option>
          <option value="last_seen">Last seen</option>
          <option value="first_seen">First seen</option>
        </select>
      </div>

      {q.isLoading && <Loading label="Loading software…" />}

      {neverEnumerated && (
        <Empty
          icon="package"
          title="No software has been enumerated here"
          message="This is not the same as “no software found” — nothing has looked yet. Upload a CycloneDX or SPDX bill of materials for this asset and its components appear here."
          action={{ label: 'Upload an SBOM', to: '/discovery/sbom' }}
        />
      )}

      {!q.isLoading && total === 0 && !neverEnumerated && (
        <Empty icon="search-x" title="Nothing matches that filter" message="No software on this asset matches the search or status you chose." />
      )}

      {total > 0 && (
        <>
          <div style={{ border: '1px solid var(--app-border)', borderRadius: 11, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr style={{ background: 'var(--app-panel2)' }}>
                  {['Name', 'Vendor', 'Version', 'End of life', 'Vulnerabilities', 'Identifier', 'Source', 'Last seen', 'Status'].map((h) => (
                    <th key={h} style={{ textAlign: 'left', padding: '8px 11px', fontSize: 10.5, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const ident = productIdentifier(r);
                  const tone = statusTone(r.status);
                  return (
                    <tr key={r.install_id} data-testid="software-row" style={{ borderTop: '1px solid var(--app-border)', opacity: tone === 'muted' ? 0.6 : 1 }}>
                      <td style={{ padding: '8px 11px', color: 'var(--app-t1)' }}>{r.name}</td>
                      <td style={{ padding: '8px 11px', color: 'var(--app-t3)' }}>{r.vendor || '—'}</td>
                      <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t2)' }}>{r.version || '—'}</td>
                      <StateCellTd
                        testId="software-eol"
                        cell={eolCell(r)}
                        href={installFindingsHref(r.install_id, 'eol')}
                      />
                      <StateCellTd
                        testId="software-vuln"
                        cell={vulnerabilityCell(r)}
                        href={installFindingsHref(r.install_id, 'vulnerability')}
                      />
                      <td className="mono" style={{ padding: '8px 11px', color: 'var(--app-t3)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ident?.value}>
                        {ident ? `${ident.kind}: ${ident.value}` : '—'}
                      </td>
                      <td style={{ padding: '8px 11px', color: 'var(--app-t3)' }} title={r.source_ref ?? undefined}>{installSourceLabel(r.source_kind)}</td>
                      <td style={{ padding: '8px 11px', color: 'var(--app-t3)', whiteSpace: 'nowrap' }} title={`First seen ${r.first_seen_at}\nLast seen ${r.last_seen_at}`}>{relativeSeen(r.last_seen_at) || '—'}</td>
                      <td style={{ padding: '8px 11px', whiteSpace: 'nowrap', color: tone === 'ok' ? 'var(--app-t2)' : 'var(--app-t3)' }}>
                        {r.status === 'removed' ? 'No longer listed' : r.status === 'stale' ? 'Stale' : 'Present'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 10, fontSize: 12, color: 'var(--app-t3)' }}>
            <span className="mono">{total} total</span>
            <span style={{ flex: 1 }} />
            <button className="ui-btn ghost" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>Previous</button>
            <button className="ui-btn ghost" disabled={(page + 1) * SOFTWARE_PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </>
      )}
    </div>
  );
}

/**
 * One lifecycle / vulnerability cell.
 *
 * A LINK only when there is a finding to open. "Not assessed" and "None known"
 * are not links, because there is nothing behind them — and a link that opens
 * an empty page is how a reader learns to stop trusting the column.
 */
function StateCellTd({ cell, href, testId }: {
  cell: ReturnType<typeof eolCell>; href: string; testId: string;
}) {
  return (
    <td data-testid={testId} style={{ padding: '8px 11px', whiteSpace: 'nowrap' }} title={cell.title}>
      {cell.actionable ? (
        <Link to={href} style={{ color: cell.tone, textDecoration: 'none', fontWeight: 600 }}>
          {cell.label}
        </Link>
      ) : (
        <span style={{ color: cell.tone }}>{cell.label}</span>
      )}
    </td>
  );
}

// -------------------------------------------------------------------- page --

export function AssetPage() {
  const { id, tab: tabParam } = useParams();
  const navigate = useNavigate();
  const tab = findAssetTab(tabParam);
  const q = useAsset(id);
  const [editOpen, setEditOpen] = useState(false);
  const [mergeOpen, setMergeOpen] = useState(false);
  const [configStack, setConfigStack] = useState<CryptoConfig[]>([]);
  const openConfig: OpenConfig = (c) => setConfigStack((s) => [...s, c]);

  // Identifiers ride along on the read; this keeps a home for the dedicated
  // endpoint without making the page wait on a second request.
  useAssetIdentifiers(id, (q.data?.identifiers ?? null) as AssetIdentifier[] | null);

  const asset = q.data;
  const ident = useMemo(() => asset ? { title: asset.display_name || asset.hostname || primaryAddressPort(asset) || asset.id, sub: primaryAddressPort(asset) } : null, [asset]);

  if (q.isLoading) {
    return (
      <div style={{ padding: '22px 26px' }}>
        <Loading label="Loading asset…" />
      </div>
    );
  }

  if (q.isError || !asset) {
    const notFound = /404|not found/i.test(q.error instanceof Error ? q.error.message : '');
    return (
      <div style={{ padding: '22px 26px' }}>
        <Link to="/inventory?lens=assets" style={{ fontSize: 12.5, color: 'var(--accent)', textDecoration: 'none' }}>
          <Icon name="chevron-left" size={13} />Back to All assets
        </Link>
        <div style={{ marginTop: 16 }}>
          {notFound ? (
            <Empty
              icon="search-x"
              title="Asset not found"
              message="This asset no longer exists. It may have been deleted, or merged into another asset — a merge records the old id in the surviving asset's History."
              action={{ label: 'Back to All assets', to: '/inventory?lens=assets' }}
            />
          ) : (
            <ErrorCard message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />
          )}
        </div>
      </div>
    );
  }

  const risk = assetRisk(asset);
  const survivorId = mergedIntoId(asset);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div style={{ padding: '14px 26px 0' }}>
        <Link to="/inventory?lens=assets" style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 12.5, color: 'var(--app-t3)', textDecoration: 'none' }}>
          <Icon name="chevron-left" size={13} />All assets
        </Link>
      </div>

      {/* Above the identity block on purpose: "what you are looking at is not
          where this thing lives any more" has to be read before the page it is
          about, not after it. */}
      {survivorId && <div style={{ paddingTop: 10 }}><MergedIntoBanner survivorId={survivorId} /></div>}

      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, padding: '10px 26px 12px' }}>
        <RiskGauge score={risk.score} level={risk.level} size={58} label="" stroke={6} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <Icon name={classIcon(asset.class_key)} size={14} style={{ color: 'var(--app-t3)' }} />
            <span className="eyebrow-app">{classLabel(asset.class_key) || 'asset'}</span>
            {!risk.assessed && (
              <span style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t3)', border: '1px solid var(--app-border2)', borderRadius: 40, padding: '1px 8px' }}>
                Not assessed
              </span>
            )}
          </div>
          <h1 style={{ margin: '3px 0 2px', fontFamily: 'var(--font-head)', fontSize: 19, fontWeight: 700, color: 'var(--app-t1)', wordBreak: 'break-word', lineHeight: 1.2 }}>
            {ident?.title}
          </h1>
          <div className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            {ident?.sub || (operatingSystem(asset) || 'no network endpoint')}
          </div>
        </div>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
          {!survivorId && asset.asset_status !== 'archived' && asset.asset_status !== 'denied' && <button className="ui-btn" onClick={() => setMergeOpen(true)}><Icon name="git-merge" size={13} />Review merge</button>}
          <button className="ui-btn" onClick={() => setEditOpen(true)} style={{ height: 31, fontSize: 12.5 }}>
            <Icon name="sliders-horizontal" size={13} />Edit
          </button>
        </PermissionGate>
      </div>

      <div role="tablist" aria-label="Asset sections" style={{ display: 'flex', gap: 2, padding: '0 26px', borderBottom: '1px solid var(--app-border)', overflowX: 'auto' }}>
        {ASSET_TABS.map((t) => {
          const active = t.key === tab.key;
          return (
            <button
              key={t.key}
              role="tab"
              aria-selected={active}
              onClick={() => { void navigate(assetTabPath(asset.id, t.key)); }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 7, padding: '9px 12px',
                border: 'none', borderBottom: `2px solid ${active ? 'var(--accent)' : 'transparent'}`,
                background: 'transparent', cursor: 'pointer', whiteSpace: 'nowrap',
                color: active ? 'var(--app-t1)' : 'var(--app-t3)',
                fontFamily: 'var(--font-body)', fontSize: 12.5, fontWeight: active ? 700 : 500,
                opacity: t.placeholder ? 0.7 : 1,
              }}
            >
              <Icon name={t.icon} size={13} />{t.label}
              {t.placeholder && <Icon name="clock" size={11} />}
            </button>
          );
        })}
      </div>

      <div role="tabpanel" style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '16px 26px 30px' }}>
        {tab.placeholder ? <PhasePlaceholder tab={tab} />
          : tab.key === 'overview' ? <OverviewTab asset={asset} />
          : tab.key === 'endpoints' ? <EndpointsTab asset={asset} />
          : tab.key === 'relationships' ? <RelationshipsTab asset={asset} />
          : tab.key === 'cryptography' ? <CryptographyTab asset={asset} onOpenConfig={openConfig} />
          : tab.key === 'findings' ? <FindingsTab asset={asset} />
          : tab.key === 'software' ? <SoftwareTab asset={asset} />
          : tab.key === 'history' ? <HistoryTab asset={asset} />
          : <OverviewTab asset={asset} />}
      </div>

      {mergeOpen && <AssetMergeModal initialAssets={[{ asset_id: asset.id, display_name: asset.display_name, hostname: asset.hostname, class_key: asset.class_key, asset_status: asset.asset_status, deleted: false, score: 0, matched_identifiers: [] }]} onClose={() => setMergeOpen(false)} />}
      {configStack.map((c, i) => (
        <ConfigDrawer
          key={i}
          config={c}
          onOpenAsset={(otherId) => { void navigate(`/inventory/assets/${otherId}`); setConfigStack([]); }}
          // Deliberately NOT passed. There is no certificate page and no
          // certificate drawer stacked on this page, so a handler here would
          // render the drawer's "View certificate" row as a button that does
          // nothing when clicked. Omitting it makes the drawer fall back to a
          // plain meta row — the certificate is still named, and no control
          // promises an action the page cannot perform. Certificate
          // drill-down is Inventory → Certificates.
          onClose={() => setConfigStack((s) => s.slice(0, -1))}
          active={i === configStack.length - 1}
          depth={i}
        />
      ))}

      {editOpen && (
        <AssetFormModal open={editOpen} asset={asset} onClose={() => setEditOpen(false)} />
      )}
    </div>
  );
}

export { DEFAULT_ASSET_TAB };
