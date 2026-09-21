// Shared bits for the CBOM section — page scaffolding, the loading/error/empty
// Note guard, value formatters, and the diff-category palette. Pages compose
// these; nothing here fetches. Mirrors the discovery section's kit pattern so
// the two read alike (components/ui is stream-1-owned and stays read-only).
import { Icon } from '../../components/ui';
import type { ArtifactKind, DiffChange, VerifyResponse } from './queries';

// ---- formatters -----------------------------------------------------------
export function fmtBytes(n?: number | null): string {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  return iso.slice(0, 10);
}

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return '—';
  return iso.slice(0, 16).replace('T', ' ');
}

export function relTime(iso?: string | null): string {
  if (!iso) return 'never';
  const mins = (Date.now() - new Date(iso).getTime()) / 60000;
  if (mins < 1) return 'just now';
  if (mins < 60) return `${Math.floor(mins)}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export function shortHash(h?: string | null, n = 12): string {
  return h ? h.slice(0, n) : '—';
}

// ---- artifact kinds -------------------------------------------------------

// The kind vocabulary itself comes from the generated contract (queries.ts
// re-exports it), not a hand-written union here: a kind added to the OpenAPI
// spec must fail THIS file's typecheck rather than silently rendering with no
// label. ARTIFACT_KINDS below is the presentation layer over that vocabulary.

export interface KindMeta {
  key: ArtifactKind;
  /** What the artifact is called, in the noun a user would say. */
  label: string;
  /** One line, on the selector and in the empty state. What it CONTAINS —
   *  not what it is for, which the user already knows. */
  blurb: string;
  icon: string;
  tone: string;
}

/**
 * Presentation for every kind. `Record<ArtifactKind, …>` is the load-bearing
 * part: a kind added to the OpenAPI spec breaks this object's typecheck, so it
 * cannot reach the list rendering as an unlabelled row.
 */
const KIND_BY_KEY: Record<ArtifactKind, KindMeta> = {
  cbom: {
    key: 'cbom',
    label: 'Cryptographic (CBOM)',
    blurb: 'Certificates, algorithms, protocols, keys and crypto libraries.',
    icon: 'key-round',
    tone: 'var(--accent)',
  },
  sbom: {
    key: 'sbom',
    label: 'Software (SBOM)',
    blurb: 'Every distinct software product installed, and the assets it was found on.',
    icon: 'package',
    tone: 'var(--ok)',
  },
  hbom: {
    key: 'hbom',
    label: 'Hardware (HBOM)',
    blurb: 'Every hardware asset, with its vendor, model, serial and firmware.',
    icon: 'cpu',
    tone: 'var(--warn)',
  },
  inventory: {
    key: 'inventory',
    label: 'Full inventory',
    blurb: 'Every asset with its endpoints, relationships, facts and open vulnerabilities.',
    icon: 'layers',
    tone: 'var(--app-t2)',
  },
};

/** In the order the Generate dialog lists them: crypto first, because that is
 *  what this page was, and the one an existing user is looking for. */
export const ARTIFACT_KINDS: KindMeta[] = ['cbom', 'sbom', 'hbom', 'inventory'].map((k) => KIND_BY_KEY[k as ArtifactKind]);

/**
 * Metadata for an artifact kind, tolerating an unknown one.
 *
 * A server newer than this bundle can return a kind the UI has never heard of,
 * and the honest rendering is the kind's own name with neutral styling — not a
 * crash, and not silently painting it as a CBOM, which would mislabel evidence.
 * An ABSENT kind is `cbom`: rows written before the column existed read back
 * that way, so that is what they are.
 */
export function kindMeta(kind?: string | null): KindMeta {
  if (!kind) return KIND_BY_KEY.cbom;
  return KIND_BY_KEY[kind as ArtifactKind] ?? { key: kind as ArtifactKind, label: kind.toUpperCase(), blurb: '', icon: 'file-badge', tone: 'var(--app-t3)' };
}

/** One entry in the Download control. `label` is the full name for a menu
 *  item or a wide button, `short` is what fits on the list row's compact
 *  button, and `hint` is the one-line explanation shown under a menu item and
 *  as the button tooltip. All three NAME the format: the compact button used
 *  to be a bare download icon whose tooltip said only "the canonical bytes",
 *  and a user reading the list concluded that only the inventory artifact —
 *  the one kind with a menu — could be downloaded as CycloneDX. */
export type DownloadOption = { format: 'cyclonedx' | 'ocsf'; label: string; short: string; hint: string };

/**
 * Which download formats this artifact offers, and why the others are absent.
 *
 * The server's rule, mirrored so the menu never offers a download that 400s:
 * CycloneDX is the canonical form of every kind; OCSF is a device-and-CVE
 * event stream and only an inventory snapshot has those to project; SPDX and
 * PDF project the crypto component model and are Enterprise.
 *
 * Mirrored, not guessed — if the two ever disagree the server refuses and the
 * user sees a clear 400, which is why the server keeps its own check.
 */
export function downloadFormatsFor(kind?: string | null): DownloadOption[] {
  const out: DownloadOption[] = [
    { format: 'cyclonedx', label: 'CycloneDX 1.7', short: 'CycloneDX', hint: 'CycloneDX 1.7 JSON — the canonical bytes, which the content hash and any signature cover.' },
  ];
  if ((kind ?? 'cbom') === 'inventory') {
    out.push({ format: 'ocsf', label: 'OCSF 1.9 events', short: 'OCSF', hint: 'OCSF 1.9 JSON Lines for a SIEM: one Device Inventory Info per asset, one Vulnerability Finding per CVE.' });
  }
  return out;
}

/** The kind badge. One glyph + one word, because a row already carries the
 *  scope and the date — the kind is what distinguishes two artifacts generated
 *  from the same scope on the same day. */
export function KindBadge({ kind }: { kind?: string | null }) {
  const meta = kindMeta(kind);
  return (
    <Pill icon={meta.icon} color={meta.tone} bg={`color-mix(in srgb, ${meta.tone} 11%, transparent)`}>
      {meta.label.replace(/ \(.*\)$/, '')}
    </Pill>
  );
}

// ---- verify verdicts ------------------------------------------------------

export type HashState = 'verified' | 'mismatch' | 'not-checked';

export interface HashVerdict {
  state: HashState;
  label: string;
  icon: string;
  tone: string;
  detail?: string;
}

/**
 * The hash half of a verify result has THREE outcomes, not two.
 *
 * `hash_valid` is a plain boolean, so "we compared and they differ" and "we
 * could not read the bytes, so we compared nothing" both arrive as `false`.
 * The server distinguishes them by omitting `hash_recomputed` in the second
 * case — a shape the OpenAPI spec documents deliberately.
 *
 * Branching on `hash_valid` alone painted an object-stored artifact whose bytes
 * merely could not be fetched (credentials rotated, object expired, storage
 * unwired) as a red "Hash mismatch", and suppressed the explanatory line
 * because `hash_recomputed` was empty. An operator holding untampered evidence
 * was told its integrity check had failed, which reads as tampering. The
 * signature half already had the three-state treatment; this gives the hash the
 * same honesty.
 */
export function hashVerdict(v: Pick<VerifyResponse, 'hash_valid' | 'hash_recomputed' | 'hash_stored'>): HashVerdict {
  if (v.hash_valid) {
    return { state: 'verified', label: 'Hash verified', icon: 'badge-check', tone: 'var(--ok)' };
  }
  if (v.hash_recomputed) {
    return {
      state: 'mismatch',
      label: 'Hash mismatch',
      icon: 'shield-x',
      tone: 'var(--danger)',
      detail: `expected ${shortHash(v.hash_stored, 24)}… · got ${shortHash(v.hash_recomputed, 24)}…`,
    };
  }
  return {
    state: 'not-checked',
    label: 'Hash not checked — artifact bytes unavailable',
    icon: 'shield-off',
    tone: 'var(--app-t3)',
    detail: 'Nothing was compared, so this is not a tamper signal. The stored bytes could not be read — check object storage configuration.',
  };
}

// ---- diff-category palette ------------------------------------------------
export interface CatMeta { c: string; bg: string; label: string; icon: string }

export const DIFF_CATEGORIES: Record<string, CatMeta> = {
  improvement: { c: 'var(--ok)', bg: 'color-mix(in srgb, var(--ok) 13%, transparent)', label: 'Improvement', icon: 'trending-up' },
  regression: { c: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)', label: 'Regression', icon: 'trending-down' },
  drift: { c: 'var(--warn)', bg: 'color-mix(in srgb, var(--warn) 14%, transparent)', label: 'Drift', icon: 'circle-alert' },
  neutral: { c: 'var(--app-t3)', bg: 'var(--app-panel2)', label: 'Neutral', icon: 'arrow-right' },
};

export function catMeta(cat: string): CatMeta {
  return DIFF_CATEGORIES[cat] ?? DIFF_CATEGORIES.neutral;
}

// Regressions first (the bad news shouldn't hide), then drift, neutral, improvement.
const CAT_RANK: Record<string, number> = { regression: 0, drift: 1, neutral: 2, improvement: 3 };
export function sortChanges(changes: DiffChange[]): DiffChange[] {
  return [...changes].sort((a, b) => (CAT_RANK[a.category] ?? 9) - (CAT_RANK[b.category] ?? 9));
}

// ---- narrative ------------------------------------------------------------

/** The anchor id a citation links to. One place, so the row and the link agree. */
export function diffRowAnchor(rowId: string): string {
  return `diff-row-${rowId}`;
}

/**
 * Who wrote the summary, as a reader should be told.
 *
 * The distinction is the point of the label. A rule-written summary is
 * arithmetic over the rows and is the same every time; a model-written one was
 * produced by a named model, off this machine, and the reader is entitled to
 * know which — not to a vague "AI" badge that could mean anything. A summary
 * with no detail at all is a server that predates the seam, and saying nothing
 * beats inventing an attribution for it.
 */
export function narrativeLabel(detail?: { source?: string; model_id?: string } | null): string | null {
  if (!detail?.source) return null;
  if (detail.source === 'model') {
    return detail.model_id ? `Summarised by ${detail.model_id}` : 'Summarised by a model';
  }
  return 'Summarised by rules';
}

/** One citation marker as the backend writes it: `[row:r12]`. */
const CITATION_RE = /\[row:([A-Za-z0-9_-]{1,32})\]/g;

export interface NarrativeSegment {
  /** Prose to render as-is, or the row id when `cite` is set. */
  text: string;
  /** Present on a citation segment: the row id it points at. */
  cite?: string;
}

/**
 * Split narrative prose into plain runs and citation markers.
 *
 * Parsed here rather than rendered from `citations` because a citation belongs
 * WHERE IT WAS WRITTEN — the marker sits immediately after the clause it
 * supports, and a list of chips under the paragraph loses which sentence each
 * one backs, which is the only thing that makes them checkable.
 */
export function narrativeSegments(text: string): NarrativeSegment[] {
  const out: NarrativeSegment[] = [];
  const re = new RegExp(CITATION_RE.source, 'g');
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push({ text: text.slice(last, m.index) });
    out.push({ text: m[1], cite: m[1] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

// ---- page scaffolding -----------------------------------------------------
export function PageWrap({ title, subtitle, count, actions, children }: {
  title: string; subtitle?: string; count?: number | string; actions?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>{title}</h2>
            {count != null && <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{count}</span>}
          </div>
          {subtitle && <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 3 }}>{subtitle}</div>}
        </div>
        {actions}
      </div>
      {children}
    </div>
  );
}

export function Note({ icon, tone, title, message, panel }: { icon: string; tone: string; title: string; message?: string; panel?: boolean }) {
  const body = (
    <div style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.85 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      {message && <div style={{ fontSize: 12.5, marginTop: 4, maxWidth: 360, marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.55 }}>{message}</div>}
    </div>
  );
  return panel ? <div className="panel" style={{ borderRadius: 14 }}>{body}</div> : body;
}

// Standard query-state guard: returns a Note to render, or null when data is ready.
export function queryNote(
  q: { isLoading: boolean; isError: boolean; error: unknown },
  empty: boolean,
  names: { thing: string; emptyTitle?: string; emptyMessage?: string; emptyIcon?: string },
): React.ReactNode | null {
  if (q.isError) return <Note panel icon="alert-triangle" tone="var(--danger-text)" title={`Couldn't load ${names.thing}`} message={q.error instanceof Error ? q.error.message : 'Request failed'} />;
  if (q.isLoading) return <Note panel icon="loader" tone="var(--app-t3)" title={`Loading ${names.thing}…`} />;
  if (empty) return <Note panel icon={names.emptyIcon || 'file-badge'} tone="var(--app-t3)" title={names.emptyTitle || `No ${names.thing}`} message={names.emptyMessage || `No ${names.thing} for this tenant yet.`} />;
  return null;
}

export function Pill({ icon, color, bg, children }: { icon?: string; color: string; bg?: string; children: React.ReactNode }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, height: 22, padding: '0 9px', borderRadius: 7, border: '1px solid var(--app-border2)', background: bg || 'var(--app-panel2)', fontSize: 11, fontWeight: 600, color, whiteSpace: 'nowrap' }}>
      {icon && <Icon name={icon} size={12} />}{children}
    </span>
  );
}
