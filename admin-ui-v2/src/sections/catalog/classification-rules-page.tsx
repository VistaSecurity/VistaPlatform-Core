// VISTA Operations — Catalog ▸ Classification rules.
//
// The `classification_rules` table: the evidence behind every class proposal
// (asset-inventory ADR-0004 D6). A rule maps something a collector observed —
// an IEEE OUI, an SNMP sysObjectID, an EtherNet/IP vendor id, a cloud resource
// type, a service banner, a port profile, a model prefix, or the management
// platform the device answered — onto a vendor and, only where the mapping is
// unambiguous, an asset class.
//
// D6's argument is that these are DATA, not code, so the fingerprint catalogue
// grows without a release and the learned classifier has features to train on.
// This page is where that actually happens: without it the seeded rules are all
// any deployment would ever have.
//
// A rule added here IS LIVE, as of workstream 2.10b. inventory-service and
// device-interrogation-service load this table through classify.Repository and
// rebuild their engine on an interval (CLASSIFICATION_RULES_REFRESH, default
// five minutes), so a rule takes effect on the next discovery rather than the
// next release.
//
// For a whole release it was not, and the page said so in as many words — a
// console that let someone add a rule and quietly did nothing with it would be
// the worst version of this page. The notice at the bottom now states the
// refresh window instead, because "it is live" with no idea of WHEN is the same
// problem one step along: an admin who adds a rule and re-runs a discovery
// thirty seconds later has to know why nothing moved.
//
// Platform data — no tenant_id, every tenant classified against the same rows —
// which is why it sits here beside Algorithms, Frameworks and the two mirrored
// catalogues rather than in a tenant surface. Reads and writes are both gated
// server-side on `catalogs.manage`.
//
// Unlike End-of-life and Vulnerability feed, this page WRITES. There is no
// upstream feed to mirror: the rules are ours and the admin's.
import { useState } from 'react';
import { Crosshair, Plus, Search, Trash2, Pencil, X } from 'lucide-react';
import { Tag, num } from '../../components/ui/primitives';
import { AcceptUpdateButton, SeededContentBadges } from './seeded-content';
import {
  useClassificationRules, useCreateClassificationRule, useUpdateClassificationRule,
  useDeleteClassificationRule, useAcceptClassificationRuleUpdate, errMsg,
  RULE_KIND_LABEL, RULE_KIND_HINT, MIN_CONFIDENCE, MAX_CONFIDENCE, PAGE_SIZE,
  type ClassificationRule, type ClassificationRuleInput, type ClassificationRuleKind,
} from './catalog-queries';

const KIND_COLOR: Record<string, string> = {
  oui: 'var(--chart-1)',
  sysobjectid: 'var(--info)',
  enip: 'var(--warn)',
  cloud_type: 'var(--ok-lime)',
  banner: 'var(--op-t2)',
  port_profile: 'var(--op-t2)',
  model: 'var(--chart-1)',
  platform: 'var(--info)',
  cdp_capabilities: 'var(--ok-lime)',
  lldp_capability: 'var(--ok-lime)',
  mdns_service: 'var(--warn)',
  os_name: 'var(--chart-1)',
};

/** The empty form, used for "Add rule" and as the reset after a save. */
const BLANK: ClassificationRuleInput = {
  rule_kind: 'oui',
  pattern: '',
  class_key: null,
  vendor: null,
  model: null,
  confidence: 0.8,
  source_url: null,
};

function toInput(rule: ClassificationRule): ClassificationRuleInput {
  return {
    rule_kind: rule.rule_kind,
    pattern: rule.pattern,
    class_key: rule.class_key,
    vendor: rule.vendor,
    model: rule.model,
    confidence: rule.confidence,
    source_url: rule.source_url,
  };
}

const inputStyle: React.CSSProperties = {
  height: 28, padding: '0 9px', fontSize: 12.5, borderRadius: 'var(--r-sm)',
  border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)',
};

/**
 * The add/edit form.
 *
 * It does NOT re-implement the engine's validation. The server runs exactly the
 * validator the classifier runs at load, and its message names what to change —
 * so the form's job is to show the per-kind hint up front and then surface the
 * server's answer verbatim, rather than to keep a second, looser copy of the
 * rules that would let through things the engine will not fire on.
 */
function RuleForm({
  initial, kinds, saving, error, onSave, onCancel,
}: {
  initial: ClassificationRuleInput;
  kinds: ClassificationRuleKind[];
  saving: boolean;
  error: string | null;
  onSave: (input: ClassificationRuleInput) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<ClassificationRuleInput>(initial);
  const set = <K extends keyof ClassificationRuleInput>(key: K, value: ClassificationRuleInput[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  // A blank optional field is NULL, not "". The null is what says "this rule
  // deliberately asserts no class" — the single most common shape in the table,
  // because most manufacturers sell across several classes under one OUI.
  const orNull = (v: string) => (v.trim() === '' ? null : v.trim());

  const assertsSomething =
    (form.class_key ?? '') !== '' || (form.vendor ?? '') !== '' || (form.model ?? '') !== '';

  return (
    <form
      data-testid="rule-form"
      onSubmit={(e) => { e.preventDefault(); onSave(form); }}
      style={{
        padding: '14px 16px', borderBottom: '1px solid var(--op-border)',
        background: 'var(--op-panel2)', display: 'flex', flexDirection: 'column', gap: 10,
      }}
    >
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Kind</span>
          <select
            aria-label="Rule kind" value={form.rule_kind} style={inputStyle}
            onChange={(e) => set('rule_kind', e.target.value as ClassificationRuleKind)}
          >
            {kinds.map((k) => <option key={k} value={k}>{RULE_KIND_LABEL[k] ?? k}</option>)}
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 260px' }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Pattern</span>
          <input
            aria-label="Pattern" value={form.pattern} required
            onChange={(e) => set('pattern', e.target.value)}
            style={{ ...inputStyle, width: '100%' }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Confidence</span>
          <input
            aria-label="Confidence" type="number" step="0.05"
            min={MIN_CONFIDENCE} max={MAX_CONFIDENCE} value={form.confidence}
            onChange={(e) => set('confidence', Number(e.target.value))}
            style={{ ...inputStyle, width: 90 }}
          />
        </label>
      </div>

      <div className="t-muted" style={{ fontSize: 11.5 }} data-testid="pattern-hint">
        {RULE_KIND_HINT[form.rule_kind] ?? ''}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Asset class (optional)</span>
          <input
            aria-label="Asset class" value={form.class_key ?? ''}
            placeholder="leave empty for vendor only"
            onChange={(e) => set('class_key', orNull(e.target.value))}
            style={{ ...inputStyle, width: 190 }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Vendor (optional)</span>
          <input
            aria-label="Vendor" value={form.vendor ?? ''}
            onChange={(e) => set('vendor', orNull(e.target.value))}
            style={{ ...inputStyle, width: 190 }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Model (optional)</span>
          <input
            aria-label="Model" value={form.model ?? ''}
            onChange={(e) => set('model', orNull(e.target.value))}
            style={{ ...inputStyle, width: 150 }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 240px' }}>
          <span className="t-muted" style={{ fontSize: 11 }}>Source URL</span>
          <input
            aria-label="Source URL" value={form.source_url ?? ''} type="url"
            placeholder="https://…"
            onChange={(e) => set('source_url', orNull(e.target.value))}
            style={{ ...inputStyle, width: '100%' }}
          />
        </label>
      </div>

      {/* The rule of thumb, stated where the decision is made. An admin filling
          this in is exactly the person who needs to read it. */}
      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6 }}>
        Leave the class empty when the vendor sells more than one kind of thing under
        this pattern. <strong>A wrong class is worse than none</strong> — an absent class shows as
        unclassified and invites someone to look; a wrong one shows as a fact and gets approved.
      </div>

      {!assertsSomething && (
        <div style={{ fontSize: 12, color: 'var(--warn)' }} data-testid="rule-asserts-nothing">
          Give the rule a class, a vendor or a model — a rule that asserts nothing can only
          waste a reviewer's time.
        </div>
      )}
      {error && (
        <div style={{ fontSize: 12, color: 'var(--danger)' }} data-testid="rule-form-error">{error}</div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <button className="op-btn sm primary" type="submit" disabled={saving || !assertsSomething}>
          {saving ? 'Saving…' : 'Save rule'}
        </button>
        <button className="op-btn sm" type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export function ClassificationRulesPage() {
  const [search, setSearch] = useState('');
  const [kind, setKind] = useState<ClassificationRuleKind | ''>('');
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<ClassificationRule | 'new' | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ClassificationRule | null>(null);

  const { data, isLoading, isError, refetch } = useClassificationRules({ search, kind, page });
  const create = useCreateClassificationRule();
  const update = useUpdateClassificationRule();
  const remove = useDeleteClassificationRule();
  const accept = useAcceptClassificationRuleUpdate();

  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;
  // The kind vocabulary comes from the server. A hard-coded list here is how a
  // ninth rule kind ships invisible — present in the engine, absent from every
  // filter and form.
  const kinds = data?.kinds ?? [];
  const lastPage = Math.max(1, Math.ceil(total / (data?.pageSize ?? PAGE_SIZE)));

  const onFilter = (fn: () => void) => { fn(); setPage(1); };

  const saving = create.isPending || update.isPending;
  const saveError = create.error
    ? errMsg(create.error, 'Failed to create the rule')
    : update.error
      ? errMsg(update.error, 'Failed to update the rule')
      : null;

  const save = (input: ClassificationRuleInput) => {
    const done = { onSuccess: () => { setEditing(null); create.reset(); update.reset(); } };
    if (editing === 'new' || editing === null) create.mutate(input, done);
    else update.mutate({ id: editing.id, input }, done);
  };

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <Crosshair size={16} style={{ color: 'var(--op-t3)' }} />
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
            Classification rules
          </span>
          {!isLoading && !isError && (
            <span className="t-muted" style={{ fontSize: 12 }} data-testid="rules-total">{num(total)} rules</span>
          )}
          <div style={{ flex: 1 }} />
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Search size={14} style={{ color: 'var(--op-t3)' }} />
            <input
              value={search}
              onChange={(e) => onFilter(() => setSearch(e.target.value))}
              placeholder="Search pattern, vendor, model, class…"
              aria-label="Search the classification rules"
              style={{ ...inputStyle, width: 250 }}
            />
          </label>
          <select
            value={kind}
            aria-label="Filter by rule kind"
            onChange={(e) => onFilter(() => setKind(e.target.value as ClassificationRuleKind | ''))}
            style={inputStyle}
          >
            <option value="">All kinds</option>
            {kinds.map((k) => <option key={k} value={k}>{RULE_KIND_LABEL[k] ?? k}</option>)}
          </select>
          <button
            className="op-btn sm primary" type="button"
            onClick={() => { create.reset(); update.reset(); setEditing('new'); }}
          >
            <Plus size={13} style={{ marginRight: 4 }} />Add rule
          </button>
        </div>

        {editing !== null && (
          <RuleForm
            key={editing === 'new' ? 'new' : editing.id}
            initial={editing === 'new' ? BLANK : toInput(editing)}
            kinds={kinds.length ? kinds : (['oui'] as ClassificationRuleKind[])}
            saving={saving}
            error={saveError}
            onSave={save}
            onCancel={() => { setEditing(null); create.reset(); update.reset(); }}
          />
        )}

        <table className="op-table">
          <thead>
            <tr><th>Kind</th><th>Pattern</th><th>Class</th><th>Vendor</th><th>Model</th><th>Confidence</th><th>Source</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><Tag color={KIND_COLOR[r.rule_kind] ?? 'var(--op-t2)'}>{RULE_KIND_LABEL[r.rule_kind] ?? r.rule_kind}</Tag></td>
                <td className="mono" style={{ fontSize: 12, color: 'var(--op-t1)', wordBreak: 'break-all' }}>
                  {r.pattern}
                  <span style={{ display: 'inline-flex', gap: 4, marginLeft: 6, verticalAlign: 'middle' }}><SeededContentBadges row={r} /></span>
                </td>
                <td>
                  {/* A null class is the NORMAL shape of a vendor-only rule, so
                      it says so rather than rendering a dash that reads as
                      missing data. */}
                  {r.class_key
                    ? <span className="mono" style={{ fontSize: 12 }}>{r.class_key}</span>
                    : <span className="t-muted" title="This rule deliberately proposes no class — only a vendor.">vendor only</span>}
                </td>
                <td className="t-muted">{r.vendor ?? '—'}</td>
                <td className="t-muted">{r.model ?? '—'}</td>
                <td className="mono" style={{ fontSize: 12 }}>{r.confidence.toFixed(2)}</td>
                <td>
                  {r.source_url
                    ? <a href={r.source_url} target="_blank" rel="noreferrer" style={{ fontSize: 11.5 }}>source</a>
                    : <span className="t-muted" style={{ fontSize: 11.5 }} title="This rule cites nothing.">uncited</span>}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <span style={{ marginRight: 6 }}>
                    <AcceptUpdateButton row={r} label={r.pattern} pending={accept.isPending} onAccept={() => accept.mutate(r.id)} />
                  </span>
                  <button
                    className="op-btn sm" type="button" aria-label={`Edit ${r.pattern}`}
                    onClick={() => { create.reset(); update.reset(); setEditing(r); }}
                  >
                    <Pencil size={12} />
                  </button>
                  <button
                    className="op-btn sm" type="button" aria-label={`Delete ${r.pattern}`}
                    style={{ marginLeft: 6 }}
                    onClick={() => setConfirmDelete(r)}
                  >
                    <Trash2 size={12} />
                  </button>
                </td>
              </tr>
            ))}
            {isLoading && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading the classification rules…</td></tr>
            )}
            {isError && !isLoading && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                Couldn't load the classification rules.
                <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                {search || kind
                  ? 'No rules match those filters.'
                  : 'No classification rules. The seeded set is applied by seed.sql — if this is empty, the seed did not run.'}
              </td></tr>
            )}
          </tbody>
        </table>
        {accept.error && (
          <div style={{ fontSize: 12, color: 'var(--danger)', padding: '8px 16px' }} data-testid="accept-error">
            {errMsg(accept.error, 'Failed to accept the update')}
          </div>
        )}

        {!isLoading && !isError && total > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderTop: '1px solid var(--op-border)' }}>
            <span className="t-muted" style={{ fontSize: 12 }}>Page {data?.page ?? page} of {num(lastPage)}</span>
            <div style={{ flex: 1 }} />
            <button className="op-btn sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</button>
            <button className="op-btn sm" disabled={page >= lastPage} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        )}
      </div>

      {confirmDelete && (
        <div className="op-panel" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }} data-testid="confirm-delete">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <strong style={{ fontSize: 13, color: 'var(--op-t1)' }}>
              Delete the {RULE_KIND_LABEL[confirmDelete.rule_kind] ?? confirmDelete.rule_kind} rule
              <span className="mono"> {confirmDelete.pattern}</span>?
            </strong>
            <div style={{ flex: 1 }} />
            <button className="op-btn sm" type="button" aria-label="Cancel delete" onClick={() => setConfirmDelete(null)}>
              <X size={12} />
            </button>
          </div>
          {/* Two things worth knowing before clicking: existing proposals keep
              their evidence, and deleting a shipped rule is remembered — upgrades
              no longer put it back (decision 4, RC-12). */}
          <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6 }} data-testid="delete-consequences">
            Class proposals already made from this rule keep their copy of it, so past
            decisions stay reviewable. Deleting a rule that ships with Vista is remembered:
            upgrades will not put it back.
          </div>
          {remove.error && (
            <div style={{ fontSize: 12, color: 'var(--danger)' }} data-testid="delete-error">
              {errMsg(remove.error, 'Failed to delete the rule')}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="op-btn sm primary" type="button" disabled={remove.isPending}
              onClick={() => remove.mutate(confirmDelete.id, { onSuccess: () => setConfirmDelete(null) })}
            >
              {remove.isPending ? 'Deleting…' : 'Delete rule'}
            </button>
            <button className="op-btn sm" type="button" onClick={() => setConfirmDelete(null)}>Keep it</button>
          </div>
        </div>
      )}

      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6 }} data-testid="rules-footnote">
        Seeded from <span className="mono">standards/classification-rules.yaml</span> and curated here.
        Rules marked <strong>Vista</strong> ship with the platform. Your edits to them survive upgrades,
        and when a later release changes a rule you edited, it shows <strong>Update available</strong> instead
        of overwriting your version.
        Every rule produces a class <em>proposal</em> that goes through Approvals in the tenant&rsquo;s
        own queue — nothing on this page classifies anything on its own. When two rules disagree about the class at similar confidence,
        the classifier proposes <strong>no</strong> class and reports both, which is the intended outcome
        rather than a failure to handle.
      </div>
      {/* The refresh window, said plainly. "It is live" with no idea of WHEN
          leaves an admin who re-runs a discovery thirty seconds later wondering
          why nothing moved — the same complaint the old "not live yet" notice
          existed to answer, one step along. */}
      <div
        data-testid="rules-are-live-notice"
        style={{
          fontSize: 11.5, lineHeight: 1.6, padding: '10px 12px',
          border: '1px solid var(--op-border2)', borderRadius: 'var(--r-sm)',
          background: 'var(--op-panel2)', color: 'var(--op-t2)',
        }}
      >
        <strong>Rules added or edited here are live within about five minutes.</strong> The
        services reload this table on an interval (<span className="mono">CLASSIFICATION_RULES_REFRESH</span>,
        default <span className="mono">5m</span>), so a new rule applies to the next discovery after
        that. A rule that fails validation is skipped and logged by name — the rest of the table
        keeps working. Existing assets are never reclassified in place: a rule that disagrees with an
        asset&rsquo;s current class raises a proposal in the tenant&rsquo;s Approvals queue.
      </div>
    </div>
  );
}
