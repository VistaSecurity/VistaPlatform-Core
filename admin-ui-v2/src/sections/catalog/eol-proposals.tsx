// Catalog ▸ End-of-life ▸ Proposals and Gaps.
//
// ADR-0008 D3 made visible: a model's claim about a support date arrives here
// as a PROPOSAL, a platform admin reads it beside the URL it cites, and only an
// accept puts it in `eol_catalogue` — where it stays marked `AI-proposed`
// forever.
//
// Two views, both mounted in every edition:
//
//   • Proposals — the review queue. Empty in Core, which is correct: Core has
//     the whole workflow and nothing that fills it.
//   • Gaps      — the subjects the catalogue could not answer for, with counts,
//     plus the lookup that puts one there deliberately. "Propose with AI" is
//     rendered only when the availability endpoint says it would work.
import { useState } from 'react';
import toast from 'react-hot-toast';
import { Check, Loader2, Search, Sparkles, X } from 'lucide-react';
import { Tag, num } from '../../components/ui/primitives';
import {
  useEolProposals, useCatalogMisses, useEnrichAvailability, useReviewProposal,
  useRunEnrichment, useEolLookup, unavailableReason, shortDate, errMsg, PAGE_SIZE,
  type CatalogMiss, type EolProposal, type ProposalStatus, type ProductKind,
} from './catalog-queries';

const STATUSES: { value: ProposalStatus | ''; label: string }[] = [
  { value: 'pending', label: 'Pending review' },
  { value: 'accepted', label: 'Accepted' },
  { value: 'rejected', label: 'Rejected' },
  { value: '', label: 'All' },
];

const STATUS_COLOR: Record<string, string> = {
  pending: 'var(--warn)',
  accepted: 'var(--ok-lime)',
  rejected: 'var(--op-t3)',
};

function Pager({ page, total, pageSize, onPage }: {
  page: number; total: number; pageSize: number; onPage: (p: number) => void;
}) {
  const last = Math.max(1, Math.ceil(total / (pageSize || PAGE_SIZE)));
  if (total === 0) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderTop: '1px solid var(--op-border)' }}>
      <span className="t-muted" style={{ fontSize: 12 }}>Page {page} of {num(last)}</span>
      <div style={{ flex: 1 }} />
      <button className="op-btn sm" disabled={page <= 1} onClick={() => onPage(Math.max(1, page - 1))}>Previous</button>
      <button className="op-btn sm" disabled={page >= last} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}

/**
 * Renders a proposed date, or says the model did not state one.
 *
 * An omitted date is the model obeying "never guess a date" — a legitimate
 * proposal, not a defective one — so it reads "not stated" rather than as a
 * blank cell a reviewer might take for zero.
 */
function ProposedDate({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <span className="t-muted" title="The model did not state this date, and was asked not to guess one.">not stated</span>;
  return <span className="mono" style={{ fontSize: 11 }}>{shortDate(iso)}</span>;
}

function ProposalRow({ p, busy, onReview }: {
  p: EolProposal;
  busy: boolean;
  onReview: (action: 'accept' | 'reject', id: string) => void;
}) {
  const subject = [p.subject_vendor, p.subject_product, p.subject_version].filter(Boolean).join(' ');
  return (
    <tr>
      {/* What was ASKED, beside what came back. A model that answered about a
          different product than the one asked about is exactly what comparing
          these two columns catches, which is why they are not collapsed. */}
      <td style={{ color: 'var(--op-t1)' }}>
        {subject}
        <div className="t-muted" style={{ fontSize: 11 }}>{p.product_kind}</div>
      </td>
      <td className="mono" style={{ fontSize: 12 }}>{p.proposed_cycle}</td>
      <td><ProposedDate iso={p.proposed_release_date} /></td>
      <td><ProposedDate iso={p.proposed_eol_date} /></td>
      <td><ProposedDate iso={p.proposed_extended_support_date} /></td>
      <td>
        {/* The citation, as a link. It is the whole review: the reviewer opens
            the vendor's own page and checks the date before accepting. */}
        <a href={p.source_url} target="_blank" rel="noreferrer" style={{ fontSize: 11 }}>
          {p.source_url}
        </a>
        <div className="t-muted mono" style={{ fontSize: 10.5 }}>{p.model_id}</div>
      </td>
      <td><Tag color={STATUS_COLOR[p.status] ?? 'var(--op-t2)'}>{p.status}</Tag></td>
      <td>
        {p.status === 'pending' ? (
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className="op-btn sm"
              disabled={busy}
              aria-label={`Accept the proposal for ${subject}`}
              onClick={() => onReview('accept', p.id)}
            >
              {busy ? <Loader2 size={12} className="spin" /> : <Check size={12} />} Accept
            </button>
            <button
              className="op-btn ghost sm"
              disabled={busy}
              aria-label={`Reject the proposal for ${subject}`}
              onClick={() => onReview('reject', p.id)}
            >
              <X size={12} /> Reject
            </button>
          </div>
        ) : (
          <span className="t-muted" style={{ fontSize: 11 }}>
            {p.reviewer_email ?? 'reviewed'} · {shortDate(p.reviewed_at)}
          </span>
        )}
      </td>
    </tr>
  );
}

export function EolProposalsTab() {
  const [status, setStatus] = useState<ProposalStatus | ''>('pending');
  const [page, setPage] = useState(1);
  const [busyId, setBusyId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useEolProposals(status, page);
  const accept = useReviewProposal('accept');
  const reject = useReviewProposal('reject');

  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;

  const review = (action: 'accept' | 'reject', id: string) => {
    setBusyId(id);
    const m = action === 'accept' ? accept : reject;
    m.mutate(id, {
      onSuccess: (res) => toast.success(res?.message ?? `Proposal ${action}ed`),
      onError: (e) => toast.error(errMsg(e, `Failed to ${action} the proposal`)),
      onSettled: () => setBusyId(null),
    });
  };

  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
        <Sparkles size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
          AI proposals
        </span>
        {!isLoading && !isError && (
          <span className="t-muted" style={{ fontSize: 12 }} data-testid="proposal-total">{num(total)} proposals</span>
        )}
        <div style={{ flex: 1 }} />
        <select
          value={status}
          aria-label="Filter proposals by review status"
          onChange={(e) => { setStatus(e.target.value as ProposalStatus | ''); setPage(1); }}
          style={{ height: 28, padding: '0 8px', fontSize: 12.5, borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
        >
          {STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
      </div>

      <table className="op-table">
        <thead>
          <tr>
            <th>Asked about</th><th>Proposed cycle</th><th>Released</th>
            <th>Support ends</th><th>Extended</th><th>Cited source</th><th>Status</th><th>Review</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => (
            <ProposalRow key={p.id} p={p} busy={busyId === p.id} onReview={review} />
          ))}
          {isLoading && (
            <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading proposals…</td></tr>
          )}
          {isError && !isLoading && (
            <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
              Couldn't load the proposal queue.
              <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
            </td></tr>
          )}
          {!isLoading && !isError && rows.length === 0 && (
            <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
              {status === 'pending'
                ? 'Nothing is waiting for review. Proposals appear here after a run over the Gaps list.'
                : 'No proposals with that status.'}
            </td></tr>
          )}
        </tbody>
      </table>

      <Pager page={data?.page ?? page} total={total} pageSize={data?.pageSize ?? PAGE_SIZE} onPage={setPage} />

      <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6, padding: '10px 16px', borderTop: '1px solid var(--op-border)' }}>
        Nothing here is in the catalogue yet. Accepting writes one row with
        <span className="mono"> source_kind = inferred</span>, the cited URL and your name on it; rejecting writes nothing
        and keeps the proposal as a record. Open the cited page and check the date before accepting — that check is the
        entire reason this queue exists.
      </div>
    </div>
  );
}

/** The "check a product" box: the Enricher seam with a person driving it. */
function LookupBox() {
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [version, setVersion] = useState('');
  const [kind, setKind] = useState<ProductKind | ''>('');
  const lookup = useEolLookup();

  const submit = () => {
    if (!product.trim()) return;
    lookup.mutate({
      product: product.trim(),
      ...(vendor.trim() ? { vendor: vendor.trim() } : {}),
      ...(version.trim() ? { version: version.trim() } : {}),
      ...(kind ? { product_kind: kind } : {}),
    }, {
      onError: (e) => toast.error(errMsg(e, 'Lookup failed')),
    });
  };

  const input = (value: string, set: (v: string) => void, placeholder: string, label: string, width: number) => (
    <input
      value={value}
      onChange={(e) => set(e.target.value)}
      onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
      placeholder={placeholder}
      aria-label={label}
      // A vendor, a product and a version are short names. The server bounds
      // them too (catalogs.MaxSubjectField) — this is the door that stops a
      // paste ever becoming a gap-list row nobody can read.
      maxLength={200}
      style={{ width, height: 28, padding: '0 9px', fontSize: 12.5, borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
    />
  );

  return (
    <div className="op-panel" style={{ padding: '13px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <Search size={16} style={{ color: 'var(--op-t3)' }} />
        <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
          Check a product
        </span>
        <div style={{ flex: 1 }} />
        {input(vendor, setVendor, 'Vendor (optional)', 'Vendor', 150)}
        {input(product, setProduct, 'Product', 'Product', 170)}
        {input(version, setVersion, 'Version (optional)', 'Version', 130)}
        <select
          value={kind}
          aria-label="Product kind"
          onChange={(e) => setKind(e.target.value as ProductKind | '')}
          style={{ height: 28, padding: '0 8px', fontSize: 12.5, borderRadius: 'var(--r-sm)', border: '1px solid var(--op-border2)', background: 'var(--op-panel2)', color: 'var(--op-t1)' }}
        >
          <option value="">Any kind</option>
          <option value="os">Operating system</option>
          <option value="software">Software</option>
          <option value="hardware">Hardware</option>
        </select>
        <button className="op-btn sm" disabled={!product.trim() || lookup.isPending} onClick={submit}>
          {lookup.isPending ? <Loader2 size={12} className="spin" /> : <Search size={12} />} Look up
        </button>
      </div>

      {lookup.isSuccess && lookup.data && (
        <div style={{ fontSize: 12, color: 'var(--op-t2)' }}>
          {/* Keyed off the FACTS, not off `matched`. A catalogue row can match
              and state nothing (no eol_date, or no source_url to cite), and
              keying off `matched` rendered an empty list — a lookup that
              visibly did nothing. The server's message is the one place the
              four outcomes are spelled out, so it answers whenever there is
              nothing to list. */}
          {lookup.data.facts.length > 0 ? (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {lookup.data.facts.map((f) => (
                <li key={f.key + f.source_ref} style={{ marginBottom: 3 }}>
                  <span className="mono">{f.key}</span> = <span className="mono">{String(f.value)}</span>
                  {' '}
                  {/* Provenance is shown, not implied. A date with no visible
                      source_kind is indistinguishable from one somebody typed. */}
                  <Tag color="var(--op-t2)">{f.source_kind}</Tag>
                  {' '}
                  <a href={f.source_url} target="_blank" rel="noreferrer" style={{ fontSize: 11 }}>source</a>
                  <span className="t-muted mono" style={{ fontSize: 10.5, marginLeft: 6 }}>{f.source_ref}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span>{lookup.data.message}</span>
          )}
        </div>
      )}
    </div>
  );
}

function MissRow({ m }: { m: CatalogMiss }) {
  return (
    <tr>
      <td style={{ color: 'var(--op-t1)' }}>{m.product}</td>
      <td><Tag color="var(--op-t2)">{m.product_kind}</Tag></td>
      <td className="t-muted">
        {m.vendor ?? <span title="Nothing named a vendor when this was asked about.">unknown</span>}
      </td>
      <td className="mono" style={{ fontSize: 12 }}>
        {m.version ?? <span className="t-muted">—</span>}
      </td>
      <td className="num">{num(m.miss_count)}</td>
      <td className="t-muted mono" style={{ fontSize: 11 }}>{shortDate(m.last_seen_at)}</td>
      <td className="t-muted mono" style={{ fontSize: 11 }}>
        {/* Never asked and asked-and-got-nothing are different, so the column
            says "never asked" rather than showing an em dash for both. */}
        {m.last_proposed_at ? shortDate(m.last_proposed_at) : <span title="No proposal run has asked about this gap yet.">never asked</span>}
      </td>
    </tr>
  );
}

export function CatalogGapsTab() {
  const [page, setPage] = useState(1);
  const { data, isLoading, isError, refetch } = useCatalogMisses(page);
  const availability = useEnrichAvailability();
  const run = useRunEnrichment();

  const rows = data?.rows ?? [];
  const total = data?.total ?? 0;
  const canPropose = availability.data?.available === true;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <LookupBox />

      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
            Gaps
          </span>
          {!isLoading && !isError && (
            <span className="t-muted" style={{ fontSize: 12 }} data-testid="gap-total">{num(total)} unanswered subjects</span>
          )}
          <div style={{ flex: 1 }} />
          {/* Rendered only when the deployment says a run would work. A button
              that always 503s is worse than no button — the reasoning #1639
              wrote down for the author seam. */}
          {canPropose && (
            <button
              className="op-btn sm"
              disabled={run.isPending}
              onClick={() => run.mutate(undefined, {
                onSuccess: () => toast.success('Proposal run started. Check the Proposals tab in a few minutes.'),
                onError: (e) => toast.error(errMsg(e, 'Failed to start the proposal run')),
              })}
            >
              {run.isPending ? <Loader2 size={12} className="spin" /> : <Sparkles size={12} />} Propose with AI
            </button>
          )}
        </div>

        <table className="op-table">
          <thead>
            <tr><th>Product</th><th>Kind</th><th>Vendor</th><th>Version</th><th className="num">Times asked</th><th>Last asked</th><th>Last proposed</th></tr>
          </thead>
          <tbody>
            {rows.map((m) => <MissRow key={m.id} m={m} />)}
            {isLoading && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>Loading the gap list…</td></tr>
            )}
            {isError && !isLoading && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                Couldn't load the gap list.
                <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void refetch()}>Retry</button>
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
                No gaps recorded. Every product the catalogue has been asked about, it could answer for.
              </td></tr>
            )}
          </tbody>
        </table>

        <Pager page={data?.page ?? page} total={total} pageSize={data?.pageSize ?? PAGE_SIZE} onPage={setPage} />
      </div>

      {!canPropose && (
        <div className="t-muted" style={{ fontSize: 11.5, lineHeight: 1.6 }} data-testid="propose-unavailable">
          {unavailableReason(availability.data)}
        </div>
      )}
    </div>
  );
}
