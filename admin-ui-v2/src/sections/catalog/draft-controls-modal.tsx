// Catalog → Frameworks → "Draft from a standard…".
//
// ADR-0008 D1's Author seam, on the platform-admin plane. Paste a standard,
// get UNPUBLISHED control drafts each cited back to the passage it came from,
// accept the good ones one at a time. Accepting calls the ordinary
// create-control endpoint — the same one the hand-authoring form calls — with
// `source_kind: inferred`, so the control list shows where it came from and
// publishing the framework is still the approval step.
//
// The review logic (state machine, citation highlighting, accept sequence) is
// shared with frontend-v2's copy of this in
// @vistasecurity/primitives/authoring; what lives here is the chrome and the
// admin endpoints.
import { useMemo, useReducer, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Check, Loader2, Sparkles, X } from 'lucide-react';
import {
  acceptDraft,
  acceptSummary,
  citedSegments,
  dropReasonLabel,
  initialReviewState,
  measurementSummary,
  pendingCount,
  reviewReducer,
  type AcceptDeps,
  type ControlDraft,
  type DraftControlsResponse,
  type DraftItem,
} from '@vistasecurity/primitives/authoring';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import { Tag } from '../../components/ui/primitives';

type MeasurementType = complianceEngineComponents['schemas']['MeasurementType'];

/** The compliance API client, as this module uses it. */
type ComplianceClient = typeof clients.compliance;

/**
 * Whether the platform plane can draft at all.
 *
 * Asked before the button is rendered, not after it is clicked. A Core build
 * has no drafting endpoint and answers `{available:false,reason:"edition"}`; an
 * Enterprise build with no `AI_PROVIDER` answers `no_provider`. Either way the
 * action is not offered, because a button that always errors is worse than no
 * button.
 */
export function useDraftingAvailability() {
  return useQuery({
    queryKey: ['platform', 'author-availability'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/admin/frameworks/draft-controls/availability', {});
      if (error || !data) throw new Error('availability unavailable');
      return data;
    },
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

function useMeasurementTypes(enabled: boolean) {
  return useQuery({
    queryKey: ['platform', 'measurement-types'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/measurement-types', {});
      if (error || !data) throw new Error('Failed to load measurement types');
      return data.measurement_types ?? [];
    },
    staleTime: 10 * 60 * 1000,
  });
}

function errMsg(e: unknown, fallback: string): string {
  return e instanceof Error && e.message ? e.message : fallback;
}

/**
 * The two calls that turn an accepted draft into rows, bound to the PLATFORM
 * endpoints.
 *
 * Exported and taking its client as an argument so the accept flow can be
 * tested without a browser: the sequence and the partial-failure rules live in
 * @vistasecurity/primitives/authoring, and this is the half that says which
 * routes they run against. Both are worth pinning — an accept that posted to
 * the tenant routes would fail confusingly, and one that dropped source_kind
 * would create controls indistinguishable from hand-written ones.
 */
export function buildAcceptDeps(
  compliance: ComplianceClient,
  frameworkId: string,
  typeIdByCode: Map<string, string>,
): AcceptDeps {
  return {
    createControl: async (body) => {
      const { data, error } = await compliance.POST('/admin/frameworks/{id}/controls', {
        params: { path: { id: frameworkId } },
        body,
      });
      if (error || !data?.control?.id) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Create control failed');
      }
      return data.control.id;
    },
    addMeasurement: async (controlId, body) => {
      const { error } = await compliance.POST('/admin/controls/{id}/measurements', {
        params: { path: { id: controlId } },
        body,
      });
      if (error) throw new Error((error as { error?: string } | undefined)?.error ?? 'Add rule failed');
    },
    measurementTypeId: (code) => typeIdByCode.get(code),
  };
}

export function DraftControlsModal({
  framework,
  onClose,
}: {
  framework: { id: string; name: string; status?: string };
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [state, dispatch] = useReducer(reviewReducer, initialReviewState);
  const [busy, setBusy] = useState(false);
  const typesQ = useMeasurementTypes(true);

  const typeIdByCode = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of (typesQ.data ?? []) as MeasurementType[]) m.set(t.code, t.id);
    return m;
  }, [typesQ.data]);

  const run = useMutation({
    mutationFn: async (text: string): Promise<DraftControlsResponse> => {
      const { data, error, response } = await clients.compliance.POST('/admin/frameworks/{id}/draft-controls', {
        params: { path: { id: framework.id } },
        body: { text },
      });
      if (error || !data) {
        throw new Error(
          (error as { error?: string } | undefined)?.error ??
            `Drafting failed (HTTP ${response.status}).`,
        );
      }
      return data;
    },
  });

  const deps = buildAcceptDeps(clients.compliance, framework.id, typeIdByCode);

  const doRun = () => {
    dispatch({ type: 'run' });
    run.mutate(state.text, {
      onSuccess: (response) => dispatch({ type: 'succeeded', response }),
      onError: (e) => dispatch({ type: 'failed', message: errMsg(e, 'Drafting failed.') }),
    });
  };

  const accept = async (item: DraftItem, modelId: string) => {
    setBusy(true);
    dispatch({ type: 'accepting', key: item.key });
    try {
      const outcome = await acceptDraft(item.draft, modelId, deps);
      dispatch({ type: 'accepted', key: item.key });
      void qc.invalidateQueries({ queryKey: ['platform', 'admin-frameworks'] });
      if (outcome.ruleErrors.length) toast(acceptSummary(outcome), { icon: '⚠️' });
      else toast.success(acceptSummary(outcome));
    } catch (e) {
      const message = errMsg(e, 'Could not add the control.');
      dispatch({ type: 'acceptFailed', key: item.key, message });
      toast.error(message);
    } finally {
      setBusy(false);
    }
  };

  const left = pendingCount(state);
  const canRun = state.text.trim().length > 0 && state.phase !== 'running';

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={`Draft controls — ${framework.name}`}
      description={
        state.phase === 'review'
          ? 'Every draft is unpublished and cites the passage it came from. Accept the ones you want; publishing the framework is still a separate step.'
          : 'Paste the text of a standard, or one section of it. Nothing is saved until you accept a draft.'
      }
      footerNote={state.phase === 'review' ? `Drafted by ${state.modelId} · platform-admin · audited` : 'Platform-admin · audited'}
      primaryLabel={state.phase === 'review' ? undefined : 'Draft controls'}
      onPrimary={state.phase === 'review' ? undefined : doRun}
      primaryLoading={state.phase === 'running'}
      primaryDisabled={!canRun}
    >
      {state.phase === 'idle' || state.phase === 'running' || state.phase === 'error' ? (
        <>
          <ModalField label="The standard">
            <textarea
              value={state.text}
              onChange={(e) => dispatch({ type: 'edit', text: e.target.value })}
              disabled={state.phase === 'running'}
              rows={14}
              placeholder={'e.g.\n4.2.1 Strong cryptography and security protocols are implemented…\n4.2.2 Certificates used for PAN transmission are confirmed as valid…'}
              style={{ ...modalInputStyle, height: 'auto', padding: '10px 12px', resize: 'vertical', fontFamily: 'var(--font-mono, monospace)', fontSize: 12 }}
            />
          </ModalField>
          <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
            The text is redacted before it is sent to the model, and the call is recorded in the audit log. Up to 64 KB —
            draft one section at a time for a long standard.
          </div>
          {state.phase === 'running' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t2)' }}>
              <Loader2 size={14} className="spin" /> Reading the text and drafting controls…
            </div>
          )}
          {state.phase === 'error' && (
            <div style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid var(--danger)', color: 'var(--danger-text)', fontSize: 12.5 }}>
              {state.message}
            </div>
          )}
          {typesQ.isError && (
            <div style={{ fontSize: 12, color: 'var(--danger-text)' }}>
              Couldn&apos;t load the measurement catalogue — a draft&apos;s rules can be reviewed but not accepted.
            </div>
          )}
        </>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--op-t2)' }}>
            <Sparkles size={14} style={{ color: 'var(--info)' }} />
            <span>
              {state.items.length === 0
                ? 'The model drafted no controls from this text.'
                : `${state.items.length} draft${state.items.length === 1 ? '' : 's'}, ${left} left to review.`}
            </span>
            <div style={{ flex: 1 }} />
            <button className="op-btn sm ghost" onClick={() => dispatch({ type: 'reset' })} disabled={busy}>
              Start over
            </button>
          </div>

          {state.truncated && (
            <div style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid var(--warn)', fontSize: 12, color: 'var(--op-t2)' }}>
              The model hit its output limit, so this is a partial reading of the text. Draft the remaining sections separately.
            </div>
          )}
          {state.notes.map((n, i) => (
            <div key={i} style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>{n}</div>
          ))}

          {state.items.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--op-t3)', padding: '8px 0' }}>
              Nothing survived review. That is not the same as the text containing no requirements — see what was discarded
              below, then try a different section.
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {state.items.map((item) => (
              <DraftCard
                key={item.key}
                item={item}
                source={state.text}
                busy={busy}
                onAccept={() => { void accept(item, state.modelId); }}
                onDiscard={() => dispatch({ type: 'discarded', key: item.key })}
              />
            ))}
          </div>

          {state.dropped.length > 0 && (
            <details style={{ marginTop: 4 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--op-t3)' }}>
                {state.dropped.length} discarded before review
              </summary>
              <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 11.5, color: 'var(--op-t3)' }}>
                {state.dropped.map((d, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    {d.subject ? <strong>{d.subject}</strong> : null} {dropReasonLabel(d.reason)}
                    {d.detail ? <span style={{ opacity: 0.8 }}> {d.detail}</span> : null}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </Modal>
  );
}

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'var(--danger)',
  High: 'var(--warn-strong)',
  Med: 'var(--warn)',
  Low: 'var(--ok-lime)',
};

function DraftCard({
  item,
  source,
  busy,
  onAccept,
  onDiscard,
}: {
  item: DraftItem;
  source: string;
  busy: boolean;
  onAccept: () => void;
  onDiscard: () => void;
}) {
  const draft: ControlDraft = item.draft;
  const decided = item.status === 'accepted' || item.status === 'discarded';
  const segments = citedSegments(source, draft.citations);

  return (
    <div
      style={{
        border: '1px solid var(--op-border)',
        borderRadius: 10,
        background: 'var(--op-panel2)',
        padding: 12,
        opacity: item.status === 'discarded' ? 0.55 : 1,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {draft.control_id && <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--op-t2)' }}>{draft.control_id}</span>}
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--op-t1)' }}>{draft.title}</span>
        {draft.severity && (
          <span style={{ fontSize: 11, fontWeight: 600, color: SEVERITY_COLOR[draft.severity] ?? 'var(--op-t3)' }}>{draft.severity}</span>
        )}
        <Tag color="var(--info)">unpublished</Tag>
      </div>

      {draft.description && (
        <div style={{ fontSize: 12, color: 'var(--op-t2)', marginTop: 6 }}>{draft.description}</div>
      )}

      {/* The cited passage, highlighted in the pasted text. This is the whole
          point of the feature: a reviewer checks the draft against the sentence
          it came from without leaving the modal. */}
      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--op-t3)', marginBottom: 4 }}>
          Cited from your text
        </div>
        <div
          className="mono"
          style={{ fontSize: 11.5, lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: 140, overflowY: 'auto', padding: '8px 10px', borderRadius: 6, background: 'var(--op-panel)', border: '1px solid var(--op-border)' }}
        >
          {segments.map((seg, i) =>
            seg.cited ? (
              <mark key={i} style={{ background: 'color-mix(in srgb, var(--info) 24%, transparent)', color: 'var(--op-t1)', padding: '1px 0' }}>
                {seg.text}
              </mark>
            ) : (
              <span key={i} style={{ color: 'var(--op-t3)' }}>{seg.text}</span>
            ),
          )}
        </div>
      </div>

      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--op-t3)', marginBottom: 4 }}>
          Measurement rules
        </div>
        {(draft.measurements ?? []).length === 0 ? (
          <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>
            None. This control will evaluate to &quot;not assessed&quot; — not to a pass — until you add one.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {(draft.measurements ?? []).map((m, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Tag color="var(--info)">{m.rule_type}</Tag>
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--op-t1)' }}>{measurementSummary(m)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {(draft.notes ?? []).length > 0 && (
        <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 11.5, color: 'var(--op-t3)' }}>
          {(draft.notes ?? []).map((n, i) => <li key={i}>{n}</li>)}
        </ul>
      )}

      {item.status === 'failed' && item.error && (
        <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--danger-text)' }}>{item.error}</div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10 }}>
        <div style={{ flex: 1 }} />
        {item.status === 'accepted' ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--ok)' }}>
            <Check size={13} /> Added, unpublished
          </span>
        ) : item.status === 'discarded' ? (
          <span style={{ fontSize: 12, color: 'var(--op-t3)' }}>Discarded</span>
        ) : (
          <>
            <button className="op-btn sm ghost" onClick={onDiscard} disabled={busy || decided}>
              <X size={13} /> Discard
            </button>
            <button className="op-btn sm" onClick={onAccept} disabled={busy || decided || item.status === 'accepting'}>
              {item.status === 'accepting' ? <Loader2 size={13} className="spin" /> : <Check size={13} />}
              {item.status === 'failed' ? 'Retry' : 'Accept'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
