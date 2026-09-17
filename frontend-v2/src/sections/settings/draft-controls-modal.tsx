// Settings → Policies → Custom Policies → "Draft from a standard…".
//
// ADR-0008 D1's Author seam, on the tenant plane. Paste a standard, get
// UNPUBLISHED control drafts each cited back to the passage it came from,
// accept the good ones one at a time. Accepting calls the ordinary
// create-control endpoint — the same one the authoring form calls — with
// `source_kind: inferred`, so the control list says where it came from.
//
// The review logic (state machine, citation highlighting, accept sequence) is
// shared with admin-ui-v2's copy of this in
// @vistasecurity/primitives/authoring; what lives here is the chrome and the
// tenant endpoints.
import { severityLabel } from '@vistasecurity/primitives/ratings';
import { useMemo, useReducer, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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
import { Icon, Modal, ModalField } from '../../components/ui';
import { STag } from './kit';

type MeasurementType = complianceEngineComponents['schemas']['MeasurementType'];

/** The compliance API client, as this module uses it. */
type ComplianceClient = typeof clients.compliance;

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)',
  high: 'var(--warn-strong)',
  medium: 'var(--warn)',
  low: 'var(--ok-lime)',
};

/**
 * Whether this deployment can draft at all.
 *
 * Asked before the button is rendered, not after it is clicked. A Core build
 * has no drafting endpoint and answers `{available:false,reason:"edition"}`; an
 * Enterprise build with no `AI_PROVIDER` answers `no_provider`. Either way the
 * action is not offered — a button that always errors is worse than no button.
 *
 * `retry: false` because the answer does not change between two clicks: it is a
 * property of the deployment, and retrying a 404 on a Core build three times
 * would put three lines in the console for the same known answer.
 */
export function useDraftingAvailability(enabled: boolean) {
  return useQuery({
    queryKey: ['settings', 'author-availability'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/custom-policies/draft-controls/availability', {});
      if (error || !data) throw new Error('availability unavailable');
      return data;
    },
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

function errMsg(e: unknown, fallback: string): string {
  return e instanceof Error && e.message ? e.message : fallback;
}

/**
 * The two calls that turn an accepted draft into rows, bound to the TENANT
 * endpoints.
 *
 * Exported and taking its client as an argument so the accept flow can be
 * tested without a browser. The sequence and the partial-failure rules live in
 * @vistasecurity/primitives/authoring; this is the half that says which routes
 * they run against.
 */
export function buildAcceptDeps(
  compliance: ComplianceClient,
  policyId: string,
  typeIdByCode: Map<string, string>,
): AcceptDeps {
  return {
    createControl: async (body) => {
      const { data, error } = await compliance.POST('/frameworks/tenant/{id}/controls', {
        params: { path: { id: policyId } },
        body,
      });
      if (error || !data?.control?.id) {
        throw new Error((error as { error?: string } | undefined)?.error ?? 'Could not add the control');
      }
      return data.control.id;
    },
    addMeasurement: async (controlId, body) => {
      const { error } = await compliance.POST('/frameworks/tenant/controls/{id}/measurements', {
        params: { path: { id: controlId } },
        body,
      });
      if (error) throw new Error((error as { error?: string } | undefined)?.error ?? 'Could not add the rule');
    },
    measurementTypeId: (code) => typeIdByCode.get(code),
  };
}

export function DraftControlsModal({
  policy,
  onClose,
}: {
  policy: { id: string; name: string };
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [state, dispatch] = useReducer(reviewReducer, initialReviewState);
  const [busy, setBusy] = useState(false);

  const typesQ = useQuery({
    queryKey: ['measurement-types'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/measurement-types', {});
      if (error || !data) throw new Error('Failed to load measurement types');
      return data.measurement_types ?? [];
    },
    staleTime: 10 * 60 * 1000,
  });

  const typeIdByCode = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of (typesQ.data ?? []) as MeasurementType[]) m.set(t.code, t.id);
    return m;
  }, [typesQ.data]);

  const run = useMutation({
    mutationFn: async (text: string): Promise<DraftControlsResponse> => {
      const { data, error, response } = await clients.compliance.POST('/custom-policies/{id}/draft-controls', {
        params: { path: { id: policy.id } },
        body: { text },
      });
      if (error || !data) {
        throw new Error((error as { error?: string } | undefined)?.error ?? `Drafting failed (HTTP ${response.status}).`);
      }
      return data;
    },
  });

  const deps = buildAcceptDeps(clients.compliance, policy.id, typeIdByCode);

  const doRun = () => {
    dispatch({ type: 'run' });
    run.mutate(state.text, {
      onSuccess: (response) => dispatch({ type: 'succeeded', response }),
      onError: (e) => dispatch({ type: 'failed', message: errMsg(e, 'Drafting failed.') }),
    });
  };

  const [toast, setToast] = useState<string | null>(null);

  const accept = async (item: DraftItem, modelId: string) => {
    setBusy(true);
    dispatch({ type: 'accepting', key: item.key });
    try {
      const outcome = await acceptDraft(item.draft, modelId, deps);
      dispatch({ type: 'accepted', key: item.key });
      void qc.invalidateQueries({ queryKey: ['custom-policy', policy.id] });
      void qc.invalidateQueries({ queryKey: ['settings', 'tenant-frameworks'] });
      setToast(acceptSummary(outcome));
    } catch (e) {
      const message = errMsg(e, 'Could not add the control.');
      dispatch({ type: 'acceptFailed', key: item.key, message });
      setToast(message);
    } finally {
      setBusy(false);
    }
  };

  const left = pendingCount(state);
  const canRun = state.text.trim().length > 0 && state.phase !== 'running';
  const composing = state.phase === 'idle' || state.phase === 'running' || state.phase === 'error';

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      icon="sparkles"
      eyebrow="Custom policy"
      title={`Draft controls — ${policy.name}`}
      description={
        composing
          ? 'Paste the text of a standard, or one section of it. Nothing is saved until you accept a draft.'
          : 'Every draft is unpublished and cites the passage it came from. Accept the ones you want.'
      }
      footerNote={state.phase === 'review' ? `Drafted by ${state.modelId} · you review every draft` : (toast ?? 'Enterprise feature')}
      primary={
        composing ? (
          <button className="ui-btn sm accent" disabled={!canRun} onClick={doRun}>
            {state.phase === 'running' ? 'Drafting…' : 'Draft controls'}
          </button>
        ) : (
          <button className="ui-btn sm accent" onClick={onClose}>Done</button>
        )
      }
      secondary={
        composing ? (
          <button className="ui-btn sm" onClick={onClose}>Cancel</button>
        ) : (
          <button className="ui-btn sm" disabled={busy} onClick={() => dispatch({ type: 'reset' })}>Start over</button>
        )
      }
    >
      {composing ? (
        <>
          <ModalField label="The standard" hint="The text is redacted before it is sent to the model, and the call is recorded in your audit log. Up to 64 KB — draft one section at a time for a long standard.">
            <textarea
              value={state.text}
              onChange={(e) => dispatch({ type: 'edit', text: e.target.value })}
              disabled={state.phase === 'running'}
              rows={14}
              placeholder={'e.g.\n4.2.1 Strong cryptography and security protocols are implemented…\n4.2.2 Certificates are confirmed as valid and not expired…'}
              style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, fontFamily: 'var(--font-mono, monospace)', outline: 'none', resize: 'vertical' }}
            />
          </ModalField>
          {state.phase === 'running' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--app-t2)' }}>
              <Icon name="loader" size={14} /> Reading the text and drafting controls…
            </div>
          )}
          {state.phase === 'error' && (
            <div style={{ padding: '10px 12px', borderRadius: 9, border: '1px solid var(--danger)', color: 'var(--danger-text)', fontSize: 12.5 }}>
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--app-t2)', marginBottom: 12 }}>
            <Icon name="sparkles" size={14} style={{ color: 'var(--accent)' }} />
            <span>
              {state.items.length === 0
                ? 'The model drafted no controls from this text.'
                : `${state.items.length} draft${state.items.length === 1 ? '' : 's'}, ${left} left to review.`}
            </span>
          </div>

          {state.truncated && (
            <div style={{ padding: '8px 10px', borderRadius: 9, border: '1px solid var(--warn)', fontSize: 12, color: 'var(--app-t2)', marginBottom: 10 }}>
              The model hit its output limit, so this is a partial reading of the text. Draft the remaining sections separately.
            </div>
          )}
          {state.notes.map((n, i) => (
            <div key={i} style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 6 }}>{n}</div>
          ))}

          {state.items.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--app-t3)', padding: '8px 0' }}>
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
            <details style={{ marginTop: 12 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--app-t3)' }}>
                {state.dropped.length} discarded before review
              </summary>
              <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 11.5, color: 'var(--app-t3)' }}>
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
        border: '1px solid var(--app-border)',
        borderRadius: 10,
        background: 'var(--app-panel2)',
        padding: 13,
        opacity: item.status === 'discarded' ? 0.55 : 1,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {draft.control_id && <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--app-t2)' }}>{draft.control_id}</span>}
        <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{draft.title}</span>
        {draft.severity && (
          <span style={{ fontSize: 11, fontWeight: 600, color: SEVERITY_COLOR[draft.severity] ?? 'var(--app-t3)' }}>{severityLabel(draft.severity)}</span>
        )}
        <STag color="var(--info)">unpublished</STag>
      </div>

      {draft.description && <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 6 }}>{draft.description}</div>}

      {/* The cited passage, highlighted in the pasted text. This is the point
          of the feature: check the draft against the sentence it came from
          without leaving the modal. */}
      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--app-t3)', marginBottom: 4 }}>
          Cited from your text
        </div>
        <div
          className="mono"
          style={{ fontSize: 11.5, lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: 140, overflowY: 'auto', padding: '8px 10px', borderRadius: 8, background: 'var(--app-panel)', border: '1px solid var(--app-border)' }}
        >
          {segments.map((seg, i) =>
            seg.cited ? (
              <mark key={i} style={{ background: 'color-mix(in srgb, var(--accent) 22%, transparent)', color: 'var(--app-t1)', padding: '1px 0' }}>
                {seg.text}
              </mark>
            ) : (
              <span key={i} style={{ color: 'var(--app-t3)' }}>{seg.text}</span>
            ),
          )}
        </div>
      </div>

      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--app-t3)', marginBottom: 4 }}>
          Measurement rules
        </div>
        {(draft.measurements ?? []).length === 0 ? (
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            None. This control will evaluate to &quot;not assessed&quot; — not to a pass — until you add one.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {(draft.measurements ?? []).map((m, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <STag color="var(--info)">{m.rule_type}</STag>
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t1)' }}>{measurementSummary(m)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {(draft.notes ?? []).length > 0 && (
        <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 11.5, color: 'var(--app-t3)' }}>
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
            <Icon name="check" size={13} /> Added, unpublished
          </span>
        ) : item.status === 'discarded' ? (
          <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>Discarded</span>
        ) : (
          <>
            <button className="ui-btn sm ghost" onClick={onDiscard} disabled={busy || decided}>Discard</button>
            <button className="ui-btn sm accent" onClick={onAccept} disabled={busy || decided || item.status === 'accepting'}>
              {item.status === 'accepting' ? 'Adding…' : item.status === 'failed' ? 'Retry' : 'Accept'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
