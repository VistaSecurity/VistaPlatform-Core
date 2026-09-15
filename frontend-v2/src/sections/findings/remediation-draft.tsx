// Findings inspector → Remediation.
//
// Two things, and the order between them is the product's whole claim:
//
//  1. The GUIDANCE for the finding's kind, from the generated findings registry
//     (@vistasecurity/primitives/findings). It renders in every edition, with no
//     model anywhere near it, and it is there whether or not this deployment has
//     AI configured. ADR-0008's "AI-native, never AI-dependent" is this block.
//  2. "Draft a remediation plan", shown ONLY when the remediator seam is live for
//     this tenant. It turns the guidance above into numbered steps for the thing
//     the finding is actually about, each citing the evidence it relies on.
//
// A Core reader sees (1) and nothing else — not a disabled button, not an upgrade
// card on a drawer they opened to triage a finding. The capability is explained
// on Settings → AI assistant, which is the page whose job that is.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { FINDING_KINDS } from '@vistasecurity/primitives/findings';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { useNavigate } from 'react-router';
import { clients } from '../../lib/clients';
import { SEAM_REMEDIATOR, useSeamAvailability } from '../../lib/ai-seams';
import { Icon } from '../../components/ui';
import type { ComplianceFinding } from './model';

type PlanDraft = complianceEngineComponents['schemas']['RemediationPlanDraft'];
type PlanStep = complianceEngineComponents['schemas']['RemediationPlanStep'];

/**
 * The registry guidance for a finding's kind.
 *
 * Resolved CLIENT-SIDE from the generated registry rather than carried on the
 * finding row, because it is a property of the kind and not of the row: 21
 * sentences, the same for every finding of that kind, and a per-row copy would
 * ship the same paragraph a thousand times and then drift from the YAML.
 *
 * Exported for the test, which drives every kind the API can return.
 */
export function guidanceFor(producer?: string, kind?: string): string | undefined {
  if (!producer || !kind) return undefined;
  return FINDING_KINDS.find((k) => k.producer === producer && k.key === kind)?.guidance;
}

/**
 * The copy for each way the capability can be unavailable.
 *
 * `undefined` means SHOW NOTHING, and three of the five are that. A drawer
 * opened to triage a finding is not the place to sell an upgrade, explain
 * someone else's configuration, or apologise for something nobody has built —
 * and a reader who wants to know why has Settings → AI assistant, which says all
 * of it in one place. The one that speaks is `disabled`, because that is this
 * organization's own switch and the person reading may be the one who flipped it.
 *
 * Exported so the test can assert the silences as well as the sentence: "shows
 * nothing" is a decision, and a decision nothing pins is one a later edit
 * reverses by accident.
 */
export const UNAVAILABLE_COPY: Record<string, string | undefined> = {
  edition: undefined,
  no_provider: undefined,
  not_built: undefined,
  unknown: undefined,
  disabled:
    'Your organization has the AI assistant switched off, so plans are not drafted. A tenant administrator can turn it back on in Settings → AI assistant.',
};

/** The sentence for a plan that came back as guidance rather than as steps. */
export const DEGRADED_COPY: Record<string, string> = {
  no_cited_steps:
    'The model could not cite anything it was shown, so nothing it wrote is checkable — showing the standard guidance instead.',
  unreadable:
    'The model answered with something that could not be read as a plan — showing the standard guidance instead.',
  refused: 'The model declined to answer for this finding — showing the standard guidance instead.',
  provider_error:
    'The model provider could not be reached — showing the standard guidance instead. Try again shortly.',
  no_provider:
    'This deployment has no model provider configured — showing the standard guidance instead.',
};

export function degradedMessage(reason?: string): string {
  const known = reason ? DEGRADED_COPY[reason] : undefined;
  // A reason this UI has no sentence for still gets an honest one. The set is
  // closed on the backend, so an unknown value means the two have drifted —
  // which is a thing to notice, not a blank panel.
  return known ?? 'No plan was drafted — showing the standard guidance instead.';
}

const box: React.CSSProperties = {
  border: '1px solid var(--app-border)',
  borderRadius: 9,
  background: 'var(--app-panel2)',
  padding: 10,
};

export function RemediationSection({ finding }: { finding: ComplianceFinding }) {
  const guidance = guidanceFor(finding.producer, finding.kind);
  const seam = useSeamAvailability(SEAM_REMEDIATOR);

  return (
    <div style={{ padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 8, borderBottom: '1px solid var(--app-border)' }}>
      <div className="eyebrow-app" style={{ marginBottom: 2 }}>Remediation</div>

      {guidance ? (
        <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>{guidance}</p>
      ) : (
        // A kind with no registry guidance is a gap in the registry, not a
        // capability a reader lacks. Say so plainly rather than showing a blank
        // where a paragraph belongs.
        <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--app-t3)' }}>
          There is no standard guidance recorded for this kind of finding yet.
        </p>
      )}

      {/* Nothing at all while the availability answer is in flight. Rendering
          "unavailable" before we have looked is the shape this area is written
          against. */}
      {!seam.loading && (seam.available
        ? <DraftControl finding={finding} />
        : UNAVAILABLE_COPY[seam.reason ?? 'unknown']
          ? (
            <p style={{ margin: '2px 0 0', fontSize: 11.5, lineHeight: 1.5, color: 'var(--app-t3)' }}>
              {UNAVAILABLE_COPY[seam.reason ?? 'unknown']}
            </p>
          )
          : null)}
    </div>
  );
}

function DraftControl({ finding }: { finding: ComplianceFinding }) {
  const [draft, setDraft] = useState<PlanDraft | null>(null);

  const drafting = useMutation({
    mutationFn: async (): Promise<PlanDraft> => {
      const { data, error, response } = await clients.compliance.POST(
        '/findings/{id}/remediation/draft',
        { params: { path: { id: finding.id } } },
      );
      if (!response.ok || error || !data) {
        // 402 / 503 / 403 all arrive here. The button is only rendered when the
        // seam is live, so these are the races — a provider that went away, a
        // switch flipped in another tab — and the honest thing is to say the
        // draft did not happen, not to invent a reason.
        throw new Error(
          response.status === 403
            ? 'Your organization has turned the AI assistant off.'
            : 'No plan could be drafted just now — the guidance above is unchanged.',
        );
      }
      return data.plan;
    },
    onSuccess: setDraft,
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Drafting failed'),
  });

  return (
    <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
      <button
        className="ui-btn sm"
        style={{ justifyContent: 'center', marginTop: 2 }}
        disabled={drafting.isPending}
        onClick={() => drafting.mutate()}
      >
        <Icon name={drafting.isPending ? 'loader' : 'sparkles'} size={13} />
        {drafting.isPending ? 'Drafting…' : draft ? 'Draft again' : 'Draft a remediation plan'}
      </button>

      {draft && <DraftPanel finding={finding} draft={draft} onDismiss={() => setDraft(null)} />}
    </PermissionGate>
  );
}

function DraftPanel({ finding, draft, onDismiss }: { finding: ComplianceFinding; draft: PlanDraft; onDismiss: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [title, setTitle] = useState(`Remediate: ${finding.summary?.slice(0, 60) ?? 'finding'}`);

  const accept = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.compliance.POST(
        '/findings/{id}/remediation/accept',
        {
          params: { path: { id: finding.id } },
          body: {
            title: title.trim(),
            model_id: draft.model_id,
            source: 'model',
            summary: draft.summary,
            steps: (draft.steps ?? []).map((s) => ({
              action: s.action,
              rationale: s.rationale,
              manual: s.manual,
            })),
          },
        },
      );
      if (!response.ok || error || !data) {
        throw new Error(response.status === 409
          ? 'This finding is already in that plan.'
          : 'The plan could not be saved — try again.');
      }
      return data;
    },
    onSuccess: () => {
      toast.success('Saved as a remediation plan');
      void qc.invalidateQueries({ queryKey: ['remediation'] });
      // The reachability half: the accepted plan has somewhere to BE, and the
      // user is taken to it rather than left looking at the drawer they came
      // from wondering whether anything happened.
      void navigate('/remediation/plans');
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not save the plan'),
  });

  const steps = draft.steps ?? [];

  // A guidance plan: the model did not answer, and the panel says which of the
  // five reasons it was rather than showing an empty list of steps — which would
  // assert that this finding needs nothing done about it.
  if (draft.source === 'guidance' || steps.length === 0) {
    return (
      <div style={{ ...box, marginTop: 8, animation: 'fadeUp .15s ease both' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
          <Icon name="info" size={14} style={{ color: 'var(--app-t3)', flex: 'none', marginTop: 1 }} />
          <p style={{ margin: 0, fontSize: 11.5, lineHeight: 1.55, color: 'var(--app-t2)' }}>
            {degradedMessage(draft.reason)}
          </p>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
          <button className="ui-btn sm" onClick={onDismiss}>Dismiss</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ ...box, marginTop: 8, animation: 'fadeUp .15s ease both' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 7 }}>
        <span className="eyebrow-app" style={{ margin: 0 }}>Drafted plan</span>
        <span className="mono" style={{ fontSize: 10, color: 'var(--app-t3)' }}>{draft.model_id}</span>
        {draft.truncated && (
          <span style={{ fontSize: 10.5, color: 'var(--warn-strong)' }}>partial — the model hit its limit</span>
        )}
      </div>

      {draft.summary && (
        <p style={{ margin: '0 0 8px', fontSize: 12, lineHeight: 1.5, color: 'var(--app-t2)' }}>{draft.summary}</p>
      )}

      <ol style={{ margin: 0, padding: '0 0 0 18px', display: 'flex', flexDirection: 'column', gap: 7 }}>
        {steps.map((s, i) => <StepRow key={i} step={s} />)}
      </ol>

      {typeof draft.dropped === 'number' && draft.dropped > 0 && (
        // Reported, never hidden. A reader deciding how hard to read the rest
        // needs to know that some of what the model wrote had nothing behind it.
        <p style={{ margin: '8px 0 0', fontSize: 11, color: 'var(--app-t3)' }}>
          {draft.dropped} further step{draft.dropped === 1 ? '' : 's'} {draft.dropped === 1 ? 'was' : 'were'} discarded for
          citing nothing this finding measured.
        </p>
      )}

      <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Plan title…"
          style={{ flex: 1, height: 28, padding: '0 10px', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', color: 'var(--app-t1)', fontSize: 12, outline: 'none' }}
        />
        <button className="ui-btn sm" onClick={onDismiss} disabled={accept.isPending}>Discard</button>
        <button
          className="ui-btn sm accent"
          disabled={!title.trim() || accept.isPending}
          onClick={() => accept.mutate()}
        >
          {accept.isPending ? 'Saving…' : 'Accept as plan'}
        </button>
      </div>

      <p style={{ margin: '8px 0 0', fontSize: 10.5, lineHeight: 1.5, color: 'var(--app-t3)' }}>
        Nothing here has been done. Accepting adds this finding to a plan with these steps as its
        notes, recorded as AI-drafted and accepted by you.
      </p>
    </div>
  );
}

function StepRow({ step }: { step: PlanStep }) {
  return (
    <li style={{ fontSize: 12, lineHeight: 1.55, color: 'var(--app-t1)' }}>
      <span>{step.action}</span>
      {step.manual && (
        <span
          className="chip"
          style={{ marginLeft: 6, fontSize: 9.5, padding: '1px 5px', color: 'var(--warn-strong)', verticalAlign: 'middle' }}
          title="The platform will not do this for you — a person carries it out."
        >
          Manual step
        </span>
      )}
      {step.rationale && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>{step.rationale}</div>
      )}
      {step.citations && step.citations.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 3 }}>
          {step.citations.map((c, i) => (
            <span
              key={i}
              className="chip mono"
              style={{ fontSize: 9.5, padding: '1px 5px', color: 'var(--app-t3)' }}
              title={c.kind === 'guidance' ? 'From the standard guidance above' : 'From this finding’s evidence'}
            >
              {c.kind === 'guidance' ? 'guidance' : c.ref}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}
