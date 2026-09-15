// Settings → AI assistant.
//
// The page is CORE and carries no feature-flag lock: it EXPLAINS the edition
// rather than being gated by it. A Core tenant opening it sees every generative
// capability marked "Enterprise", the rule-based behaviour that answers instead,
// and the two switches they own — which is more useful than an upgrade card, and
// is the honest version of "AI-native, never AI-dependent" (ADR-0008).
//
// One endpoint behind it: GET/PUT /api/v1/auth-service/tenant/ai. The status half
// is the deployment's (provider, edition, which seams can answer); the controls
// half is the tenant's.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { AI_QUERY_KEY, useAIStatus, type AIStatus } from '../../lib/ai-seams';
import { Icon } from '../../components/ui';
import { settingsPageMeta, type SettingsNavItem } from './nav';
import {
  AMBER, GREEN, SCard, SPage, SRow, SSection, STable, STableRow, STag, SToggle, StateNote,
  type STableCol,
} from './kit';

// The sentence the whole page is built around. It is stated once, at the top,
// in the tenant's own words rather than the architecture's — and it is true of
// every row in the table below, which is why the table states a rule default
// per seam rather than leaving the promise abstract.
export const HONEST_LINE = 'Nothing here depends on AI; every capability has a rule-based default.';

// AIStatus and AI_QUERY_KEY moved to ../../lib/ai-seams when the Findings
// inspector became the second consumer of this endpoint. One key, so the two
// surfaces share a cache entry rather than fetching the same answer twice.

// Human labels for the seam keys. Deliberately here rather than on the wire:
// these are UI copy, and a backend that shipped display strings would be a
// second place to change them. The parity test in pages-ai.test.ts asserts every
// key the API can return has one.
export const SEAM_LABELS: Record<string, string> = {
  matcher: 'Asset matching',
  classifier: 'Asset classification',
  drift_detector: 'Drift detection',
  enricher: 'Catalogue enrichment',
  narrator: 'Written summaries',
  query: 'Ask a question',
  author: 'Drafting from a standard',
  remediator: 'Remediation plans',
};

export function seamLabel(key: string): string {
  return SEAM_LABELS[key] ?? key;
}

/** The three states a seam row can be in, in the order a reader cares about. */
export type SeamState = 'live' | 'edition' | 'unconfigured' | 'not-built';

/**
 * Which of the four a row is in — pure, so the test can drive every combination
 * without rendering.
 *
 * The distinction that matters is between "your edition does not include this"
 * and "nobody has configured a provider": one is a purchase and the other is
 * ten minutes of an administrator's time, and showing the same grey dash for
 * both would send every reader to the wrong place.
 *
 * ORDER MATTERS, and `not-built` comes first of the three not-live reasons.
 * Whether a capability has been written is not a fact about the reader's
 * licence: an unbuilt seam read "Not yet built" on an Enterprise build and
 * "Enterprise" on a Core one, which told a Core tenant that upgrading would
 * give them something nothing implements. `built` is on the wire precisely so
 * this branch does not have to be inferred from `edition_linked`.
 */
export function seamState(
  seam: AIStatus['seams'][number],
  status: Pick<AIStatus, 'edition_linked' | 'provider_configured'>,
): SeamState {
  if (seam.live) return 'live';
  if (!seam.built) return 'not-built';
  if (seam.edition_required === 'enterprise' && !status.edition_linked) return 'edition';
  if (seam.family === 'generative' && !status.provider_configured) return 'unconfigured';
  return 'not-built';
}

const STATE_COPY: Record<SeamState, { label: string; tone: string }> = {
  live: { label: 'On', tone: GREEN },
  edition: { label: 'Enterprise', tone: 'var(--accent)' },
  unconfigured: { label: 'No provider', tone: AMBER },
  'not-built': { label: 'Not yet built', tone: 'var(--app-t3)' },
};

const SEAM_COLS: STableCol[] = [
  { label: 'Capability', w: '1.1fr' },
  { label: 'Where', w: '1fr' },
  { label: 'Without AI', w: '2fr' },
  { label: 'Status', w: '130px', align: 'right' },
];

/**
 * Which of the three top-level states the page is in.
 *
 * Pure, and ORDERED, because the order is the part that can be wrong: react-
 * query reports `isLoading` alongside `isError` while a failed query is
 * retrying, so a loading-first branch shows a spinner forever on a page that
 * has already failed — and this page's whole job is to say what is true.
 * `ready` additionally requires data, so a 200 with an unreadable body renders
 * the error card rather than an empty table that reads as "you have nothing".
 */
export type AIPageState = 'error' | 'loading' | 'ready';

export function aiPageState(q: { isError: boolean; isLoading: boolean; hasData: boolean }): AIPageState {
  if (q.isError) return 'error';
  if (q.isLoading || !q.hasData) return 'loading';
  return 'ready';
}

export function AIAssistantPage({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const { data, isLoading, isError, refetch } = useAIStatus();

  const state = aiPageState({ isError, isLoading, hasData: Boolean(data) });

  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job} maxWidth={1020}>
      {state === 'error' ? (
        <SCard>
          <StateNote
            icon="alert-triangle"
            tone="var(--danger-text)"
            title="Couldn’t load the AI assistant settings"
            message="The settings failed to load, so this page cannot say what is turned on. Nothing has changed; try again."
          />
          <button className="ui-btn" style={{ marginTop: 14 }} onClick={() => void refetch()}>Try again</button>
        </SCard>
      ) : state === 'loading' || !data ? (
        <SCard>
          <StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Reading what this deployment has turned on." />
        </SCard>
      ) : (
        <AIAssistantBody status={data} />
      )}
    </SPage>
  );
}

function AIAssistantBody({ status }: { status: AIStatus }) {
  return (
    <>
      <ProviderCard status={status} />
      <SSection title="Capabilities" desc="Every AI capability, where it appears, and what answers when no model does.">
        <STable cols={SEAM_COLS}>
          {status.seams.map((seam, i) => {
            const state = seamState(seam, status);
            const copy = STATE_COPY[state];
            return (
              <STableRow
                key={seam.key}
                cols={SEAM_COLS}
                first={i === 0}
                cells={[
                  <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{seamLabel(seam.key)}</span>,
                  <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{seam.surface && seam.surface.length > 0 ? seam.surface : '—'}</span>,
                  <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{seam.rule_default}</span>,
                  <STag color={copy.tone}>{copy.label}</STag>,
                ]}
              />
            );
          })}
        </STable>
      </SSection>
      <ControlsSection status={status} />
    </>
  );
}

function ProviderCard({ status }: { status: AIStatus }) {
  const tone = status.provider_configured ? GREEN : 'var(--app-t3)';
  const liveCount = status.seams.filter((s) => s.live).length;

  return (
    <SSection title="This deployment" desc={HONEST_LINE}>
      <SCard>
        <SRow label="Model provider" hint="Configured by whoever runs this deployment, not from this page.">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name={status.provider_configured ? 'plug-zap' : 'unplug'} size={14} style={{ color: tone }} />
            <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>
              {status.provider_configured
                ? status.provider_name
                : status.edition_linked
                  ? 'None configured'
                  : 'Not included in this edition'}
            </span>
          </div>
        </SRow>
        {status.provider_configured && status.model_id && (
          <SRow label="Model" hint="The model id this deployment asks for.">
            <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)' }}>{status.model_id}</span>
          </SRow>
        )}
        <SRow
          label="Capabilities on"
          hint="How many of the capabilities below can answer here right now."
          last
        >
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{liveCount} of {status.seams.length}</span>
        </SRow>
      </SCard>
      {!status.edition_linked && (
        <div style={{ marginTop: 10 }}>
          <SCard>
            <StateNote
              icon="info"
              tone="var(--accent)"
              title="The generative capabilities are part of Enterprise"
              message={`This build has no model provider in it, so the capabilities marked Enterprise below cannot be switched on here. ${HONEST_LINE} Each row says what answers instead, and those are what this deployment is doing today.`}
            />
          </SCard>
        </div>
      )}
    </SSection>
  );
}

function ControlsSection({ status }: { status: AIStatus }) {
  const qc = useQueryClient();
  const [assistantDisabled, setAssistantDisabled] = useState(status.tenant.assistant_disabled);
  const [recordQuestions, setRecordQuestions] = useState(status.tenant.record_questions);

  const dirty =
    assistantDisabled !== status.tenant.assistant_disabled ||
    recordQuestions !== status.tenant.record_questions;

  const save = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.PUT('/tenant/ai', {
        body: { assistant_disabled: assistantDisabled, record_questions: recordQuestions },
      });
      if (!response.ok || error || !data) throw new Error('Failed to save the AI assistant settings');
      return data;
    },
    onSuccess: (next) => {
      qc.setQueryData(AI_QUERY_KEY, next);
    },
  });

  // The interim notice, rendered from the SAME copy the Custom Policies
  // page uses rather than a second sentence saying the same thing differently.
  // The endpoint's boolean decides whether it is shown; nav.ts owns the words.
  const authoringNotice = settingsPageMeta('custom-policies').authoringDisabled;

  return (
    <SSection
      title="Your organization's controls"
      desc="These two are yours. They apply to every capability above, in every edition."
    >
      <SCard>
        <SRow
          label="Use the AI assistant"
          hint={
            assistantDisabled
              ? 'Off. No generative capability runs for your organization, even where this deployment has a provider — every one of them falls back to the rule-based behaviour listed above.'
              : 'On. Where this deployment has a model provider, the generative capabilities above may run for your organization.'
          }
        >
          <SToggle on={!assistantDisabled} onChange={(v) => setAssistantDisabled(!v)} />
        </SRow>
        <SRow
          label="Record the questions we send"
          hint={
            recordQuestions
              ? 'On. The audit trail stores the text a person typed alongside each AI call, as well as the fingerprint. Secrets are removed before anything is sent or recorded.'
              : 'Off (the default). The audit trail records that a call happened — which capability, which model, who asked and a fingerprint of the request — but not the text anyone typed.'
          }
          last={!authoringNotice || !status.tenant.authoring_disabled}
        >
          <SToggle on={recordQuestions} onChange={setRecordQuestions} />
        </SRow>
        {status.tenant.authoring_disabled && authoringNotice && (
          <SRow
            label="Drafting on custom policies"
            hint={authoringNotice.message}
            last
          >
            <STag color={AMBER}>Temporarily off</STag>
          </SRow>
        )}
      </SCard>

      <PermissionGate
        permission={TENANT_PERMISSIONS.settings.update}
        fallback={
          <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14 }}>
            You don’t have permission to change these settings.
          </p>
        }
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
          <button className="ui-btn accent" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save changes'}
          </button>
          {save.isError && <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn’t save — try again.</span>}
          {save.isSuccess && !dirty && <span style={{ fontSize: 12, color: GREEN }}>Saved.</span>}
          {dirty && !save.isPending && <span style={{ fontSize: 11.5, color: AMBER }}>Unsaved changes</span>}
        </div>
      </PermissionGate>
    </SSection>
  );
}
