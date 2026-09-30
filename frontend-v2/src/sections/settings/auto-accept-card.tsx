// Settings → Identification rules → "When a sighting is ambiguous"
// (workstream 4.6), and the rule-merge switch beneath it ( Phase 4).
//
// The controls in the product that grant the platform permission to merge two of
// a tenant's assets without asking. They are deliberately their own card with
// their own explanation and their own warning, rather than a slider dropped
// beside the precedence table: a tenant moving these is changing what the
// platform is allowed to DECIDE, and that is not the same kind of act as
// reordering a list they are reading.
//
// Two different grants, and the card keeps them apart. The THRESHOLD lets a
// model's score settle a question, and is off until the tenant says otherwise.
// The RULE MERGE is fixed conditions with no score, and is on until the tenant
// says otherwise — owner decision D1.
import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { SCard } from './kit';
import {
  useIdentificationSettings, useSetAutoAcceptThreshold, useSetAutoMergeExisting,
} from '../inventory/asset-queries';

/** The steps the control offers, as percentages. */
export const THRESHOLD_STEPS = [0, 70, 80, 90, 95, 99] as const;

/**
 * What a threshold means, in a sentence.
 *
 * Zero is not "0% confidence required" — it is OFF, and saying it as a
 * percentage would read as the most permissive setting rather than the most
 * restrictive one. That inversion is the single most dangerous thing this
 * control could get wrong.
 */
export function thresholdSummary(pct: number): string {
  if (pct <= 0) {
    return 'Off. Every ambiguous sighting waits for a person, whatever the matcher scores it.';
  }
  return `A merge the matcher scores ${pct}% or higher is accepted without asking. Anything below waits for a person.`;
}

/** The label on each step. */
export function thresholdLabel(pct: number): string {
  return pct <= 0 ? 'Never' : `${pct}%`;
}

/**
 * Which intake paths the threshold governs: all of them.
 *
 * It did not always. Until BUILD_PLAN 4.6a, device-interrogation-service ran its
 * own identification engines and did not read this setting, so an interrogation
 * or cloud-collector observation was never auto-accepted whatever was set here —
 * and this note said so, because a setting whose stated scope is wider than its
 * real one is a setting that lies. The gap is closed; the note now says what is
 * true, which is the wider claim and therefore the one to keep checking.
 *
 * Shown whether or not the threshold is on: someone deciding whether to turn it
 * on needs to know what it covers.
 */
export const THRESHOLD_SCOPE_NOTE =
  'The threshold applies to every sighting, whichever way it reached us — discovery, imports, SBOM uploads, '
  + 'passively observed hosts, device interrogation and cloud collectors.';

/** The label on the rule-merge switch, as the owner wrote it ( D1). */
export const RULE_MERGE_LABEL = 'Merge records the rules are sure are one device';

/**
 * The read-failure line, verbatim from the spec's state table. It says the truth
 * about BOTH halves of the failure: nothing was changed, and the rule is not
 * paused by our not being able to read it.
 */
export const RULE_MERGE_READ_ERROR =
  'Could not read this setting. Nothing has changed — rule merges keep running with the last saved value.';

/**
 * What "sure" means, in plain words — the same-device rule's conditions, one per
 * line. This is the disclosure that makes an on-by-default switch acceptable, so
 * it is always visible, on or off: someone deciding whether to turn it OFF needs
 * exactly this list.
 */
export const RULE_MERGE_CONDITIONS = [
  'the same MAC address or serial number was seen directly on the device — not relayed second-hand from somewhere else,',
  'an address alone never counts: a record known by a name is not merged with a device just because it later used the same address,',
  'both records are on the same network segment,',
  'nothing contradicts it — two different serial numbers, cloud ids or agent ids are always two devices,',
  'and neither record has ever been marked “keep separate”. A decision you made is never overridden.',
] as const;

/**
 * The control itself. Effective value from the server — never a default the
 * tenant did not choose: an absent setting reads ON (owner decision D1) and the
 * API says so, so this component has no default of its own to get wrong.
 */
function RuleMergeControl() {
  const settingsQ = useIdentificationSettings();
  const save = useSetAutoMergeExisting();
  const enabled = settingsQ.data?.auto_merge_existing;

  return (
    <div
      data-testid="rule-merge"
      style={{ marginTop: 18, paddingTop: 16, borderTop: '1px solid var(--app-border)' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ flex: 1, minWidth: 0, fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>
          {RULE_MERGE_LABEL}
        </div>

        {settingsQ.isLoading && (
          <span
            data-testid="rule-merge-skeleton"
            aria-hidden="true"
            style={{ width: 38, height: 22, borderRadius: 40, background: 'var(--app-panel2)', flex: 'none' }}
          />
        )}

        {enabled !== undefined && (
          // BOTH permissions, matching the two chained gates on the PUT behind
          // this switch — see the note on the threshold's Save button below.
          <PermissionGate
            allOf={[TENANT_PERMISSIONS.settings.update, TENANT_PERMISSIONS.assets.update]}
            fallback={
              <span data-testid="rule-merge-readonly" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
                {enabled ? 'On' : 'Off'} — read-only, you do not have permission to change this.
              </span>
            }
          >
            <button
              role="switch"
              aria-checked={enabled}
              aria-label={RULE_MERGE_LABEL}
              data-testid="rule-merge-toggle"
              disabled={save.isPending}
              onClick={() => save.mutate(!enabled)}
              style={{
                width: 38, height: 22, borderRadius: 40, border: 'none', padding: 0, position: 'relative', flex: 'none',
                cursor: save.isPending ? 'default' : 'pointer', opacity: save.isPending ? 0.6 : 1,
                background: enabled ? 'var(--accent-gradient)' : 'var(--app-track)', transition: 'background .18s',
              }}
            >
              <span
                style={{
                  position: 'absolute', top: 2, left: enabled ? 18 : 2, width: 18, height: 18, borderRadius: 50,
                  background: '#fff', transition: 'left .18s', boxShadow: '0 1px 2px rgba(0,0,0,.3)',
                }}
              />
            </button>
          </PermissionGate>
        )}
      </div>

      {settingsQ.isError && (
        <div data-testid="rule-merge-error" style={{ fontSize: 12.5, color: 'var(--warn-strong)', marginTop: 8 }}>
          {RULE_MERGE_READ_ERROR}
        </div>
      )}

      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.65, marginTop: 8 }}>
        Sometimes Vista Platform holds two records of one device — one built from a network address and a name, another
        from the device’s own hardware address. When fixed rules (not a score) are <em>sure</em> they are the same
        device, it merges them without asking. Sure means:
        <ul data-testid="rule-merge-conditions" style={{ margin: '6px 0 6px', paddingLeft: 18 }}>
          {RULE_MERGE_CONDITIONS.map((c) => <li key={c}>{c}</li>)}
        </ul>
        Values you typed always win. A record you entered is kept as the survivor — unless it is still waiting for
        approval and the other record is already approved; then the approved record is kept and your values are
        carried onto it. Every rule merge is
        listed under <strong style={{ color: 'var(--app-t2)' }}>Discovery → Approvals → Merged automatically</strong>,
        with the reasons. Turn this off and the same cases wait for a person, as ordinary merge proposals.
      </div>
    </div>
  );
}

export function AutoAcceptCard() {
  const settingsQ = useIdentificationSettings();
  const save = useSetAutoAcceptThreshold();

  const serverPct = settingsQ.data ? Math.round(settingsQ.data.auto_accept_threshold * 100) : undefined;

  // The draft, carrying the server value it was seeded from.
  //
  // `undefined` until the server answers, so the control never renders a
  // default the tenant did not choose — a row of buttons sitting on "Never"
  // while the real setting is 95% is worse than a spinner.
  //
  // Reset during RENDER rather than in an effect (React's "adjusting state when
  // a prop changes"). An effect would paint the stale value first and then
  // correct it, which on this particular control means briefly showing the
  // wrong answer to "may the platform merge my assets without asking".
  const [draft, setDraft] = useState<{ base: number; value: number } | undefined>(undefined);
  if (serverPct !== undefined && draft?.base !== serverPct) {
    setDraft({ base: serverPct, value: serverPct });
  }
  const pct = draft?.value;
  const setPct = (v: number) => setDraft((d) => ({ base: d?.base ?? v, value: v }));

  const modelID = settingsQ.data?.matcher_model_id;
  const dirty = pct !== undefined && serverPct !== undefined && pct !== serverPct;

  return (
    <SCard>
      <div className="eyebrow-app" style={{ marginBottom: 8 }}>When a sighting is ambiguous</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.65, marginBottom: 14 }}>
        When the identifiers disagree — one says this is the database server you already have, another says it is something else — the platform does not guess. It creates a <strong style={{ color: 'var(--app-t2)' }}>merge proposal</strong> in Discovery → Approvals and a person decides.
        <br />
        A matcher scores each candidate and puts the strongest first, with its reasons. You can let a score above a line you choose settle it without you.
        <br />
        <span data-testid="threshold-scope-note">{THRESHOLD_SCOPE_NOTE}</span>
      </div>

      {settingsQ.isLoading && (
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Loading…</div>
      )}
      {settingsQ.isError && (
        <div style={{ fontSize: 12.5, color: 'var(--warn-strong)' }}>
          Could not read this setting. Nothing has changed — merges are not auto-accepted while it cannot be read.
        </div>
      )}

      {pct !== undefined && (
        <>
          <div
            role="radiogroup"
            aria-label="Auto-accept threshold"
            style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginBottom: 11 }}
          >
            {THRESHOLD_STEPS.map((step) => (
              <button
                key={step}
                role="radio"
                aria-checked={pct === step}
                data-testid={`threshold-${step}`}
                className="ui-btn sm"
                disabled={save.isPending}
                onClick={() => setPct(step)}
                style={{
                  borderColor: pct === step ? 'var(--accent)' : undefined,
                  background: pct === step ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : undefined,
                  fontWeight: pct === step ? 700 : undefined,
                }}
              >
                {thresholdLabel(step)}
              </button>
            ))}
          </div>

          <div data-testid="threshold-summary" style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.6, marginBottom: 11 }}>
            {thresholdSummary(pct)}
          </div>

          {/* The warning. It is shown when auto-accept is ON rather than at the
              moment of saving, because the hazard is a STATE, not an event: a
              tenant who enabled this months ago and is now reading the page is
              the person who most needs to see it. */}
          {pct > 0 && (
            <div
              data-testid="auto-accept-warning"
              style={{
                display: 'flex', gap: 9, padding: '10px 12px', borderRadius: 10, marginBottom: 11,
                border: '1px solid color-mix(in srgb, var(--warn) 45%, transparent)',
                background: 'color-mix(in srgb, var(--warn) 10%, transparent)',
              }}
            >
              <Icon name="alert-triangle" size={15} style={{ color: 'var(--warn-strong)', flex: 'none', marginTop: 1 }} />
              <div style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.6 }}>
                <strong style={{ color: 'var(--app-t1)' }}>An auto-accepted merge cannot be undone from here.</strong>
                {' '}The sighting is written into the asset the matcher chose, and putting it back is manual work. Everything it does appears under “Merged automatically” in Discovery → Approvals, with the score and the reasons — check it there.
                <br />
                Two things are never auto-accepted whatever the score: a sighting whose serial number, cloud id, agent id or CMDB sys_id <em>disagrees</em> with the candidate’s, and anything involving an asset still waiting for approval.
              </div>
            </div>
          )}

          {modelID ? (
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginBottom: 11 }}>
              scored by {modelID}
            </div>
          ) : (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 11, lineHeight: 1.6 }}>
              No matcher is configured on this deployment, so nothing is scored and this threshold cannot take effect whatever it is set to. Merge proposals still appear in Approvals for a person to decide.
            </div>
          )}

          {/*
            BOTH permissions, matching the two chained gates on the PUT behind
            this button.

            settings.update because this is a Settings page, and the sibling
            card on the same page (Drift baseline) asks for it — a role granted
            one and not the other could otherwise edit half a page with nothing
            saying why (security review X.5, X5-11).

            assets.update because the threshold authorises the platform to MERGE
            two of this tenant's assets without asking, which is the same act as
            accepting a merge proposal by hand (workstream 4.6). Dropping it
            would let settings.update alone authorise asset rewriting.
          */}
          <PermissionGate
            allOf={[TENANT_PERMISSIONS.settings.update, TENANT_PERMISSIONS.assets.update]}
            fallback={<span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Read-only — you do not have permission to change this.</span>}
          >
            <button
              className="ui-btn sm accent"
              data-testid="save-threshold"
              disabled={!dirty || save.isPending}
              style={{ opacity: dirty && !save.isPending ? 1 : 0.5 }}
              onClick={() => save.mutate(pct / 100)}
            >
              <Icon name="check" size={12} />
              {save.isPending ? 'Saving…' : 'Save'}
            </button>
            {dirty && (
              <button className="ui-btn sm" disabled={save.isPending} onClick={() => setPct(serverPct)}>
                Cancel
              </button>
            )}
          </PermissionGate>
        </>
      )}

      <RuleMergeControl />
    </SCard>
  );
}
