// Accepting a draft: turning one reviewed proposal into real rows through the
// ORDINARY authoring endpoints.
//
// There is no "apply drafts" endpoint and there should not be. A draft becomes
// a control the same way a hand-typed one does — the same route, the same
// validation, the same permission — with `source_kind: inferred` recording
// where it came from. That is what makes the review step unskippable: a client
// that ignored the review UI would still have to make the same calls a person
// makes, one control at a time.
//
// Shared by both authoring apps for the same reason as the state machine: the
// sequence is identical and only the endpoints differ, so each app supplies
// [AcceptDeps] and this owns the order and the partial-failure rules.
import type { ControlDraft, MeasurementDraft } from './drafts';
import { sourceRefFor } from './drafts';
import { parseSeverity, controlWeight, type ControlSeverity } from '../ratings';

/** The control body both create-control endpoints take. */
export interface ControlBody {
  control_id: string;
  title: string;
  description: string;
  baseline_severity: ControlSeverity;
  crypto_relevant: boolean;
  source_kind: 'inferred';
  source_ref: string;
}

/** The measurement body both add-measurement endpoints take. */
export interface MeasurementBody {
  measurement_type_id: string;
  // The four rule types the engine evaluates, taken from the draft's own type
  // rather than widened to string: a body typed `string` here would not satisfy
  // either create-measurement endpoint, and widening it to make the call
  // compile would move the check from the compiler to a 400 at runtime.
  rule_type: MeasurementDraft['rule_type'];
  predicate: Record<string, unknown>;
  weight: number;
}

export interface AcceptDeps {
  /** POST the control; resolves to the new control's id. */
  createControl(body: ControlBody): Promise<string>;
  /** POST one measurement rule onto a control. */
  addMeasurement(controlId: string, body: MeasurementBody): Promise<void>;
  /** Resolve a measurement-type code to its id in this deployment. */
  measurementTypeId(code: string): string | undefined;
}

export interface AcceptOutcome {
  controlId: string;
  rulesAdded: number;
  /** One sentence per rule that could not be added. The control still exists. */
  ruleErrors: string[];
}

/**
 * Build the create-control body for a draft.
 *
 * Two fields are decided here rather than by the model:
 *
 * - `baseline_severity` is validated against the four the column's CHECK admits. The
 *   server already normalises it, so this is the second lock rather than the
 *   first. Invalid or missing severity prevents acceptance.
 * - `crypto_relevant` is true exactly when the draft carries at least one rule
 *   over the cryptographic measurement catalogue. A control with no rule is not
 *   evidence of cryptographic relevance, and flagging every draft as relevant
 *   would quietly inflate the crypto-control count on every framework.
 */
export function controlBodyFor(draft: ControlDraft, modelId: string): ControlBody {
  const severity = parseSeverity(draft.severity ?? '');
  if (!severity || severity === 'info' || controlWeight(severity) == null) {
    throw new Error('Choose a valid control severity before accepting this draft.');
  }
  return {
    control_id: draft.control_id?.trim() || draft.title.slice(0, 100),
    title: draft.title,
    description: draft.description ?? '',
    baseline_severity: severity,
    crypto_relevant: (draft.measurements?.length ?? 0) > 0,
    source_kind: 'inferred',
    source_ref: sourceRefFor(draft.model_id || modelId),
  };
}

/** Build the add-measurement body, or null when the code is not in the catalogue. */
export function measurementBodyFor(
  rule: MeasurementDraft,
  measurementTypeId: (code: string) => string | undefined,
): MeasurementBody | null {
  const id = measurementTypeId(rule.measurement_type_code);
  if (!id) return null;
  return {
    measurement_type_id: id,
    rule_type: rule.rule_type,
    predicate: (rule.predicate ?? {}) as Record<string, unknown>,
    weight: 1,
  };
}

/**
 * Accept one draft: create the control, then add its rules.
 *
 * # Partial failure is reported, not retried
 *
 * If the control is created and a rule then fails, this RESOLVES with the
 * failures listed rather than rejecting. The row exists; reporting the whole
 * accept as failed would invite a retry that creates a second control with the
 * same id, and a duplicated control in a published framework is a duplicated
 * finding for every tenant subscribed to it.
 *
 * A failure to create the control at all rejects, because nothing was written
 * and retrying is exactly the right thing to do.
 */
export async function acceptDraft(
  draft: ControlDraft,
  modelId: string,
  deps: AcceptDeps,
): Promise<AcceptOutcome> {
  const controlId = await deps.createControl(controlBodyFor(draft, modelId));

  const outcome: AcceptOutcome = { controlId, rulesAdded: 0, ruleErrors: [] };
  for (const rule of draft.measurements ?? []) {
    const body = measurementBodyFor(rule, deps.measurementTypeId);
    if (!body) {
      // The server already drops rules naming an unknown measurement type, so
      // reaching here means the catalogue changed between drafting and
      // accepting. Say so rather than silently creating a control with fewer
      // rules than the reviewer approved.
      outcome.ruleErrors.push(`"${rule.measurement_type_code}" is not in this platform's measurement catalogue, so that rule was not added.`);
      continue;
    }
    try {
      await deps.addMeasurement(controlId, body);
      outcome.rulesAdded += 1;
    } catch (e) {
      outcome.ruleErrors.push(
        `Rule on "${rule.measurement_type_code}" could not be added: ${e instanceof Error ? e.message : 'unknown error'}`,
      );
    }
  }
  return outcome;
}

/** A sentence for the toast after an accept, honest about partial success. */
export function acceptSummary(outcome: AcceptOutcome): string {
  if (outcome.ruleErrors.length === 0) {
    return outcome.rulesAdded === 0
      ? 'Control added (unpublished). It has no rule yet, so it will evaluate to "not assessed".'
      : `Control added (unpublished) with ${outcome.rulesAdded} rule${outcome.rulesAdded === 1 ? '' : 's'}.`;
  }
  return `Control added (unpublished), but ${outcome.ruleErrors.length} rule${outcome.ruleErrors.length === 1 ? '' : 's'} could not be: ${outcome.ruleErrors.join(' ')}`;
}
