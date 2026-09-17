import { describe, expect, it } from 'vitest';
import { FINDING_KINDS } from '@vistasecurity/primitives/findings';
import { seamAvailability, type AIStatus } from '../../lib/ai-seams';
import { DEGRADED_COPY, degradedMessage, guidanceFor, UNAVAILABLE_COPY } from './remediation-draft';
import { draftedByTitle, isAIDrafted } from '../remediation/plan-detail';

// The Findings inspector's Remediation block: the guidance that renders in every
// edition, and the availability rule that decides whether the drafting button
// appears beside it.
//
// Both polarities everywhere. A button that cannot be hidden ships an
// Enterprise capability to Core; a button that cannot appear ships a seam with
// no consumer. Only one of the two is visible to whoever notices.

const SEAM = 'remediator';

function status(over: Partial<AIStatus> = {}): AIStatus {
  return {
    provider_configured: true,
    provider_name: 'anthropic',
    edition_linked: true,
    seams: [
      {
        key: SEAM,
        live: true,
        built: true,
        edition_required: 'enterprise',
        family: 'generative',
        surface: 'Draft a remediation plan on a finding',
        rule_default: 'Every finding carries the remediation guidance for its kind.',
      },
    ],
    tenant: { record_questions: false, assistant_disabled: false, authoring_disabled: false },
    ...over,
  };
}

/** A seam row with one field overridden, keeping everything else live. */
function withSeam(over: Partial<AIStatus['seams'][number]>, rest: Partial<AIStatus> = {}): AIStatus {
  const s = status(rest);
  return { ...s, seams: [{ ...s.seams[0], ...over }] };
}

describe('guidanceFor', () => {
  it('resolves the registry guidance for a real producer/kind', () => {
    const g = guidanceFor('crypto', 'weak_configuration');
    expect(g).toBeTruthy();
    expect(g).toContain('strong or recommended alternatives');
    expect(g).toContain('weak or acceptable components');
  });

  // The registry is the remediator's null default. A kind with no guidance is a
  // finding whose inspector would show a blank where the answer belongs, and
  // whose drafted plan would have nothing to degrade to.
  it('every registered kind has guidance', () => {
    for (const kind of FINDING_KINDS) {
      expect(kind.guidance, `${kind.producer}/${kind.key}`).toBeTruthy();
    }
  });

  it('returns nothing for an unregistered kind, and for a finding missing either half', () => {
    expect(guidanceFor('crypto', 'not_a_kind')).toBeUndefined();
    expect(guidanceFor('not_a_producer', 'weak_configuration')).toBeUndefined();
    expect(guidanceFor(undefined, 'weak_configuration')).toBeUndefined();
    expect(guidanceFor('crypto', undefined)).toBeUndefined();
  });
});

describe('seamAvailability — the button appears exactly when the seam can answer', () => {
  it('is available on an Enterprise build with a provider and the assistant on', () => {
    const a = seamAvailability(SEAM, status(), false, false);
    expect(a).toMatchObject({ loading: false, available: true });
    expect(a.ruleDefault).toBeTruthy();
  });

  it('is not available while the answer is still loading, and says so', () => {
    const a = seamAvailability(SEAM, undefined, true, false);
    // `loading` and not a reason: rendering "unavailable" before we have looked
    // tells a user a capability is off when nobody has checked.
    expect(a).toEqual({ loading: true, available: false });
  });

  it('fails closed on a read that did not complete, and does not claim to know why', () => {
    expect(seamAvailability(SEAM, undefined, false, true)).toEqual({
      loading: false, available: false, reason: 'unknown',
    });
  });

  it('reports `edition` on a Core build', () => {
    const a = seamAvailability(SEAM, withSeam({ live: false }, { edition_linked: false, provider_configured: false }), false, false);
    expect(a).toMatchObject({ available: false, reason: 'edition' });
  });

  it('reports `no_provider` on an Enterprise build with nothing configured', () => {
    const a = seamAvailability(SEAM, withSeam({ live: false }, { provider_configured: false }), false, false);
    expect(a).toMatchObject({ available: false, reason: 'no_provider' });
  });

  // The tenant switch wins over everything. A live seam plus a disabled
  // assistant is a button that would answer 403, which reads as broken.
  it('reports `disabled` when the tenant turned the assistant off, even with a live seam', () => {
    const a = seamAvailability(SEAM, status({
      tenant: { record_questions: false, assistant_disabled: true, authoring_disabled: false },
    }), false, false);
    expect(a).toMatchObject({ available: false, reason: 'disabled' });
  });

  // `not_built` before the edition, for the reason the settings page does it:
  // whether something has been written is not a fact about the reader's licence.
  it('reports `not_built` before `edition` for a seam nothing implements', () => {
    const a = seamAvailability(SEAM, withSeam({ live: false, built: false }, { edition_linked: false }), false, false);
    expect(a).toMatchObject({ available: false, reason: 'not_built' });
  });

  it('reports `not_built` for a seam key the API did not return at all', () => {
    const a = seamAvailability('no_such_seam', status(), false, false);
    expect(a).toMatchObject({ available: false, reason: 'not_built' });
  });
});

describe('the copy for each unavailable reason', () => {
  // Three of the four silences are deliberate. A drawer opened to triage a
  // finding is not where an upgrade is sold, and a decision to show nothing that
  // nothing pins is one a later edit reverses by accident.
  it('says nothing for edition, no_provider, not_built and unknown', () => {
    for (const reason of ['edition', 'no_provider', 'not_built', 'unknown']) {
      expect(UNAVAILABLE_COPY[reason], reason).toBeUndefined();
    }
  });

  it('speaks only for the switch this organization owns, and names where to change it', () => {
    expect(UNAVAILABLE_COPY.disabled).toContain('Settings → AI assistant');
  });
});

describe('degradedMessage', () => {
  // The empty-plan state the spec calls for: the model could not cite anything,
  // and the panel says so rather than showing an empty list of steps — which
  // would assert that this finding needs nothing done about it.
  it('names the no-citations case explicitly', () => {
    expect(degradedMessage('no_cited_steps')).toContain('could not cite');
    expect(degradedMessage('no_cited_steps')).toContain('standard guidance');
  });

  it('has a distinct sentence for every reason the backend can send', () => {
    const reasons = ['no_provider', 'provider_error', 'refused', 'unreadable', 'no_cited_steps'];
    const seen = new Set(reasons.map((r) => degradedMessage(r)));
    expect(seen.size).toBe(reasons.length);
    for (const r of reasons) expect(DEGRADED_COPY[r]).toBeTruthy();
  });

  it('still says something honest for a reason it has never seen', () => {
    expect(degradedMessage('a_reason_from_the_future')).toContain('standard guidance');
    expect(degradedMessage(undefined)).toContain('standard guidance');
  });
});

describe('the AI-drafted chip on a plan item', () => {
  it('appears for an item accepted from a draft', () => {
    expect(isAIDrafted({ source_kind: 'inferred' })).toBe(true);
  });

  // The inverse polarity, which is the half that keeps the chip meaning
  // something. An item added by hand carries no provenance, and a historical one
  // carries none because the column is deliberately not backfilled.
  it('does not appear for a hand-added item, or a pre-column one', () => {
    expect(isAIDrafted({ source_kind: null })).toBe(false);
    expect(isAIDrafted({})).toBe(false);
    expect(isAIDrafted({ source_kind: 'declared' })).toBe(false);
    expect(isAIDrafted({ source_kind: 'measured' })).toBe(false);
  });

  it('names the model in the tooltip when the row records one', () => {
    expect(draftedByTitle('remediator:claude-x')).toContain('claude-x');
    // And says nothing false when it does not: `remediator:model` is the
    // fallback source_ref for a draft with no model id.
    expect(draftedByTitle('remediator:model')).not.toContain('remediator');
    expect(draftedByTitle(undefined)).toContain('accepted by a person');
  });

  it('always says a person accepted it, whatever the model', () => {
    for (const ref of ['remediator:claude-x', 'remediator:model', undefined]) {
      expect(draftedByTitle(ref)).toContain('accepted by a person');
      expect(draftedByTitle(ref)).toContain('Nothing was done automatically');
    }
  });
});
