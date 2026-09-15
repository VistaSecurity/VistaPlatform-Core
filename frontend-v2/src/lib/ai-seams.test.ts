// The availability chain, over ALL EIGHT seams at once.
//
// Gate 4's third question is "a tenant with no provider sees no AI UI", and
// every AI control in this app answers it through one function:
// `seamAvailability`, fed a real `/tenant/ai` payload. The per-surface tests
// beside it — `app/ask-mode.test.ts` for the palette toggle,
// `sections/findings/remediation-draft.test.ts` for the Draft button — each
// drive that chain for ONE seam key, which is the right shape for a test about
// a surface and leaves one thing unstated: the property is meant to hold for
// every capability the API can report, including ones no surface exists for yet.
//
// That gap is not hypothetical. The precedence inside `seamAvailability` was
// wrong once in exactly the place a single-seam test cannot see: `edition` was
// returned before `not_built`, so a seam nothing implements read as
// "Enterprise" on a Core build — telling a Core reader that upgrading would buy
// them a capability that does not exist, while the same seam on an Enterprise
// build correctly read "not yet built". Whether something has been written is
// not a fact about the reader's licence.
//
// So this file sweeps the whole seam vocabulary through the whole chain, in the
// four deployment shapes that exist.
import { describe, expect, it } from 'vitest';
import { SEAM_LABELS } from '../sections/settings/pages-ai';
import { seamAvailability, type AISeamStatus, type AIStatus } from './ai-seams';

// The eight keys the backend's `ai.Seam` constants spell, taken from the
// settings page's label table rather than retyped — that table is already pinned
// to the API's vocabulary in both directions by pages-ai.test.ts, so borrowing
// it means this file cannot drift from the API on its own.
const SEAM_KEYS = Object.keys(SEAM_LABELS);

const GENERATIVE = new Set(['enricher', 'narrator', 'query', 'author', 'remediator']);

/** One seam row of the shape `GET /tenant/ai` returns. */
function seamRow(key: string, over: Partial<AISeamStatus> = {}): AISeamStatus {
  const generative = GENERATIVE.has(key);
  return {
    key,
    live: over.live ?? false,
    built: over.built ?? true,
    edition_required: over.edition_required ?? (generative ? 'enterprise' : 'core'),
    family: over.family ?? (generative ? 'generative' : 'classical'),
    surface: over.surface ?? `Where you meet ${key}`,
    rule_default: over.rule_default ?? `What answers instead of ${key}.`,
  };
}

function status(over: {
  edition_linked?: boolean;
  provider_configured?: boolean;
  assistant_disabled?: boolean;
  seam?: (key: string) => Partial<AISeamStatus>;
} = {}): AIStatus {
  return {
    provider_configured: over.provider_configured ?? false,
    edition_linked: over.edition_linked ?? false,
    seams: SEAM_KEYS.map((k) => seamRow(k, over.seam ? over.seam(k) : {})),
    tenant: {
      record_questions: false,
      assistant_disabled: over.assistant_disabled ?? false,
      authoring_disabled: true,
    },
  };
}

const all = (s: AIStatus) => SEAM_KEYS.map((k) => ({ key: k, ...seamAvailability(k, s, false, false) }));

describe('the seam vocabulary this file sweeps', () => {
  // Without this the sweeps below would pass by examining nothing, which is the
  // failure mode the whole area is written against.
  it('covers all eight seams', () => {
    expect(SEAM_KEYS).toHaveLength(8);
    expect(SEAM_KEYS).toEqual(expect.arrayContaining([...GENERATIVE]));
  });
});

describe('Core: no generative capability is offered, and nothing is mislabelled', () => {
  // A Core build has no model clients at all, whatever AI_PROVIDER says — which
  // is why provider_configured is false here even though it is a separate fact.
  const core = status({ edition_linked: false, provider_configured: false });

  it('offers no generative seam', () => {
    for (const s of all(core)) {
      if (!GENERATIVE.has(s.key)) continue;
      expect(s.available, `${s.key} was offered on a Core build`).toBe(false);
    }
  });

  it('names the edition as the reason — a purchase, not a misconfiguration', () => {
    for (const s of all(core)) {
      if (!GENERATIVE.has(s.key)) continue;
      expect(s.reason, s.key).toBe('edition');
    }
  });

  // The classical seams are Core and run in-process. A page that reported them
  // off would be telling the truth about the generative half and a lie about the
  // rest — and the rule-based defaults are the product's central claim.
  it('still offers the classical seams a Core deployment genuinely has', () => {
    const live = status({
      edition_linked: false,
      provider_configured: false,
      seam: (k) => (GENERATIVE.has(k) ? {} : { live: true }),
    });
    for (const s of all(live)) {
      if (GENERATIVE.has(s.key)) continue;
      expect(s.available, `${s.key} is a Core capability and was hidden`).toBe(true);
    }
  });

  // The one that was wrong. An unbuilt seam must read "nobody has written it",
  // never "your edition does not include it" — on a Core build as much as on an
  // Enterprise one, because the two builds must not disagree about whether
  // something exists.
  it('says not_built, never edition, for a seam nothing implements', () => {
    const unbuilt = status({ edition_linked: false, seam: () => ({ built: false }) });
    for (const s of all(unbuilt)) {
      expect(s.reason, s.key).toBe('not_built');
    }
  });

  it('every seam still carries its rule default, so no surface renders a blank', () => {
    for (const s of all(core)) {
      expect(s.ruleDefault, s.key).toBeTruthy();
    }
  });
});

describe('Enterprise with no provider: the administrator is the fix, not the finance team', () => {
  const noProvider = status({ edition_linked: true, provider_configured: false });

  it('offers no generative seam', () => {
    for (const s of all(noProvider)) {
      if (!GENERATIVE.has(s.key)) continue;
      expect(s.available, s.key).toBe(false);
      expect(s.reason, s.key).toBe('no_provider');
    }
  });

  // The inverse polarity. Without it, a chain that answered "unavailable" for
  // everything would satisfy every assertion above.
  it('offers them once a provider is reachable', () => {
    const live = status({
      edition_linked: true,
      provider_configured: true,
      seam: () => ({ live: true }),
    });
    for (const s of all(live)) {
      expect(s.available, s.key).toBe(true);
      expect(s.reason, s.key).toBeUndefined();
    }
  });
});

describe("the tenant's kill switch outranks everything", () => {
  it('hides every seam, including ones the deployment can serve', () => {
    const off = status({
      edition_linked: true,
      provider_configured: true,
      assistant_disabled: true,
      seam: () => ({ live: true }),
    });
    for (const s of all(off)) {
      expect(s.available, s.key).toBe(false);
      expect(s.reason, s.key).toBe('disabled');
    }
  });

  // `disabled` is the only one of the four reasons whose fix belongs to the
  // reader's own organization, so it is the only one a surface says anything
  // about. Reporting `edition` for a switched-off tenant would send them to buy
  // something they already have.
  it('is reported as the tenant switch even on a Core build', () => {
    const off = status({ edition_linked: false, assistant_disabled: true });
    for (const s of all(off)) {
      expect(s.reason, s.key).toBe('disabled');
    }
  });
});

describe('an answer we do not have yet is never rendered as a no', () => {
  it('reports loading rather than unavailable while the read is in flight', () => {
    for (const key of SEAM_KEYS) {
      const a = seamAvailability(key, undefined, true, false);
      expect(a.loading, key).toBe(true);
      expect(a.available, key).toBe(false);
      expect(a.reason, key).toBeUndefined();
    }
  });

  it('fails closed on a read that did not complete, and does not claim to know why', () => {
    for (const key of SEAM_KEYS) {
      const a = seamAvailability(key, undefined, false, true);
      expect(a.available, key).toBe(false);
      expect(a.reason, key).toBe('unknown');
    }
  });

  it('treats a seam the API did not return at all as not built', () => {
    const partial: AIStatus = { ...status({ edition_linked: true, provider_configured: true }), seams: [] };
    for (const key of SEAM_KEYS) {
      expect(seamAvailability(key, partial, false, false).reason, key).toBe('not_built');
    }
  });
});


// The invariant every caller depends on, asserted where it is PRODUCED.
//
// `askToggleVisible` used to read `!loading && available`, and the `loading`
// half never changed an answer: this function returns `available: false` on its
// loading arm, and it is the only thing that builds a SeamAvailability. A clause
// that cannot change an outcome is worse than none — it reads as the thing
// keeping the third state honest and is not, and it would have absorbed exactly
// the regression below in silence.
//
// So the clause went and this took its place. The difference is that this one
// can fail: make the loading arm return `available: true` and it goes red, while
// the old clause would have kept every caller correct and told nobody the
// invariant had broken.
describe('the loading arm is never also available', () => {
  it('holds for every seam, under every combination of edition, provider and kill switch', () => {
    const shapes: AIStatus[] = [
      status(),
      status({ edition_linked: true, provider_configured: true }),
      status({ edition_linked: true, provider_configured: true, seam: () => ({ live: true }) }),
      status({ assistant_disabled: true, edition_linked: true, provider_configured: true }),
      status({ seam: () => ({ built: false }) }),
    ];
    for (const st of shapes) {
      for (const key of SEAM_KEYS) {
        const loading = seamAvailability(key, st, true, false);
        expect(loading.loading).toBe(true);
        expect(loading.available).toBe(false);
      }
    }
  });

  it('holds with no payload at all, loading or errored', () => {
    // The two states a first paint actually passes through.
    expect(seamAvailability('query', undefined, true, false).available).toBe(false);
    expect(seamAvailability('query', undefined, false, true).available).toBe(false);
  });

  it('is reachable — a live seam really can be available', () => {
    // The other polarity. An invariant that held because nothing is EVER
    // available would pass the sweep above and mean nothing.
    const live = seamAvailability('query', status({
      edition_linked: true, provider_configured: true, seam: () => ({ live: true }),
    }), false, false);
    expect(live).toEqual({ loading: false, available: true, ruleDefault: 'What answers instead of query.' });
  });
});
