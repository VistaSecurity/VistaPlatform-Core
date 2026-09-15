// The command palette's ask mode (ADR-0006 D9, build-plan 4.4b).
//
// These run against the REAL chain a browser runs: a `/tenant/ai` payload of the
// shape the endpoint returns → `seamAvailability` → `askToggleVisible`, which is
// the exact function the palette calls. Asserting on a hand-made
// `SeamAvailability` would have proved the boolean logic and nothing about
// whether a Core deployment hides the toggle.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { seamAvailability, type AIStatus } from '../lib/ai-seams';
import {
  SEAM_QUERY, askRows, askToggleVisible, readAskFailure, readableSummary,
  type AskAnswer,
} from './ask-mode';
import type { Asset } from './palette-results';

/** A `/tenant/ai` body, with the query seam's row overridable. */
function status(over: {
  live?: boolean; built?: boolean; edition_linked?: boolean;
  provider_configured?: boolean; assistant_disabled?: boolean;
} = {}): AIStatus {
  return {
    provider_configured: over.provider_configured ?? true,
    provider_name: 'anthropic',
    edition_linked: over.edition_linked ?? true,
    seams: [
      {
        key: SEAM_QUERY,
        live: over.live ?? true,
        built: over.built ?? true,
        edition_required: 'enterprise',
        family: 'generative',
        surface: 'Ask in the command palette (⌘K)',
        rule_default: 'Inventory is searched with the query language directly, from the search bar and saved views.',
      },
    ],
    tenant: {
      record_questions: false,
      assistant_disabled: over.assistant_disabled ?? false,
      authoring_disabled: true,
    },
  };
}

function visible(s: AIStatus | undefined, loading = false, isError = false): boolean {
  return askToggleVisible(seamAvailability(SEAM_QUERY, s, loading, isError));
}

describe('the ask toggle is shown only when something can answer (D9)', () => {
  it('is shown on an Enterprise deployment with a provider and the assistant on', () => {
    expect(visible(status())).toBe(true);
  });

  it('is HIDDEN in Core — the seam is not linked, whatever AI_PROVIDER says', () => {
    expect(visible(status({ live: false, edition_linked: false }))).toBe(false);
  });

  it('is HIDDEN when no model provider is reachable', () => {
    expect(visible(status({ live: false, provider_configured: false }))).toBe(false);
  });

  it('is HIDDEN when the tenant has switched the assistant off', () => {
    // The deployment can answer; this organization has said not to. A toggle
    // here would lead to a 403 the user cannot interpret.
    expect(visible(status({ assistant_disabled: true }))).toBe(false);
  });

  it('is HIDDEN when nobody has built the seam', () => {
    expect(visible(status({ live: false, built: false }))).toBe(false);
  });

  it('is HIDDEN while the answer is still in flight', () => {
    // The third state. Showing the toggle here would flash a control that then
    // vanishes on a Core deployment; hiding it is the one that never lies.
    expect(visible(status(), true)).toBe(false);
  });

  it('is HIDDEN when the status read failed', () => {
    // Fail closed: a read that did not complete is not evidence the capability
    // is there.
    expect(visible(undefined, false, true)).toBe(false);
  });
});

describe('readAskFailure', () => {
  it('reads a 422 as a REFUSAL carrying the diagnostics verbatim', () => {
    const got = readAskFailure(422, {
      error: 'could not be turned into a query',
      query: 'hostnaem:web*',
      attempts: 2,
      errors: [{
        code: 'unknown_field',
        message: 'no field "hostnaem" on assets',
        span: { start: 0, end: 8 },
        suggestion: 'did you mean "hostname"?',
      }],
    });

    expect(got.kind).toBe('refusal');
    if (got.kind !== 'refusal') return;
    expect(got.refusal.query).toBe('hostnaem:web*');
    expect(got.refusal.attempts).toBe(2);
    expect(got.refusal.errors).toHaveLength(1);
    // Verbatim: the span and the suggestion are what a caret and a "did you
    // mean" are drawn from, and flattening them is what "invalid query" looks
    // like from the inside.
    expect(got.refusal.errors[0].suggestion).toBe('did you mean "hostname"?');
    expect(got.refusal.errors[0].span).toEqual({ start: 0, end: 8 });
  });

  it('does NOT read a 400 as a refusal, even one carrying an errors array', () => {
    // Picked out by STATUS, not by sniffing the body. A client guessing from
    // shape would render a request bug as a language diagnostic and send the
    // user to fix a query they never wrote.
    const got = readAskFailure(400, { error: 'Invalid request body', errors: [] });
    expect(got.kind).toBe('error');
  });

  it('reads a 402 as an error carrying the platform sentence', () => {
    const got = readAskFailure(402, { error: 'Asking questions in words is part of Vista Platform Enterprise.' });
    expect(got.kind).toBe('error');
    if (got.kind !== 'error') return;
    expect(got.message).toContain('Enterprise');
  });

  it('never leaves the panel with nothing to say', () => {
    const got = readAskFailure(500, null);
    expect(got.kind).toBe('error');
    if (got.kind !== 'error') return;
    expect(got.message.length).toBeGreaterThan(0);
  });
});

describe('readableSummary', () => {
  it('strips the citation markers for display', () => {
    // They stay on the wire — they are the checkable part and the citation list
    // is derived from them — but a uuid mid-sentence is unreadable, and the
    // rows are listed directly underneath.
    const out = readableSummary('Two servers match [row:550e8400-e29b-41d4-a716-446655440000] .');
    expect(out).toBe('Two servers match.');
  });

  it('leaves prose with no markers alone', () => {
    const fixed = 'No assets matched this query.';
    expect(readableSummary(fixed)).toBe(fixed);
  });
});

describe('askRows', () => {
  it('maps the answer rows through the SAME builder search mode uses', () => {
    const answer: AskAnswer = {
      query: 'environment:production and status:monitoring',
      rows: [{
        id: '550e8400-e29b-41d4-a716-446655440000',
        display_name: 'web01',
        class_key: 'server',
        environment: 'production',
        risk_score: 0,
      } as unknown as Asset],
      text: 'One matches [row:550e8400-e29b-41d4-a716-446655440000].',
      citations: [{ kind: 'row', ref: '550e8400-e29b-41d4-a716-446655440000' }],
      tools: [{ tool: 'vistaplatform_query_assets' }],
      provenance: { source_kind: 'inferred', source_ref: 'query:model', confidence: 0, model_id: 'm1' },
    };

    const rows = askRows(answer);
    expect(rows).toHaveLength(1);
    expect(rows[0].kind).toBe('asset');
    expect(rows[0].label).toBe('web01');
    // The asset PAGE, like search mode — not a pre-filtered list the user has
    // to choose out of a second time.
    expect(rows[0].to).toBe('/inventory/assets/550e8400-e29b-41d4-a716-446655440000');
    // Score 0 with nothing that scored it is NOT ASSESSED, and must not be
    // badged as though somebody looked and found it clean.
    expect(rows[0].badge).toBeUndefined();
  });

  it('returns nothing for an answer with no rows', () => {
    expect(askRows({ rows: [] } as unknown as AskAnswer)).toEqual([]);
  });
});


// D9's "the SAME result rows", as wired rather than as available.
//
// `classesOfAssets` and `relationshipItem` being correct is worth nothing if
// the palette's ask branch does not call them — which is exactly the state this
// replaced: the builders existed, search mode used them, and ask mode returned
// `askRows(...)` alone. So this reads the component. It is a coarse guard and
// it is the one that fails when the wiring is deleted; `palette-results.test.ts`
// pins what the rows themselves say.
describe('ask mode renders the same three kinds search mode does', () => {
  const palette = readFileSync(join(new URL('.', import.meta.url).pathname, 'command-palette.tsx'), 'utf8');

  it('builds class rows from the ANSWER, not from the typed sentence', () => {
    // `matchingClasses` substring-matches the typed text, and what is typed in
    // ask mode is a question — "which switches are end of life?" matches no
    // class label. Reusing it would have rendered nothing and looked shipped.
    expect(palette).toContain('classesOfAssets(askAnswerRows)');
  });

  it('builds relationship rows in ask mode too', () => {
    expect(palette).toContain('relationshipItem(topAsset.id, name, rel)');
  });

  it('enables the relationship read on OPEN, not on the search-mode gate', () => {
    // `enabled` carries "search mode and two characters typed", which is never
    // true in ask mode. Gating the relationship query on it is what left ask
    // answers with no relationship rows at all, silently.
    expect(palette).toContain('enabled: open && !!topAsset?.id');
    expect(palette).not.toContain('enabled: enabled && !!topAsset?.id');
  });
});
