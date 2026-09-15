// The command palette's ASK mode: the client half of the Query seam
// (ADR-0006 D2/D9, ADR-0008 D1).
//
// # What the box is for, and what it is not
//
// It is a way of WRITING A QUERY by talking. The answer is a predicate you can
// read, edit, run and save; the rows are what it selected; the prose is a
// reading of the rows with a citation on every sentence. That order is the
// design, and it is why the panel shows the query first — a user who disagrees
// with the summary edits the predicate, which is only possible because the thing
// between the question and the rows is a checkable artefact rather than a hidden
// prompt.
//
// # Why a refusal is a first-class outcome here
//
// When the model cannot write a query that validates, the server answers 422
// with the validator's own diagnostics — `{code, message, span, suggestion}`,
// one per problem, spans in bytes into the attempted query. Those are shown
// VERBATIM, through the same renderer the query editor uses for a query the user
// typed, because they are the same thing: the reason a predicate was refused,
// against a predicate now sitting in an editable box. Replacing them with "could
// not answer" would throw away the only thing a person can act on.
//
// Everything here is pure or a query hook; the rendering is in
// command-palette.tsx.

import { useMutation } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { useSeamAvailability, type SeamAvailability } from '../lib/ai-seams';
import type { Diagnostic } from '../sections/inventory/query-editor';
import { assetItem, type Asset, type CommandItem } from './palette-results';

/** The seam key, as the backend's `ai.Seam` constants spell it. */
export const SEAM_QUERY = 'query';

/** One tool the answer was composed from. */
export interface AskToolCall {
  tool: string;
  args?: Record<string, unknown>;
}

/** A 200 from `POST /ask`. */
export interface AskAnswer {
  /** The CANONICAL predicate that ran, including the default scope. */
  query: string;
  rows: Asset[];
  /** The summary, with `[row:<id>]` markers still in it. */
  text: string;
  citations: { kind: string; ref: string }[];
  tools: AskToolCall[];
  provenance: { source_kind: string; source_ref: string; confidence: number; model_id?: string };
}

/** A 422 from `POST /ask`: a provider answered and could not write a valid query. */
export interface AskRefusal {
  error: string;
  /** The model's last attempt. May be absent — it produced none. */
  query?: string;
  errors: Diagnostic[];
  attempts: number;
}

/** What the panel renders. Exactly one of these three, never two. */
export type AskResult =
  | { kind: 'answer'; answer: AskAnswer }
  | { kind: 'refusal'; refusal: AskRefusal }
  | { kind: 'error'; message: string };

/**
 * Whether the ask toggle is offered at all.
 *
 * `useSeamAvailability` is already the AND of "this deployment can answer
 * through the query seam" and "this tenant has not switched the assistant off",
 * which is exactly D9's "without a provider, the toggle is not shown". A toggle
 * that led to a 403 would be worse than no toggle: the user cannot tell whether
 * they are broken or switched off.
 *
 * `loading` matters as much. Rendering the toggle before the answer arrives
 * would flash a control that then vanishes; rendering "unavailable" would tell a
 * user a capability is off when nobody has looked yet.
 */
export function useAskAvailability(): SeamAvailability {
  return useSeamAvailability(SEAM_QUERY);
}

/**
 * D9's rule, as one function: the toggle is shown only when the query seam can
 * answer for this tenant.
 *
 * It is exported and the palette calls it rather than inlining the expression,
 * so the rule can be driven from a real `/tenant/ai` payload in a test without
 * mounting React — and so changing it is a change to a function a test names,
 * rather than to an expression inside a component no unit test can reach.
 *
 * It used to read `!availability.loading && availability.available`. The
 * `loading` half never changed an answer: `seamAvailability` returns
 * `available: false` on its loading arm, and that is the only thing that builds
 * a `SeamAvailability`. It was a second statement of an invariant rather than a
 * check — and a clause that cannot change an outcome is worse than none, because
 * it reads as the thing keeping the third state honest and is not.
 *
 * What actually keeps it honest is the INVARIANT, so that is what is now
 * asserted, in `ai-seams.test.ts`: no arm of `seamAvailability` ever returns
 * loading AND available. Break that arm and the invariant test fails, which the
 * redundant clause here would have silently absorbed.
 *
 * The third state is still a third state: loading renders nothing rather than
 * an "unavailable" toggle, because saying a capability is off before anyone has
 * looked is the failure this whole area is written against. That behaviour now
 * comes from `available` being false while loading, which is where it belongs.
 */
export function askToggleVisible(availability: SeamAvailability): boolean {
  return availability.available;
}

/**
 * Reads a `POST /ask` failure into the shape the panel renders.
 *
 * The 422 is picked out by STATUS rather than by sniffing the body for an
 * `errors` key: a 400 from a malformed request carries an `error` string too,
 * and a client that guessed from shape would render a request bug as a language
 * diagnostic and send the user to fix a query they never wrote.
 */
export function readAskFailure(status: number, body: unknown): AskResult {
  const asObject = (body ?? {}) as Record<string, unknown>;
  if (status === 422 && Array.isArray(asObject.errors)) {
    return {
      kind: 'refusal',
      refusal: {
        error: typeof asObject.error === 'string' ? asObject.error : 'That question could not be turned into a query.',
        query: typeof asObject.query === 'string' ? asObject.query : undefined,
        errors: asObject.errors as Diagnostic[],
        attempts: typeof asObject.attempts === 'number' ? asObject.attempts : 0,
      },
    };
  }
  const message = typeof asObject.error === 'string' && asObject.error !== ''
    ? asObject.error
    : 'Nothing was asked — the request did not complete.';
  return { kind: 'error', message };
}

/**
 * The rows an answer selected, as palette result rows.
 *
 * The SAME builder search mode uses (`assetItem`), which is the whole of D9's
 * "renders the tool results as the same result rows". A separate ask-mode row
 * renderer would be a second thing to keep correct and the first place the two
 * modes would start to disagree about what an asset looks like.
 */
export function askRows(answer: AskAnswer): CommandItem[] {
  return (answer.rows ?? []).map(assetItem);
}

/**
 * The summary with its citation markers removed, for display.
 *
 * The markers are kept on the wire — they are the checkable part, and the
 * citation list is derived from them — but `[row:550e8400-…]` mid-sentence is
 * unreadable. The rows are listed directly underneath, so the citation is
 * discharged by the panel's layout rather than by an inline marker.
 */
export function readableSummary(text: string): string {
  return text.replace(/\[row:[A-Za-z0-9_-]{1,64}\]/g, '').replace(/\s+([.,;:])/g, '$1').replace(/[ \t]{2,}/g, ' ').trim();
}

/**
 * The ask mutation.
 *
 * A mutation and not a query: a question is an action with a cost — it spends
 * the tenant's model budget — so it runs when the user presses Enter and never
 * on a keystroke, a refocus or a cache revalidation. react-query would happily
 * refetch a `useQuery` on any of those.
 */
export function useAsk() {
  return useMutation<AskResult, Error, string>({
    mutationFn: async (question: string): Promise<AskResult> => {
      const { data, error, response } = await clients.inventory.POST('/ask', {
        body: { question },
      });
      if (data) return { kind: 'answer', answer: data };
      return readAskFailure(response?.status ?? 0, error);
    },
  });
}
