// A scope the server refused, and which half of the modal says so.
//
// Closes A2's `TODO(phase1-E)`. cbom-service answers a bad scope query with
// QUERY_LANGUAGE §10's diagnostics — `{error, query, errors[]}`, one entry per
// problem, each with a BYTE span into the echoed text — and the interim
// treatment joined them into one footer sentence. The spans exist to put a
// caret under the offending word, so they are routed to the shared renderer
// instead.
//
// What must not regress is the SPLIT: a query refusal renders inline, and
// everything else — a duplicate name, a system scope, a 500 — stays a sentence,
// because for those there is nothing to point at. Getting it wrong in either
// direction is silent: an empty diagnostics panel, or a caret nobody sees.
import { describe, expect, it } from 'vitest';
import { ScopeQueryError, throwScopeError } from './scope-modals';

/** The envelope `writeQueryError` sends. */
const queryRefusal = {
  error: 'Invalid query',
  query: 'environment:production and hostnaem:web-1',
  errors: [{
    code: 'unknown_field',
    message: 'no field "hostnaem" on assets',
    span: { start: 27, end: 35 },
    suggestion: 'did you mean "hostname"?',
  }],
};

function caught(error: unknown, fallback = 'Failed to save the scope'): unknown {
  try {
    throwScopeError(error, fallback);
  } catch (e) {
    return e;
  }
  throw new Error('throwScopeError returned instead of throwing');
}

describe('throwScopeError', () => {
  it('carries the diagnostics through for a QUERY refusal', () => {
    const e = caught(queryRefusal);
    expect(e).toBeInstanceOf(ScopeQueryError);
    const d = (e as ScopeQueryError).diagnostics;
    expect(d.query).toBe(queryRefusal.query);
    expect(d.errors).toHaveLength(1);
    expect(d.errors[0].code).toBe('unknown_field');
    expect(d.errors[0].suggestion).toBe('did you mean "hostname"?');
    // The span is left in the server's own units here. Converting is
    // `ServerQueryErrors`' job, and doing it twice would move the caret.
    expect(d.errors[0].span).toEqual({ start: 27, end: 35 });
  });

  it('is a PLAIN error for a failure that is not about the query', () => {
    // A duplicate name has no span to underline. Routing it to the diagnostics
    // panel would render an empty box where a usable sentence belongs.
    const e = caught({ error: 'A scope with that name already exists' });
    expect(e).toBeInstanceOf(Error);
    expect(e).not.toBeInstanceOf(ScopeQueryError);
    expect((e as Error).message).toBe('A scope with that name already exists');
  });

  it('falls back to the caller’s wording when the body says nothing usable', () => {
    expect((caught(undefined) as Error).message).toBe('Failed to save the scope');
    expect((caught({}) as Error).message).toBe('Failed to save the scope');
    expect((caught('a bare string') as Error).message).toBe('Failed to save the scope');
  });

  it('does NOT treat a diagnostics list with no usable span as a query refusal', () => {
    // `queryDiagnostics` drops an entry it cannot place, and an envelope left
    // with none is not something the inline renderer can show. It degrades to
    // the sentence rather than to an empty panel.
    const e = caught({ error: 'Invalid query', query: 'x', errors: [{ message: 'broken' }] });
    expect(e).not.toBeInstanceOf(ScopeQueryError);
    expect((e as Error).message).toBe('broken');
  });
});
