// One place that turns an openapi-fetch result into "it worked" or a thrown,
// explainable failure. Mutations use `unwrap`; do not hand-roll `if (error)`.
//
// Why `error` alone is not enough: openapi-fetch parses the error body, and a
// 4xx/5xx with NO body (a proxy 502, a bare 403, a handler that only sets the
// status) yields a falsy `error`. `if (error) throw` then lets it through and
// the UI toasts success for a write that never happened. `response.ok` is the
// authority; `error` only supplies the reason.

/**
 * Pull a human-readable reason out of a parsed error body. Understands the
 * query-diagnostics shape (`errors: [{message, suggestion}]`), per-setting
 * `problems: string[]` and the common single-string shapes (`message` / `error` / `detail`). Returns null when the
 * body carries nothing usable, so callers can fall back to their own text.
 */
export function errorMessage(error: unknown): string | null {
  if (!error || typeof error !== 'object') return null;
  const e = error as Record<string, unknown>;
  const diagnostics = e.errors;
  if (Array.isArray(diagnostics) && diagnostics.length > 0) {
    const first = diagnostics[0] as Record<string, unknown>;
    const message = typeof first.message === 'string' ? first.message : null;
    const suggestion = typeof first.suggestion === 'string' ? first.suggestion : '';
    if (message) return suggestion ? `${message} — ${suggestion}` : message;
  }
  // `problems: string[]` — per-setting validation failures (agent/sensor config).
  const problems = e.problems;
  if (Array.isArray(problems) && problems.length > 0 && problems.every((x) => typeof x === 'string')) {
    return problems.join('; ');
  }
  for (const key of ['message', 'error', 'detail']) {
    const v = e[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

/** A failed API call. `message` is the server's reason when it gave one, else the caller's fallback. */
export class ApiError extends Error {
  readonly status: number;
  /** The parsed error body, if the server sent one (undefined for a bodiless failure). */
  readonly body: unknown;
  /** True when `message` came from the server rather than the caller's fallback. */
  readonly fromServer: boolean;
  constructor(message: string, status: number, body: unknown, fromServer: boolean) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.fromServer = fromServer;
  }
}

interface ApiResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/**
 * Return the response data, or throw an `ApiError`.
 *
 * Fails when `!response.ok` OR `error` is set, so a bodiless 4xx/5xx cannot
 * pass as success. The thrown message is the server's own reason
 * (`errorMessage(error)`) when there is one, otherwise `fallback`.
 *
 * Success with no body (204 No Content, or any ok response openapi-fetch
 * gives no `data` for) returns `undefined as T`. Callers of such endpoints
 * should type or ignore the result accordingly. Pass `{ requireData: true }`
 * for endpoints whose callers read the body: an ok response without one is
 * then treated as a failure (status preserved) instead of a later TypeError.
 */
export function unwrap<T>(result: ApiResult<T>, fallback: string, opts?: { requireData?: boolean }): T {
  const { data, error, response } = result;
  if (!response.ok || error) {
    const reason = errorMessage(error);
    throw new ApiError(reason ?? fallback, response.status, error, reason !== null);
  }
  if (opts?.requireData && (data === undefined || data === null)) {
    throw new ApiError(fallback, response.status, undefined, false);
  }
  return data as T;
}

/** The message to show for a caught mutation failure: the server's reason, the thrown text, or `fallback`. */
export function failureMessage(e: unknown, fallback: string): string {
  return e instanceof Error && e.message ? e.message : fallback;
}
