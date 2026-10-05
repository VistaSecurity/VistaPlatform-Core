// What a refused discovery-job Cancel/Re-run says to the person who clicked.
//
// inventory-service answers a refusal with `{ error: <code>, details: <reason> }`
// — 409 `job_not_cancellable` / `job_not_rerunnable` with the reason ("job
// already completed"), 403 with the permission it wanted. The reason is what
// the user can act on; the code ("job_not_cancellable") is for programs. A
// generic "Failed to cancel job" used to be all anyone saw, which is how a
// refused cancel read as a broken button.
export function jobActionError(error: unknown, fallback: string): Error {
  if (error && typeof error === 'object') {
    const body = error as { error?: unknown; details?: unknown };
    if (typeof body.details === 'string' && body.details.trim() !== '') return new Error(body.details);
    // A bare `error` is a sentence ("job not found") or a code ("forbidden"); only a sentence reads as one.
    if (typeof body.error === 'string' && /\s/.test(body.error)) return new Error(body.error);
  }
  return new Error(fallback);
}
