// Guard URLs that come from data (catalogue rows, AI proposals, vendor feeds)
// before they go into an href. Only absolute http(s) is allowed, so a stored
// `javascript:` / `data:` / `vbscript:` value cannot execute when an operator
// clicks the link. Returns the normalized URL, or null when it is not a safe
// http(s) link — callers then render plain text instead. Same rule as
// frontend-v2/src/lib/url.ts; the two apps do not share a lib package.
export function safeHttpUrl(raw?: string | null): string | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw); // absolute only: relative and scheme-relative values throw
  } catch {
    return null;
  }
  return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
}
