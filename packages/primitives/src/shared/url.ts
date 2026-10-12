// Guard server-supplied URLs (catalogue rows, AI proposals, vendor feeds) before they go into an href. Only absolute http(s)
// is allowed, so a tampered `javascript:` / `data:` / `vbscript:` value
// cannot execute when the link is clicked. Returns the normalized URL, or null
// when it is not a safe http(s) link (callers render plain text instead).
export function safeHttpUrl(raw?: string | null): string | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw); // absolute only — relative/scheme-relative throw and are rejected
  } catch {
    return null;
  }
  return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
}
