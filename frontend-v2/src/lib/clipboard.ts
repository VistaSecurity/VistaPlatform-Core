// Robust copy-to-clipboard that works in BOTH secure and insecure contexts.
//
// `navigator.clipboard` only exists in a secure context (HTTPS or localhost).
// The dev stack is reached over plain HTTP via a LAN hostname
// (e.g. http://devbox.example.com:3000), where `navigator.clipboard` is
// undefined — so we fall back to the legacy `document.execCommand('copy')`
// path via a temporary, off-screen textarea. Returns whether the copy landed.
export async function copyToClipboard(text: string): Promise<boolean> {
  // Preferred path — async Clipboard API (secure contexts).
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or blocked — fall through to the legacy path.
    }
  }

  // Fallback — works over plain HTTP. Deprecated but widely supported.
  if (typeof document === 'undefined') return false;
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
