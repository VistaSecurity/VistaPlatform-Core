// Generic-webhook connection options: how Vista authenticates to the receiver
// (none / bearer token / basic / one custom header) and the HMAC signing secret.
//
// The delivery service has always understood `auth` ({type, token | username +
// password}) and `headers`, but the form only exposed the URL — so a receiver
// that needed an Authorization header could not be configured from the UI.
//
// Every value here is a credential, and the API never returns one: it comes back
// masked (`••••wxyz`). So nothing is prefilled — a blank credential on EDIT means
// "keep the stored value" (the server treats an omitted / blank / still-masked
// credential as unchanged; see notification-service channel_secrets.go). A
// CHANGE of mode or header name is a genuinely new credential and must be
// entered.
//
// The signing secret (`config.webhook_secret`) is write-only the same way. On
// create, leaving it blank makes the server generate one and return it ONCE.
// On edit, entering a new value rotates it.
//
// Kept DOM-free so the request the modal builds is unit-testable.

export type WebhookAuthMode = 'none' | 'bearer' | 'basic' | 'header';

export type WebhookOptions = {
  mode: WebhookAuthMode;
  token: string;
  username: string;
  password: string;
  headerName: string;
  headerValue: string;
  /** New signing secret. Blank = keep the stored one (edit) / let the server generate (create). */
  signingSecret: string;
};

export const WEBHOOK_AUTH_MODES: Array<{ value: WebhookAuthMode; label: string }> = [
  { value: 'none', label: 'None' },
  { value: 'bearer', label: 'Bearer token' },
  { value: 'basic', label: 'Basic (username + password)' },
  { value: 'header', label: 'Custom header' },
];

type Cfg = Record<string, unknown> | null | undefined;

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** The mode a stored (masked) config is in. */
export function webhookModeOf(existing: Cfg): WebhookAuthMode {
  const auth = asObject(existing?.auth);
  if (auth?.type === 'bearer') return 'bearer';
  if (auth?.type === 'basic') return 'basic';
  const headers = asObject(existing?.headers);
  if (headers && Object.keys(headers).length > 0) return 'header';
  return 'none';
}

/** The first stored header name (values are masked, names are not secret). */
function storedHeaderName(existing: Cfg): string {
  const headers = asObject(existing?.headers);
  return headers ? Object.keys(headers)[0] ?? '' : '';
}

/** Form state for a channel being edited (or a fresh one). No credential is prefilled. */
export function initialWebhookOptions(existing: Cfg): WebhookOptions {
  const mode = webhookModeOf(existing);
  return {
    mode,
    token: '',
    username: '',
    password: '',
    headerName: mode === 'header' ? storedHeaderName(existing) : '',
    headerValue: '',
    signingSecret: '',
  };
}

// RFC 9110 token characters — what an HTTP header name may contain.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Why these options cannot be saved yet, or null. On edit, a blank credential
 * is fine ONLY when it keeps a stored one of the same kind.
 */
export function webhookOptionsError(opts: WebhookOptions, existing: Cfg, isEdit: boolean): string | null {
  const sameMode = isEdit && webhookModeOf(existing) === opts.mode;
  switch (opts.mode) {
    case 'bearer':
      if (!opts.token.trim() && !sameMode) return 'Enter the bearer token.';
      return null;
    case 'basic':
      if (!opts.username.trim() && !sameMode) return 'Enter the username.';
      if (!opts.password.trim() && !sameMode) return 'Enter the password.';
      return null;
    case 'header': {
      const name = opts.headerName.trim();
      if (!name) return 'Enter the header name.';
      if (!HEADER_NAME.test(name)) return 'That is not a valid HTTP header name.';
      const sameHeader = sameMode && name.toLowerCase() === storedHeaderName(existing).toLowerCase();
      if (!opts.headerValue.trim() && !sameHeader) return 'Enter the header value.';
      return null;
    }
    default:
      return null;
  }
}

/**
 * The webhook credential part of the config to POST/PUT, merged over `config`
 * (which already carries the URL and any keys the form does not expose).
 *
 *  - mode none: `auth` and `headers` are REMOVED (a config that omits a whole
 *    nested object removes it).
 *  - a blank credential on edit is left OUT, so the server keeps the stored one.
 *  - the signing secret is sent only when the user typed one.
 */
export function applyWebhookOptions(config: Record<string, unknown>, opts: WebhookOptions): Record<string, unknown> {
  const out: Record<string, unknown> = { ...config };
  delete out.auth;
  delete out.headers;
  // Never let a masked signing secret carried from the GET ride along as if new.
  delete out.webhook_secret;

  switch (opts.mode) {
    case 'bearer': {
      const auth: Record<string, unknown> = { type: 'bearer' };
      if (opts.token.trim()) auth.token = opts.token.trim();
      out.auth = auth;
      break;
    }
    case 'basic': {
      const auth: Record<string, unknown> = { type: 'basic' };
      if (opts.username.trim()) auth.username = opts.username.trim();
      if (opts.password.trim()) auth.password = opts.password;
      out.auth = auth;
      break;
    }
    case 'header': {
      const name = opts.headerName.trim();
      // Blank value + same stored header on edit: send it blank so the server keeps the stored value.
      out.headers = { [name]: opts.headerValue.trim() };
      break;
    }
    default:
      break;
  }

  // Blank keeps the stored secret: the server restores an omitted credential, so
  // leaving the key out is exactly "unchanged" (edit), or "generate one" (create).
  if (opts.signingSecret.trim()) out.webhook_secret = opts.signingSecret.trim();
  return out;
}

/** How many custom headers the stored config has (the form edits exactly one). */
export function storedHeaderCount(existing: Cfg): number {
  const headers = asObject(existing?.headers);
  return headers ? Object.keys(headers).length : 0;
}

/** A fresh signing secret in the same shape the server generates. */
export function generateSigningSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return 'whsec_' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
