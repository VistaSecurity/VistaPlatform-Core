// Pure helpers behind Settings → People & Access → Roles & Permissions.
// Kept out of the .tsx so they are unit-testable — the frontend-v2 vitest setup
// is node-environment with no jsdom/react harness, so anything worth pinning has
// to be a function, not a rendered tree.
//
// Two INDEPENDENT locks govern a permission checkbox, and conflating them is the
// bug this module exists to prevent:
//
//  1. `editable` (role-level) — false for built-in roles. The seed's
//     reconciliation block re-asserts the canonical grant set for every
//     is_system_role=true role on every helm upgrade and every tenant
//     onboarding, so an accepted edit would be silently reverted. The backend
//     refuses all three write verbs with 403 `system_role_immutable`; the UI
//     renders the whole matrix read-only rather than letting the user try.
//  2. `grantable` (per-permission) — false when the CALLING user does not hold
//     that permission themselves. Without this guard `users.manage` is a de
//     facto superuser permission (mint a role carrying anything, assign it to
//     yourself). `granted && !grantable` is a legitimate state: the role keeps
//     it, the caller could not have added it.
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';

export type MatrixRow = AuthC['schemas']['MatrixPermission'];
export type TenantRole = AuthC['schemas']['Role'];

/** Stable machine-readable discriminators from RoleErrorResponse.code. */
export type RoleErrorCode =
  | 'role_not_found'
  | 'system_role_immutable'
  | 'permission_not_held'
  | 'unknown_permissions'
  | 'invalid_permission_id'
  | 'invalid_role_name'
  | 'role_name_conflict'
  | 'role_in_use'
  | 'reassign_to_self'
  | 'role_referenced_by_sso';

/**
 * A rejected role request. The typed client hands back a plain RoleErrorResponse
 * body, but throwing a bare object loses the stack and trips
 * `@typescript-eslint/only-throw-error`, so mutations wrap it: the body stays
 * reachable at `.body` and every reader below unwraps it transparently.
 */
export class RoleApiError extends Error {
  readonly body: unknown;
  constructor(body: unknown, fallback: string) {
    super(roleErrorMessage(body, fallback));
    this.name = 'RoleApiError';
    this.body = body;
  }
}

function asRecord(err: unknown): Record<string, unknown> | null {
  if (!err || typeof err !== 'object') return null;
  const rec = err as Record<string, unknown>;
  // Unwrap RoleApiError so callers can pass either the raw body or the throw.
  if (rec.body && typeof rec.body === 'object') return rec.body as Record<string, unknown>;
  return rec;
}

/**
 * The stable `code` off a RoleErrorResponse. ALWAYS branch on this, never on the
 * human message — the message is copy and will be reworded.
 */
export function roleErrorCode(err: unknown): RoleErrorCode | undefined {
  const c = asRecord(err)?.code;
  return typeof c === 'string' && c ? (c as RoleErrorCode) : undefined;
}

/** Human-readable message, falling back when the body isn't a role error. */
export function roleErrorMessage(err: unknown, fallback: string): string {
  const e = asRecord(err)?.error;
  if (typeof e === 'string' && e.trim()) return e;
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

/** `user_count` off a 409 `role_in_use`. */
export function roleErrorUserCount(err: unknown): number | undefined {
  const n = asRecord(err)?.user_count;
  return typeof n === 'number' ? n : undefined;
}

/** `missing_permissions` off a 403 `permission_not_held`. */
export function roleErrorMissingPermissions(err: unknown): string[] {
  const m = asRecord(err)?.missing_permissions;
  return Array.isArray(m) ? m.filter((x): x is string => typeof x === 'string') : [];
}

// --- permission lock states ---------------------------------------------------

export type PermissionLock =
  /** Toggleable: the role is custom and the caller holds the permission. */
  | 'editable'
  /** Built-in role — the whole matrix is read-only. */
  | 'system'
  /** Caller doesn't hold this permission, so they may neither add nor drop it. */
  | 'not-held';

export function permissionLock(row: Pick<MatrixRow, 'grantable'>, editable: boolean): PermissionLock {
  if (!editable) return 'system';
  if (!row.grantable) return 'not-held';
  return 'editable';
}

export function isLocked(lock: PermissionLock): boolean {
  return lock !== 'editable';
}

/**
 * Why a control is locked, for the hover title / inline note. Returns undefined
 * for an editable row so callers can spread it into `title` without a branch.
 */
export function lockReason(lock: PermissionLock, granted: boolean): string | undefined {
  if (lock === 'system') {
    return 'Built-in role — the platform re-applies its permissions on every upgrade, so this set is fixed.';
  }
  if (lock === 'not-held') {
    return granted
      ? "You don't hold this permission yourself, so you can't change it here. The role keeps it."
      : "You can't grant a permission you don't hold yourself.";
  }
  return undefined;
}

// --- matrix shaping -----------------------------------------------------------

export interface ResourceGroup { resource: string; rows: MatrixRow[] }

/**
 * Group the catalogue by `resource` for the grid. The API already returns rows
 * ordered by resource then action; this preserves that order rather than
 * re-sorting, so the UI and the API agree on what "first" means.
 */
export function groupByResource(rows: MatrixRow[]): ResourceGroup[] {
  const out: ResourceGroup[] = [];
  const index = new Map<string, ResourceGroup>();
  for (const r of rows) {
    const key = r.resource || 'other';
    let g = index.get(key);
    if (!g) {
      g = { resource: key, rows: [] };
      index.set(key, g);
      out.push(g);
    }
    g.rows.push(r);
  }
  return out;
}

/** The ids the role grants today — the checkbox set the drawer opens with. */
export function grantedIds(rows: MatrixRow[]): Set<string> {
  return new Set(rows.filter((r) => r.granted).map((r) => r.id));
}

/**
 * What to PUT. The endpoint REPLACES the grant set, so a locked-but-granted row
 * must be carried through explicitly or saving would silently strip permissions
 * the caller was never allowed to touch.
 */
export function permissionIdsToSubmit(rows: MatrixRow[], selected: Set<string>, editable: boolean): string[] {
  const out: string[] = [];
  for (const r of rows) {
    const locked = isLocked(permissionLock(r, editable));
    if (locked ? r.granted : selected.has(r.id)) out.push(r.id);
  }
  return out;
}

/** Has the user actually changed anything? Drives the Save button's enabled state. */
export function isDirty(rows: MatrixRow[], selected: Set<string>, editable: boolean): boolean {
  const next = permissionIdsToSubmit(rows, selected, editable);
  const before = rows.filter((r) => r.granted).map((r) => r.id);
  if (next.length !== before.length) return true;
  const has = new Set(next);
  return before.some((id) => !has.has(id));
}

// --- delete flow --------------------------------------------------------------

export type DeleteStep =
  /** Bare confirm — no attempt made yet, or a retriable failure. */
  | 'confirm'
  /** 409 role_in_use: pick a role to move the holders to, then retry. */
  | 'reassign'
  /** 409 role_referenced_by_sso: no retry helps; the SSO mapping must change first. */
  | 'sso-blocked';

/**
 * Where the delete dialog goes after a failed attempt. `role_in_use` is the only
 * failure with a retry the UI can offer; `role_referenced_by_sso` is terminal
 * here because reassigning holders doesn't clear the mapping reference.
 */
export function nextDeleteStep(code: RoleErrorCode | undefined): DeleteStep {
  if (code === 'role_in_use') return 'reassign';
  if (code === 'role_referenced_by_sso') return 'sso-blocked';
  return 'confirm';
}

/** Roles a holder may be moved to — anything in the tenant except the doomed role. */
export function reassignTargets(roles: TenantRole[], deletingId: string): TenantRole[] {
  return roles.filter((r) => r.id !== deletingId);
}

/**
 * Slug preview for the create form. Mirrors the server's derivation so the user
 * sees the immutable `name` before committing to it; the server remains the
 * authority and will reject anything that doesn't match `^[a-z][a-z0-9_]{1,49}$`.
 */
export function slugifyRoleName(displayName: string): string {
  const slug = displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 50);
  return slug;
}

/** Does a derived/typed slug satisfy the server's rule? Used for inline validation. */
export function isValidRoleName(name: string): boolean {
  return /^[a-z][a-z0-9_]{1,49}$/.test(name);
}
