// @vitest-environment jsdom
//
// PARITY CONTRACT between the tenant auth stack (auth/*, rbac/context.tsx) and
// the platform auth stack (platform-auth/*, platform-auth/rbac.tsx).
//
// The two stacks are deliberately WHOLLY SEPARATE and share no code. The
// compliance reason: a tenant session and a platform-admin session are
// different trust domains (different credentials, cookie families, services
// and audit scopes), and the platform-admin path must be reviewable, and
// changeable, without touching code that every tenant request runs through.
// Sharing a generic session provider would couple the two blast radii.
//
// Separate code drifts, though (: the platform copy treated a bodiless
// 500 on changePassword as success; the tenant copy was fine). This file is
// the contract that keeps them honest: every behavioural case below is driven
// through BOTH stacks via an adapter and must produce the same outcome. Only
// the genuine differences (cookie name, endpoint paths, response shapes, the
// force_password_change flag) are adapter INPUTS, never per-case exceptions.
//
// A second, static guard fails when a name exported by one stack has no
// counterpart (or a declared reason for none) in the other, so adding
// behaviour to one side forces an explicit decision about the other.
import { act, createElement, type ReactNode } from 'react';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider, useAuth } from './auth';
import { PermissionProvider, usePermissions } from './rbac';
import { PlatformAuthProvider, usePlatformAuth } from './platform-auth';
import { PlatformPermissionProvider, usePlatformPermissions } from './platform-auth/rbac';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// ---------------------------------------------------------------- adapters --

interface Session {
  user: unknown;
  isAuthenticated: boolean;
  isInitializing: boolean;
  login(email: string, password: string): Promise<void>;
  logout(): Promise<void>;
  changePassword?(cur: string, next: string, confirm: string): Promise<void>;
  forcePasswordChange?: boolean;
}
interface Perms {
  permissions: string[];
  isLoading: boolean;
  isError: boolean;
  hasPermission(p: string): boolean;
  hasAnyPermission(ps: string[]): boolean;
  hasAllPermissions(ps: string[]): boolean;
}
interface Notifier { success: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn>; info: ReturnType<typeof vi.fn>; warning: ReturnType<typeof vi.fn> }

interface Adapter {
  name: string;
  cookie: string;
  paths: { login: string; me: string; logout: string; refresh: string; permissions: string; changePassword?: string };
  userBody(forcePasswordChange: boolean): unknown;
  loginBody: unknown;
  permissionsBody(names: string[]): unknown;
  /** Whether this stack has a force_password_change concept at all. */
  hasForcePasswordChange: boolean;
  AuthProvider: (p: Record<string, unknown>) => ReactNode;
  useSession(): Session;
  PermProvider: (p: Record<string, unknown>) => ReactNode;
  usePerms(): Perms;
}

const tenant: Adapter = {
  name: 'tenant',
  cookie: 'csrf_token',
  paths: { login: '/auth/login', me: '/auth/me', logout: '/auth/logout', refresh: '/auth/refresh', permissions: '/user/permissions' },
  userBody: () => ({ user: { id: 'u1', email: 'a@b.c' }, tenant: { id: 't1', name: 'T' } }),
  loginBody: { user: { id: 'u1', email: 'a@b.c' } },
  permissionsBody: (names) => ({ permissions: names }),
  hasForcePasswordChange: false,
  AuthProvider: AuthProvider as unknown as Adapter['AuthProvider'],
  useSession: () => useAuth() as unknown as Session,
  PermProvider: PermissionProvider as unknown as Adapter['PermProvider'],
  usePerms: () => usePermissions(),
};

const platform: Adapter = {
  name: 'platform',
  cookie: 'platform_csrf_token',
  paths: {
    login: '/auth/login', me: '/admin/auth/me', logout: '/admin/auth/logout', refresh: '/auth/refresh',
    permissions: '/admin/user/permissions', changePassword: '/admin/auth/change-password',
  },
  userBody: (force) => ({ user: { id: 'u1', email: 'a@b.c', force_password_change: force } }),
  loginBody: { user: { id: 'u1', email: 'a@b.c' } },
  permissionsBody: (names) => ({ permissions: names.map((name) => ({ name })) }),
  hasForcePasswordChange: true,
  AuthProvider: PlatformAuthProvider as unknown as Adapter['AuthProvider'],
  useSession: () => usePlatformAuth() as unknown as Session,
  PermProvider: PlatformPermissionProvider as unknown as Adapter['PermProvider'],
  usePerms: () => usePlatformPermissions(),
};

// ------------------------------------------------------------- test harness --

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const bodiless = (status: number) => new Response(null, { status });

type Handler = () => Response;
function stubFetch(a: Adapter, handlers: Partial<Record<keyof Adapter['paths'], Handler>>) {
  const fn = vi.fn(async (input: Request | string) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    for (const [key, path] of Object.entries(a.paths)) {
      if (url.pathname.endsWith(path) && handlers[key as keyof Adapter['paths']]) {
        return handlers[key as keyof Adapter['paths']]!();
      }
    }
    return json({}, 404);
  });
  vi.stubGlobal('fetch', fn);
  // The permission providers build their client with the contract's default
  // RELATIVE base URL, which node's Request rejects outside a browser.
  const NativeRequest = globalThis.Request;
  vi.stubGlobal('Request', class extends NativeRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(typeof input === 'string' && input.startsWith('/') ? `http://api.test${input}` : input, init);
    }
  });
  return fn;
}

const setCookie = (name: string) => { document.cookie = `${name}=t; path=/`; };
const hasCookie = (name: string) => document.cookie.split('; ').some((c) => c.startsWith(`${name}=`));
const clearCookie = (name: string) => { document.cookie = `${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`; };

interface Mounted {
  session: { current?: Session };
  perms: { current?: Perms };
  queryClient: QueryClient;
  notifier: Notifier;
  onUnauthenticated: ReturnType<typeof vi.fn>;
  rerender(): Promise<void>;
  renders: { session: Session[]; perms: Perms[] };
}

let container: HTMLDivElement;
let root: Root;
beforeEach(() => { container = document.createElement('div'); root = createRoot(container); });
afterEach(() => {
  act(() => root.unmount());
  vi.unstubAllGlobals();
  clearCookie('csrf_token');
  clearCookie('platform_csrf_token');
});

async function mount(a: Adapter, opts: { withPerms?: boolean } = {}): Promise<Mounted> {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const session: { current?: Session } = {};
  const perms: { current?: Perms } = {};
  const renders = { session: [] as Session[], perms: [] as Perms[] };
  const notifier: Notifier = { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() };
  const onUnauthenticated = vi.fn();
  function SessionProbe() { session.current = a.useSession(); renders.session.push(session.current); return null; }
  function PermProbe() { perms.current = a.usePerms(); renders.perms.push(perms.current); return null; }
  // Stable element identities, so a re-render of the tree presents the SAME props.
  const sessionProbe = createElement(SessionProbe);
  const permProbe = createElement(PermProbe);
  const permTree = createElement(a.PermProvider, { children: permProbe });
  const tree = () => createElement(QueryClientProvider, { client: queryClient },
    createElement(a.AuthProvider, { baseUrl: 'http://api.test', notifier, onUnauthenticated, children: [sessionProbe, opts.withPerms ? permTree : null] }));
  await act(async () => { root.render(tree()); });
  return {
    session, perms, queryClient, notifier, onUnauthenticated, renders,
    rerender: async () => { await act(async () => { root.render(tree()); }); },
  };
}

// ------------------------------------------------------------------ matrix ---

describe.each([tenant, platform])('auth parity: $name stack', (a) => {
  it('login success sets the session and clears the query cache', async () => {
    stubFetch(a, {
      login: () => { setCookie(a.cookie); return json(a.loginBody); },
      me: () => json(a.userBody(false)),
    });
    const m = await mount(a);
    m.queryClient.setQueryData(['stale'], 'x');
    expect(m.session.current!.isAuthenticated).toBe(false);

    await act(async () => { await m.session.current!.login('a@b.c', 'pw'); });

    expect(m.session.current!.user).toMatchObject({ id: 'u1' });
    expect(m.session.current!.isAuthenticated).toBe(true);
    expect(m.queryClient.getQueryData(['stale'])).toBeUndefined();
    expect(m.notifier.success).toHaveBeenCalledWith('Signed in');
  });

  it('login with a bodiless 500 throws and leaves state unchanged', async () => {
    stubFetch(a, { login: () => bodiless(500), me: () => json(a.userBody(false)) });
    const m = await mount(a);
    m.queryClient.setQueryData(['keep'], 'x');

    await act(async () => { await expect(m.session.current!.login('a@b.c', 'pw')).rejects.toThrow(); });

    expect(m.session.current!.user).toBeNull();
    expect(m.session.current!.isAuthenticated).toBe(false);
    expect(m.queryClient.getQueryData(['keep'])).toBe('x');
    expect(m.notifier.success).not.toHaveBeenCalled();
    expect(m.notifier.error).toHaveBeenCalled();
  });

  it('changePassword with a bodiless 500 throws and leaves force_password_change unchanged', async () => {
    setCookie(a.cookie);
    const forced = a.hasForcePasswordChange;
    stubFetch(a, {
      me: () => json(a.userBody(true)),
      ...(a.paths.changePassword ? { changePassword: () => bodiless(500) } : {}),
    });
    const m = await mount(a);
    await vi.waitFor(() => expect(m.session.current!.user).not.toBeNull());

    if (!a.paths.changePassword) {
      // The tenant stack has no change-password flow. If one is added, this
      // fails and the new flow must be driven through the same case.
      expect(m.session.current!.changePassword).toBeUndefined();
      expect(m.session.current!.forcePasswordChange).toBeUndefined();
      return;
    }
    expect(m.session.current!.forcePasswordChange).toBe(forced);
    await act(async () => { await expect(m.session.current!.changePassword!('a', 'b', 'b')).rejects.toThrow(); });
    expect(m.session.current!.forcePasswordChange).toBe(true);
    expect(m.notifier.success).not.toHaveBeenCalledWith('Password changed');
  });

  it('logout clears the cache and the session', async () => {
    setCookie(a.cookie);
    stubFetch(a, { me: () => json(a.userBody(false)), logout: () => json({}) });
    const m = await mount(a);
    await vi.waitFor(() => expect(m.session.current!.isAuthenticated).toBe(true));
    m.queryClient.setQueryData(['stale'], 'x');

    await act(async () => { await m.session.current!.logout(); });

    expect(m.session.current!.user).toBeNull();
    expect(m.session.current!.isAuthenticated).toBe(false);
    expect(hasCookie(a.cookie)).toBe(false);
    expect(m.queryClient.getQueryData(['stale'])).toBeUndefined();
    expect(m.onUnauthenticated).toHaveBeenCalledTimes(1);
  });

  it('logout still clears locally when the server call fails', async () => {
    setCookie(a.cookie);
    stubFetch(a, { me: () => json(a.userBody(false)), logout: () => bodiless(500) });
    const m = await mount(a);
    await vi.waitFor(() => expect(m.session.current!.isAuthenticated).toBe(true));

    await act(async () => { await m.session.current!.logout(); });

    expect(m.session.current!.isAuthenticated).toBe(false);
    expect(hasCookie(a.cookie)).toBe(false);
  });

  it('session init on a 401 (me and refresh) ends logged-out', async () => {
    setCookie(a.cookie);
    stubFetch(a, { me: () => bodiless(401), refresh: () => bodiless(401) });
    const m = await mount(a);
    await vi.waitFor(() => expect(m.session.current!.isInitializing).toBe(false));

    expect(m.session.current!.user).toBeNull();
    expect(m.session.current!.isAuthenticated).toBe(false);
    expect(hasCookie(a.cookie)).toBe(false);
  });

  it('session init with no session cookie never calls the server', async () => {
    const f = stubFetch(a, { me: () => json(a.userBody(false)) });
    const m = await mount(a);
    await vi.waitFor(() => expect(m.session.current!.isInitializing).toBe(false));
    expect(m.session.current!.isAuthenticated).toBe(false);
    expect(f).not.toHaveBeenCalled();
  });

  it('permission provider on a 500 exposes isError and fails closed', async () => {
    stubFetch(a, { permissions: () => bodiless(500) });
    const m = await mount(a, { withPerms: true });
    await vi.waitFor(() => expect(m.perms.current!.isError).toBe(true));

    expect(m.perms.current!.permissions).toEqual([]);
    expect(m.perms.current!.hasPermission('assets.read')).toBe(false);
    expect(m.perms.current!.hasAnyPermission(['assets.read'])).toBe(false);
    // allOf over a non-empty list also denies; the empty list is vacuous in both.
    expect(m.perms.current!.hasAllPermissions(['assets.read'])).toBe(false);
  });

  it('hasPermission / hasAnyPermission / hasAllPermissions evaluate the same for the same grants', async () => {
    stubFetch(a, { permissions: () => json(a.permissionsBody(['a.read', 'b.write'])) });
    const m = await mount(a, { withPerms: true });
    await vi.waitFor(() => expect(m.perms.current!.permissions).toEqual(['a.read', 'b.write']));
    const p = m.perms.current!;

    const observed = {
      has: [p.hasPermission('a.read'), p.hasPermission('c.x'), p.hasPermission('')],
      any: [p.hasAnyPermission(['c.x', 'b.write']), p.hasAnyPermission(['c.x']), p.hasAnyPermission([])],
      all: [p.hasAllPermissions(['a.read', 'b.write']), p.hasAllPermissions(['a.read', 'c.x']), p.hasAllPermissions([])],
    };
    expect(observed).toEqual({
      has: [true, false, false],
      any: [true, false, false],
      all: [true, false, true],
    });
  });

  it('provider values are referentially stable across re-renders with the same props', async () => {
    setCookie(a.cookie);
    stubFetch(a, { me: () => json(a.userBody(false)), permissions: () => json(a.permissionsBody(['a.read'])) });
    const m = await mount(a, { withPerms: true });
    await vi.waitFor(() => expect(m.session.current!.isAuthenticated).toBe(true));
    await vi.waitFor(() => expect(m.perms.current!.permissions).toEqual(['a.read']));

    const permBefore = m.perms.current!;
    const { login, logout, changePassword } = m.session.current!;
    await m.rerender();
    await m.rerender();

    expect(m.perms.current).toBe(permBefore);
    expect(m.perms.current!.hasPermission).toBe(permBefore.hasPermission);
    expect(m.session.current!.login).toBe(login);
    expect(m.session.current!.logout).toBe(logout);
    expect(m.session.current!.changePassword).toBe(changePassword);
  });
});

// ------------------------------------------------------------ static guard ---

// tenant export -> platform counterpart. `null` = intentionally one-sided, with
// the reason. Adding an export to either index.ts fails this guard until the
// table says what the other stack does about it.
const TENANT_TO_PLATFORM: Record<string, string | null> = {
  tokenManager: 'platformTokenManager',
  createAuthClient: 'createPlatformAuthClient',
  AuthClient: 'PlatformAuthClient',
  AuthResponse: 'PlatformLoginResponse',
  MeResponse: 'CurrentPlatformUser',
  AuthUser: 'PlatformUser',
  AuthProvider: 'PlatformAuthProvider',
  useAuth: 'usePlatformAuth',
  AuthState: 'PlatformAuthState',
  AuthProviderProps: 'PlatformAuthProviderProps',
  PermissionProvider: 'PlatformPermissionProvider',
  usePermissions: 'usePlatformPermissions',
  PermissionGate: 'PlatformPermissionGate',
  PermissionState: 'PlatformPermissionState',
  PermissionProviderProps: 'PlatformPermissionProviderProps',
  PermissionGateProps: 'PlatformPermissionGateProps',
  TENANT_PERMISSIONS: 'PLATFORM_PERMISSIONS',
  TenantPermissionKey: 'PlatformPermissionKey',
  // One-sided by design:
  AuthTenant: null, // a platform session has no tenant
  //: only the TENANT sign-in can be handed a platform account; the platform
  // sign-in has no tenant analogue to refuse, so there is nothing to mirror.
  PlatformAccountError: null,
  PLATFORM_ACCOUNT_CODE: null,
  // The tenant inventory lens keys a remembered column choice by user and must
  // render without a provider; admin-ui has no such per-user convenience yet.
  useOptionalAuth: null,
  // Legacy tenant wire types from auth/types.ts (web-ui shapes), no platform analogue:
  ApiResponse: null, User: null, Tenant: null, AuthResponseType: null,
  LoginRequest: null, RegisterRequest: null, AuthContextType: null,
};
// Platform exports with no tenant counterpart, and why.
const PLATFORM_ONLY: Record<string, string> = {
  PLATFORM_CSRF_COOKIE: 'tenant cookie name is private to auth/token.ts',
};

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/** Names exported by an index.ts, values and types alike (types are erased at runtime). */
function exportedNames(path: string): Set<string> {
  const src = readFileSync(here(path), 'utf8').replace(/\/\/.*$/gm, '');
  const names = new Set<string>();
  for (const m of src.matchAll(/export\s+(?:type\s+)?\{([^}]*)\}/g)) {
    for (const part of m[1].split(',')) {
      const t = part.trim();
      if (!t) continue;
      const alias = t.split(/\s+as\s+/).pop()!.trim();
      names.add(alias);
    }
  }
  return names;
}

describe('auth parity: exports have counterparts', () => {
  const tenantExports = new Set([...exportedNames('./auth/index.ts'), ...exportedNames('./rbac/index.ts')]);
  const platformExports = exportedNames('./platform-auth/index.ts');

  it('parses a non-trivial export set from both stacks (the guard cannot be inert)', () => {
    expect(tenantExports.size).toBeGreaterThan(10);
    expect(platformExports.size).toBeGreaterThan(10);
    expect(tenantExports.has('AuthProvider')).toBe(true);
    expect(platformExports.has('PlatformAuthProvider')).toBe(true);
  });

  it('every tenant export is classified, and its platform counterpart exists', () => {
    const unclassified = [...tenantExports].filter((n) => !(n in TENANT_TO_PLATFORM));
    expect(unclassified, 'tenant exports with no counterpart decision').toEqual([]);
    const missing = Object.entries(TENANT_TO_PLATFORM)
      .filter(([t, p]) => p !== null && tenantExports.has(t) && !platformExports.has(p))
      .map(([t, p]) => `${t} -> ${p}`);
    expect(missing, 'platform counterparts not exported').toEqual([]);
  });

  it('every platform export is the counterpart of a tenant export, or declared platform-only', () => {
    const mapped = new Set(Object.values(TENANT_TO_PLATFORM).filter((p): p is string => p !== null));
    const orphans = [...platformExports].filter((n) => !mapped.has(n) && !(n in PLATFORM_ONLY));
    expect(orphans, 'platform exports with no tenant counterpart decision').toEqual([]);
  });

  it('the table has no stale entries', () => {
    const stale = [
      ...Object.keys(TENANT_TO_PLATFORM).filter((n) => !tenantExports.has(n)),
      ...Object.keys(PLATFORM_ONLY).filter((n) => !platformExports.has(n)),
    ];
    expect(stale).toEqual([]);
  });
});
