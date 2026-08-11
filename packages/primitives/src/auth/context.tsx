// AuthProvider / useAuth — session state for the new UI. Headless: takes a
// notifier and an onUnauthenticated callback as props so it never imports a
// toast library or a router. Clean re-implementation of web-ui's session flow
// (init → me, login, logout, refresh-on-init-failure).
import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { INotifier } from '../shared/di';
import { tokenManager } from './token';
import { createAuthClient, type AuthClient, type AuthUser, type AuthTenant } from './client';

export interface AuthState {
  user: AuthUser | null;
  tenant: AuthTenant | null;
  isAuthenticated: boolean;
  /** True during the initial session-restoration check on app startup. */
  isInitializing: boolean;
  isLoginLoading: boolean;
  login(email: string, password: string): Promise<void>;
  logout(): Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}

export interface AuthProviderProps {
  children: React.ReactNode;
  /** Optional user-facing notifier (e.g. react-hot-toast wrapper). */
  notifier?: INotifier;
  /** Called after logout / when the session is found dead. App handles navigation. */
  onUnauthenticated?: () => void;
  /** Override the auth-service base URL (tests). */
  baseUrl?: string;
}

export function AuthProvider({ children, notifier, onUnauthenticated, baseUrl }: AuthProviderProps) {
  const queryClient = useQueryClient();
  const [client] = useState<AuthClient>(() => createAuthClient(baseUrl));
  const [user, setUser] = useState<AuthUser | null>(null);
  const [tenant, setTenant] = useState<AuthTenant | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [isLoginLoading, setIsLoginLoading] = useState(false);

  const isAuthenticated = tokenManager.hasToken() && user !== null;

  // Restore session on startup.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!tokenManager.hasToken()) {
        setIsInitializing(false);
        return;
      }
      try {
        const me = await client.me();
        if (!cancelled) { setUser(me.user); setTenant(me.tenant ?? null); }
      } catch {
        // One refresh attempt, then give up and clear.
        try {
          await client.refresh();
          const me = await client.me();
          if (!cancelled) { setUser(me.user); setTenant(me.tenant ?? null); }
        } catch {
          tokenManager.clearTokens();
          if (!cancelled) { setUser(null); setTenant(null); }
        }
      } finally {
        if (!cancelled) setIsInitializing(false);
      }
    })();
    return () => { cancelled = true; };
  }, [client]);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoginLoading(true);
    try {
      await client.login(email, password);
      queryClient.clear(); // fresh data for the new session
      // login body has user but not tenant — fetch full context via /auth/me.
      const me = await client.me();
      setUser(me.user);
      setTenant(me.tenant ?? null);
      notifier?.success('Signed in');
    } catch (e) {
      notifier?.error(e instanceof Error ? e.message : 'Sign-in failed');
      throw e;
    } finally {
      setIsLoginLoading(false);
    }
  }, [client, queryClient, notifier]);

  const logout = useCallback(async () => {
    try {
      await client.logout();
    } catch {
      // ignore — clear locally regardless
    } finally {
      tokenManager.clearTokens();
      setUser(null);
      setTenant(null);
      queryClient.clear();
      onUnauthenticated?.();
    }
  }, [client, queryClient, onUnauthenticated]);

  const value: AuthState = { user, tenant, isAuthenticated, isInitializing, isLoginLoading, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
