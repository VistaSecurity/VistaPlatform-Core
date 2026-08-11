// PlatformAuthProvider / usePlatformAuth — platform-admin session state for the
// admin console. Headless: takes a notifier + onUnauthenticated as props (never
// imports a toast lib or a router). Mirrors the tenant AuthProvider's flow
// (init → me, login, logout, refresh-on-init-failure) against the platform
// auth surface. There is no tenant in a platform session.
import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { INotifier } from '../shared/di';
import { platformTokenManager } from './token';
import { createPlatformAuthClient, type PlatformAuthClient, type CurrentPlatformUser } from './client';

export interface PlatformAuthState {
  user: CurrentPlatformUser | null;
  isAuthenticated: boolean;
  /** True during the initial session-restoration check on app startup. */
  isInitializing: boolean;
  isLoginLoading: boolean;
  /** The signed-in user must set a new password before using the app. */
  forcePasswordChange: boolean;
  login(email: string, password: string): Promise<void>;
  logout(): Promise<void>;
  /** Change own password (clears forcePasswordChange on success). */
  changePassword(currentPassword: string, newPassword: string, confirmPassword: string): Promise<void>;
}

const PlatformAuthContext = createContext<PlatformAuthState | undefined>(undefined);

export function usePlatformAuth(): PlatformAuthState {
  const ctx = useContext(PlatformAuthContext);
  if (!ctx) throw new Error('usePlatformAuth must be used within a PlatformAuthProvider');
  return ctx;
}

export interface PlatformAuthProviderProps {
  children: React.ReactNode;
  /** Optional user-facing notifier (e.g. react-hot-toast wrapper). */
  notifier?: INotifier;
  /** Called after logout / when the session is found dead. App handles navigation. */
  onUnauthenticated?: () => void;
  /** Override the admin-service base URL (tests). */
  baseUrl?: string;
}

export function PlatformAuthProvider({ children, notifier, onUnauthenticated, baseUrl }: PlatformAuthProviderProps) {
  const queryClient = useQueryClient();
  const [client] = useState<PlatformAuthClient>(() => createPlatformAuthClient(baseUrl));
  const [user, setUser] = useState<CurrentPlatformUser | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [isLoginLoading, setIsLoginLoading] = useState(false);

  const isAuthenticated = platformTokenManager.hasToken() && user !== null;
  const forcePasswordChange = user?.force_password_change ?? false;

  // Restore session on startup.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!platformTokenManager.hasToken()) {
        setIsInitializing(false);
        return;
      }
      try {
        const me = await client.me();
        if (!cancelled) setUser(me);
      } catch {
        // One refresh attempt, then give up and clear.
        try {
          await client.refresh();
          const me = await client.me();
          if (!cancelled) setUser(me);
        } catch {
          platformTokenManager.clearTokens();
          if (!cancelled) setUser(null);
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
      // login body has the user, but fetch via /admin/auth/me for the canonical
      // session shape (role as name string, force_password_change).
      const me = await client.me();
      setUser(me);
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
      platformTokenManager.clearTokens();
      setUser(null);
      queryClient.clear();
      onUnauthenticated?.();
    }
  }, [client, queryClient, onUnauthenticated]);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string, confirmPassword: string) => {
    await client.changePassword(currentPassword, newPassword, confirmPassword);
    // Reflect the cleared flag without a full reload.
    const me = await client.me();
    setUser(me);
    notifier?.success('Password changed');
  }, [client, notifier]);

  const value: PlatformAuthState = {
    user, isAuthenticated, isInitializing, isLoginLoading, forcePasswordChange, login, logout, changePassword,
  };
  return <PlatformAuthContext.Provider value={value}>{children}</PlatformAuthContext.Provider>;
}
