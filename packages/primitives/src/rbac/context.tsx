// RBAC primitives: PermissionProvider / usePermissions / PermissionGate.
// Router-free and headless — gating logic only. Loads the current user's
// effective permission names from the typed contract (/user/permissions).
import React, { createContext, useContext } from 'react';
import { useQuery } from '@tanstack/react-query';
import { createAuthServiceClient } from '@vistasecurity/api-contract';

export interface PermissionState {
  permissions: string[];
  isLoading: boolean;
  hasPermission(p: string): boolean;
  hasAnyPermission(ps: string[]): boolean;
  hasAllPermissions(ps: string[]): boolean;
}

const PermissionContext = createContext<PermissionState | undefined>(undefined);

export function usePermissions(): PermissionState {
  const ctx = useContext(PermissionContext);
  if (!ctx) throw new Error('usePermissions must be used within a PermissionProvider');
  return ctx;
}

export interface PermissionProviderProps {
  children: React.ReactNode;
  /** Gate the fetch on auth (default true — mount it inside the authenticated tree). */
  enabled?: boolean;
}

export function PermissionProvider({ children, enabled = true }: PermissionProviderProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['user-permissions'],
    queryFn: async (): Promise<string[]> => {
      const c = createAuthServiceClient();
      const { data, error } = await c.GET('/user/permissions', {});
      if (error || !data) throw new Error('Failed to load permissions');
      return data.permissions;
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  const permissions = data ?? [];
  const value: PermissionState = {
    permissions,
    isLoading,
    hasPermission: (p) => permissions.includes(p),
    hasAnyPermission: (ps) => ps.some((p) => permissions.includes(p)),
    hasAllPermissions: (ps) => ps.every((p) => permissions.includes(p)),
  };
  return <PermissionContext.Provider value={value}>{children}</PermissionContext.Provider>;
}

export interface PermissionGateProps {
  permission?: string;
  anyOf?: string[];
  allOf?: string[];
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

/** Renders children only when the permission predicate passes. Hidden while loading.
 * Fails CLOSED: a gate with no predicate (or an empty `anyOf`/`allOf`) grants nothing,
 * so an optional permission that resolves to `undefined` hides the children rather than
 * exposing them. */
export function PermissionGate({ permission, anyOf, allOf, fallback = null, children }: PermissionGateProps) {
  const { hasPermission, hasAnyPermission, hasAllPermissions, isLoading } = usePermissions();
  if (isLoading) return null;
  const checks: boolean[] = [];
  if (permission) checks.push(hasPermission(permission));
  if (anyOf && anyOf.length > 0) checks.push(hasAnyPermission(anyOf));
  if (allOf && allOf.length > 0) checks.push(hasAllPermissions(allOf));
  const ok = checks.length > 0 && checks.every(Boolean);
  return <>{ok ? children : fallback}</>;
}
