// Platform RBAC primitives: PlatformPermissionProvider / usePlatformPermissions
// / PlatformPermissionGate. Router-free, headless — gating only. Loads the
// current platform user's effective permission NAMES from the typed contract
// (GET /admin/user/permissions, which returns Permission objects → map to .name).
// Parallel to the tenant rbac module but on the admin-service contract.
import React, { createContext, useContext } from 'react';
import { useQuery } from '@tanstack/react-query';
import { createAdminServiceClient } from '@vistasecurity/api-contract';

export interface PlatformPermissionState {
  permissions: string[];
  isLoading: boolean;
  hasPermission(p: string): boolean;
  hasAnyPermission(ps: string[]): boolean;
  hasAllPermissions(ps: string[]): boolean;
}

const PlatformPermissionContext = createContext<PlatformPermissionState | undefined>(undefined);

export function usePlatformPermissions(): PlatformPermissionState {
  const ctx = useContext(PlatformPermissionContext);
  if (!ctx) throw new Error('usePlatformPermissions must be used within a PlatformPermissionProvider');
  return ctx;
}

export interface PlatformPermissionProviderProps {
  children: React.ReactNode;
  /** Gate the fetch on auth (default true — mount it inside the authenticated tree). */
  enabled?: boolean;
}

export function PlatformPermissionProvider({ children, enabled = true }: PlatformPermissionProviderProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['platform', 'user-permissions'],
    queryFn: async (): Promise<string[]> => {
      const c = createAdminServiceClient();
      const { data, error } = await c.GET('/admin/user/permissions', {});
      if (error || !data) throw new Error('Failed to load platform permissions');
      return (data.permissions ?? []).map((p) => p.name);
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });

  const permissions = data ?? [];
  const value: PlatformPermissionState = {
    permissions,
    isLoading,
    hasPermission: (p) => permissions.includes(p),
    hasAnyPermission: (ps) => ps.some((p) => permissions.includes(p)),
    hasAllPermissions: (ps) => ps.every((p) => permissions.includes(p)),
  };
  return <PlatformPermissionContext.Provider value={value}>{children}</PlatformPermissionContext.Provider>;
}

export interface PlatformPermissionGateProps {
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
export function PlatformPermissionGate({ permission, anyOf, allOf, fallback = null, children }: PlatformPermissionGateProps) {
  const { hasPermission, hasAnyPermission, hasAllPermissions, isLoading } = usePlatformPermissions();
  if (isLoading) return null;
  const checks: boolean[] = [];
  if (permission) checks.push(hasPermission(permission));
  if (anyOf && anyOf.length > 0) checks.push(hasAnyPermission(anyOf));
  if (allOf && allOf.length > 0) checks.push(hasAllPermissions(allOf));
  const ok = checks.length > 0 && checks.every(Boolean);
  return <>{ok ? children : fallback}</>;
}
