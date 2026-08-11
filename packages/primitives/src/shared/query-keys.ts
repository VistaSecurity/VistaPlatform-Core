// Query keys owned by the primitives package. Intentionally minimal — only the
// keys for data this package fetches (permissions, current user, tenant
// features). The app's full query-key factory (assets, certificates, etc.)
// stays in the app; it is not a primitives concern.
//
// Kept byte-compatible with web-ui's existing keys so caches don't split when
// web-ui adopts the package in Phase 4:
//   auth.currentUser  -> ['auth', 'current-user']
//   auth.permissions  -> ['user-permissions']
//   tenant.features   -> ['tenant', 'features']

export const primitivesQueryKeys = {
  auth: {
    currentUser: () => ['auth', 'current-user'] as const,
    permissions: () => ['user-permissions'] as const,
  },
  tenant: {
    features: () => ['tenant', 'features'] as const,
  },
} as const;
