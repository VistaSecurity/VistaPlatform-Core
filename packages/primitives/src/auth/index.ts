// Auth primitives (build-and-swap: consumed by frontend-v2; web-ui untouched).
export type {
  ApiResponse,
  User,
  Tenant,
  AuthResponse as AuthResponseType,
  LoginRequest,
  RegisterRequest,
  AuthContextType,
} from './types';
export { tokenManager } from './token';
export { createAuthClient } from './client';
export type { AuthClient, AuthResponse, MeResponse, AuthUser, AuthTenant } from './client';
export { AuthProvider, useAuth } from './context';
export type { AuthState, AuthProviderProps } from './context';
