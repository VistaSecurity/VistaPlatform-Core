// Auth domain types — extracted verbatim from web-ui/src/types/index.ts (Phase 1).
// These are the shared identity contract both surfaces depend on.

export interface ApiResponse<T> {
  data?: T;
  message?: string;
  error?: string;
  details?: string;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: 'billing_admin' | 'tenant_admin' | 'security_admin' | 'viewer' | 'api_user';
  is_active: boolean;
  email_verified: boolean;
  last_login_at: string | null;
  avatar_url?: string | null;
  timezone?: string;
  preferences?: Record<string, any>;
  eula_accepted_at?: string | null;
  eula_version?: string | null;
  onboarding_completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  domain?: string | null;
  subscription_tier_id: string;
  trial_ends_at: string | null;
  billing_email: string;
  payment_status: 'trial' | 'active' | 'past_due' | 'canceled';
  sso_enabled?: boolean;
  custom_branding?: Record<string, any>;
  ui_config?: Record<string, any>;
  settings: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  tenant_name: string;
}

export interface AuthContextType {
  user: User | null;
  tenant: Tenant | null;
  isAuthenticated: boolean;
  hasValidToken?: boolean;
  isLoading: boolean;
  /** True only while a login() call is in progress. */
  isLoginLoading: boolean;
  /** True only during the initial session-restoration check on app startup. */
  isInitializing: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => void;
  refreshAuth: () => Promise<void>;
}
