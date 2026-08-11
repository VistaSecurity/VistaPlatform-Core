// Dependency-injection seams for the headless primitives (ADR-0004).
//
// The package owns logic but never owns UI or transport decisions. Anything
// app-specific — how a toast is shown, how an authenticated request is made —
// is passed in through these interfaces so the same logic serves both web-ui
// and frontend-v2 without forking.

/**
 * User-facing notifications. In web-ui this is backed by react-hot-toast; the
 * package never imports a toast library directly (the one real coupling seam
 * found in the current auth code — see EXTRACTION_PLAN.md SEAM 1).
 */
export interface INotifier {
  success(message: string): void;
  error(message: string): void;
  warning?(message: string): void;
  info?(message: string): void;
}

/** Minimal HTTP surface the primitives need. The app supplies a configured
 *  client (cookie/CSRF wiring, base URL, 401-refresh interceptor) — the package
 *  does not construct axios or know the base URL. Phase 2 wires this. */
export interface IHttpClient {
  get<T = unknown>(url: string, config?: unknown): Promise<{ data: T }>;
  post<T = unknown>(url: string, body?: unknown, config?: unknown): Promise<{ data: T }>;
  put<T = unknown>(url: string, body?: unknown, config?: unknown): Promise<{ data: T }>;
  delete<T = unknown>(url: string, config?: unknown): Promise<{ data: T }>;
}

/** Config the app injects so the package stays environment-agnostic. */
export interface IPrimitivesConfig {
  http: IHttpClient;
  notifier: INotifier;
}
