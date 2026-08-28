// Thin runtime wrapper around the generated cbom-service types.
//
// This file is hand-written (the *.d.ts beside it is generated — do not edit
// that one). It wires `openapi-fetch` to Vista Platform's auth model:
//   - httpOnly cookies are sent automatically via `credentials: "include"`
//   - the JS-readable `csrf_token` cookie is echoed as the `X-CSRF-Token`
//     header on every request (matches services/.../web-ui axios interceptor)
//
// Every Vista Platform TS consumer (frontend-v2, and the old web-ui during the
// transition) should create its client through here so the auth wiring lives
// in exactly one place.
import createClient, { type Client, type Middleware } from "openapi-fetch";
import type { paths, components } from "./cbom-service";
import type {
  paths as inventoryPaths,
  components as inventoryComponents,
} from "./inventory-service";
import type {
  paths as complianceEnginePaths,
  components as complianceEngineComponents,
} from "./compliance-engine";
import type {
  paths as authPaths,
  components as authComponents,
} from "./auth-service";
import type {
  paths as sensorManagerPaths,
  components as sensorManagerComponents,
} from "./sensor-manager";
import type {
  paths as auditServicePaths,
  components as auditServiceComponents,
} from "./audit-service";
import type {
  paths as deviceInterrogationPaths,
  components as deviceInterrogationComponents,
} from "./device-interrogation-service";
import type {
  paths as notificationServicePaths,
  components as notificationServiceComponents,
} from "./notification-service";
import type {
  paths as adminServicePaths,
  components as adminServiceComponents,
} from "./admin-service";
import type {
  paths as monitoringServicePaths,
  components as monitoringServiceComponents,
} from "./monitoring-service";
import type {
  paths as resourceTrackerServicePaths,
} from "./resource-tracker-service";
import type {
  paths as tenantHealthServicePaths,
} from "./tenant-health-service";

/** Convenience aliases for the most-used schema types. */
export type Scope = components["schemas"]["Scope"];
export type ScopeListResponse = components["schemas"]["ScopeListResponse"];
export type CreateScopeRequest = components["schemas"]["CreateScopeRequest"];
export type UpdateScopeRequest = components["schemas"]["UpdateScopeRequest"];
export type PreviewResult = components["schemas"]["PreviewResult"];
export type Predicate = components["schemas"]["Predicate"];
export type PredicateClause = components["schemas"]["PredicateClause"];
/** ADR-0002 go-forward envelope types (carried ahead of the backend). */
export type ApiError = components["schemas"]["Error"];
export type Pagination = components["schemas"]["Pagination"];

/** Convenience aliases for inventory-service infrastructure-assets. */
export type Asset = inventoryComponents["schemas"]["Asset"];
export type AssetListResponse =
  inventoryComponents["schemas"]["AssetListResponse"];
export type AssetResponse = inventoryComponents["schemas"]["AssetResponse"];
export type AssetInput = inventoryComponents["schemas"]["AssetInput"];
export type AssetIdsRequest =
  inventoryComponents["schemas"]["AssetIdsRequest"];
export type ApprovalResult =
  inventoryComponents["schemas"]["ApprovalResult"];

/** Convenience aliases for compliance-engine frameworks (tenant-facing reads + subscriptions). */
export type PublishedFramework =
  complianceEngineComponents["schemas"]["PublishedFramework"];
export type PublishedFrameworkListResponse =
  complianceEngineComponents["schemas"]["PublishedFrameworkListResponse"];
export type PublishedFrameworkViewResponse =
  complianceEngineComponents["schemas"]["PublishedFrameworkViewResponse"];
export type LicensedFramework =
  complianceEngineComponents["schemas"]["LicensedFramework"];
export type LicensedFrameworkListResponse =
  complianceEngineComponents["schemas"]["LicensedFrameworkListResponse"];
export type AvailableFramework =
  complianceEngineComponents["schemas"]["AvailableFramework"];
export type AvailableFrameworkListResponse =
  complianceEngineComponents["schemas"]["AvailableFrameworkListResponse"];
export type DefaultFrameworkDescriptor =
  complianceEngineComponents["schemas"]["DefaultFrameworkDescriptor"];
export type DefaultFrameworkResponse =
  complianceEngineComponents["schemas"]["DefaultFrameworkResponse"];
export type SubscribeFrameworkRequest =
  complianceEngineComponents["schemas"]["SubscribeFrameworkRequest"];
export type SetDefaultFrameworkRequest =
  complianceEngineComponents["schemas"]["SetDefaultFrameworkRequest"];

/** Convenience aliases for auth-service cross-cutters (/auth/me, /user/permissions, /tenant/features). */
export type MeResponse = authComponents["schemas"]["MeResponse"];
export type AuthUser = authComponents["schemas"]["User"];
export type AuthTenant = authComponents["schemas"]["Tenant"];
export type PermissionsResponse =
  authComponents["schemas"]["PermissionsResponse"];
export type FeaturesResponse = authComponents["schemas"]["FeaturesResponse"];
export type FeatureFlags = authComponents["schemas"]["FeatureFlags"];
export type UsageLimits = authComponents["schemas"]["UsageLimits"];
export type UsageLimit = authComponents["schemas"]["UsageLimit"];

/** Convenience aliases for sensor-manager (tenant sensor lifecycle). */
export type Sensor = sensorManagerComponents["schemas"]["Sensor"];
export type SensorListResponse =
  sensorManagerComponents["schemas"]["SensorListResponse"];
export type SensorStats = sensorManagerComponents["schemas"]["SensorStats"];
export type SensorCommand =
  sensorManagerComponents["schemas"]["SensorCommand"];
export type SensorHealthMetrics =
  sensorManagerComponents["schemas"]["SensorHealthMetrics"];
export type PendingSensor =
  sensorManagerComponents["schemas"]["PendingSensor"];
export type PendingSensorListResponse =
  sensorManagerComponents["schemas"]["PendingSensorListResponse"];
export type CreatePendingSensorRequest =
  sensorManagerComponents["schemas"]["CreatePendingSensorRequest"];
export type CreateSensorCommandRequest =
  sensorManagerComponents["schemas"]["CreateSensorCommandRequest"];

/** Convenience aliases for audit-service activity logs. */
export type ActivityLog = auditServiceComponents["schemas"]["ActivityLog"];
export type ActivityLogListResponse =
  auditServiceComponents["schemas"]["ActivityLogListResponse"];
export type ActivityLogResponse =
  auditServiceComponents["schemas"]["ActivityLogResponse"];
export type ActivityLogPagination =
  auditServiceComponents["schemas"]["ActivityLogPagination"];
export type QueryActivityLogsRequest =
  auditServiceComponents["schemas"]["QueryActivityLogsRequest"];

/** Convenience aliases for device-interrogation-service (interrogation jobs). */
export type InterrogationJob =
  deviceInterrogationComponents["schemas"]["InterrogationJob"];
export type JobListResponse =
  deviceInterrogationComponents["schemas"]["JobListResponse"];
export type JobStats = deviceInterrogationComponents["schemas"]["JobStats"];

/** Convenience aliases for notification-service (tenant channels + rules). */
export type TenantNotificationChannel =
  notificationServiceComponents["schemas"]["TenantNotificationChannel"];
export type TenantNotificationRule =
  notificationServiceComponents["schemas"]["TenantNotificationRule"];
export type CreateChannelRequest =
  notificationServiceComponents["schemas"]["CreateChannelRequest"];
export type UpdateChannelRequest =
  notificationServiceComponents["schemas"]["UpdateChannelRequest"];
export type CreateRuleRequest =
  notificationServiceComponents["schemas"]["CreateRuleRequest"];
export type UpdateRuleRequest =
  notificationServiceComponents["schemas"]["UpdateRuleRequest"];

/** Convenience aliases for admin-service (tenant /my-billing surface). */
export type Invoice = adminServiceComponents["schemas"]["Invoice"];
export type InvoiceListResponse =
  adminServiceComponents["schemas"]["InvoiceListResponse"];
export type SubscriptionResponse =
  adminServiceComponents["schemas"]["SubscriptionResponse"];
export type PaymentMethod = adminServiceComponents["schemas"]["PaymentMethod"];
export type PaymentMethodListResponse =
  adminServiceComponents["schemas"]["PaymentMethodListResponse"];
export type Discount = adminServiceComponents["schemas"]["Discount"];
export type ChangePlanRequest =
  adminServiceComponents["schemas"]["ChangePlanRequest"];

/** Convenience aliases for monitoring-service (tenant /status surface). */
export type SystemStatusResponse =
  monitoringServiceComponents["schemas"]["SystemStatusResponse"];
export type SystemMetrics =
  monitoringServiceComponents["schemas"]["SystemMetrics"];
export type SystemHealthOverview =
  monitoringServiceComponents["schemas"]["SystemHealthOverview"];
export type ServiceStatus =
  monitoringServiceComponents["schemas"]["ServiceStatus"];

function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie.match(
    new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)"),
  );
  return match ? decodeURIComponent(match[1]) : undefined;
}

/** The default CSRF cookie name (tenant sessions). Platform-admin sessions use
 * a distinct cookie (`platform_csrf_token`) so the two never collide on a shared
 * host — pass `csrfCookie` to the client factories to select it. */
export const DEFAULT_CSRF_COOKIE = "csrf_token";

/**
 * Build a middleware that echoes the named CSRF cookie as `X-CSRF-Token`. Cookie
 * auth itself rides on `credentials: "include"`; this header is the CSRF
 * double-submit companion. The cookie name must match the one the target
 * service's auth middleware validates (`csrf_token` for tenant routes,
 * `platform_csrf_token` for platform-admin routes).
 */
export function makeCsrfMiddleware(
  cookieName: string = DEFAULT_CSRF_COOKIE,
): Middleware {
  return {
    async onRequest({ request }) {
      const token = readCookie(cookieName);
      if (token) request.headers.set("X-CSRF-Token", token);
      return request;
    },
  };
}

/** Default (tenant) CSRF middleware. Retained for backward compatibility; new
 * code should prefer `makeCsrfMiddleware(opts.csrfCookie)` via the factories. */
export const csrfMiddleware: Middleware = makeCsrfMiddleware();

/**
 * App-level hook the 401 middleware calls when an authenticated request is
 * rejected. Returns whether the session was recovered (e.g. via a silent
 * refresh-token exchange) — if so, idempotent requests are retried once.
 * Each app registers exactly one handler at startup (see
 * `@vistasecurity/primitives/shared` `createSessionExpiryHandler`).
 */
export type SessionExpiredHandler = (request: Request) => Promise<boolean>;

/**
 * Two-phase form of the session-expiry hook. `onAuthFailure` is the
 * `SessionExpiredHandler` above. `onRecoveryFailed` is called when a request
 * replayed AFTER a successful recovery is rejected again — the refresh
 * exchange "succeeded" but produced a session the data plane does not accept.
 * Without this phase that state never reaches the app: refresh 200s, the
 * replay 401s, the error surfaces, and nothing ever redirects to sign-in —
 * the user is stranded on a page of dead panels with a live-looking cookie.
 */
export interface SessionExpiryHandlers {
  onAuthFailure: SessionExpiredHandler;
  onRecoveryFailed(request: Request): Promise<void>;
}

let sessionExpiredHandler: SessionExpiryHandlers | null = null;

/** Register (or clear, with `null`) the app's session-expiry handler. The
 * bare-function form is the legacy single-phase handler; it simply never
 * hears about failed recoveries. */
export function setSessionExpiredHandler(
  handler: SessionExpiredHandler | SessionExpiryHandlers | null,
): void {
  sessionExpiredHandler =
    handler === null
      ? null
      : typeof handler === "function"
        ? { onAuthFailure: handler, onRecoveryFailed: async () => {} }
        : handler;
}

/** Suffixes of endpoints that run BEFORE a session exists — no RequireAuth
 * middleware in front of them on either auth-service or admin-service — so a
 * 401 there is a legitimate application response (bad password, dead refresh
 * token, an expired invite/reset token, an SSO handshake step), never a sign
 * that an existing session died. `.endsWith()` against these tenant-shaped
 * suffixes also matches the platform equivalents for free, since platform
 * routes are literally "/admin" + the same suffix (e.g. "/admin/auth/login"
 * ends with "/auth/login").
 *
 * Deliberately an ALLOWLIST, not a blacklist: every other "/auth/*" endpoint
 * (session-only routes like /auth/me, /auth/legal/pending, /auth/legal/accept,
 * /auth/logout, /auth/sessions, /auth/sso/link, /auth/sso/unlink, ...) sits
 * behind RequireAuth, so a 401 there always means the session expired and
 * must go through the real recovery/redirect path. The previous blacklist
 * ("anything containing /auth/ except /auth/me") wrongly swept up every one
 * of those, including the legal-acceptance endpoints — a stale/expiring
 * session mid-flow surfaced as a bare "couldn't verify legal terms" error
 * instead of a clean session-expiry redirect.
 *
 * Keep this list in sync with the unauthenticated route registrations in
 * services/auth-service/internal/api/router.go, services/auth-service/ee/sso/routes.go,
 * and services/admin-service/internal/api/server.go. */
const AUTH_FLOW_PATH_SUFFIXES = [
  "/auth/login",
  "/auth/refresh",
  "/auth/register",
  "/auth/register/complete",
  "/auth/verify-email",
  "/auth/resend-verification",
  "/auth/forgot-password",
  "/auth/reset-password",
  "/auth/legal/current",
  "/auth/initiate",
  "/auth/methods",
  "/auth/authenticate",
  "/auth/complete",
  "/auth/invitations/lookup",
  "/auth/invitations/accept",
  "/auth/sso/platform/register/complete",
];

function isAuthFlowPath(pathname: string): boolean {
  if (pathname.includes("/auth/legal/documents/")) return true;
  return AUTH_FLOW_PATH_SUFFIXES.some((suffix) => pathname.endsWith(suffix));
}

/**
 * Build the session-expiry middleware every factory installs. On a 401 from a
 * non-auth-flow endpoint it defers to the registered handler; if the handler
 * recovers the session, GET/HEAD requests are replayed once (mutations are not
 * auto-replayed — their caller surfaces the error and the next attempt rides
 * the refreshed session). With no handler registered the 401 passes through
 * untouched.
 */
export function makeSessionExpiryMiddleware(
  fetchImpl?: typeof globalThis.fetch,
): Middleware {
  return {
    async onResponse({ request, response }) {
      if (response.status !== 401 || !sessionExpiredHandler) return undefined;
      if (isAuthFlowPath(new URL(request.url).pathname)) return undefined;
      const handler = sessionExpiredHandler;
      const recovered = await handler.onAuthFailure(request);
      if (recovered && (request.method === "GET" || request.method === "HEAD")) {
        const doFetch = fetchImpl ?? globalThis.fetch;
        const retry = await doFetch(new Request(request));
        if (retry.status === 401) {
          // The replay carried the token the refresh just minted and was
          // rejected anyway. Left alone this repeats forever — refresh 200,
          // replay 401, error card — and the redirect-to-login latch never
          // fires, because the latch only trips when the refresh REJECTS.
          // Hand it to the app to confirm and, if the session really is
          // unusable, end it. The 401 still returns to the caller so the
          // page renders its error state while the navigation happens.
          await handler.onRecoveryFailed(request);
        }
        return retry;
      }
      return undefined;
    },
  };
}

export interface CreateClientOptions {
  /** Override the base URL (default: the gateway path for cbom-service). */
  baseUrl?: string;
  /** Inject a fetch implementation (tests / SSR). */
  fetch?: typeof globalThis.fetch;
  /** CSRF cookie name to echo as `X-CSRF-Token` (default: `csrf_token`).
   * Platform-admin clients must pass `platform_csrf_token`. */
  csrfCookie?: string;
}

/**
 * Construct a typed cbom-service client. All paths, params, request bodies and
 * responses are checked against the generated contract types at compile time.
 */
export function createCbomServiceClient(
  opts: CreateClientOptions = {},
): Client<paths> {
  const client = createClient<paths>({
    baseUrl: opts.baseUrl ?? "/api/v1/cbom-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed inventory-service client (v2 CMDB surface). All paths,
 * params, request bodies and responses are checked against the generated
 * contract types at compile time.
 */
export function createInventoryServiceClient(
  opts: CreateClientOptions = {},
): Client<inventoryPaths> {
  const client = createClient<inventoryPaths>({
    baseUrl: opts.baseUrl ?? "/api/v2/inventory-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed compliance-engine client (v1 surface). All paths, params,
 * request bodies and responses are checked against the generated contract
 * types at compile time.
 */
export function createComplianceEngineClient(
  opts: CreateClientOptions = {},
): Client<complianceEnginePaths> {
  const client = createClient<complianceEnginePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/compliance-engine",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed auth-service client (v1 surface). Covers the three
 * cross-cutter endpoints (`/auth/me`, `/user/permissions`, `/tenant/features`)
 * every page calls on load. All paths, params, request bodies and responses
 * are checked against the generated contract types at compile time.
 */
export function createAuthServiceClient(
  opts: CreateClientOptions = {},
): Client<authPaths> {
  const client = createClient<authPaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/auth-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed sensor-manager client (v1 surface). Covers the tenant
 * sensor lifecycle the Operations area reads/writes — list/get/stats, status
 * and delete, per-sensor commands and health, and pending registrations. All
 * paths, params, request bodies and responses are checked against the
 * generated contract types at compile time.
 */
export function createSensorManagerClient(
  opts: CreateClientOptions = {},
): Client<sensorManagerPaths> {
  const client = createClient<sensorManagerPaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/sensor-manager",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed audit-service client (v1 surface). Covers the tenant
 * activity-logs read surface (list, get, query, summary, and the user /
 * resource pivots). All paths, params, request bodies and responses are
 * checked against the generated contract types at compile time.
 */
export function createAuditServiceClient(
  opts: CreateClientOptions = {},
): Client<auditServicePaths> {
  const client = createClient<auditServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/audit-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed device-interrogation-service client (v1 surface). Covers the
 * interrogation-jobs read surface (list / get / stats / active / results) the
 * Operations area shows for device + cloud discovery runs. All paths, params,
 * request bodies and responses are checked against the generated contract types
 * at compile time.
 */
export function createDeviceInterrogationServiceClient(
  opts: CreateClientOptions = {},
): Client<deviceInterrogationPaths> {
  const client = createClient<deviceInterrogationPaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/device-interrogation-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed notification-service client (v1 surface). Covers the Tenant
 * Admin notification settings — channels (list/create/get/update/delete/test)
 * and alert-routing rules (list/create/get/update/delete). All paths, params,
 * request bodies and responses are checked against the generated contract types
 * at compile time.
 */
export function createNotificationServiceClient(
  opts: CreateClientOptions = {},
): Client<notificationServicePaths> {
  const client = createClient<notificationServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/notification-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed admin-service client (v1 surface). Covers the tenant
 * self-service billing page (`/my-billing`) — invoices, subscription, plan
 * change/cancel/reactivate, payment-method setup/confirm/list, active discount,
 * and the Stripe billing-portal session. All paths, params, request bodies and
 * responses are checked against the generated contract types at compile time.
 */
export function createAdminServiceClient(
  opts: CreateClientOptions = {},
): Client<adminServicePaths> {
  const client = createClient<adminServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/admin-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed monitoring-service client (v1 surface). Covers the tenant
 * system-status reads (`/status/*`) — full status, metrics, the Dashboard
 * health overview, a single service's status, and incident history. All paths,
 * params and responses are checked against the generated contract types at
 * compile time.
 */
export function createMonitoringServiceClient(
  opts: CreateClientOptions = {},
): Client<monitoringServicePaths> {
  const client = createClient<monitoringServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/monitoring-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed resource-tracker-service client (v1 surface). Covers the
 * platform-admin resource-usage + cost-monitoring reads (tenant resource usage,
 * quotas, AWS cost breakdown, optimization analysis). Spec'd as part of the
 * admin-ui-v2 prep — this service had no contract before. All paths, params and
 * responses are checked against the generated contract types at compile time.
 */
export function createResourceTrackerServiceClient(
  opts: CreateClientOptions = {},
): Client<resourceTrackerServicePaths> {
  const client = createClient<resourceTrackerServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/resource-tracker-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}

/**
 * Construct a typed tenant-health-service client (v1 surface). Covers the
 * platform-admin tenant-health reads (per-tenant scoring, trends, metrics,
 * benchmarks, comparison, insights) and on-demand recalculation. Spec'd as part
 * of the admin-ui-v2 prep — this service had no contract before. All paths,
 * params and responses are checked against the generated contract types at
 * compile time.
 */
export function createTenantHealthServiceClient(
  opts: CreateClientOptions = {},
): Client<tenantHealthServicePaths> {
  const client = createClient<tenantHealthServicePaths>({
    baseUrl: opts.baseUrl ?? "/api/v1/tenant-health-service",
    credentials: "include",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(makeCsrfMiddleware(opts.csrfCookie));
  client.use(makeSessionExpiryMiddleware(opts.fetch));
  return client;
}
