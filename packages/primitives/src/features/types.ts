// Feature-flag types — extracted verbatim from web-ui/src/hooks/useFeatures.ts
// (Phase 1). Flags resolve from the tenant's tier + active per-tenant overrides;
// they are independent of RBAC permissions.
//
// Add a new flag by appending to FeatureName + FeaturesMap here AND to
// `knownFeatures` in services/auth-service/internal/api/features.go.

export type FeatureName =
  | 'custom_policies'
  | 'threshold_overrides'
  | 'ot_active_probing'
  | 'ot_primary_lens'
  | 'cbom_signing'
  | 'sso_saml'
  | 'custom_branding'
  | 'cmdb_sync'
  | 'siem_export'
  | 'billing_portal';

export interface FeaturesMap {
  custom_policies: boolean;
  threshold_overrides: boolean;
  /**
   * When true, the tenant's discovery jobs may opt into active OT/ICS
   * probing (Modbus, OPC UA, EtherNet/IP, BACnet). Each job still has to
   * enable the specific protocols explicitly — this flag only controls
   * whether the per-job toggles appear at all.
   */
  ot_active_probing: boolean;
  /**
   * When true, promote the "OT" lens out of the lens-switcher's "More"
   * overflow dropdown into a primary always-visible tab.
   */
  ot_primary_lens: boolean;
  /**
   * When true, CBOM artifacts may be signed and carry compliance-attestation
   * layers, and artifact comparison/drift is available. Artifact *generation*
   * and CycloneDX export are unconditional — this gates the audit-grade
   * evidence surface only.
   */
  cbom_signing: boolean;
  /**
   * When true, federated sign-in is available (tenant OIDC/SAML, social
   * signup, staff SSO). Local users, invitations, and RBAC are
   * unconditional.
   */
  sso_saml: boolean;
  /**
   * When true, the tenant may white-label the UI with its own marks (logo,
   * favicon, custom CSS). The palette/theme selector is unconditional.
   */
  custom_branding: boolean;
  /** Sync inventory out to an external CMDB/ITSM (ServiceNow, Device42, SolarWinds). */
  cmdb_sync: boolean;
  /** Forward audit events to an external SIEM (Splunk, Datadog, Elastic, webhook). */
  siem_export: boolean;
  /**
   * When true, the tenant-facing self-service billing surface is available:
   * subscription, invoices, plan change and the payment portal
   * (admin-service `/my-billing/**`, which only an Enterprise build mounts).
   * Usage-against-limits (auth-service `/billing/usage/current`) is Core and
   * is NOT gated by this flag.
   */
  billing_portal: boolean;
}

export interface UsageLimit {
  current: number;
  /** null = unlimited */
  limit: number | null;
}

export interface LimitsMap {
  /** Active compliance framework subscriptions (excludes Best Practices). */
  compliance_frameworks?: UsageLimit;
}

// Defaults are all-off: a client that cannot reach the features endpoint must
// degrade to the Core surface, never to an unlocked one.
export const defaultFeatures: FeaturesMap = {
  custom_policies: false,
  threshold_overrides: false,
  ot_active_probing: false,
  ot_primary_lens: false,
  cbom_signing: false,
  sso_saml: false,
  custom_branding: false,
  cmdb_sync: false,
  siem_export: false,
  billing_portal: false,
};
