// The audit event categories audit.activity_logs accepts. Mirrors the
// EventCategory* constants in shared/middleware/audit/types.go (and the
// validEventCategories set in shared/middleware/audit/categories.go), which are
// held equal to the database CHECK by TestEventCategories_MatchTheSchemaCheck.
// No generated TS constant exists for these yet, so a category added there must
// be added here in the same change. The filter chips use this static list
// rather than whatever the current page of rows happens to contain.
export const AUDIT_EVENT_CATEGORIES = [
  'asset',
  'certificate',
  'user',
  'authentication',
  'compliance',
  'report',
  'discovery',
  'config',
  'system',
  'data',
  'tenant',
  'job',
  'integration',
] as const;
