// Package cloudaccount is the cloud account as an asset (asset-inventory
// ADR-0009 D1).
//
// The account — an AWS account, an Azure subscription, a GCP project — is the
// thing a tenant owns and connects through a cloud integration. It is a
// DECLARED asset of class `cloud_account`, created when the integration is
// added (device-interrogation-service), identified by one `cloud_resource_id`
// of the form `<provider>:<account id>`, and every cloud resource any
// collector records hangs off it with a measured `hosted_on` edge.
//
// It lives in shared/ because two services record cloud resources:
// device-interrogation-service (the collectors that go through
// upsertDeviceAsset: enumeration, load balancers, CDN, API gateways) and
// inventory-service (the at-rest findings — buckets, databases, key stores —
// that reach inventory only as findings). Two spellings of the account's
// identity, or two implementations of "which account is this resource in",
// would hang one resource under two accounts. One package is how they agree.
package cloudaccount

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// ClassKey is the account's class.
const ClassKey = string(assetclass.KeyCloudAccount)

// Providers are the cloud integration types an account can be declared for.
var Providers = []string{"aws", "azure", "gcp"}

// NormalizeProvider lower-cases a provider name and returns "" for anything
// that is not a cloud provider an integration can be added for.
func NormalizeProvider(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	for _, known := range Providers {
		if p == known {
			return p
		}
	}
	return ""
}

// ResourceID is the account asset's cloud_resource_id: `<provider>:<account>`.
// Empty when either half is unknown — an account nobody can name is not an
// asset anybody can find again.
func ResourceID(provider, accountID string) string {
	provider = NormalizeProvider(provider)
	accountID = strings.TrimSpace(accountID)
	if provider == "" || accountID == "" {
		return ""
	}
	return provider + ":" + accountID
}

// DisplayName is the account asset's name when the integration gives none.
func DisplayName(provider, accountID string) string {
	label := map[string]string{"aws": "AWS account", "azure": "Azure subscription", "gcp": "GCP project"}[NormalizeProvider(provider)]
	if label == "" {
		label = "Cloud account"
	}
	return label + " " + strings.TrimSpace(accountID)
}

// AccountFromResourceID reads the account out of a provider's own resource
// id, or "" when the id does not say:
//
//   - AWS ARN `arn:partition:service:region:account:resource` — field 4, which
//     is EMPTY on an S3 bucket ARN (the bucket namespace is global);
//   - Azure ARM path `/subscriptions/<id>/…`;
//   - GCP resource name or self-link containing `projects/<id>/`.
//
// The resource's own statement of its owner beats the integration's account:
// a resource shared into the integration's account from another one belongs
// to the account that created it.
func AccountFromResourceID(provider, resourceID string) string {
	rid := strings.TrimSpace(resourceID)
	switch NormalizeProvider(provider) {
	case "aws":
		parts := strings.Split(rid, ":")
		if len(parts) >= 6 && parts[0] == "arn" {
			return strings.TrimSpace(parts[4])
		}
	case "azure":
		return segmentAfter(rid, "subscriptions")
	case "gcp":
		return segmentAfter(rid, "projects")
	}
	return ""
}

// segmentAfter returns the path segment following `key/`, case-insensitively.
func segmentAfter(path, key string) string {
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], key) {
			return strings.TrimSpace(parts[i+1])
		}
	}
	return ""
}

// Resolve decides which account a resource is in: the account the finding
// states, else the one its resource id states, else the integration's.
func Resolve(provider, stated, resourceID, integrationAccount string) string {
	for _, v := range []string{stated, AccountFromResourceID(provider, resourceID), integrationAccount} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// Integration is what the platform knows about one cloud integration's
// account.
type Integration struct {
	ID       uuid.UUID
	Provider string
	// AccountID is platform_integrations.account_id; "" when the integration
	// does not state one (an AWS integration created before its first
	// successful connection test).
	AccountID string
	// AutoApprove is platform_integrations.auto_approve_resources.
	AutoApprove bool
	Name        string
}

// LoadIntegration reads one tenant integration on a tenant-scoped
// transaction. A missing or deleted integration is (nil, nil).
func LoadIntegration(ctx context.Context, tx *sql.Tx, tenantID, integrationID uuid.UUID) (*Integration, error) {
	var in Integration
	err := tx.QueryRowContext(ctx, `
		SELECT id, integration_type, coalesce(account_id, ''), auto_approve_resources, integration_name
		  FROM platform_integrations
		 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, integrationID, tenantID).
		Scan(&in.ID, &in.Provider, &in.AccountID, &in.AutoApprove, &in.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cloudaccount: read integration %s: %w", integrationID, err)
	}
	in.Provider = NormalizeProvider(in.Provider)
	in.AccountID = strings.TrimSpace(in.AccountID)
	return &in, nil
}

// FindAsset returns the account asset's id, or "" when the tenant has none
// for that account. More than one owner of one identifier is a broken
// invariant the identity engine would report as a conflict; here it is an
// error rather than a guess.
func FindAsset(ctx context.Context, r *pgidentity.Repository, tenantID, provider, accountID string) (string, error) {
	rid := ResourceID(provider, accountID)
	if rid == "" {
		return "", nil
	}
	refs, err := r.FindByIdentifier(ctx, tenantID, identity.KindCloudResourceID, rid, "")
	if err != nil {
		return "", err
	}
	switch len(refs) {
	case 0:
		return "", nil
	case 1:
		return refs[0].ID, nil
	}
	return "", fmt.Errorf("cloudaccount: %d assets own %s", len(refs), rid)
}

// LinkHostedOn writes the measured `hosted_on` edge from a cloud resource to
// its account asset, and reports whether there was an account to link to.
//
// The status comes from EdgeStatusFor, so the edge is `active` exactly when
// both ends are approved and `pending` otherwise — and approving the resource
// later promotes it (inventory-service's promoteEdgesForApprovedAssets).
// Callers that auto-approve a resource must therefore do it BEFORE calling
// this, so the edge enters active.
//
// No account asset is not an error: the tenant may have reached the resource
// through an integration that names no account, or the resource may state an
// account nobody connected. The edge waits for the next run.
func LinkHostedOn(ctx context.Context, r *pgidentity.Repository, tenantID, resourceAssetID, provider, accountID string, source identity.Source, at time.Time) (bool, error) {
	accountAsset, err := FindAsset(ctx, r, tenantID, provider, accountID)
	if err != nil || accountAsset == "" {
		return false, err
	}
	if accountAsset == resourceAssetID {
		// The account asset itself — nothing hosts an account.
		return false, nil
	}
	status, err := r.EdgeStatusFor(ctx, tenantID, source.Kind, resourceAssetID, accountAsset)
	if err != nil {
		return false, err
	}
	if err := r.UpsertRelationship(ctx, tenantID, pgidentity.Edge{
		FromAssetID: resourceAssetID,
		ToAssetID:   accountAsset,
		Type:        string(relationships.HostedOn),
		SourceKind:  source.Kind,
		SourceRef:   source.Ref,
		Status:      status,
		ObservedAt:  at,
	}); err != nil {
		if errors.Is(err, pgidentity.ErrSelfEdge) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ApproveAsset moves a pending asset to monitoring inside the caller's
// transaction, records WHY in asset_history, and promotes the edges the
// approval makes live (pgidentity.PromoteEdgesForApproved — the one
// implementation of that rule). It reports whether anything changed: an asset
// that is already monitoring, denied, archived or deleted is left exactly as
// a person last decided.
//
// Used for the two approvals ADR-0009 makes without a person in Approvals:
// the account asset (approved by the act of adding the integration, D1) and a
// resource an account-level rule approves (D5). The rule id, when there is
// one, goes into the history row so the timeline says which rule decided.
func ApproveAsset(ctx context.Context, r *pgidentity.Repository, tenantID, assetID uuid.UUID, source identity.Source, changes map[string]any) (bool, error) {
	tx := r.Tx()
	if tx == nil {
		return false, errors.New("cloudaccount: ApproveAsset needs a bound transaction")
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE assets SET asset_status = 'monitoring', updated_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
		   AND asset_status = 'pending_approval'`, tenantID, assetID)
	if err != nil {
		return false, fmt.Errorf("cloudaccount: approve %s: %w", assetID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if changes == nil {
		changes = map[string]any{}
	}
	changes["asset_status"] = identity.StatusMonitoring
	if err := r.RecordHistory(ctx, identity.HistoryEntry{
		TenantID: tenantID.String(), AssetID: assetID.String(),
		Action: identity.ActionApproved, Source: source, Changes: changes, At: time.Now().UTC(),
	}); err != nil {
		return false, err
	}
	return true, pgidentity.PromoteEdgesForApproved(ctx, tx, tenantID, []uuid.UUID{assetID})
}
