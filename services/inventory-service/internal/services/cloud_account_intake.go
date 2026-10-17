package services

// The account half of the cloud intake on THIS service's side
// (asset-inventory ADR-0009 D1, D5).
//
// device-interrogation-service records most cloud resources itself, through
// its upsertDeviceAsset funnel, and does the account work there. The at-rest
// collectors' resources — buckets, managed databases, key stores — reach
// inventory ONLY as findings (the pipeline import and RecordCloudKeyStores),
// so the same two steps have to happen here too, through the same shared
// helpers:
//
//  1. the finding's account goes onto the `observation` the tenant's
//     auto-approval rules are evaluated against (Discovery.CloudAccountID),
//     so an account rule can approve it — shared/approval decides;
//  2. the resolved asset gets its measured `hosted_on` edge to the account
//     asset (cloudaccount.LinkHostedOn).
//
// Which account a finding is in is cloudaccount.Resolve's answer — the
// account the finding states, else the one its resource id states, else the
// account of the integration whose credentials read it — the same precedence
// device-interrogation-service uses, so one resource cannot hang under two
// accounts depending on which path recorded it.

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// cloudAccountResolver answers "which account is this cloud finding in" for
// one import request, reading each integration's account at most once.
type cloudAccountResolver struct {
	s        *AssetService
	tenantID uuid.UUID
	mu       sync.Mutex
	byInteg  map[string]string
}

func (s *AssetService) newCloudAccountResolver(tenantID uuid.UUID) *cloudAccountResolver {
	return &cloudAccountResolver{s: s, tenantID: tenantID, byInteg: map[string]string{}}
}

// cloudFindingProvider is the provider a cloud finding names, from its
// envelope or, failing that, its device_type prefix (`aws_s3_bucket`).
func cloudFindingProvider(f IngestFinding) string {
	if p := cloudaccount.NormalizeProvider(rawDataString(f.RawData, "cloud_provider")); p != "" {
		return p
	}
	dt := rawDataString(f.RawData, "device_type")
	if i := strings.IndexByte(dt, '_'); i > 0 {
		return cloudaccount.NormalizeProvider(dt[:i])
	}
	return ""
}

// account returns the finding's provider and account, both "" for a finding
// that is not a cloud provider's listing.
func (a *cloudAccountResolver) account(f IngestFinding) (string, string) {
	if a == nil || !isCloudAPIFinding(f) {
		return "", ""
	}
	provider := cloudFindingProvider(f)
	// The key-store records state the account under the provider's own name
	// for it (subscription_id, project_id); the device path's envelope says
	// cloud_account_id.
	stated := rawDataString(f.RawData, "cloud_account_id", "account_id", "subscription_id", "project_id")
	return provider, cloudaccount.Resolve(provider, stated, cloudResourceID(f), a.integrationAccount(f))
}

// attributes projects the cloud-resource base fields used by the Cloud lens
// onto an asset created or refreshed from a finding. Findings are the only
// inventory path for at-rest resources such as S3 buckets, so relying on the
// device materializer to add these fields leaves those assets grouped under
// Unknown even though the envelope carries provider, integration and region.
//
// Only the four registry-defined cloud_resource fields are admitted here. The
// provider-native id remains an asset identifier, never a duplicate attribute.
func (a *cloudAccountResolver) attributes(f IngestFinding) map[string]interface{} {
	provider, account := a.account(f)
	if provider == "" {
		return nil
	}
	out := map[string]interface{}{"provider": provider}
	if account != "" {
		out["account_id"] = account
	}
	if region := rawDataString(f.RawData, "cloud_region", "region"); region != "" {
		out["region"] = region
	}
	spelling := rawDataString(f.RawData, "resource_type", "cloud_resource_type", "device_type")
	if pt, ok := assetclass.ProviderTypeOf(spelling); ok && (pt.Provider == "" || pt.Provider == provider) {
		out["provider_type"] = pt.Type
	}
	return out
}

// integrationAccount reads the account of the integration that read the
// finding. A failed read is "unknown", logged: the finding then simply has no
// account, which is what it had before accounts existed.
func (a *cloudAccountResolver) integrationAccount(f IngestFinding) string {
	raw := rawDataString(f.RawData, "integration_id", "source_integration_id")
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || a.s.db == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if v, ok := a.byInteg[id.String()]; ok {
		return v
	}
	var acct string
	err = database.WithTenantTx(context.Background(), a.s.db, a.tenantID, func(tx *sqlx.Tx) error {
		in, err := cloudaccount.LoadIntegration(context.Background(), tx.Tx, a.tenantID, id)
		if in != nil {
			acct = in.AccountID
		}
		return err
	})
	if err != nil {
		log.Printf("[AssetService] cloud account of integration %s unreadable: %v", id, err)
	}
	a.byInteg[id.String()] = acct
	return acct
}

// linkCloudAccount writes the resolved cloud resource's `hosted_on` edge to
// its account asset. A failure is logged and the batch continues — the edge is
// re-asserted on the resource's next observation.
func (s *AssetService) linkCloudAccount(ctx context.Context, accounts *cloudAccountResolver, tenantID, assetID uuid.UUID, f IngestFinding) {
	provider, account := accounts.account(f)
	if account == "" || s.identityRepo == nil {
		return
	}
	source := identity.Source{Kind: identity.SourceMeasured, Ref: "cloud", Mode: identity.ModeActive}
	if provider != "" {
		source.Ref = "cloud:" + provider
	}
	err := s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		_, err := cloudaccount.LinkHostedOn(ctx, r, tenantID.String(), assetID.String(), provider, account, source, time.Now().UTC())
		return err
	})
	if err != nil {
		log.Printf("[AssetService] IngestFindings: hosted_on edge %s -> %s account %s not written (batch continues): %v",
			assetID, provider, account, err)
	}
}

// placeCloudResource puts a cloud resource in its account's site and its
// region's location there (DCIM row 2.1, shared/cloudaccount.PlaceInRegion).
// A resource whose account has no asset is left unplaced until the account is
// declared. Failures are logged; the batch continues.
func (s *AssetService) placeCloudResource(ctx context.Context, accounts *cloudAccountResolver, tenantID, assetID uuid.UUID, f IngestFinding, region string) bool {
	provider, account := accounts.account(f)
	if account == "" || s.identityRepo == nil || strings.EqualFold(strings.TrimSpace(region), "global") {
		return false
	}
	var moved bool
	err := s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		var err error
		moved, err = cloudaccount.PlaceInRegion(ctx, r, tenantID, assetID, provider, account, region)
		return err
	})
	if err != nil {
		log.Printf("[AssetService] IngestFindings: placing %s in %s/%s not written (batch continues): %v", assetID, provider, region, err)
		return false
	}
	return moved
}
