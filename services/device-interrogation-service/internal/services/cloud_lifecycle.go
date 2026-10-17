package services

// One cloud enumeration per account, per type, per region, and the evidence
// the lifecycle needs to tell "gone" from "not looked for" (asset-inventory
// ADR-0009 D3 and D6; DCIM BUILD_PLAN row 4.6).
//
// D3 collapses the two collection switches. `resource_types` used to choose
// only the crypto / at-rest collectors while compute and network enumeration
// rode an integration-level `enumerate_compute` boolean; the enumeration
// listings are now resource types like any other (`compute_instances`,
// `networks`, `security_groups`), selected the same way, defaulting — with
// everything else — to "everything the credentials can read", and reported
// per type and per region on the job. AWS regions are discovered from the
// account (ec2:DescribeRegions) instead of typed into the Discover modal.
//
// D6 makes disappearance a lifecycle event. Every resource a listing returns
// carries `cloud.listing` (which listing) and `cloud.last_enumerated_at` (the
// run's clock); the account asset carries `cloud.enumeration_coverage`, the
// time each listing last COMPLETED. inventory-service's stale sweep reads the
// three: a resource whose listing completed after it was last returned is
// absent, and moves to stale on its class's window. A listing that failed or
// was partial records no coverage and so moves nothing — "could not look" is
// never evidence of "is not there".

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// The enumeration listings as resource types (ADR-0009 D3).
const (
	CloudTypeComputeInstances = "compute_instances"
	CloudTypeNetworks         = "networks"
	CloudTypeSecurityGroups   = "security_groups"
	// CloudTypeRegionDiscovery is the outcome row for the region listing
	// itself, recorded only when it FAILS (the run then reads the
	// integration's own region and says so).
	CloudTypeRegionDiscovery = "region_discovery"
)

// cloudEnumerationSelection is which enumeration listings a run was asked for.
type cloudEnumerationSelection struct {
	Instances, Networks, Groups bool
}

func selectEnumeration(resourceTypes []string) cloudEnumerationSelection {
	var sel cloudEnumerationSelection
	for _, t := range resourceTypes {
		switch strings.TrimSpace(t) {
		case CloudTypeComputeInstances:
			sel.Instances = true
		case CloudTypeNetworks:
			sel.Networks = true
		case CloudTypeSecurityGroups:
			sel.Groups = true
		}
	}
	return sel
}

func (e cloudEnumerationSelection) any() bool { return e.Instances || e.Networks || e.Groups }

// needsNetworks: instances are placed by their ENIs' prefixes, so selecting
// instances reads the networks too.
func (e cloudEnumerationSelection) needsNetworks() bool { return e.Networks || e.Instances }

// needsGroups: an instance's group membership is named from the group listing.
func (e cloudEnumerationSelection) needsGroups() bool { return e.Groups || e.Instances }

// cloudTerminalResource is a resource the provider still lists but reports in
// a terminal state. It is never created; an existing asset for it gets the
// state as `cloud.provider_state`, which the lifecycle records as the reason.
type cloudTerminalResource struct {
	ResourceID string
	State      string
}

// merge folds one region's plan into the run's.
func (p *cloudEnumerationPlan) merge(other cloudEnumerationPlan) {
	p.Networks = append(p.Networks, other.Networks...)
	p.Subnets = append(p.Subnets, other.Subnets...)
	p.Instances = append(p.Instances, other.Instances...)
	p.Terminal = append(p.Terminal, other.Terminal...)
	p.SecurityGroups = append(p.SecurityGroups, other.SecurityGroups...)
	if p.SecurityGroupIDs == nil {
		p.SecurityGroupIDs = map[string]bool{}
	}
	for id := range other.SecurityGroupIDs {
		p.SecurityGroupIDs[id] = true
	}
}

// annotateListing stamps an enumerated resource with the listing that returned
// it and the provider's lifecycle state.
func (r *cloudEnumResource) annotateListing(listing string) {
	if r.Facts == nil {
		r.Facts = map[string]any{}
	}
	r.Facts[facts.KeyCloudListing] = listing
	provider, _ := r.Facts[facts.KeyCloudProvider].(string)
	if state := normalizeProviderState(provider, cloudRawState(r.Metadata)); state != "" {
		r.Facts[facts.KeyCloudProviderState] = state
	}
}

// cloudRawState reads the provider's own state word off a resource's metadata.
func cloudRawState(metadata map[string]interface{}) string {
	for _, key := range []string{"state", "provisioning_state", "status", "key_state"} {
		if v, ok := metadata[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// normalizeProviderState lower-cases a provider state and folds the
// spellings that mean the same thing. GCP's `TERMINATED` is a STOPPED
// instance (it can be started again), not a deleted one, so it is recorded as
// `stopped` and never read as terminal.
func normalizeProviderState(provider, raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, " ", "_")
	if strings.EqualFold(provider, "gcp") && v == "terminated" {
		return "stopped"
	}
	switch v {
	case "pendingdeletion", "pending-deletion":
		return "pending_deletion"
	}
	return v
}

// cloudListingFacts are the lifecycle facts one recorded resource carries:
// which listing returned it, when, and what state the provider reports.
// Nothing without a listing — a resource recorded outside a run (a
// single-resource refresh) proves nothing about the listing it belongs to.
func cloudListingFacts(scope cloudScope, listing, state string) map[string]any {
	listing = strings.TrimSpace(listing)
	if listing == "" || scope.RunAt.IsZero() {
		return nil
	}
	out := map[string]any{
		facts.KeyCloudListing:          listing,
		facts.KeyCloudLastEnumeratedAt: scope.RunAt.Format(time.RFC3339Nano),
	}
	if state != "" {
		out[facts.KeyCloudProviderState] = state
	}
	return out
}

// discoverAWSRegions answers the regions an AWS run reads when the request
// named none: the account's enabled regions. A failed listing is RECORDED and
// the run falls back to the integration's own region, so the job says it
// read one region because it could not list the rest — never silently.
func (s *CloudDiscoveryService) discoverAWSRegions(ctx context.Context, integrationID uuid.UUID) []string {
	client, err := awsclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
	if err != nil {
		return nil
	}
	return discoverRegionsWith(ctx, client.EC2ClientForRegion(client.GetRegion()), client.GetRegion())
}

func discoverRegionsWith(ctx context.Context, api awsclient.RegionAPI, fallback string) []string {
	regions, err := awsclient.ListEnabledRegions(ctx, api)
	if err == nil && len(regions) > 0 {
		return regions
	}
	if err == nil {
		err = fmt.Errorf("the account listed no enabled regions")
	}
	cloudOutcomesFrom(ctx).Attempt(CloudTypeRegionDiscovery, cloudScopeGlobal, 0, err)
	logCloudCollectorFailure(CloudTypeRegionDiscovery, cloudScopeGlobal, err)
	if fallback == "" {
		return nil
	}
	return []string{fallback}
}

// recordTerminalStates writes `cloud.provider_state` on the existing assets of
// resources the provider reports terminal. A terminal resource with no asset
// is ignored: it is never created.
func (s *CloudDiscoveryService) recordTerminalStates(ctx context.Context, tenantID uuid.UUID, vendor string, terminal []cloudTerminalResource) {
	if len(terminal) == 0 || s.devices == nil {
		return
	}
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	repo := s.devices.Repo()
	source := cloudSource(stringPtr(vendor))
	for _, t := range terminal {
		err := repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
			refs, err := r.FindByIdentifier(ctx, tenantID.String(), identity.KindCloudResourceID, t.ResourceID, "")
			if err != nil || len(refs) != 1 {
				return err
			}
			rows := cloudFactRows(map[string]any{facts.KeyCloudProviderState: t.State}, source, scope.RunAt)
			return r.UpsertFacts(ctx, refs[0], facts.ProducerCloudCollector, rows)
		})
		if err != nil {
			log.Printf("[cloud lifecycle] terminal state of %s not recorded: %v", t.ResourceID, err)
		}
	}
}

// recordEnumerationCoverage stamps the account asset with every listing this
// run completed (CloudOutcomeRecorder.Covered), merged over what earlier runs
// recorded: a run that read only KMS must not erase when the instances were
// last listed. No account asset, no coverage — and so nothing this account
// lists can be judged absent until one is declared.
func (s *CloudDiscoveryService) recordEnumerationCoverage(ctx context.Context, tenantID uuid.UUID, vendor string) {
	covered := cloudOutcomesFrom(ctx).Covered()
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	if len(covered) == 0 || scope.AccountID == "" || scope.RunAt.IsZero() || s.devices == nil {
		return
	}
	provider := cloudaccount.NormalizeProvider(scope.Provider)
	source := cloudSource(stringPtr(vendor))
	err := s.devices.Repo().RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		assetID, err := cloudaccount.FindAsset(ctx, r, tenantID.String(), provider, scope.AccountID)
		if err != nil || assetID == "" {
			return err
		}
		merged := map[string]any{}
		var raw []byte
		err = r.Tx().QueryRowContext(ctx, `
			SELECT value FROM public.asset_facts
			 WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND source_ref = $4`,
			tenantID, assetID, facts.KeyCloudEnumerationCoverage, source.Ref).Scan(&raw)
		if err == nil {
			_ = json.Unmarshal(raw, &merged)
		}
		at := scope.RunAt.Format(time.RFC3339Nano)
		sort.Strings(covered)
		for _, listing := range covered {
			merged[listing] = at
		}
		rows := cloudFactRows(map[string]any{facts.KeyCloudEnumerationCoverage: merged}, source, scope.RunAt)
		return r.UpsertFacts(ctx, identity.AssetRef{TenantID: tenantID.String(), ID: assetID}, facts.ProducerCloudCollector, rows)
	})
	if err != nil {
		log.Printf("[cloud lifecycle] enumeration coverage for %s:%s not recorded: %v", provider, scope.AccountID, err)
	}
}
