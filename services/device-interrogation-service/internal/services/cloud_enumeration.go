package services

// Cloud enumeration — compute instances, their network interfaces, virtual
// networks, subnets and security groups on AWS, Azure and GCP (BUILD_PLAN
// 2.4, ADR-0004 D1 item 6; DCIM row 1.5f).
//
// What this adds to cloud discovery, and what it deliberately does not:
//
// **It adds inventory, not findings.** Everything here goes through the SAME
// identification engine every other cloud resource goes through
// (`upsertDeviceAsset` → `resolveObservation`), so an instance found here and
// the same host seen by the sensor or named in a CMDB pull resolve to ONE
// asset. New assets land `pending_approval` like any other, and a re-run
// matches on `cloud_resource_id` and updates rather than duplicating.
//
// **It writes no sensor_discoveries.** An EC2 instance negotiates no protocol
// and states no at-rest encryption; it is not a crypto finding. The old
// crypto-config-less fallback would have written it as a TLS endpoint on port
// 443 with no version and no cipher suite — the phantom-endpoint mistake this
// codebase has already paid for twice. `inventoryOnlyDeviceTypes`
// (cloud_discovery_service.go) is what keeps them out of that path.
//
// **Networks are IPAM, not assets (DCIM row 1.5f, asset-inventory ADR-0009
// amendment).** A VPC / VNet / GCP network is a container prefix and each of
// its subnets a prefix, all carrying `cloud_network_ref` = the network's
// provider id; an instance's ENI / NIC is an observed `virtual` interface and
// its private addresses are `ip_addresses` on it. Which subnet an instance is
// in is therefore prefix containment of its address — there is no VPC or
// subnet asset and no `contains` edge VPC → subnet → instance any more. All of
// it travels on sightings through the intake seam (identity.ObservedInterface /
// ObservedPrefix, shared/identity/observed_network.go); nothing here writes an
// interface, address or prefix itself.
//
// **`hosted_on` → the account asset.** The account became an asset in
// asset-inventory ADR-0009 D1 (declared when the integration is added; see
// cloud_account.go), and every resource recorded through upsertDeviceAssetWith
// — enumerated ones included — gets the measured `hosted_on` edge to it there.
// The region is still not an asset (a region is a place, not a thing anybody
// owns): it stays the `cloud.region` fact, beside `cloud.account_id`.
//
// **Security groups are assets (asset-inventory ADR-0009 D2, DCIM row 4.6).**
// A group, NSG or GCP firewall rule is recorded as a `security_group` asset
// before the instances, and each instance in it gets a measured `member_of`
// edge to it (cloud_tier1.go). Identity and membership only: the rules
// themselves are never retrieved into a struct that has a field for them. The
// `cloud.security_groups` membership fact is still written on the member.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// Device types the enumeration emits. Each one has a row in
// shared/assetclass's device_type table; a type with no row would be classed
// `cloud_resource`, which is true but coarse, and the class is what the
// Inventory lenses facet on. Networks and subnets have no device type: they
// are prefixes, not assets (row 1.5f).
const (
	DeviceTypeAWSEC2Instance     = "aws_ec2_instance"
	DeviceTypeAzureVM            = "azure_vm"
	DeviceTypeGCPComputeInstance = "gcp_compute_instance"
)

// cloudPrefixNetworkType is `prefixes.network_type` for every prefix a cloud
// enumeration records.
const cloudPrefixNetworkType = "cloud"

// Enumeration is NOT gated on a `resource_types` entry, and that is a decision
// rather than an omission.
//
// `resource_types` selects which CRYPTO collectors run — load balancers, KMS,
// buckets — and each of those is an independent posture question an operator
// might reasonably want on its own. The inventory is not: an account's
// instances and networks are the frame everything else hangs on, and a
// discovery run that found a TLS listener on a machine it did not inventory is
// half an answer. So enumeration runs on every cloud job for an integration
// that has it on, and the single switch is the integration's
// `enumerate_compute` (cloud_integration_auth.go), which exists because the
// extra API calls cost real quota in a large account.
//
// Consequence worth knowing: an EXISTING saved schedule starts enumerating on
// the next run without being edited. That is the intended default-on behaviour;
// an operator who does not want it turns the integration toggle off.

// CloudEnumerationCounts is what one enumeration pass found, for the job result.
//
// Networks and Subnets count the VPCs / VNets / networks and their subnets the
// run read — recorded as prefixes, not assets, since row 1.5f. SecurityGroups
// counts DISTINCT groups observed as membership, not assets: there is no
// security-group asset (see the file comment). Both are still reported
// because "this run saw 14 security groups" is what tells an operator the
// membership fact is populated.
type CloudEnumerationCounts struct {
	Instances      int `json:"instances"`
	Networks       int `json:"networks"`
	Subnets        int `json:"subnets"`
	SecurityGroups int `json:"security_groups"`
}

// Total is the number of ASSETS the enumeration recorded: the instances.
// Networks and subnets are prefixes and security groups are membership, so
// neither counts.
func (c CloudEnumerationCounts) Total() int {
	return c.Instances
}

// Empty reports whether nothing at all was enumerated, so the job result can
// omit the block rather than claim four zeros for a run that never enumerated.
func (c CloudEnumerationCounts) Empty() bool {
	return c.Instances == 0 && c.Networks == 0 && c.Subnets == 0 && c.SecurityGroups == 0
}

// cloudEnumResource is one compute instance an enumeration found, in a
// provider-independent shape.
//
// The provider builders produce these from their own projections and nothing
// else; recording them is provider-independent. That split is what makes the
// builders pure functions a test can drive from a recorded API response with no
// database, no credential and no network.
type cloudEnumResource struct {
	DeviceType string
	// ResourceID is the canonical `cloud_resource_id`: an ARN on AWS, a
	// `/subscriptions/...` resource id on Azure, a partial resource name on GCP.
	// It is the identity the engine deduplicates on, so a resource without one
	// is dropped rather than recorded under a weaker key.
	ResourceID  string
	DisplayName string
	Hostname    string
	IPAddress   string
	// CloudNetworkRef is the VPC / VNet / GCP network this resource sits in,
	// as the provider's canonical resource id: which ADDRESS SPACE its
	// private addresses are in. Every prefix the enumeration records carries
	// the same value (cloudNetwork.NetworkRef), so the identity scope of an
	// instance's address is its subnet's prefix whether the address was
	// reported by this enumeration or by an agent inside the instance — and
	// two VPCs with the same CIDR stay two address spaces.
	CloudNetworkRef string
	// Interfaces are the instance's ENIs / NICs as observed `virtual`
	// interfaces with their private addresses, and Prefixes the prefixes of
	// the networks and subnets those interfaces sit in (DCIM row 1.5f). They
	// ride on the instance's sighting; the engine records them.
	Interfaces []identity.ObservedInterface
	Prefixes   []identity.ObservedPrefix
	Facts      map[string]any
	Attributes map[string]any
	Tags       map[string]interface{}
	Metadata   map[string]interface{}
	// MemberOf are the canonical resource ids of the security groups the
	// resource is in: each becomes a `member_of` edge to that group's asset
	// when the group is in the inventory (ADR-0009 D4).
	MemberOf []string
}

// cloudNetwork is one VPC / VNet / GCP network, or one subnet of one, as the
// enumeration read it: the prefixes it becomes.
type cloudNetwork struct {
	// ResourceID is the provider's canonical id of this network or subnet.
	ResourceID string
	// NetworkRef is the id of the VPC / VNet / GCP network it belongs to — its
	// own ResourceID for a network, its parent's for a subnet. It is the
	// prefix's `cloud_network_ref` (see cloudEnumResource.CloudNetworkRef).
	NetworkRef string
	// Account is the account / subscription / project the network is in, as
	// the provider states it; Region its region ("" for a global GCP network).
	Account string
	Region  string
	Name    string
	// CIDRs are the address ranges: a VPC's CIDR blocks, a subnet's prefix.
	CIDRs []string
}

// prefixes are the network's address ranges as observed prefixes.
//
// `dhcp_managed` is stated FALSE, deliberately: a cloud subnet hands the SAME address to the
// SAME instance for that instance's whole life, which is not the lease churn
// the dynamic-address rule exists for. A learned prefix nobody has stated a
// posture on reads as dynamic (row 1.4), and that would stop every instance's
// address from deciding anything — the address is precisely how an agent
// installed inside the instance, or the sensor seeing it on the wire, reaches
// the same asset. The honest qualifier: the address is stable for an
// instance's life, NOT across instances; a freed address handed to the next
// instance carries a different `cloud_resource_id`, and the singleton guard
// turns that into a merge proposal (ADR-0002 D3 erratum).
//
// A range too broad to be anybody's (probeconsent.TooBroadToClaim) is not
// recorded: a prefix is a consent and approval scope (row 1.6), held to the
// rule every scope write is.
//
// The prefixes carry no scope here; recordNetworkPrefixes scopes each to its
// region's location under the account's site (DCIM row 2.1) once it holds the
// account's transaction.
func (n cloudNetwork) prefixes() []identity.ObservedPrefix {
	notDHCP := false
	var out []identity.ObservedPrefix
	for _, raw := range n.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			log.Printf("[cloud enumeration] %s: %q is not a CIDR prefix; not recorded", n.ResourceID, raw)
			continue
		}
		if probeconsent.TooBroadToClaim(p) {
			log.Printf("[cloud enumeration] %s: %s is too broad to record as a prefix; skipped", n.ResourceID, raw)
			continue
		}
		f := notDHCP
		out = append(out, identity.ObservedPrefix{
			Prefix:          p.Masked().String(),
			NetworkType:     cloudPrefixNetworkType,
			CloudNetworkRef: n.NetworkRef,
			DHCPManaged:     &f,
		})
	}
	return out
}

// cloudEnumerationPlan is one provider's whole enumeration, built before
// anything is written.
//
// Built-then-recorded rather than written as it goes, because the prefixes
// have to exist BEFORE any instance is resolved: the scope an instance's
// private address identifies within is looked up at observation time, and an
// instance resolved before its subnet's prefix exists would be scoped to the
// tenant default and then never re-scoped.
type cloudEnumerationPlan struct {
	Provider  string
	Vendor    string
	Networks  []cloudNetwork
	Subnets   []cloudNetwork
	Instances []cloudEnumResource
	// SecurityGroupIDs are the distinct groups seen, for the count. The groups
	// themselves are membership facts on the resources, not rows.
	SecurityGroupIDs map[string]bool
	// Terminal are resources the provider still lists in a terminal state
	// (ADR-0009 D6). Never created; an existing asset gets the state.
	Terminal []cloudTerminalResource
	// SecurityGroups are the groups as ASSETS (ADR-0009 D2), recorded before
	// the instances so each instance's `member_of` edge finds its group.
	SecurityGroups []cloudEnumResource
}

func (p cloudEnumerationPlan) counts() CloudEnumerationCounts {
	return CloudEnumerationCounts{
		Instances:      len(p.Instances),
		Networks:       len(p.Networks),
		Subnets:        len(p.Subnets),
		SecurityGroups: len(p.SecurityGroupIDs),
	}
}

// networkPrefixesByAccount groups every network's and subnet's prefixes by the
// account they are in, networks first, each prefix once.
func (p cloudEnumerationPlan) networkPrefixesByAccount() (map[string][]identity.ObservedPrefix, []string) {
	out := map[string][]identity.ObservedPrefix{}
	var order []string
	seen := map[string]bool{}
	for _, group := range [][]cloudNetwork{p.Networks, p.Subnets} {
		for _, n := range group {
			account := strings.TrimSpace(n.Account)
			for _, pr := range n.prefixes() {
				key := account + "|" + pr.CloudNetworkRef + "|" + pr.Prefix
				if seen[key] {
					continue
				}
				seen[key] = true
				if _, ok := out[account]; !ok {
					order = append(order, account)
				}
				out[account] = append(out[account], pr)
			}
		}
	}
	return out, order
}

// prefixRegions maps each network prefix (keyed as networkPrefixesByAccount
// dedupes them: account|network ref|prefix) to the region its network or
// subnet is in. The first statement wins, networks before subnets, as there.
func (p cloudEnumerationPlan) prefixRegions() map[string]string {
	out := map[string]string{}
	for _, group := range [][]cloudNetwork{p.Networks, p.Subnets} {
		for _, n := range group {
			region := strings.TrimSpace(n.Region)
			if region == "" {
				continue
			}
			account := strings.TrimSpace(n.Account)
			for _, pr := range n.prefixes() {
				key := account + "|" + pr.CloudNetworkRef + "|" + pr.Prefix
				if _, ok := out[key]; !ok {
					out[key] = region
				}
			}
		}
	}
	return out
}

// scopeToRegions places the account's prefixes in their regions' locations
// under the account's site (DCIM row 2.1, ADR-0009 D1), creating the site and
// the locations as needed, inside the caller's transaction. A prefix whose
// network names no region stays unscoped.
func scopeToRegions(ctx context.Context, r *pgidentity.Repository, tenantID uuid.UUID, accountAsset, provider, account, stated string, prefixes []identity.ObservedPrefix, regions map[string]string) ([]identity.ObservedPrefix, error) {
	assetID, err := uuid.Parse(accountAsset)
	if err != nil {
		return prefixes, err
	}
	var name string
	if err := r.Tx().QueryRowContext(ctx, `SELECT coalesce(display_name, '') FROM public.assets WHERE tenant_id = $1 AND id = $2`, tenantID, assetID).Scan(&name); err != nil {
		return prefixes, err
	}
	siteID, err := cloudaccount.EnsureSite(ctx, r, tenantID, assetID, provider, account, name)
	if err != nil {
		return prefixes, err
	}
	locations := map[string]uuid.UUID{}
	out := make([]identity.ObservedPrefix, len(prefixes))
	for i, pr := range prefixes {
		out[i] = pr
		region := regions[stated+"|"+pr.CloudNetworkRef+"|"+pr.Prefix]
		if region == "" {
			continue
		}
		loc, ok := locations[region]
		if !ok {
			if loc, err = cloudaccount.EnsureRegionLocation(ctx, r, tenantID, siteID, provider, region); err != nil {
				return prefixes, err
			}
			locations[region] = loc
		}
		out[i].ScopeKind, out[i].ScopeID = string(dcim.ObjectKindLocation), loc.String()
	}
	return out, nil
}

// CloudDiscoveryResult is one cloud discovery run's whole output: the resources
// it found (crypto/at-rest collectors AND enumeration), plus what the
// enumeration half counted.
//
// It exists because the per-provider Discover*Resources methods return a device
// slice and nothing else, and the enumeration counts are not derivable from it
// — a security group is membership, not a device, so a count taken from the
// devices would silently mean "groups that happened to be attached" rather than
// "groups the run enumerated".
type CloudDiscoveryResult struct {
	Devices     []models.Device
	Enumeration CloudEnumerationCounts
	Identity    CloudIdentitySummary
	Retained    map[string]identity.IngestResult
	// EnumerationSkipped names why enumeration did not run, or "" when it did.
	// Reported rather than left blank so a job whose counts are all zero says
	// whether it found nothing or was switched off.
	EnumerationSkipped string
}

// DiscoverResourceEvidence runs the requested provider collectors, preserving
// retained outcomes and persistence failures for both job and single-resource
// callers. Account-wide compute enumeration belongs to DiscoverResources.
func (s *CloudDiscoveryService) DiscoverResourceEvidence(
	ctx context.Context,
	tenantID, integrationID uuid.UUID,
	cloudProvider string,
	resourceTypes, regions, resourceGroups []string,
) (*CloudDiscoveryResult, error) {
	out := &CloudDiscoveryResult{}
	run := &cloudRunEvidence{}
	ctx = context.WithValue(ctx, cloudRunKey{}, run)
	// The run's scope, resolved once. Every resource the collectors below
	// record reaches `upsertDeviceAsset`, which reads this to write the
	// resource's `cloud.account_id` / `cloud.region`. Resolved here rather than
	// per-resource because it is one row per run, and here rather than in
	// `DiscoverResources` because the single-resource callers come through this
	// function too.
	ctx = s.beginCloudRun(ctx, tenantID, integrationID, cloudProvider)
	defer func() {
		run.mu.Lock()
		out.Identity = run.summary
		out.Retained = run.retained
		run.mu.Unlock()
	}()

	var err error
	switch cloudProvider {
	case "aws":
		out.Devices, err = s.DiscoverAWSResources(ctx, tenantID, integrationID, resourceTypes, regions)
	case "azure":
		out.Devices, err = s.DiscoverAzureResources(ctx, tenantID, integrationID, resourceTypes, resourceGroups)
	case "gcp":
		out.Devices, err = s.DiscoverGCPResources(ctx, tenantID, integrationID, resourceTypes)
	default:
		return nil, fmt.Errorf("unknown cloud provider: %s", cloudProvider)
	}
	if err != nil {
		return nil, err
	}

	run.mu.Lock()
	recordErr := run.failure
	run.mu.Unlock()
	if recordErr != nil {
		return nil, fmt.Errorf("persist cloud evidence: %w", recordErr)
	}

	return out, nil
}

// DiscoverResources is one cloud discovery run over one account: the regions
// first (AWS: discovered from the account when the request names none), then
// every selected resource type in every region — the crypto / at-rest
// collectors and the enumeration listings alike, one selection
// (asset-inventory ADR-0009 D3) — and finally the run's lifecycle evidence:
// the provider's terminal states and the listings it completed (D6).
func (s *CloudDiscoveryService) DiscoverResources(ctx context.Context, tenantID, integrationID uuid.UUID, cloudProvider string, resourceTypes, regions, resourceGroups []string) (*CloudDiscoveryResult, error) {
	// One run, one account sync, one scope and one rule cache for both halves.
	ctx = s.beginCloudRun(ctx, tenantID, integrationID, cloudProvider)
	if cloudProvider == "aws" && len(regions) == 0 {
		regions = s.discoverAWSRegions(ctx, integrationID)
	}
	out, err := s.DiscoverResourceEvidence(ctx, tenantID, integrationID, cloudProvider, resourceTypes, regions, resourceGroups)
	if err != nil {
		return nil, err
	}
	run := &cloudRunEvidence{summary: out.Identity, retained: out.Retained}
	ctx = context.WithValue(ctx, cloudRunKey{}, run)
	defer func() { run.mu.Lock(); out.Identity = run.summary; out.Retained = run.retained; run.mu.Unlock() }()
	vendor := map[string]string{"aws": "AWS", "azure": "Azure", "gcp": "GCP"}[cloudProvider]
	defer s.recordEnumerationCoverage(ctx, tenantID, vendor)

	sel := selectEnumeration(resourceTypes)
	if !sel.any() {
		out.EnumerationSkipped = "no compute, network or security-group listing was selected for this run"
		return out, nil
	}

	settings, err := loadCloudIntegrationSettings(ctx, s.bypassDB, tenantID, integrationID)
	if err != nil {
		// The crypto half already succeeded and its devices are recorded. A
		// settings read that failed is a reason to skip enumeration and say so,
		// not to throw away a run that worked.
		out.EnumerationSkipped = fmt.Sprintf("integration settings unreadable: %v", err)
		log.Printf("[cloud enumeration] %s: %s", cloudProvider, out.EnumerationSkipped)
		return out, nil
	}

	enumerated, counts, err := s.enumerate(ctx, tenantID, integrationID, cloudProvider, settings.Environment, regions, sel)
	if err != nil {
		// Same reasoning: enumeration is additive. Losing it must not lose the
		// crypto findings the same run produced.
		out.EnumerationSkipped = err.Error()
		log.Printf("[cloud enumeration] %s: %v", cloudProvider, err)
		return out, nil
	}
	out.Devices = append(out.Devices, enumerated...)
	out.Enumeration = counts
	run.mu.Lock()
	recordErr := run.failure
	run.mu.Unlock()
	if recordErr != nil {
		return nil, fmt.Errorf("persist cloud enumeration: %w", recordErr)
	}
	return out, nil
}

// enumerate builds and records one provider's enumeration plan.
func (s *CloudDiscoveryService) enumerate(
	ctx context.Context,
	tenantID, integrationID uuid.UUID,
	cloudProvider, environment string,
	regions []string,
	sel cloudEnumerationSelection,
) ([]models.Device, CloudEnumerationCounts, error) {
	var (
		plan cloudEnumerationPlan
		err  error
	)
	switch cloudProvider {
	case "aws":
		var client *awsclient.Client
		client, err = awsclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
		if err == nil {
			plan, err = s.enumerateAWS(ctx, client, regions, sel)
		}
	case "azure":
		var client *azureclient.Client
		client, err = azureclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey, s.azureOptions...)
		if err == nil {
			plan, err = s.enumerateAzure(ctx, client, sel)
		}
	case "gcp":
		var client *gcpclient.Client
		client, err = gcpclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey, s.gcpOptions...)
		if err == nil {
			plan, err = s.enumerateGCP(ctx, client, sel)
		}
	default:
		return nil, CloudEnumerationCounts{}, fmt.Errorf("unknown cloud provider: %s", cloudProvider)
	}
	if err != nil {
		return nil, CloudEnumerationCounts{}, err
	}
	if !sel.Groups {
		// Listed only to name the instances' groups; the groups themselves
		// were not asked for as assets.
		plan.SecurityGroups = nil
	}
	if !sel.Networks {
		// Listed only to place the instances; each instance still carries the
		// prefixes it sits in. The account's network inventory was not asked
		// for, so it is not recorded on its own.
		plan.Networks, plan.Subnets = nil, nil
	}
	s.recordTerminalStates(ctx, tenantID, plan.Vendor, plan.Terminal)
	return s.recordEnumeration(ctx, tenantID, integrationID, environment, plan)
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

// recordEnumeration writes a plan: the account's network prefixes first, then
// the instances
// through the identification engine, each carrying its interfaces, addresses
// and the prefixes it sits in.
//
// The returned devices carry ASSET ids (upsertDeviceAsset rewrites Device.ID),
// which is what the caller's job result and the Devices page read.
func (s *CloudDiscoveryService) recordEnumeration(
	ctx context.Context,
	tenantID, integrationID uuid.UUID,
	environment string,
	plan cloudEnumerationPlan,
) ([]models.Device, CloudEnumerationCounts, error) {
	counts := plan.counts()
	if counts.Empty() {
		return nil, counts, nil
	}

	// 1. Prefixes, before any instance resolves, so its addresses are scoped by
	//    them. Failures are logged, never fatal: a prefix we could not record
	//    costs an instance its scope until the next run, which makes its
	//    address unable to VOTE on identity — it does not make the instance
	//    unrecordable, because `cloud_resource_id` decides on its own.
	s.recordNetworkPrefixes(ctx, tenantID, plan)

	// 2. The security groups, before the instances that are members of them.
	devices := make([]models.Device, 0, len(plan.SecurityGroups)+len(plan.Instances))
	for _, sg := range plan.SecurityGroups {
		device, err := s.recordCloudResource(ctx, tenantID, integrationID, plan.Vendor, sg)
		if err != nil {
			log.Printf("[cloud enumeration] security group %s not recorded: %v", sg.ResourceID, err)
			continue
		}
		devices = append(devices, *device)
	}

	// 3. The instances.
	for i := range plan.Instances {
		res := plan.Instances[i]
		device, err := s.recordCloudResource(ctx, tenantID, integrationID, plan.Vendor, res)
		if err != nil {
			// One contested or unwritable resource must not lose the rest
			// of the run. A contested one already has a merge proposal
			// waiting in Approvals, which is the actionable half.
			log.Printf("[cloud enumeration] %s %s not recorded: %v", res.DeviceType, res.ResourceID, err)
			continue
		}
		devices = append(devices, *device)
	}

	log.Printf("[cloud enumeration] %s: %d instances, %d networks, %d subnets, %d security groups",
		plan.Provider, counts.Instances, counts.Networks, counts.Subnets, counts.SecurityGroups)
	return devices, counts, nil
}

// recordNetworkPrefixes records every network's and subnet's prefixes on the
// account they belong to, as one measured sighting of the account per account
// (DCIM row 1.5f).
//
// Why on the ACCOUNT: a prefix is not a property of any instance — an empty
// subnet is still a subnet — and the seam records prefixes only beside an
// asset an observation resolved to. The account is the asset the provider's
// listing is about, and it already exists: it is declared when the
// integration is added (cloud_account.go). Each instance's sighting also
// carries the prefixes it sits in, so an instance never depends on this step
// having run; this step is what records the networks nothing runs in.
//
// An account with no asset is skipped, not created: an account is declared by
// a person adding an integration, never discovered (ADR-0009 D1), and a
// listing must not mint one.
func (s *CloudDiscoveryService) recordNetworkPrefixes(ctx context.Context, tenantID uuid.UUID, plan cloudEnumerationPlan) {
	byAccount, order := plan.networkPrefixesByAccount()
	if len(order) == 0 {
		return
	}
	regions := plan.prefixRegions()
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	repo := s.devices.Repo()
	now := time.Now().UTC()
	for _, stated := range order {
		account := firstNonEmpty(stated, scope.AccountID)
		if _, ok := cloudNetworkSighting(tenantID, plan.Provider, plan.Vendor, account, byAccount[stated], now); !ok {
			log.Printf("[cloud enumeration] %s: %d prefixes name no account; recorded only with the instances in them",
				plan.Provider, len(byAccount[stated]))
			continue
		}
		var assetID string
		prefixes := byAccount[stated]
		if err := repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
			var err error
			assetID, err = cloudaccount.FindAsset(ctx, r, tenantID.String(), plan.Provider, account)
			if err != nil || assetID == "" {
				return err
			}
			// The account's site and its regions' locations, and each
			// prefix's scope in them (DCIM row 2.1).
			prefixes, err = scopeToRegions(ctx, r, tenantID, assetID, plan.Provider, account, stated, prefixes, regions)
			return err
		}); err != nil {
			log.Printf("[cloud enumeration] %s account %s: lookup failed; its prefixes wait for the next run: %v", plan.Provider, account, err)
			continue
		}
		if assetID == "" {
			log.Printf("[cloud enumeration] %s account %s is not an asset (no integration declares it); its prefixes are recorded only with the instances in them",
				plan.Provider, account)
			continue
		}
		sighting, _ := cloudNetworkSighting(tenantID, plan.Provider, plan.Vendor, account, prefixes, now)
		res, err := s.devices.resolveSighting(ctx, sighting, nil)
		if err != nil {
			log.Printf("[cloud enumeration] %s account %s: prefixes not recorded: %v", plan.Provider, account, err)
			continue
		}
		if res.Asset.ID != assetID {
			log.Printf("[cloud enumeration] %s account %s: the network listing resolved to %q (outcome %s), not the account asset %s",
				plan.Provider, account, res.Asset.ID, res.Outcome, assetID)
		}
	}
}

// cloudNetworkSighting is the account's sighting that carries its networks'
// prefixes: the account's own identifier and nothing else that could match or
// mint an asset. ok is false when the account cannot be named.
func cloudNetworkSighting(tenantID uuid.UUID, provider, vendor, account string, prefixes []identity.ObservedPrefix, at time.Time) (identity.Sighting, bool) {
	rid := cloudaccount.ResourceID(provider, account)
	if rid == "" || len(prefixes) == 0 {
		return identity.Sighting{}, false
	}
	return identity.Sighting{
		TenantID: tenantID.String(),
		Source:   cloudSource(stringPtr(vendor)),
		// The provider's API answering about the account's own networks: the
		// same authoritative listing every enumerated resource is.
		Channel:     identity.ChannelAPI,
		ObservedAt:  at,
		ReceiptID:   "cloud-networks:" + rid + ":" + at.Format(time.RFC3339Nano),
		ClassHint:   cloudaccount.ClassKey,
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindCloudResourceID, Value: rid}},
		Prefixes:    prefixes,
	}, true
}

// enumeratedDevice is the device record one enumerated instance is resolved
// as — the shape recordCloudResource hands upsertDeviceAssetWith.
func enumeratedDevice(tenantID, integrationID uuid.UUID, vendor string, res cloudEnumResource, now time.Time) models.Device {
	metadata := map[string]interface{}{}
	for k, v := range res.Metadata {
		metadata[k] = v
	}
	metadata["cloud_resource_id"] = res.ResourceID
	return models.Device{
		ID:              uuid.New(),
		TenantID:        tenantID,
		DeviceType:      res.DeviceType,
		Vendor:          stringPtr(vendor),
		Hostname:        stringPtr(res.Hostname),
		IPAddress:       stringPtr(res.IPAddress),
		DiscoveryMethod: "cloud_api",
		CredentialID:    &integrationID,
		// "discovered", never "connected". The provider's API was read; nothing
		// connected to the resource, and nothing tested whether it could be.
		// normalizeConnectionStatus maps this onto `unknown`, which is the one of
		// the four permitted values that means "we have not measured this" — and
		// which the Devices page renders in neutral grey rather than green.
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB(metadata),
		Tags:             models.JSONB(res.Tags),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// withEnumeratedNetwork puts an enumerated resource's interfaces and prefixes
// on its sighting: the one place the cloud collectors' network projection
// reaches the intake seam.
func withEnumeratedNetwork(s identity.Sighting, res *cloudEnumResource) identity.Sighting {
	if res == nil {
		return s
	}
	s.Interfaces = append([]identity.ObservedInterface(nil), res.Interfaces...)
	s.Prefixes = append([]identity.ObservedPrefix(nil), res.Prefixes...)
	return s
}

// recordCloudResource resolves one enumerated resource to an asset and writes
// its facts and class attributes in the SAME transaction as the resolution.
//
// One transaction, deliberately: an asset created here whose facts landed in a
// later transaction that failed would keep its identity and lose its placement,
// and no later run would repair it — the next observation matches the asset
// that exists and never takes the create path again.
func (s *CloudDiscoveryService) recordCloudResource(
	ctx context.Context,
	tenantID, integrationID uuid.UUID,
	vendor string,
	res cloudEnumResource,
) (*models.Device, error) {
	if strings.TrimSpace(res.ResourceID) == "" {
		return nil, fmt.Errorf("resource carries no cloud_resource_id; not recorded under a weaker identifier")
	}
	device := enumeratedDevice(tenantID, integrationID, vendor, res, time.Now())

	classKey := DeviceTypeClassKey(res.DeviceType)
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	listing, _ := res.Facts[facts.KeyCloudListing].(string)
	values := map[string]any{}
	for k, v := range res.Facts {
		values[k] = v
	}
	for k, v := range cloudListingFacts(scope, firstNonEmpty(listing, cloudListingFrom(ctx)), "") {
		values[k] = v
	}
	factRows := cloudFactRows(values, cloudSource(device.Vendor), time.Now().UTC())
	attrs := filterClassAttributes(classKey, mergeAttributes(res.Attributes, cloudProviderTypeAttr(res.DeviceType)), res.DeviceType)
	source := cloudSource(device.Vendor)

	ctx = context.WithValue(ctx, cloudEnumerationContextKey{}, &res)
	err := s.upsertDeviceAssetWith(ctx, &device, res.ResourceID, res.CloudNetworkRef, func(r *pgidentity.Repository, assetID uuid.UUID) error {
		ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
		if len(factRows) > 0 {
			if err := r.UpsertFacts(ctx, ref, facts.ProducerCloudCollector, factRows); err != nil {
				return fmt.Errorf("writing cloud facts: %w", err)
			}
		}
		if classKey == string(assetclass.KeyDnsZone) {
			zone, _ := res.Attributes["zone_name"].(string)
			names, err := dnsZoneCertificateNames(ctx, r, tenantID, zone)
			if err != nil {
				return fmt.Errorf("certificate names under %s: %w", zone, err)
			}
			if len(names) > 0 {
				if attrs == nil {
					attrs = map[string]any{}
				}
				attrs["certificate_names"] = names
			}
		}
		if len(attrs) > 0 {
			if err := mergeAssetAttributes(ctx, r.Tx(), tenantID, assetID, attrs); err != nil {
				return fmt.Errorf("writing class attributes: %w", err)
			}
		}
		// The account + region mirrored as a cluster, the instance one of its
		// VMs (DCIM row 4.2; ADR-0010 D8) — for NetBox sync fidelity only.
		if provider, account, region, ok := cloudMirrorKey(classKey, res.Facts); ok {
			err := r.MirrorCloudCluster(ctx, ref, provider, account, region)
			if errors.Is(err, pgidentity.ErrUnknownClusterType) {
				log.Printf("[cloud enumeration] %s: no %q cluster type; the account+region is not mirrored: %v", res.ResourceID, provider, err)
			} else if err != nil {
				return fmt.Errorf("mirroring the account and region as a cluster: %w", err)
			}
		}
		return linkMemberOf(ctx, r, tenantID, assetID, res.MemberOf, source, time.Now().UTC())
	})
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// cloudMirrorKey is the cloud account + region an enumerated compute instance
// is mirrored into as a cluster member (DCIM row 4.2): its provider, account
// and region facts. ok is false for anything but a compute instance, or when
// any of the three is unknown — a mirror keyed on a guess would merge two
// accounts' regions.
func cloudMirrorKey(classKey string, values map[string]any) (provider, account, region string, ok bool) {
	if classKey != string(assetclass.KeyComputeInstance) {
		return "", "", "", false
	}
	str := func(k string) string { v, _ := values[k].(string); return strings.TrimSpace(v) }
	provider, account, region = strings.ToLower(str(facts.KeyCloudProvider)), str(facts.KeyCloudAccountID), str(facts.KeyCloudRegion)
	return provider, account, region, provider != "" && account != "" && region != ""
}

// cloudFactRows turns a key→value map into fact rows with the collector's
// provenance.
//
// Keys are checked against the registry HERE as well as in UpsertFacts, so an
// unregistered key costs one fact rather than the whole resource: UpsertFacts
// returns on the first bad key and would abort the transaction that was also
// writing the attributes.
func cloudFactRows(values map[string]any, source identity.Source, at time.Time) []pgidentity.Fact {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]pgidentity.Fact, 0, len(values))
	for _, key := range keys {
		v := values[key]
		if v == nil {
			continue
		}
		if !facts.MayWrite(facts.ProducerCloudCollector, key) {
			log.Printf("[cloud enumeration] dropping fact %q: not registered for producer %s", key, facts.ProducerCloudCollector)
			continue
		}
		if err := facts.ValidateValue(key, v); err != nil {
			log.Printf("[cloud enumeration] dropping fact %q: %v", key, err)
			continue
		}
		out = append(out, pgidentity.Fact{
			Key:        key,
			Value:      v,
			SourceKind: source.Kind,
			SourceRef:  source.Ref,
			// The provider's API answered about its own resource. That is as
			// direct as a measurement gets short of asking the machine itself.
			Confidence: 1,
			ObservedAt: at,
		})
	}
	return out
}

// filterClassAttributes drops any attribute the class schema does not declare.
//
// `assets.attributes` is class-schema-validated by contract (the schemas are
// `additionalProperties: false`) but not by a database constraint, so an
// attribute nothing declared would be stored, facet on nothing, and be invisible
// to the CMDB mapping while looking like data. Dropping it with a line is the
// honest failure; storing it silently is the one that costs an afternoon later.
func filterClassAttributes(classKey string, in map[string]any, deviceType string) map[string]any {
	if len(in) == 0 || classKey == "" {
		return nil
	}
	allowed, ok := assetclass.Attributes(classKey)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		if _, declared := allowed[k]; !declared {
			log.Printf("[cloud enumeration] %s: attribute %q is not declared by class %s; dropped", deviceType, k, classKey)
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeAssetAttributes merges class attributes into `assets.attributes`,
// without blanking what is already there. Same "empty never wins" rule the
// metadata and tag merges follow.
func mergeAssetAttributes(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, attrs map[string]any) error {
	if len(attrs) == 0 {
		return nil
	}
	if tx == nil {
		return fmt.Errorf("mergeAssetAttributes needs a bound transaction")
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("marshal asset attributes: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE public.assets
		SET attributes = COALESCE(attributes, '{}'::jsonb) || $3::jsonb, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID, string(raw))
	return err
}

// ---------------------------------------------------------------------------
// Interfaces and prefixes (DCIM row 1.5f)
// ---------------------------------------------------------------------------

// cloudNIC is one ENI / NIC of an instance in a provider-independent shape,
// before it becomes an observed interface.
type cloudNIC struct {
	// Name is the provider's name for it: the ENI id on AWS (`eni-…`), the
	// NIC's resource name on Azure, `nic0` on GCP.
	Name string
	MAC  string
	// State is the provider's attachment state, mapped by nicOperStatus.
	State string
	// Addresses are its private addresses, primary first.
	Addresses []string
	// Subnet is the subnet it sits in, as the plan indexes subnets (the
	// subnet's provider id); "" when the provider does not say.
	Subnet string
}

// cloudInterfaces projects an instance's NICs onto observed interfaces: type
// `virtual`, the NIC's MAC, its private addresses with source `cloud` and the
// length of the subnet they sit in. A NIC with no name is dropped (the intake
// would drop it too: an interface needs a name).
//
// Nothing else crosses: a NIC's attachment ids, its owner, its description and
// its public address are not interface posture. The public address is the
// NAT-outside side and is recorded on the instance (natOutsideAddresses).
func cloudInterfaces(nics []cloudNIC, subnetLen map[string]int) []identity.ObservedInterface {
	var out []identity.ObservedInterface
	for _, nic := range nics {
		name := strings.TrimSpace(nic.Name)
		if name == "" {
			continue
		}
		ifc := identity.ObservedInterface{
			Name:       name,
			Type:       string(dcim.InterfaceTypeVirtual),
			MAC:        strings.ToLower(strings.TrimSpace(nic.MAC)),
			OperStatus: nicOperStatus(nic.State),
		}
		for _, a := range nic.Addresses {
			if a = strings.TrimSpace(a); a == "" {
				continue
			}
			ifc.Addresses = append(ifc.Addresses, identity.ObservedAddress{
				Address:   a,
				PrefixLen: subnetLen[strings.ToLower(nic.Subnet)],
				Source:    "cloud",
			})
		}
		out = append(out, ifc)
	}
	return out
}

// nicOperStatus maps a provider's NIC attachment state onto an interface's
// operational status. An ENI that is `in-use` is attached and carrying the
// instance's traffic; `available` is detached. Anything else — attaching,
// detaching, a state this code has not seen — is `unknown`, and no state at
// all is left unsaid rather than guessed.
func nicOperStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "":
		return ""
	case "in-use", "attached", "succeeded":
		return "up"
	case "available", "detached":
		return "down"
	default:
		return "unknown"
	}
}

// subnetPrefixLengths indexes each subnet's prefix length by its id
// (case-folded), for the length an instance's address is configured with.
func subnetPrefixLengths(subnets []cloudNetwork) map[string]int {
	out := map[string]int{}
	for _, sn := range subnets {
		for _, c := range sn.CIDRs {
			if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
				out[strings.ToLower(sn.ResourceID)] = p.Bits()
				break
			}
		}
	}
	return out
}

// instancePrefixes are the prefixes an instance sits in: its network's and
// those of the subnets its NICs are in. They ride on the instance's sighting
// so an instance never resolves before the prefixes that scope its addresses
// exist, whatever happened to the account's network sighting.
func instancePrefixes(networkRef string, nics []cloudNIC, networks, subnets []cloudNetwork) []identity.ObservedPrefix {
	want := map[string]bool{}
	for _, nic := range nics {
		if v := strings.ToLower(strings.TrimSpace(nic.Subnet)); v != "" {
			want[v] = true
		}
	}
	var out []identity.ObservedPrefix
	seen := map[string]bool{}
	add := func(n cloudNetwork) {
		for _, p := range n.prefixes() {
			if !seen[p.Prefix] {
				seen[p.Prefix] = true
				out = append(out, p)
			}
		}
	}
	for _, n := range networks {
		if networkRef != "" && strings.EqualFold(n.ResourceID, networkRef) {
			add(n)
		}
	}
	for _, sn := range subnets {
		if want[strings.ToLower(sn.ResourceID)] {
			add(sn)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Shared fact/attribute helpers
// ---------------------------------------------------------------------------

// cloudPlacementFacts is the `cloud.*` set every enumerated resource carries.
//
// `cloud.vpc_id` and `cloud.subnet_id` are no longer written (retired in
// standards/fact-keys.yaml by row 1.5f): which network and subnet a resource
// is in is prefix containment of its addresses.
func cloudPlacementFacts(provider, accountID, region, resourceID string, groups []map[string]any) map[string]any {
	out := map[string]any{}
	set := func(key, value string) {
		if v := strings.TrimSpace(value); v != "" {
			out[key] = v
		}
	}
	set(facts.KeyCloudProvider, provider)
	set(facts.KeyCloudAccountID, accountID)
	set(facts.KeyCloudRegion, region)
	set(facts.KeyCloudResourceID, resourceID)
	if len(groups) > 0 {
		out[facts.KeyCloudSecurityGroups] = groups
	}
	return out
}

// tagsToJSONB converts a provider's tag map for `assets.tags`. Values have
// already been through the name-based redactor at the projection boundary.
func tagsToJSONB(tags map[string]string) map[string]interface{} {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}

// firstAddress returns the first address in a list, which is what goes in
// `assets.primary_address`. Every address is on the instance's interfaces.
func firstAddress(addrs []string) string {
	for _, a := range addrs {
		if v := strings.TrimSpace(a); v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Cloud scope — account and region on every cloud-discovered asset
// ---------------------------------------------------------------------------
//
// Account and region are SCOPING ATTRIBUTES, not asset classes ( decision
// D6). They carry no crypto posture of their own, so they need no asset rows,
// no findings, no risk scores and no lens presence — which is also why nothing
// here touches `shared/assetclass` or the chart-parity audit that follows a
// change to it. Recording them on the resource is what lets Inventory → Map
// group resources by account and region, and hang a bucket or a CDN
// distribution off its region, without a region ever becoming a node in the
// inventory itself. (The networks and subnets are prefixes since row 1.5f.)
//
// Enumeration already writes them (`cloudPlacementFacts`,
// `cloudResourceAttributes`). What follows is the SAME two helpers, on the same
// transaction hook, for the resources the crypto and at-rest collectors record
// instead — buckets, CDN distributions, key stores, load balancers, API
// gateways. One write path, not two: a second producer of the same two values
// is how one fact acquires two spellings, which is the mistake this file's
// header used to warn about for `member_of`.

// cloudScopeKey carries one run's provider and owning account down to the
// per-resource write.
type cloudScopeKey struct{}

// cloudScope is what a run knows about WHERE it is reading from.
type cloudScope struct {
	Provider string
	// AccountID is the integration's own account, and is EMPTY when the
	// integration does not state one. Empty travels as empty: no
	// `cloud.account_id` fact is written, and the map roots the resource at its
	// region rather than under an invented account.
	AccountID string
	// RunAt is the run's one clock reading: every resource the run records
	// carries it as `cloud.last_enumerated_at`, and the account's
	// `cloud.enumeration_coverage` is stamped with it, so "present this run"
	// is an equality rather than a race between two time.Now() calls.
	RunAt time.Time
}

// beginCloudRun prepares a run's context: the tenant's account assets and
// account approval rules are brought in line with its integrations
// (CloudAccountService.SyncTenant), the run's scope is resolved once, and the
// approval rules are cached for the run. A sync that fails is logged and the
// run continues — resources then stay pending and unlinked, which is the
// state they had before accounts existed, not a lost run.
func (s *CloudDiscoveryService) beginCloudRun(ctx context.Context, tenantID, integrationID uuid.UUID, provider string) context.Context {
	if _, begun := ctx.Value(cloudApprovalKey{}).(*cloudApprovalRules); begun {
		// DiscoverResources begins the run before its evidence half does.
		return ctx
	}
	if s.accounts != nil {
		if _, err := s.accounts.SyncTenant(ctx, tenantID); err != nil {
			log.Printf("[cloud account] sync for tenant %s before the run failed (resources may stay pending): %v", tenantID, err)
		}
	}
	if _, ok := ctx.Value(cloudScopeKey{}).(cloudScope); !ok {
		ctx = context.WithValue(ctx, cloudScopeKey{}, s.resolveCloudScope(ctx, tenantID, integrationID, provider))
	}
	return withCloudApprovalRules(ctx)
}

// resolveCloudScope reads the integration's account id once per run.
//
// A read that fails is logged and returns the scope WITHOUT an account. Unknown
// is not a default: the alternative — stamping every resource with the tenant's
// first account, or with the integration uuid dressed up as one — produces a
// map that looks complete and groups resources under an account nobody owns.
func (s *CloudDiscoveryService) resolveCloudScope(ctx context.Context, tenantID, integrationID uuid.UUID, provider string) cloudScope {
	scope := cloudScope{Provider: strings.TrimSpace(provider), RunAt: time.Now().UTC().Truncate(time.Microsecond)}
	if s.bypassDB == nil {
		return scope
	}
	var accountID sql.NullString
	err := s.bypassDB.QueryRowContext(ctx, `
		SELECT account_id
		  FROM platform_integrations
		 WHERE id = $1
		   AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		   AND is_active = true
		   AND deleted_at IS NULL`, integrationID, tenantID).Scan(&accountID)
	if err != nil {
		log.Printf("[cloud scope] account id for integration %s unreadable; resources will carry no cloud.account_id: %v", integrationID, err)
		return scope
	}
	scope.AccountID = strings.TrimSpace(accountID.String)
	return scope
}

// accountIDFromARN reads the account field out of an AWS ARN.
//
// `arn:partition:service:region:account-id:resource`. The field is legitimately
// EMPTY on an S3 bucket ARN, and present on CloudFront's
// `arn:aws:cloudfront::<account>:distribution/<id>` where the REGION field is
// the empty one instead. Preferred over the integration's account because the
// resource's own statement of its owner is the better answer for a
// cross-account resource — a shared VPC belongs to the account that created it,
// not to the credential that happened to be able to read it.
func accountIDFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return strings.TrimSpace(parts[4])
}

// cloudScopeValues decides what a non-enumerated cloud resource's scope
// actually is: the `cloud.*` fact values, and the `cloud_resource` class
// attributes, both possibly empty.
//
// Pure, and separated from the transaction hook so the decisions — which of
// the three values is present, where the account comes from, what a CloudFront
// distribution's region is — are testable without a database.
//
// Only the three scoping values. Network placement is prefix containment of a
// resource's addresses (row 1.5f), which only the enumeration path records.
func cloudScopeValues(scope cloudScope, device models.Device) (map[string]any, map[string]any) {
	provider := strings.TrimSpace(scope.Provider)
	// `cloudRegionForDevice` answers the literal "global" for a CloudFront
	// distribution, which is what the resource actually is rather than a region
	// it does not have. Carried through unchanged.
	region := strings.TrimSpace(cloudRegionForDevice(device))
	account := strings.TrimSpace(firstNonEmpty(
		accountIDFromARN(cloudResourceIDFromMetadata(device.Metadata)),
		scope.AccountID,
	))

	values := map[string]any{}
	if provider != "" {
		values[facts.KeyCloudProvider] = provider
	}
	if account != "" {
		values[facts.KeyCloudAccountID] = account
	}
	if region != "" {
		values[facts.KeyCloudRegion] = region
	}
	if len(values) == 0 {
		return nil, nil
	}
	attrs := filterClassAttributes(
		DeviceTypeClassKey(device.DeviceType),
		mergeAttributes(cloudResourceAttributes(provider, account, region), cloudProviderTypeAttr(device.DeviceType)),
		device.DeviceType,
	)
	return values, attrs
}

// cloudScopeExtra builds the transaction hook that writes a non-enumerated
// cloud resource's scope, or nil when there is nothing honest to write.
//
// Nil rather than a hook that writes empties: "we did not collect a region" and
// "the region is blank" must not become the same row. `cloudRegionForDevice`
// answers the literal "global" for a CloudFront distribution, which is what the
// resource actually is rather than a region it does not have, and that answer
// is carried through unchanged.
func (s *CloudDiscoveryService) cloudScopeExtra(ctx context.Context, device *models.Device) func(*pgidentity.Repository, uuid.UUID) error {
	if device == nil {
		return nil
	}
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	values, attrs := cloudScopeValues(scope, *device)
	if listed := cloudListingFacts(scope, cloudListingFrom(ctx), normalizeProviderState(scope.Provider, cloudRawState(device.Metadata))); len(listed) > 0 {
		if values == nil {
			values = map[string]any{}
		}
		for k, v := range listed {
			values[k] = v
		}
	}
	if len(values) == 0 && len(attrs) == 0 {
		return nil
	}

	tenantID := device.TenantID
	factRows := cloudFactRows(values, cloudSource(device.Vendor), time.Now().UTC())
	if len(factRows) == 0 && len(attrs) == 0 {
		return nil
	}

	return func(r *pgidentity.Repository, assetID uuid.UUID) error {
		ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
		if len(factRows) > 0 {
			if err := r.UpsertFacts(ctx, ref, facts.ProducerCloudCollector, factRows); err != nil {
				return fmt.Errorf("writing cloud scope facts: %w", err)
			}
		}
		if len(attrs) > 0 {
			if err := mergeAssetAttributes(ctx, r.Tx(), tenantID, assetID, attrs); err != nil {
				return fmt.Errorf("writing cloud scope attributes: %w", err)
			}
		}
		return nil
	}
}
