package services

// Cloud enumeration — compute instances, virtual networks, subnets and security
// groups on AWS, Azure and GCP (BUILD_PLAN 2.4, ADR-0004 D1 item 6).
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
// **Containment is `contains`, one direction only.** ADR-0003 D2 defines
// `contains` as "virtual network → subnet, cluster → node" — container to
// contained — so a VPC contains its subnets and a subnet contains its
// instances. `member_of` is NOT also emitted: the reverse of a type is a LABEL
// (`contained_by`), never a second edge, and emitting both would give one fact
// two spellings and double every traversal.
//
// **No `hosted_on`.** ADR-0003 offers "cloud resource → account or region" for
// it, and this platform models neither an account nor a region as an asset. An
// edge needs two assets; inventing an "account" asset to hang one off would be
// a node nothing else in the product knows about. The account and the region
// are recorded where they belong — as the `cloud.account_id` and `cloud.region`
// facts on the resource itself.
//
// **Security groups are not assets.** They are membership, recorded as the
// `cloud.security_groups` fact on the resource that is in them (and, for GCP,
// computed from firewall targeting). A security group is a policy object, not a
// configuration item: it has no address, no lifecycle a CMDB tracks, and making
// one an asset would put a rule set in the inventory the product exists to keep
// rule sets out of.

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
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// Device types the enumeration emits. Each one has a row in
// shared/assetclass's device_type table; a type with no row would be classed
// `cloud_resource`, which is true but coarse, and the class is what the
// Inventory lenses facet on.
const (
	DeviceTypeAWSEC2Instance     = "aws_ec2_instance"
	DeviceTypeAWSVPC             = "aws_vpc"
	DeviceTypeAWSSubnet          = "aws_subnet"
	DeviceTypeAzureVM            = "azure_vm"
	DeviceTypeAzureVNet          = "azure_virtual_network"
	DeviceTypeAzureSubnet        = "azure_subnet"
	DeviceTypeGCPComputeInstance = "gcp_compute_instance"
	DeviceTypeGCPNetwork         = "gcp_network"
	DeviceTypeGCPSubnetwork      = "gcp_subnetwork"
)

// Enumeration is NOT gated on a `resource_types` entry, and that is a decision
// rather than an omission.
//
// `resource_types` selects which CRYPTO collectors run — load balancers, KMS,
// buckets — and each of those is an independent posture question an operator
// might reasonably want on its own. The inventory is not: an account's
// instances, networks and subnets are the frame everything else hangs on, and a
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
// SecurityGroups counts DISTINCT groups observed as membership, not assets:
// there is no security-group asset (see the file comment). It is still reported
// because "this run saw 14 security groups" is what tells an operator the
// membership fact is populated.
type CloudEnumerationCounts struct {
	Instances      int `json:"instances"`
	Networks       int `json:"networks"`
	Subnets        int `json:"subnets"`
	SecurityGroups int `json:"security_groups"`
}

// Total is the number of ASSETS the enumeration recorded. Security groups are
// excluded because they are not assets.
func (c CloudEnumerationCounts) Total() int {
	return c.Instances + c.Networks + c.Subnets
}

// Empty reports whether nothing at all was enumerated, so the job result can
// omit the block rather than claim four zeros for a run that never enumerated.
func (c CloudEnumerationCounts) Empty() bool {
	return c.Instances == 0 && c.Networks == 0 && c.Subnets == 0 && c.SecurityGroups == 0
}

// cloudEnumResource is one resource an enumeration found, in a
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
	// ParentID is the ResourceID of the container: the VPC of a subnet, the
	// subnet of an instance. Empty means the container was not enumerated (a
	// shared VPC owned by another account, an instance with no subnet), and no
	// edge is written rather than one pointing at nothing.
	ParentID string
	// SegmentCIDR, on a subnet, is the prefix a `cidr` network segment is
	// created or matched for. It is what makes an instance's private address
	// resolve to a scope (ADR-0002 D3).
	SegmentCIDR string
	// CloudNetworkRef is the VPC / VNet / GCP network this resource sits in,
	// as the provider's canonical resource id. On a subnet it is the same as
	// ParentID; on an instance it is its subnet's parent, which ParentID does
	// not carry.
	//
	// It is the segment's identity, not a decoration: two VPCs with the same
	// CIDR are two address spaces, and a segment keyed on the CIDR alone made
	// two instances at one private address resolve to one scope and then to one
	// ASSET. `network_segments` is unique on
	// (tenant_id, value, coalesce(cloud_network_ref, '')) for this reason.
	CloudNetworkRef string
	Facts           map[string]any
	Attributes      map[string]any
	Tags            map[string]interface{}
	Metadata        map[string]interface{}
}

// cloudEnumerationPlan is one provider's whole enumeration, built before
// anything is written.
//
// Built-then-recorded rather than written as it goes, because the subnets have
// to exist as network segments BEFORE any instance is resolved: the scope an
// instance's private address identifies within is looked up at observation
// time, and an instance resolved before its subnet's segment exists would be
// scoped to the tenant default and then never re-scoped (the next observation
// MATCHES the asset that exists and never takes the create path again).
type cloudEnumerationPlan struct {
	Provider  string
	Vendor    string
	Networks  []cloudEnumResource
	Subnets   []cloudEnumResource
	Instances []cloudEnumResource
	// SecurityGroupIDs are the distinct groups seen, for the count. The groups
	// themselves are membership facts on the resources, not rows.
	SecurityGroupIDs map[string]bool
}

func (p cloudEnumerationPlan) counts() CloudEnumerationCounts {
	return CloudEnumerationCounts{
		Instances:      len(p.Instances),
		Networks:       len(p.Networks),
		Subnets:        len(p.Subnets),
		SecurityGroups: len(p.SecurityGroupIDs),
	}
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
	ctx = context.WithValue(ctx, cloudScopeKey{}, s.resolveCloudScope(ctx, tenantID, integrationID, cloudProvider))
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

// DiscoverResources also enumerates configured compute/network inventory.
func (s *CloudDiscoveryService) DiscoverResources(ctx context.Context, tenantID, integrationID uuid.UUID, cloudProvider string, resourceTypes, regions, resourceGroups []string) (*CloudDiscoveryResult, error) {
	out, err := s.DiscoverResourceEvidence(ctx, tenantID, integrationID, cloudProvider, resourceTypes, regions, resourceGroups)
	if err != nil {
		return nil, err
	}
	run := &cloudRunEvidence{summary: out.Identity, retained: out.Retained}
	ctx = context.WithValue(ctx, cloudRunKey{}, run)
	defer func() { run.mu.Lock(); out.Identity = run.summary; out.Retained = run.retained; run.mu.Unlock() }()
	var recordErr error

	settings, err := loadCloudIntegrationSettings(ctx, s.bypassDB, tenantID, integrationID)
	if err != nil {
		// The crypto half already succeeded and its devices are recorded. A
		// settings read that failed is a reason to skip enumeration and say so,
		// not to throw away a run that worked.
		out.EnumerationSkipped = fmt.Sprintf("integration settings unreadable: %v", err)
		log.Printf("[cloud enumeration] %s: %s", cloudProvider, out.EnumerationSkipped)
		return out, nil
	}
	if !settings.EnumerateCompute {
		out.EnumerationSkipped = "enumerate_compute is off for this integration"
		return out, nil
	}

	enumerated, counts, err := s.enumerate(ctx, tenantID, integrationID, cloudProvider, settings.Environment, regions)
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
	recordErr = run.failure
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
			plan, err = s.enumerateAWS(ctx, client, regions)
		}
	case "azure":
		var client *azureclient.Client
		client, err = azureclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
		if err == nil {
			plan, err = s.enumerateAzure(ctx, client)
		}
	case "gcp":
		var client *gcpclient.Client
		client, err = gcpclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
		if err == nil {
			plan, err = s.enumerateGCP(ctx, client)
		}
	default:
		return nil, CloudEnumerationCounts{}, fmt.Errorf("unknown cloud provider: %s", cloudProvider)
	}
	if err != nil {
		return nil, CloudEnumerationCounts{}, err
	}
	return s.recordEnumeration(ctx, tenantID, integrationID, environment, plan)
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

// recordEnumeration writes a plan: segments first, then networks, subnets and
// instances through the identification engine, then the containment edges.
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
	if counts.Total() == 0 {
		return nil, counts, nil
	}

	// 1. Segments, from the subnets' CIDRs. Failures are logged, never fatal: a
	//    segment we could not create costs an instance its scope, which makes
	//    its address unable to VOTE on identity — it does not make the instance
	//    unrecordable, because `cloud_resource_id` decides on its own.
	s.ensureSubnetSegments(ctx, tenantID, plan, environment)

	// 2. The resources, containers first so an edge's far end already exists.
	assetByResource := make(map[string]uuid.UUID, counts.Total())
	devices := make([]models.Device, 0, counts.Total())
	record := func(group []cloudEnumResource) {
		for i := range group {
			res := group[i]
			device, err := s.recordCloudResource(ctx, tenantID, integrationID, plan.Vendor, res)
			if err != nil {
				// One contested or unwritable resource must not lose the rest
				// of the run. A contested one already has a merge proposal
				// waiting in Approvals, which is the actionable half.
				log.Printf("[cloud enumeration] %s %s not recorded: %v", res.DeviceType, res.ResourceID, err)
				continue
			}
			assetByResource[res.ResourceID] = device.ID
			devices = append(devices, *device)
		}
	}
	record(plan.Networks)
	record(plan.Subnets)
	record(plan.Instances)

	// 3. Containment edges, once both ends are known assets.
	edges := 0
	for _, group := range [][]cloudEnumResource{plan.Subnets, plan.Instances} {
		for _, res := range group {
			if res.ParentID == "" {
				continue
			}
			parent, okParent := assetByResource[res.ParentID]
			child, okChild := assetByResource[res.ResourceID]
			if !okParent || !okChild {
				continue
			}
			if err := s.writeContainsEdge(ctx, tenantID, plan.Provider, parent, child); err != nil {
				log.Printf("[cloud enumeration] contains edge %s -> %s not written: %v", res.ParentID, res.ResourceID, err)
				continue
			}
			edges++
		}
	}

	log.Printf("[cloud enumeration] %s: %d instances, %d networks, %d subnets, %d security groups, %d containment edges",
		plan.Provider, counts.Instances, counts.Networks, counts.Subnets, counts.SecurityGroups, edges)
	return devices, counts, nil
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
	metadata := map[string]interface{}{}
	for k, v := range res.Metadata {
		metadata[k] = v
	}
	metadata["cloud_resource_id"] = res.ResourceID

	device := models.Device{
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
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	classKey := DeviceTypeClassKey(res.DeviceType)
	factRows := cloudFactRows(res.Facts, cloudSource(device.Vendor), time.Now().UTC())
	attrs := filterClassAttributes(classKey, res.Attributes, res.DeviceType)

	ctx = context.WithValue(ctx, cloudEnumerationContextKey{}, &res)
	err := s.upsertDeviceAssetWith(ctx, &device, res.ResourceID, res.CloudNetworkRef, func(r *pgidentity.Repository, assetID uuid.UUID) error {
		ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
		if len(factRows) > 0 {
			if err := r.UpsertFacts(ctx, ref, facts.ProducerCloudCollector, factRows); err != nil {
				return fmt.Errorf("writing cloud facts: %w", err)
			}
		}
		if len(attrs) > 0 {
			if err := mergeAssetAttributes(ctx, r.Tx(), tenantID, assetID, attrs); err != nil {
				return fmt.Errorf("writing class attributes: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// writeContainsEdge writes one `contains` edge, container → contained.
func (s *CloudDiscoveryService) writeContainsEdge(ctx context.Context, tenantID uuid.UUID, provider string, from, to uuid.UUID) error {
	// Repo() is the existing accessor for exactly this — the writes that are not
	// a resolution — and borrowing it keeps ONE repository per service rather
	// than a second handle that could disagree about which connection it is on.
	repo, err := s.devices.Repo()
	if err != nil {
		return err
	}
	source := cloudSource(stringPtr(provider))
	return repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		status, statusErr := r.EdgeStatusFor(ctx, tenantID.String(), source.Kind, from.String(), to.String())
		if statusErr != nil {
			return statusErr
		}
		edgeErr := r.UpsertRelationship(ctx, tenantID.String(), pgidentity.Edge{
			FromAssetID: from.String(),
			ToAssetID:   to.String(),
			Type:        string(relationships.Contains),
			SourceKind:  source.Kind,
			SourceRef:   source.Ref,
			Status:      status,
			ObservedAt:  time.Now().UTC(),
		})
		if errors.Is(edgeErr, pgidentity.ErrSelfEdge) {
			// Both ends resolved to one asset. Meaningless rather than wrong —
			// it means two resources matched the same identity — and dropped
			// with a line saying so.
			log.Printf("[cloud enumeration] contains edge resolved to itself (%s); dropped", from)
			return nil
		}
		return edgeErr
	})
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
// Network segments
// ---------------------------------------------------------------------------

// ensureSubnetSegments creates a `cidr` network segment for every enumerated
// subnet that does not already have one.
//
// Why a segment per SUBNET and not per VPC: `ScopeForAddress` — the one lookup
// every intake uses to answer "which segment is this address in" — consults
// only `cidr` and `ip_range` segments, because neither a `domain` nor a
// `cloud_vpc` segment can be decided from an address. `FindOrCreateCloudSegment`
// creates the `cloud_vpc` kind, valued by the VPC id, and no address is ever
// inside "vpc-0123". A subnet's CIDR is the finest prefix the provider states
// and is what an instance's private address actually falls in.
//
// `dynamic` is false: a cloud subnet hands the SAME address to the SAME
// instance for that instance's whole life, which is not the DHCP-lease churn
// within one host's session that the dynamic flag was written for. Marking it
// dynamic would stop an instance's address deciding anything, and the address is
// precisely how an agent installed inside the instance, or the sensor seeing it
// on the wire, reaches the same asset.
//
// The honest qualifier: the address is stable for an instance's life, NOT
// across instances. A freed address is handed to the next instance launched
// into the subnet, and that reuse is what the limitation below is about. `false`
// is the deliberate choice here, with its cost stated rather than assumed away.
//
// **A CIDR is not unique in a cloud account, and the segment is keyed
// accordingly.** Two VPCs built from one Terraform module both get 10.0.0.0/16
// and their subnets both get 10.0.1.0/24. `network_segments` used to be unique
// on (tenant, value), so those two subnets SHARED one segment — and two
// instances at 10.0.1.20 then shared a scope, and `ip_address` matched them
// into ONE asset, silently, with no merge proposal. (A `cloud_resource_id` the
// engine has never seen owns nothing, so it cannot decide; being higher in the
// precedence list buys nothing when the value is new.)
//
// The key is now (tenant, value, coalesce(cloud_network_ref, ”)) and the
// segment carries the VPC / VNet / network resource id, so those are two
// segments, two scopes, two assets — and `ScopeForAddress` takes the network
// the observation was made in, so an instance resolves within its own VPC.
//
// **The residual, which is real and is NOT silent.** Address REUSE inside ONE
// subnet — EC2 hands a freed private address to the next instance launched —
// is the same CIDR in the same VPC, so it is legitimately one segment. There
// the new instance carries a `cloud_resource_id` the matched asset disagrees
// with, and the engine's singleton guard (ADR-0002 D3 erratum,
// [identity.Kind.Singleton]) turns that into ADR-0002 D3's outcome three: the
// new instance becomes its own pending asset and a merge proposal asks a human
// whether it is the machine that used to answer to that address. Which is the
// honest answer — from the outside, an address that changed hands and a machine
// that was rebuilt look identical.
func (s *CloudDiscoveryService) ensureSubnetSegments(ctx context.Context, tenantID uuid.UUID, plan cloudEnumerationPlan, environment string) {
	env := normalizeSegmentEnvironment(environment)
	for _, subnet := range plan.Subnets {
		cidr := strings.TrimSpace(subnet.SegmentCIDR)
		if cidr == "" {
			continue
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			// A value ScopeForAddress could not parse would match nothing and
			// sit in the table forever. Not stored.
			log.Printf("[cloud enumeration] subnet %s: %q is not a CIDR prefix; no segment created", subnet.ResourceID, cidr)
			continue
		}
		name := subnet.DisplayName
		if name == "" {
			name = cidr
		}
		if err := s.ensureCIDRSegment(ctx, tenantID, cidr, name, env, plan.Provider, subnet); err != nil {
			log.Printf("[cloud enumeration] subnet %s: segment for %s not created: %v", subnet.ResourceID, cidr, err)
		}
	}
}

// ensureCIDRSegment inserts one `cidr` segment, or leaves an existing one
// exactly as it is.
//
// ON CONFLICT DO NOTHING rather than an upsert: a segment with this CIDR may be
// the operator's own, with their environment, their location and their
// auto-approval settings on it. Overwriting those because a cloud run saw the
// same prefix would silently change which discoveries auto-approve.
func (s *CloudDiscoveryService) ensureCIDRSegment(
	ctx context.Context,
	tenantID uuid.UUID,
	cidr, name, environment, provider string,
	subnet cloudEnumResource,
) error {
	// NULL rather than '' for a subnet whose VPC was not enumerated: the column
	// is nullable, the unique index coalesces, and a literal '' would claim the
	// segment belongs to a network called "".
	var networkRef any
	if v := strings.TrimSpace(subnet.CloudNetworkRef); v != "" {
		networkRef = v
	}
	metadata := map[string]interface{}{
		// ScopeForAddress reads this key; false is the value it defaults to,
		// written explicitly so the row states its own answer.
		"dynamic": false,
		// Provenance. `network_segments` has no source column, and a segment an
		// operator drew and a segment a cloud run derived are different things
		// to anyone later deciding whether it is safe to edit.
		"source":          "cloud_discovery",
		"cloud_provider":  provider,
		"cloud_subnet_id": subnet.ResourceID,
	}
	if subnet.ParentID != "" {
		metadata["cloud_vpc_id"] = subnet.ParentID
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// The conflict target is the EXPRESSION the unique index is built on,
		// not the bare columns: uniqueness is
		// (tenant_id, value, coalesce(cloud_network_ref, '')), so two VPCs
		// sharing a CIDR are two rows rather than one silently reused.
		_, execErr := tx.ExecContext(ctx, `
			INSERT INTO public.network_segments
				(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata, cloud_network_ref)
			VALUES ($1, $2, 'cidr', $3, 'cloud', $4::public.environment_type, true, $5::jsonb, $6)
			ON CONFLICT (tenant_id, value, coalesce(cloud_network_ref, ''::text)) DO NOTHING`,
			tenantID, name, cidr, environment, string(raw), networkRef)
		return execErr
	})
}

// normalizeSegmentEnvironment maps an integration's free-text environment onto
// the `environment_type` enum, defaulting to `production`.
//
// The default matches inventory-service's own cloud-segment path
// (asset_service.go), which has defaulted to `production` since the column was
// added. Two spellings of the same default would be worse than one that is
// occasionally wrong, and the operator can change a segment's environment.
func normalizeSegmentEnvironment(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "production", "prod":
		return "production"
	case "staging", "stage":
		return "staging"
	case "development", "dev":
		return "development"
	case "test", "testing", "qa":
		return "test"
	default:
		return "production"
	}
}

// ---------------------------------------------------------------------------
// Shared fact/attribute helpers
// ---------------------------------------------------------------------------

// cloudPlacementFacts is the `cloud.*` set every enumerated resource carries.
func cloudPlacementFacts(provider, accountID, region, resourceID, vpcID, subnetID string, groups []map[string]any) map[string]any {
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
	set(facts.KeyCloudVPCID, vpcID)
	set(facts.KeyCloudSubnetID, subnetID)
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
// `assets.primary_address`. The rest stay on the `net.interfaces` fact: an
// asset has one primary address and any number of interfaces.
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
// draw account → region → VPC → subnet → instance, and hang a bucket or a CDN
// distribution off its region, without an account or a region ever becoming a
// node in the inventory itself.
//
// Enumeration already writes them (`cloudPlacementFacts`,
// `cloudResourceAttributes`). What follows is the SAME two helpers, on the same
// transaction hook, for the resources the crypto and at-rest collectors record
// instead — buckets, CDN distributions, key stores, load balancers, API
// gateways. One write path, not two: a second producer of the same two values
// is how one fact acquires two spellings, which is the mistake this file's
// header already warns about for `member_of`.

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
}

// resolveCloudScope reads the integration's account id once per run.
//
// A read that fails is logged and returns the scope WITHOUT an account. Unknown
// is not a default: the alternative — stamping every resource with the tenant's
// first account, or with the integration uuid dressed up as one — produces a
// map that looks complete and groups resources under an account nobody owns.
func (s *CloudDiscoveryService) resolveCloudScope(ctx context.Context, tenantID, integrationID uuid.UUID, provider string) cloudScope {
	scope := cloudScope{Provider: strings.TrimSpace(provider)}
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
// Only the three scoping values. VPC and subnet placement belong to the
// enumeration path, which is the only one that has them.
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
		cloudResourceAttributes(provider, account, region),
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
