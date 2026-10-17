package services

// The Tier-1 cloud classes (asset-inventory ADR-0009 D2; DCIM row 4.6):
// serverless functions, container clusters, secret stores and DNS zones on
// AWS, Azure and GCP, and security groups as assets with `member_of` edges
// (ADR-0009 D4).
//
// Each is a resource type of its own in the one selection (cloud_lifecycle.go)
// and runs through the same per-type, per-region outcome dispatch as every
// other collector (runCloudCollectors). Each resource is recorded through the
// enumeration funnel (recordCloudResource): the identity engine on its
// `cloud_resource_id`, the account's `hosted_on` edge and auto-approval, the
// `cloud.*` facts and the class attributes, in one transaction. None of them
// is a crypto finding, so none becomes a sensor_discoveries row.
//
// Collect posture, never key material: the collectors' projection structs
// (internal/cloud/{aws,azure,gcp}/tier1.go) carry a function's environment
// variable NAMES and never a value, a secret's rotation and encryption key
// reference and never a value, and a security group's identity and never its
// rules.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// The Tier-1 resource types (the selection keys).
const (
	CloudTypeServerlessFunctions = "serverless_functions"
	CloudTypeContainerClusters   = "container_clusters"
	CloudTypeSecretStores        = "secret_stores"
	CloudTypeDNSZones            = "dns_zones"
)

// Device types of the Tier-1 resources and security groups. Each is an alias
// in the class registry's provider-type mapping (standards/asset-classes.yaml).
const (
	DeviceTypeAWSLambdaFunction       = "aws_lambda_function"
	DeviceTypeAzureFunctionApp        = "azure_function_app"
	DeviceTypeGCPCloudFunction        = "gcp_cloud_function"
	DeviceTypeAWSEKSCluster           = "aws_eks_cluster"
	DeviceTypeAzureAKSCluster         = "azure_aks_cluster"
	DeviceTypeGCPGKECluster           = "gcp_gke_cluster"
	DeviceTypeAWSSecret               = "aws_secretsmanager_secret"
	DeviceTypeAzureKeyVaultSecret     = "azure_keyvault_secret"
	DeviceTypeGCPSecret               = "gcp_secret"
	DeviceTypeAWSHostedZone           = "aws_route53_hosted_zone"
	DeviceTypeAzureDNSZone            = "azure_dns_zone"
	DeviceTypeGCPManagedZone          = "gcp_dns_managed_zone"
	DeviceTypeAWSSecurityGroup        = "aws_security_group"
	DeviceTypeAzureNetworkSecurityGrp = "azure_network_security_group"
	DeviceTypeGCPFirewall             = "gcp_firewall"
)

func init() {
	for _, dt := range []string{
		DeviceTypeAWSLambdaFunction, DeviceTypeAzureFunctionApp, DeviceTypeGCPCloudFunction,
		DeviceTypeAWSEKSCluster, DeviceTypeAzureAKSCluster, DeviceTypeGCPGKECluster,
		DeviceTypeAWSSecret, DeviceTypeAzureKeyVaultSecret, DeviceTypeGCPSecret,
		DeviceTypeAWSHostedZone, DeviceTypeAzureDNSZone, DeviceTypeGCPManagedZone,
		DeviceTypeAWSSecurityGroup, DeviceTypeAzureNetworkSecurityGrp, DeviceTypeGCPFirewall,
	} {
		inventoryOnlyDeviceTypes[dt] = true
	}
}

// tier1Resource builds the provider-independent shape one Tier-1 resource is
// recorded as. `region` may be "" (Route 53, DNS zones, secrets on GCP).
func tier1Resource(provider, deviceType, resourceID, display, account, region, state string, attrs map[string]any, tags map[string]string, metadata map[string]any) cloudEnumResource {
	facts := cloudPlacementFacts(provider, account, region, resourceID, nil)
	if st := normalizeProviderState(provider, state); st != "" {
		facts["cloud.provider_state"] = st
	}
	md := map[string]interface{}{"region": region, "state": state}
	for k, v := range metadata {
		md[k] = v
	}
	return cloudEnumResource{
		DeviceType:  deviceType,
		ResourceID:  resourceID,
		DisplayName: display,
		Facts:       facts,
		Attributes:  mergeAttributes(cloudResourceAttributes(provider, account, region), attrs),
		Tags:        tagsToJSONB(tags),
		Metadata:    md,
	}
}

// recordTier1 records one listing's resources through the enumeration funnel.
// One resource that cannot be recorded is logged and skipped; it does not
// lose the others (the listing itself answered, which is what the outcome
// row reports).
func (s *CloudDiscoveryService) recordTier1(ctx context.Context, tenantID, integrationID uuid.UUID, vendor string, resources []cloudEnumResource) []models.Device {
	devices := make([]models.Device, 0, len(resources))
	for _, res := range resources {
		d, err := s.recordCloudResource(ctx, tenantID, integrationID, vendor, res)
		if err != nil {
			log.Printf("[cloud tier1] %s %s not recorded: %v", res.DeviceType, res.ResourceID, err)
			continue
		}
		devices = append(devices, *d)
	}
	return devices
}

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

func awsLambdaResources(fns []awsclient.Function) []cloudEnumResource {
	out := make([]cloudEnumResource, 0, len(fns))
	for _, f := range fns {
		attrs := map[string]any{"runtime": f.Runtime, "handler": f.Handler, "environment_variable_names": f.EnvironmentVarKeys}
		if f.MemoryMB > 0 {
			attrs["memory_mb"] = f.MemoryMB
		}
		if f.RoleName != "" {
			attrs["role_names"] = []string{f.RoleName}
		}
		out = append(out, tier1Resource("aws", DeviceTypeAWSLambdaFunction, f.ARN, f.Name, accountIDFromARN(f.ARN), f.Region, f.State, attrs, nil,
			map[string]any{"resource_type": "lambda", "function_name": f.Name}))
	}
	return out
}

func awsClusterResources(cls []awsclient.Cluster) []cloudEnumResource {
	out := make([]cloudEnumResource, 0, len(cls))
	for _, c := range cls {
		access := "private"
		switch {
		case c.EndpointPublic && c.EndpointPrivate:
			access = "public_and_private"
		case c.EndpointPublic:
			access = "public"
		}
		r := tier1Resource("aws", DeviceTypeAWSEKSCluster, c.ARN, c.Name, accountIDFromARN(c.ARN), c.Region, c.Status,
			map[string]any{"kubernetes_version": c.Version, "endpoint_access": access}, nil,
			map[string]any{"resource_type": "eks", "cluster_name": c.Name})
		for _, sg := range c.SecurityGroupIDs {
			if arn := awsclient.EC2ResourceARN(c.Region, accountIDFromARN(c.ARN), "security-group", sg); arn != "" {
				r.MemberOf = append(r.MemberOf, arn)
			}
		}
		out = append(out, r)
	}
	return out
}

func awsSecretResources(secs []awsclient.Secret) []cloudEnumResource {
	out := make([]cloudEnumResource, 0, len(secs))
	for _, sec := range secs {
		state := "active"
		if sec.PendingDeletion {
			state = "pending_deletion"
		}
		out = append(out, tier1Resource("aws", DeviceTypeAWSSecret, sec.ARN, sec.Name, accountIDFromARN(sec.ARN), sec.Region, state,
			map[string]any{"rotation_enabled": sec.RotationEnabled, "last_rotated_at": sec.LastRotated, "encryption_key_ref": sec.KMSKeyID},
			sec.Tags, map[string]any{"resource_type": "secretsmanager"}))
	}
	return out
}

func awsZoneResources(zones []awsclient.HostedZone, account string) []cloudEnumResource {
	out := make([]cloudEnumResource, 0, len(zones))
	for _, z := range zones {
		vis := "public"
		if z.Private {
			vis = "private"
		}
		out = append(out, tier1Resource("aws", DeviceTypeAWSHostedZone, z.ARN, z.Name, account, cloudScopeGlobal, "",
			map[string]any{"zone_name": z.Name, "visibility": vis, "record_count": z.RecordCount}, nil,
			map[string]any{"resource_type": "route53", "hosted_zone_id": z.ID}))
	}
	return out
}

func awsTier1Collectors(s *CloudDiscoveryService, tenantID, integrationID uuid.UUID, client *awsclient.Client) map[string]cloudCollector {
	rec := func(ctx context.Context, res []cloudEnumResource) []models.Device {
		return s.recordTier1(ctx, tenantID, integrationID, "AWS", res)
	}
	return map[string]cloudCollector{
		CloudTypeServerlessFunctions: {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			fns, err := client.ListFunctions(ctx, region)
			return rec(ctx, awsLambdaResources(fns)), err
		}},
		CloudTypeContainerClusters: {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			cls, err := client.ListClusters(ctx, region)
			return rec(ctx, awsClusterResources(cls)), err
		}},
		CloudTypeSecretStores: {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			secs, err := client.ListSecrets(ctx, region)
			return rec(ctx, awsSecretResources(secs)), err
		}},
		CloudTypeDNSZones: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			zones, err := client.ListHostedZones(ctx)
			return rec(ctx, awsZoneResources(zones, client.GetAccountID())), err
		}},
	}
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

func azureTier1Collectors(s *CloudDiscoveryService, tenantID, integrationID uuid.UUID, client *azureclient.Client) map[string]cloudCollector {
	if client == nil {
		return noClientCollectors()
	}
	sub := client.GetSubscriptionID()
	rec := func(ctx context.Context, res []cloudEnumResource) []models.Device {
		return s.recordTier1(ctx, tenantID, integrationID, "Azure", res)
	}
	return map[string]cloudCollector{
		CloudTypeServerlessFunctions: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			apps, err := client.ListFunctionApps(ctx)
			res := make([]cloudEnumResource, 0, len(apps))
			for _, a := range apps {
				attrs := map[string]any{"runtime": a.Runtime}
				if a.IdentityName != "" {
					attrs["role_names"] = []string{a.IdentityName}
				}
				res = append(res, tier1Resource("azure", DeviceTypeAzureFunctionApp, a.ResourceID, a.Name, sub, a.Location, a.State, attrs, a.Tags,
					map[string]any{"resource_type": "function_app"}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeContainerClusters: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			cls, err := client.ListManagedClusters(ctx)
			res := make([]cloudEnumResource, 0, len(cls))
			for _, c := range cls {
				access := "public"
				if c.PrivateCluster {
					access = "private"
				}
				res = append(res, tier1Resource("azure", DeviceTypeAzureAKSCluster, c.ResourceID, c.Name, sub, c.Location, c.State,
					map[string]any{"kubernetes_version": c.KubernetesVersion, "endpoint_access": access}, c.Tags,
					map[string]any{"resource_type": "aks"}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeSecretStores: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			secs, err := client.ListVaultSecrets(ctx)
			res := make([]cloudEnumResource, 0, len(secs))
			for _, sec := range secs {
				state := "enabled"
				if !sec.Enabled {
					state = "disabled"
				}
				res = append(res, tier1Resource("azure", DeviceTypeAzureKeyVaultSecret, sec.ResourceID, sec.Vault+"/"+sec.Name, sub, sec.Location, state,
					nil, sec.Tags, map[string]any{"resource_type": "key_vault_secret", "vault": sec.Vault}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeDNSZones: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			zones, err := client.ListDNSZones(ctx)
			res := make([]cloudEnumResource, 0, len(zones))
			for _, z := range zones {
				vis := "public"
				if z.Private {
					vis = "private"
				}
				res = append(res, tier1Resource("azure", DeviceTypeAzureDNSZone, z.ResourceID, z.Name, sub, cloudScopeGlobal, "",
					map[string]any{"zone_name": z.Name, "visibility": vis, "record_count": z.RecordCount}, z.Tags,
					map[string]any{"resource_type": "dns_zone"}))
			}
			return rec(ctx, res), err
		}},
	}
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

// gcpServiceAccountName is the account part of a service account e-mail.
func gcpServiceAccountName(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

func gcpTier1Collectors(s *CloudDiscoveryService, tenantID, integrationID uuid.UUID, client *gcpclient.Client) map[string]cloudCollector {
	if client == nil {
		return noClientCollectors()
	}
	project := client.GetProjectID()
	rec := func(ctx context.Context, res []cloudEnumResource) []models.Device {
		return s.recordTier1(ctx, tenantID, integrationID, "GCP", res)
	}
	return map[string]cloudCollector{
		CloudTypeServerlessFunctions: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			fns, err := client.ListCloudFunctions(ctx)
			res := make([]cloudEnumResource, 0, len(fns))
			for _, f := range fns {
				attrs := map[string]any{"runtime": f.Runtime, "handler": f.EntryPoint, "environment_variable_names": f.EnvironmentVarKeys}
				if f.MemoryMB > 0 {
					attrs["memory_mb"] = f.MemoryMB
				}
				if f.ServiceAccount != "" {
					attrs["role_names"] = []string{gcpServiceAccountName(f.ServiceAccount)}
				}
				res = append(res, tier1Resource("gcp", DeviceTypeGCPCloudFunction, f.Name, gcpclient.ResourceShortName(f.Name), project, f.Region, f.State,
					attrs, f.Labels, map[string]any{"resource_type": "cloud_function"}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeContainerClusters: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			cls, err := client.ListGKEClusters(ctx)
			res := make([]cloudEnumResource, 0, len(cls))
			for _, c := range cls {
				access := "public"
				if c.PrivateEndpoint {
					access = "private"
				}
				res = append(res, tier1Resource("gcp", DeviceTypeGCPGKECluster, c.ResourceName, c.Name, project, c.Location, c.Status,
					map[string]any{"kubernetes_version": c.Version, "endpoint_access": access}, c.Labels,
					map[string]any{"resource_type": "gke"}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeSecretStores: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			secs, err := client.ListSecrets(ctx)
			res := make([]cloudEnumResource, 0, len(secs))
			for _, sec := range secs {
				res = append(res, tier1Resource("gcp", DeviceTypeGCPSecret, sec.Name, gcpclient.ResourceShortName(sec.Name), project, cloudScopeGlobal, "",
					map[string]any{"rotation_enabled": sec.Rotation, "encryption_key_ref": sec.KMSKeyName}, sec.Labels,
					map[string]any{"resource_type": "secret_manager"}))
			}
			return rec(ctx, res), err
		}},
		CloudTypeDNSZones: {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			zones, err := client.ListManagedZones(ctx)
			res := make([]cloudEnumResource, 0, len(zones))
			for _, z := range zones {
				vis := z.Visibility
				if vis != "public" && vis != "private" {
					vis = "unknown"
				}
				id := fmt.Sprintf("projects/%s/managedZones/%s", project, z.Name)
				res = append(res, tier1Resource("gcp", DeviceTypeGCPManagedZone, id, z.DNSName, project, cloudScopeGlobal, "",
					map[string]any{"zone_name": z.DNSName, "visibility": vis}, z.Labels, map[string]any{"resource_type": "managed_zone"}))
			}
			return rec(ctx, res), err
		}},
	}
}

// ---------------------------------------------------------------------------
// Security groups as assets, and member_of (ADR-0009 D2, D4)
// ---------------------------------------------------------------------------

// linkMemberOf writes the measured `member_of` edge from a resource to each
// security group it is in, on the resource's own transaction. A group that is
// not in the inventory (its listing was not selected, or refused) is skipped:
// the membership is still the `cloud.security_groups` fact, and the edge is
// written by the run that records the group.
func linkMemberOf(ctx context.Context, r *pgidentity.Repository, tenantID uuid.UUID, assetID uuid.UUID, groups []string, source identity.Source, at time.Time) error {
	for _, g := range groups {
		refs, err := r.FindByIdentifier(ctx, tenantID.String(), identity.KindCloudResourceID, g, "")
		if err != nil {
			return err
		}
		if len(refs) != 1 || refs[0].ID == assetID.String() {
			continue
		}
		status, err := r.EdgeStatusFor(ctx, tenantID.String(), source.Kind, assetID.String(), refs[0].ID)
		if err != nil {
			return err
		}
		if err := r.UpsertRelationship(ctx, tenantID.String(), pgidentity.Edge{
			FromAssetID: assetID.String(), ToAssetID: refs[0].ID, Type: string(relationships.MemberOf),
			SourceKind: source.Kind, SourceRef: source.Ref, Status: status, ObservedAt: at,
		}); err != nil {
			return fmt.Errorf("member_of %s: %w", g, err)
		}
	}
	return nil
}

// dnsZoneCertificateNames cross-references the zone with the tenant's
// certificate inventory: the subject and SAN names that fall under it, bounded
// (ADR-0009 D2 — "an attribute only": the certificate rows are not linked).
func dnsZoneCertificateNames(ctx context.Context, r *pgidentity.Repository, tenantID uuid.UUID, zone string) ([]string, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if zone == "" || r.Tx() == nil {
		return nil, nil
	}
	rows, err := r.Tx().QueryContext(ctx, `
		SELECT DISTINCT lower(n) FROM (
			SELECT common_name AS n FROM public.certificates WHERE tenant_id = $1 AND common_name IS NOT NULL
			UNION ALL
			SELECT unnest(subject_alternative_names) FROM public.certificates WHERE tenant_id = $1
		) names
		WHERE lower(n) = $2 OR right(lower(n), length($2) + 1) = '.' || $2
		ORDER BY 1 LIMIT 50`, tenantID, zone)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// cloudProviderTypeAttr is the `provider_type` class attribute for a device
// type, from the class registry's mapping.
func cloudProviderTypeAttr(deviceType string) map[string]any {
	if pt, ok := assetclass.ProviderTypeOf(deviceType); ok {
		return map[string]any{"provider_type": pt.Type}
	}
	return nil
}

// securityGroupResource is one group as an asset.
func securityGroupResource(provider, deviceType, resourceID, name, account, region, networkRef string, tags map[string]string) cloudEnumResource {
	return tier1Resource(provider, deviceType, resourceID, name, account, region, "",
		map[string]any{"network_ref": networkRef}, tags, map[string]any{"resource_type": "security_group"})
}

// attachMemberOf sets each instance's MemberOf from its
// `cloud.security_groups` membership, through ref (provider id → the group's
// canonical resource id).
func attachMemberOf(instances []cloudEnumResource, ref func(id string, inst cloudEnumResource) string) {
	for i := range instances {
		groups, _ := instances[i].Facts["cloud.security_groups"].([]map[string]any)
		for _, g := range groups {
			id, _ := g["id"].(string)
			if r := ref(id, instances[i]); r != "" {
				instances[i].MemberOf = append(instances[i].MemberOf, r)
			}
		}
	}
}

// awsSecurityGroups turns one region's group listing into assets, and links
// the region's instances to them.
func awsSecurityGroups(plan *cloudEnumerationPlan, groups []awsclient.SecurityGroup, region string) {
	for _, g := range groups {
		arn := awsclient.EC2ResourceARN(g.Region, g.AccountID, "security-group", g.GroupID)
		if arn == "" {
			continue
		}
		r := securityGroupResource("aws", DeviceTypeAWSSecurityGroup, arn, firstNonEmpty(g.GroupName, g.GroupID), g.AccountID, g.Region,
			awsclient.EC2ResourceARN(g.Region, g.AccountID, "vpc", g.VPCID), g.Tags)
		r.annotateListing(CloudListingKey(CloudTypeSecurityGroups, region))
		plan.SecurityGroups = append(plan.SecurityGroups, r)
	}
	attachMemberOf(plan.Instances, func(id string, inst cloudEnumResource) string {
		account, _ := inst.Facts["cloud.account_id"].(string)
		reg, _ := inst.Facts["cloud.region"].(string)
		return awsclient.EC2ResourceARN(reg, account, "security-group", id)
	})
}

// azureSecurityGroups: NSGs as assets; Azure ids are case-insensitive, so an
// instance's reference resolves through the listing's own spelling.
func azureSecurityGroups(plan *cloudEnumerationPlan, nsgs []azureclient.NetworkSecurityGroup) {
	canonical := map[string]string{}
	for _, g := range nsgs {
		if g.ResourceID == "" {
			continue
		}
		canonical[strings.ToLower(g.ResourceID)] = g.ResourceID
		r := securityGroupResource("azure", DeviceTypeAzureNetworkSecurityGrp, g.ResourceID, g.Name, g.SubscriptionID, g.Location, "", g.Tags)
		r.annotateListing(CloudListingKey(CloudTypeSecurityGroups, cloudScopeGlobal))
		plan.SecurityGroups = append(plan.SecurityGroups, r)
	}
	attachMemberOf(plan.Instances, func(id string, _ cloudEnumResource) string {
		if c, ok := canonical[strings.ToLower(id)]; ok {
			return c
		}
		return id
	})
}

// gcpSecurityGroups: firewall rules as the group assets (GCP has no security
// group object; a firewall targets instances, ADR-0009 D2).
func gcpSecurityGroups(plan *cloudEnumerationPlan, project string, firewalls []gcpclient.ComputeFirewall) {
	for _, fw := range firewalls {
		id := gcpclient.ResourceName(fw.SelfLink)
		if id == "" {
			continue
		}
		r := securityGroupResource("gcp", DeviceTypeGCPFirewall, id, fw.Name, project, cloudScopeGlobal, gcpclient.ResourceName(fw.Network), nil)
		r.annotateListing(CloudListingKey(CloudTypeSecurityGroups, cloudScopeGlobal))
		plan.SecurityGroups = append(plan.SecurityGroups, r)
	}
	attachMemberOf(plan.Instances, func(id string, _ cloudEnumResource) string { return id })
}

// noClientCollectors is the Tier-1 table for a provider client that could not
// be built: every type is present (so the dispatch table stays whole) and
// fails rather than answering empty.
func noClientCollectors() map[string]cloudCollector {
	fail := cloudCollector{collect: func(context.Context, string) ([]models.Device, error) {
		return nil, fmt.Errorf("no provider client")
	}}
	return map[string]cloudCollector{
		CloudTypeServerlessFunctions: fail, CloudTypeContainerClusters: fail, CloudTypeSecretStores: fail, CloudTypeDNSZones: fail,
	}
}
