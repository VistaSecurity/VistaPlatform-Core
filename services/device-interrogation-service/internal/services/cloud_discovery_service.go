package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// CloudDiscoveryService handles cloud resource discovery
type CloudDiscoveryService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection threaded into the KMS
	// and storage sub-services and the cloud-client integration lookups. Shared
	// platform integrations have tenant_id NULL, so callers must explicitly
	// authorize integration IDs before decrypting credentials. Pre-flip it
	// resolves to the same connection as db.
	bypassDB  *sql.DB
	masterKey string
	// devices is the managed-asset store. Cloud discovery no longer writes
	// rows of its own: every resource it finds goes through the same
	// identification engine and the same asset_management upsert the Devices
	// page uses, so a bucket found here and the same bucket named anywhere else
	// resolve to one asset.
	devices *DeviceService
}

// NewCloudDiscoveryService creates a new cloud discovery service. db is the
// RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass)
// connection. All cloud discovery runs under a known tenantID; device writes use
// tenant-scoped transactions, and integration reads use explicit tenant/shared
// predicates on bypassDB. Pre-flip both handles resolve to the same connection.
func NewCloudDiscoveryService(db, bypassDB *sql.DB, masterKey string) *CloudDiscoveryService {
	return &CloudDiscoveryService{
		db:        db,
		bypassDB:  bypassDB,
		masterKey: masterKey,
		devices:   NewDeviceServiceWithKey(db, masterKey),
	}
}

// GetIntegrationCloudProvider retrieves the cloud provider type from an integration
// the caller can use. Shared platform integrations have tenant_id NULL, so the
// authorization check runs on the bypass connection with an explicit tenant/shared
// predicate instead of relying on RLS alone.
func (s *CloudDiscoveryService) GetIntegrationCloudProvider(ctx context.Context, tenantID, integrationID uuid.UUID) (string, error) {
	return authorizeCloudIntegration(ctx, s.bypassDB, tenantID, integrationID, "")
}

// DiscoverAWSResources discovers AWS resources and creates devices
func (s *CloudDiscoveryService) DiscoverAWSResources(ctx context.Context, tenantID uuid.UUID, integrationID uuid.UUID, resourceTypes []string, regions []string) ([]models.Device, error) {
	if _, err := authorizeCloudIntegration(ctx, s.bypassDB, tenantID, integrationID, "aws"); err != nil {
		return nil, fmt.Errorf("AWS integration not authorized: %w", err)
	}

	// Create AWS client
	awsClient, err := awsclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS client: %w", err)
	}

	var discoveredDevices []models.Device

	// If no regions specified, use the client's default region
	if len(regions) == 0 {
		regions = []string{awsClient.GetRegion()}
	}

	// Discover resources by type.
	//
	// Every requested type is collected independently, once per region, and
	// its outcome is recorded ( slice E). The dispatch used to be a switch
	// that was wrong in opposite directions in its two halves: alb/elb/nlb,
	// api_gateway and cloudfront returned the error and abandoned the whole
	// run, so one failing type lost the results of every type that worked;
	// kms, s3 and rds logged a warning nobody reads while the job still
	// reported `success: true`, so an IAM denial, a throttle and a genuinely
	// empty account were indistinguishable. Neither aborts and neither is
	// swallowed now — see runCloudCollectors.
	//
	// A resource type absent from this map is NOT silently ignored any more:
	// it stays `not_attempted` on the job result, which says "you asked and
	// nothing looked" instead of showing up as zero found.
	storage := NewStorageEncryptionService(s.db, s.bypassDB, s.masterKey)
	collectors := map[string]cloudCollector{
		"api_gateway": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return s.discoverAPIGateways(ctx, tenantID, awsClient, []string{region})
		}},
		"cloudfront": {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			return s.discoverCloudFrontDistributions(ctx, tenantID, awsClient)
		}},
		"kms": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return s.discoverKMSKeys(ctx, tenantID, integrationID, awsClient, []string{region})
		}},
		"s3": {collect: func(ctx context.Context, _ string) ([]models.Device, error) {
			return storage.DiscoverS3BucketEncryption(ctx, tenantID, awsClient)
		}},
		"rds": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return storage.DiscoverRDSEncryption(ctx, tenantID, awsClient, []string{region})
		}},
	}
	for _, lbType := range []string{"alb", "elb", "nlb"} {
		lbType := lbType
		collectors[lbType] = cloudCollector{regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return s.discoverLoadBalancers(ctx, tenantID, awsClient, lbType, []string{region})
		}}
	}

	discoveredDevices = append(discoveredDevices, runCloudCollectors(ctx, resourceTypes, regions, collectors)...)

	return discoveredDevices, nil
}

// discoverLoadBalancers discovers ALB, ELB, or NLB resources
func (s *CloudDiscoveryService) discoverLoadBalancers(ctx context.Context, tenantID uuid.UUID, awsClient *awsclient.Client, lbType string, regions []string) ([]models.Device, error) {
	var devices []models.Device

	for _, region := range regions {
		// Create region-specific client
		cfg := awsClient.GetConfig()
		cfg.Region = region
		regionClient := elasticloadbalancingv2.NewFromConfig(cfg)

		// List all load balancers
		paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(regionClient, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list load balancers in %s: %w", region, err)
			}

			for _, lb := range page.LoadBalancers {
				// Filter by type
				lbTypeStr := string(lb.Type)
				if (lbType == "alb" && lbTypeStr != "application") ||
					(lbType == "nlb" && lbTypeStr != "network") ||
					(lbType == "elb" && lbTypeStr != "classic") {
					continue
				}

				// Get listeners to check for TLS
				listeners, err := regionClient.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
					LoadBalancerArn: lb.LoadBalancerArn,
				})
				if err != nil {
					continue // Skip if we can't get listeners
				}

				// Check if any listener uses TLS
				hasTLS := false
				for _, listener := range listeners.Listeners {
					if listener.Protocol == elbv2types.ProtocolEnumHttps || listener.Protocol == elbv2types.ProtocolEnumTls {
						hasTLS = true
						break
					}
				}

				if !hasTLS {
					continue // Skip load balancers without TLS
				}

				// Create device metadata first
				metadata := map[string]interface{}{
					"arn":            awsconfig.ToString(lb.LoadBalancerArn),
					"scheme":         string(lb.Scheme),
					"state":          string(lb.State.Code),
					"vpc_id":         awsconfig.ToString(lb.VpcId),
					"region":         region,
					"listener_count": len(listeners.Listeners),
				}

				// Interrogate load balancer for detailed crypto configs
				interrogationService := NewAWSInterrogationService(awsClient)
				cryptoConfigs, err := interrogationService.InterrogateLoadBalancer(ctx, awsconfig.ToString(lb.LoadBalancerArn))
				if err != nil {
					// Log but continue - we still want to create the device
					fmt.Printf("Warning: failed to interrogate load balancer %s: %v\n", awsconfig.ToString(lb.LoadBalancerArn), err)
				} else if len(cryptoConfigs) > 0 {
					// Perform TLS handshake against the ALB DNS to get actual certificate chain
					lbHostname := ""
					if lb.DNSName != nil {
						lbHostname = *lb.DNSName
					}

					// Convert CryptoConfig to map for JSON storage
					configMaps := make([]map[string]interface{}, 0, len(cryptoConfigs))
					for _, cfg := range cryptoConfigs {
						configMap := map[string]interface{}{
							"protocol":         cfg.Protocol,
							"protocol_version": cfg.ProtocolVersion,
							"cipher_suite":     cfg.CipherSuite,
							"key_size":         cfg.KeySize,
							"hash_algorithm":   cfg.HashAlgorithm,
							"port":             cfg.Port,
							"hostname":         cfg.Hostname,
							"ip_address":       cfg.IPAddress,
							"metadata":         cfg.Metadata,
						}

						// Perform TLS handshake for each HTTPS listener port
						if lbHostname != "" && (cfg.Protocol == "HTTPS" || cfg.Protocol == "TLS") {
							handshakeResult, hsErr := cloudTLSHandshake(ctx, lbHostname, cfg.Port)
							if hsErr != nil {
								log.Printf("Warning: TLS handshake error for %s:%d: %v", lbHostname, cfg.Port, hsErr)
							} else if handshakeResult != nil && handshakeResult.Success {
								// The negotiated cipher is a real measurement
								// from this endpoint — prefer it.
								configMap["cipher_suite"] = &handshakeResult.CipherSuite
								applyHandshakeKeyExchange(configMap, handshakeResult)
								configMap["negotiated_protocol_version"] = handshakeResult.TLSVersion

								// protocol_version must stay the WEAKEST
								// version the listener permits, not the one
								// our modern client happened to negotiate. A
								// listener on ELBSecurityPolicy-TLS-1-0-2015-04
								// negotiates TLS 1.2 with us and still accepts
								// TLS 1.0 from anyone who asks; overwriting
								// with the negotiated version hides exactly
								// the finding we exist to produce. Only adopt
								// the handshake version when the API told us
								// nothing.
								if cfg.ProtocolVersion == nil {
									configMap["protocol_version"] = &handshakeResult.TLSVersion
								}
								if handshakeResult.ALPN != "" {
									if cfgMeta, ok := configMap["metadata"].(map[string]interface{}); ok {
										cfgMeta["alpn"] = handshakeResult.ALPN
									}
								}

								// Enrich certificates with ACM metadata if available
								certs := handshakeResult.Certificates
								if cfgMeta, ok := configMap["metadata"].(map[string]interface{}); ok {
									if acmCerts, ok := cfgMeta["certificates"].([]map[string]interface{}); ok {
										certs = EnrichCertificatesWithACM(certs, acmCerts)
									}
								}

								// Store handshake certificates in the config for downstream processing
								configMap["certificates"] = certs
								configMap["handshake_verified"] = true
							} else if handshakeResult != nil {
								// Handshake failed (e.g., private ALB) -- record the failure
								configMap["handshake_verified"] = false
								configMap["handshake_error"] = handshakeResult.Error
								log.Printf("TLS handshake skipped for %s:%d (likely private): %s", lbHostname, cfg.Port, handshakeResult.Error)
							}
						}

						configMaps = append(configMaps, configMap)
					}
					metadata["crypto_configs"] = configMaps
				}

				// Create device
				deviceType := "aws_alb"
				switch lbType {
				case "nlb":
					deviceType = "aws_nlb"
				case "elb":
					deviceType = "aws_elb"
				}

				hostname := ""
				if lb.DNSName != nil {
					hostname = *lb.DNSName
				}

				integrationID := awsClient.GetIntegrationID()
				device := models.Device{
					ID:               uuid.New(),
					TenantID:         tenantID,
					DeviceType:       deviceType,
					Vendor:           stringPtr("AWS"),
					Hostname:         stringPtr(hostname),
					DiscoveryMethod:  "cloud_api",
					CredentialID:     &integrationID,
					ConnectionStatus: "discovered",
					Metadata:         models.JSONB(metadata),
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}

				// Resolve to an asset (creating a pending one if this load
				// balancer is new) and configure management on it.
				if err := s.upsertDeviceAsset(ctx, &device, getStringFromMap(metadata, "arn")); err != nil {
					log.Printf("Warning: failed to record %s %s: %v", deviceType, hostname, err)
					continue
				}

				devices = append(devices, device)
			}
		}
	}

	return devices, nil
}

// discoverAPIGateways discovers API Gateway v2 resources
func (s *CloudDiscoveryService) discoverAPIGateways(ctx context.Context, tenantID uuid.UUID, awsClient *awsclient.Client, regions []string) ([]models.Device, error) {
	var devices []models.Device

	for _, region := range regions {
		cfg := awsClient.GetConfig()
		cfg.Region = region
		regionClient := apigatewayv2.NewFromConfig(cfg)

		// Add timeout for API Gateway calls (30 seconds per region)
		regionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// List all APIs
		// Note: API Gateway v2 GetApis doesn't have a paginator, but supports NextToken
		var nextToken *string
		for {
			input := &apigatewayv2.GetApisInput{}
			if nextToken != nil {
				input.NextToken = nextToken
			}

			output, err := regionClient.GetApis(regionCtx, input)
			if err != nil {
				// Log and skip this region instead of failing entire job
				log.Printf("Warning: failed to list API Gateways in %s: %v (skipping region)", region, err)
				break
			}

			for _, api := range output.Items {

				// Check if API has domain configurations (TLS)
				domains, err := regionClient.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{})
				if err != nil {
					continue
				}

				hasTLS := false
				for _, domain := range domains.Items {
					// Check if this domain is associated with this API
					apiMappings, err := regionClient.GetApiMappings(ctx, &apigatewayv2.GetApiMappingsInput{
						DomainName: domain.DomainName,
					})
					if err != nil {
						continue
					}

					for _, mapping := range apiMappings.Items {
						if awsconfig.ToString(mapping.ApiId) == awsconfig.ToString(api.ApiId) {
							hasTLS = true
							break
						}
					}
					if hasTLS {
						break
					}
				}

				if !hasTLS {
					continue
				}

				hostname := ""
				if api.ApiEndpoint != nil {
					hostname = *api.ApiEndpoint
					// Strip https:// prefix for hostname used in TLS handshake
					hostname = strings.TrimPrefix(hostname, "https://")
					hostname = strings.TrimPrefix(hostname, "http://")
				}

				metadata := map[string]interface{}{
					"api_id":   awsconfig.ToString(api.ApiId),
					"protocol": string(api.ProtocolType),
					"region":   region,
					"api_name": awsconfig.ToString(api.Name),
				}

				// Interrogate the mapped custom domains. TLS on API Gateway
				// is a property of the domain, and its SecurityPolicy
				// (TLS_1_0 / TLS_1_2) is a MINIMUM — a handshake against the
				// endpoint cannot show that TLS 1.0 is still accepted.
				cryptoConfigs := make([]map[string]interface{}, 0, 2)
				interrogationService := NewAWSInterrogationService(awsClient)
				domainConfigs, iErr := interrogationService.InterrogateAPIGateway(regionCtx, awsconfig.ToString(api.ApiId))
				if iErr != nil {
					log.Printf("Warning: failed to interrogate API Gateway %s: %v", awsconfig.ToString(api.ApiId), iErr)
				}
				for _, cfg := range domainConfigs {
					cryptoConfigs = append(cryptoConfigs, map[string]interface{}{
						"protocol":         cfg.Protocol,
						"protocol_version": cfg.ProtocolVersion,
						"cipher_suite":     cfg.CipherSuite,
						"port":             cfg.Port,
						"hostname":         cfg.Hostname,
						"tls_versions":     cfg.Metadata["tls_versions"],
						"metadata":         cfg.Metadata,
					})
				}

				// Perform TLS handshake against the API Gateway endpoint
				if hostname != "" {
					handshakeResult, hsErr := cloudTLSHandshake(ctx, hostname, 443)
					if hsErr != nil {
						log.Printf("Warning: TLS handshake error for API Gateway %s: %v", hostname, hsErr)
					} else if handshakeResult != nil && handshakeResult.Success {
						cryptoConfig := map[string]interface{}{
							"protocol":           "HTTPS",
							"protocol_version":   handshakeResult.TLSVersion,
							"cipher_suite":       handshakeResult.CipherSuite,
							"port":               443,
							"hostname":           hostname,
							"certificates":       handshakeResult.Certificates,
							"handshake_verified": true,
						}
						applyHandshakeKeyExchange(cryptoConfig, handshakeResult)
						cryptoConfigs = append(cryptoConfigs, cryptoConfig)
					} else if handshakeResult != nil {
						log.Printf("TLS handshake skipped for API Gateway %s: %s", hostname, handshakeResult.Error)
					}
				}
				if len(cryptoConfigs) > 0 {
					metadata["crypto_configs"] = cryptoConfigs
				}

				integrationID := awsClient.GetIntegrationID()
				device := models.Device{
					ID:               uuid.New(),
					TenantID:         tenantID,
					DeviceType:       "aws_api_gateway",
					Vendor:           stringPtr("AWS"),
					Hostname:         stringPtr(hostname),
					DiscoveryMethod:  "cloud_api",
					CredentialID:     &integrationID,
					ConnectionStatus: "discovered",
					Metadata:         models.JSONB(metadata),
					CreatedAt:        time.Now(),
					UpdatedAt:        time.Now(),
				}

				if err := s.upsertDeviceAsset(ctx, &device, getStringFromMap(metadata, "api_id")); err != nil {
					log.Printf("Warning: failed to record aws_api_gateway %s: %v", hostname, err)
					continue
				}

				devices = append(devices, device)
			}
		}
	}

	return devices, nil
}

// discoverCloudFrontDistributions discovers CloudFront distributions
func (s *CloudDiscoveryService) discoverCloudFrontDistributions(ctx context.Context, tenantID uuid.UUID, awsClient *awsclient.Client) ([]models.Device, error) {
	var devices []models.Device
	cfClient := awsClient.GetCloudFrontClient()

	// List all distributions
	paginator := cloudfront.NewListDistributionsPaginator(cfClient, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list CloudFront distributions: %w", err)
		}

		for _, dist := range page.DistributionList.Items {
			// Check if distribution uses HTTPS
			hasHTTPS := false
			if dist.Aliases != nil && len(dist.Aliases.Items) > 0 {
				hasHTTPS = true
			}
			if dist.DefaultCacheBehavior != nil {
				policy := dist.DefaultCacheBehavior.ViewerProtocolPolicy
				if policy == cloudfronttypes.ViewerProtocolPolicyHttpsOnly || policy == cloudfronttypes.ViewerProtocolPolicyRedirectToHttps {
					hasHTTPS = true
				}
			}

			if !hasHTTPS {
				continue
			}

			hostname := ""
			if dist.DomainName != nil {
				hostname = *dist.DomainName
			}

			status := ""
			if dist.Status != nil {
				status = *dist.Status
			}

			metadata := map[string]interface{}{
				"distribution_id": awsconfig.ToString(dist.Id),
				"status":          status,
				"enabled":         dist.Enabled,
			}

			// Interrogate the distribution configuration. This is the only
			// way to see the ORIGIN-side TLS settings: a distribution can
			// serve viewers over TLS 1.2+ while reaching its origin over
			// TLS 1.0 or cleartext, and no client-side handshake against the
			// CloudFront domain can reveal that.
			cryptoConfigs := make([]map[string]interface{}, 0, 2)
			interrogationService := NewAWSInterrogationService(awsClient)
			apiConfigs, iErr := interrogationService.InterrogateCloudFront(ctx, awsconfig.ToString(dist.Id))
			if iErr != nil {
				log.Printf("Warning: failed to interrogate CloudFront distribution %s: %v", awsconfig.ToString(dist.Id), iErr)
			}
			for _, cfg := range apiConfigs {
				cryptoConfigs = append(cryptoConfigs, map[string]interface{}{
					"protocol":         cfg.Protocol,
					"protocol_version": cfg.ProtocolVersion,
					"cipher_suite":     cfg.CipherSuite,
					"port":             cfg.Port,
					"hostname":         cfg.Hostname,
					"tls_versions":     cfg.Metadata["tls_versions"],
					"metadata":         cfg.Metadata,
				})
			}

			// Perform TLS handshake against the CloudFront distribution domain
			if hostname != "" {
				handshakeResult, hsErr := cloudTLSHandshake(ctx, hostname, 443)
				if hsErr != nil {
					log.Printf("Warning: TLS handshake error for CloudFront %s: %v", hostname, hsErr)
				} else if handshakeResult != nil && handshakeResult.Success {
					cryptoConfig := map[string]interface{}{
						"protocol":           "HTTPS",
						"protocol_version":   handshakeResult.TLSVersion,
						"cipher_suite":       handshakeResult.CipherSuite,
						"port":               443,
						"hostname":           hostname,
						"certificates":       handshakeResult.Certificates,
						"handshake_verified": true,
					}
					applyHandshakeKeyExchange(cryptoConfig, handshakeResult)
					cryptoConfigs = append(cryptoConfigs, cryptoConfig)
				} else if handshakeResult != nil {
					log.Printf("TLS handshake skipped for CloudFront %s: %s", hostname, handshakeResult.Error)
				}
			}
			if len(cryptoConfigs) > 0 {
				metadata["crypto_configs"] = cryptoConfigs
			}

			integrationID := awsClient.GetIntegrationID()
			device := models.Device{
				ID:               uuid.New(),
				TenantID:         tenantID,
				DeviceType:       "aws_cloudfront",
				Vendor:           stringPtr("AWS"),
				Hostname:         stringPtr(hostname),
				DiscoveryMethod:  "cloud_api",
				CredentialID:     &integrationID,
				ConnectionStatus: "discovered",
				Metadata:         models.JSONB(metadata),
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			}

			if err := s.upsertDeviceAsset(ctx, &device, getStringFromMap(metadata, "distribution_id")); err != nil {
				log.Printf("Warning: failed to record aws_cloudfront %s: %v", hostname, err)
				continue
			}

			devices = append(devices, device)
		}
	}

	return devices, nil
}

// WriteSensorDiscoveries writes cloud-discovered devices into the sensor_discoveries table
// so they are processed by the discovery-processor-service through the unified pipeline.
// It uses the "Platform Device Interrogation Agent" system sensor as the sensor_id.
func (s *CloudDiscoveryService) WriteSensorDiscoveries(ctx context.Context, tenantID uuid.UUID, batchID string, integrationID uuid.UUID, cloudProvider string, devices []models.Device) (int, error) {
	inserted := 0
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var err error
		inserted, err = s.writeSensorDiscoveriesTx(ctx, tx, tenantID, batchID, integrationID, cloudProvider, devices, time.Time{}, true)
		return err
	})
	return inserted, err
}

func (s *CloudDiscoveryService) writeSensorDiscoveriesTx(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, batchID string, integrationID uuid.UUID, cloudProvider string, devices []models.Device, observedAt time.Time, resolveDNS bool) (int, error) {
	hasFindings := false
	for _, device := range devices {
		if !inventoryOnlyDeviceTypes[device.DeviceType] {
			hasFindings = true
			break
		}
	}
	if !hasFindings {
		return 0, nil
	}

	// Look up the system sensor for this tenant (Platform Device Interrogation
	// Agent). RLS-scoped read on `sensors` under the known tenantID.
	var systemSensorID uuid.UUID
	sensorQuery := `
		SELECT id FROM sensors
		WHERE tenant_id = $1 AND profile = 'device_interrogation' AND platform_managed
		  AND deleted_at IS NULL
		ORDER BY created_at, id
		LIMIT 1
	`
	if err := tx.QueryRowContext(ctx, sensorQuery, tenantID).Scan(&systemSensorID); err != nil {
		return 0, fmt.Errorf("failed to find system sensor for tenant %s: %w (ensure system sensors are provisioned)", tenantID, err)
	}

	insertQuery := `
		INSERT INTO sensor_discoveries (
			id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
			confidence, metadata, hostname, timestamp, created_at
		) VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING
	`

	inserted := 0
	now := time.Now()

	for _, device := range devices {
		seen := observedAt
		if seen.IsZero() {
			seen = device.CreatedAt
		}
		if seen.IsZero() {
			seen = now
		}
		// An ENUMERATED resource is inventory, not a crypto finding. It
		// negotiated no protocol and states no at-rest encryption, so the
		// crypto-config-less fallback below would write it as a TLS endpoint on
		// port 443 with no version and no cipher suite — the phantom-endpoint
		// fabrication this file already documents twice. It is skipped here and
		// nowhere else: the identification engine has already recorded it as an
		// asset (cloud_enumeration.go), which is the whole of what it is.
		if inventoryOnlyDeviceTypes[device.DeviceType] {
			continue
		}

		// Extract crypto configs from device metadata.
		cryptoConfigs := extractCryptoConfigs(device.Metadata)

		// Region the resource lives in, for inventory-service's
		// FindOrCreateCloudSegment (which requires BOTH cloud_provider and
		// cloud_region and therefore never fired while this was unset).
		cloudRegion := cloudRegionForDevice(device)

		// Determine hostname
		hostname := ""
		if device.Hostname != nil {
			hostname = *device.Hostname
		}

		// Resolve dest_ip: use device IP, or resolve hostname, or fall back to 0.0.0.0
		destIP := "0.0.0.0"
		if device.IPAddress != nil && *device.IPAddress != "" {
			destIP = *device.IPAddress
		} else if hostname != "" && resolveDNS {
			// Try DNS resolution
			ips, err := net.LookupIP(hostname)
			if err == nil && len(ips) > 0 {
				destIP = ips[0].String()
			}
		}

		// If crypto configs exist, create one sensor_discovery per config
		if len(cryptoConfigs) > 0 {
			for _, cfg := range cryptoConfigs {
				protocol := "TLS"
				if proto, ok := cfg["protocol"].(string); ok && proto != "" {
					protocol = proto
				}

				port := 443
				if p, ok := cfg["port"].(int); ok {
					port = p
				} else if p, ok := cfg["port"].(float64); ok {
					port = int(p)
				}

				cfgHostname := hostname
				if h, ok := cfg["hostname"].(string); ok && h != "" {
					cfgHostname = h
				}

				// Build metadata JSONB.
				//
				// There is deliberately NO asset_id / device_id here. The
				// `device` a cloud collector builds is a value it invented for
				// this run — its ID is a fresh uuid.New() per row — so those
				// keys named an asset that has never existed, sitting beside
				// the REAL asset ids the interrogable collectors emit under the
				// same names. Identity for a cloud resource comes from
				// cloud_resource_id (the arn / resource id / self link), which
				// the identification engine reads from raw_metadata; a
				// fabricated uuid could only ever be a wrong answer that looks
				// like a right one.
				metadata := map[string]interface{}{
					"discovery_method": "cloud_api",
					"cloud_provider":   cloudProvider,
					"cloud_region":     cloudRegion,
					"device_type":      device.DeviceType,
					"integration_id":   integrationID.String(),
					"version":          getStringFromMap(cfg, "protocol_version"),
					"cipher_suite":     getStringFromMap(cfg, "cipher_suite"),
					"hash_algorithm":   getStringFromMap(cfg, "hash_algorithm"),
					"raw_metadata":     device.Metadata,
				}
				if ks, ok := cfg["key_size"].(float64); ok && ks > 0 {
					metadata["key_size"] = int(ks)
				} else if ks, ok := cfg["key_size"].(int); ok && ks > 0 {
					metadata["key_size"] = ks
				}

				// Include TLS handshake certificates for downstream processing.
				// The discovery-processor-service and inventory-service
				// extractCertificatesFromFinding() look for RawData["certificates"].
				if certs, ok := cfg["certificates"]; ok && certs != nil {
					metadata["certificates"] = certs

					// Compute certificate quality flags + OCSP status so cloud
					// discoveries reach the same enrichment as the sensor path.
					// discovery-processor's extractCryptoDetails reads these flags
					// (cert_has_sct, cert_is_ev, cert_known_bad_ca, ocsp_status, …)
					// from the metadata but never computes them; the ACM/handshake
					// path never produced them, so they were silently empty.
					if pems := canonicalCertPEMs(certs); len(pems) > 0 {
						if v := discovery.ClassifyCertChainFromPEMsWith(pems, resolveDNS, platformOCSPClient()); v != nil {
							for k, val := range v.QualityFlags {
								metadata[k] = val
							}
							if v.OCSPStatus != "" {
								metadata["ocsp_status"] = v.OCSPStatus
								if v.OCSPDetail != "" {
									metadata["ocsp_detail"] = v.OCSPDetail
								}
							}
						}
					}
				}
				if verified, ok := cfg["handshake_verified"]; ok {
					metadata["handshake_verified"] = verified
				}

				// The handshake's negotiated key-exchange group and the
				// endpoint's classical / hybrid support. For a TLS 1.3
				// listener the group is the only key exchange there is.
				for _, key := range []string{discovery.MetaKeyExchangeAlgorithm, discovery.MetaKeyExchangeGroupRaw, discovery.MetaTLSSupportsClassicalKex, discovery.MetaTLSSupportsPQCHybridKex, discovery.MetaTLSPQCHybridKexGroup} {
					if v, ok := cfg[key]; ok && v != nil {
						metadata[key] = v
					}
				}

				// The full set of protocol versions the endpoint permits.
				// discovery-processor's extractCryptoDetails reads
				// "tls_versions" into SupportedTLSVersions, which is what
				// inventory-service's hasWeakTLSVersion inspects to flag an
				// endpoint that negotiates TLS 1.2 but still accepts TLS 1.0.
				// It may sit on the config itself or inside its metadata.
				if tv, ok := cfg["tls_versions"]; ok && tv != nil {
					metadata["tls_versions"] = tv
				} else if cfgMeta, ok := cfg["metadata"].(map[string]interface{}); ok {
					if tv, ok := cfgMeta["tls_versions"]; ok && tv != nil {
						metadata["tls_versions"] = tv
					}
				}

				// vpc_id is the third input FindOrCreateCloudSegment takes.
				if vpc := getStringFromMap(map[string]interface{}(device.Metadata), "vpc_id"); vpc != "" {
					metadata["vpc_id"] = vpc
				}

				// Provider-API certificate records (ACM today) join the SAME
				// canonical "certificates" array as the handshake chain, and
				// every entry is labelled with where it came from.
				//
				// They used to be written under `acm_certificates`, which no
				// materializer reads — CLAUDE.md's *Single certificate format*
				// rule names exactly this as the thing not to do. The
				// consequence was not cosmetic: a live ACM certificate reached
				// `assets.metadata` and this row's metadata and nothing else,
				// so it appeared in no certificate inventory and no expiry
				// band, while the certificate that DID materialize was the
				// distribution's default one captured in a handshake.
				//
				// mergeProviderCertificates dedupes by ARN, because
				// EnrichCertificatesWithACM has already folded the ACM facts
				// into an observed certificate wherever it could match one.
				var providerCerts interface{}
				if cfgMeta, ok := cfg["metadata"].(map[string]interface{}); ok {
					providerCerts = cfgMeta["certificates"]
				}
				if certs := mergeProviderCertificates(metadata["certificates"], providerCerts); len(certs) > 0 {
					metadata["certificates"] = certs
				}

				metadataJSON, err := json.Marshal(metadata)
				if err != nil {
					return inserted, fmt.Errorf("marshal cloud discovery metadata: %w", err)
				}

				result, err := tx.ExecContext(ctx, insertQuery,
					cloudDiscoveryReceiptID(tenantID, batchID, protocol, destIP, port, metadataJSON), systemSensorID, tenantID, batchID,
					// Canonical protocol_type spelling — see
					// cryptoparse.NormalizeProtocol.
					cryptoparse.NormalizeProtocol(protocol), destIP, port,
					1.0, metadataJSON, stringPtr(cfgHostname),
					seen, now,
				)
				if err != nil {
					return inserted, fmt.Errorf("persist cloud discovery: %w", err)
				}
				affected, err := result.RowsAffected()
				if err != nil {
					return inserted, err
				}
				inserted += int(affected)
			}
		} else {
			// No crypto configs - create a single default entry. No asset_id /
			// device_id, for the reason stated above.
			metadata := map[string]interface{}{
				"discovery_method": "cloud_api",
				"cloud_provider":   cloudProvider,
				"cloud_region":     cloudRegion,
				"device_type":      device.DeviceType,
				"integration_id":   integrationID.String(),
				"raw_metadata":     device.Metadata,
			}

			metadataJSON, err := json.Marshal(metadata)
			if err != nil {
				return inserted, fmt.Errorf("marshal cloud discovery metadata: %w", err)
			}

			// Protocol/port for the fallback row.
			//
			// This branch used to hardcode TLS:443 for EVERY device with no
			// crypto config, which put an S3 bucket in Inventory as a TLS
			// endpoint on port 443 with no version and no cipher suite. A
			// bucket is not a TLS endpoint; the invented protocol is worse
			// than no protocol, because the UI renders it as a measurement.
			// An at-rest resource therefore carries NO protocol, no port, and
			// an explicit at_rest flag the ingest path reads to mean "this
			// finding describes no endpoint" (DATA_MODEL §2: such an asset
			// simply has no asset_endpoints row).
			protocol, port, atRest := atRestDiscoveryShape(device.DeviceType)
			if atRest {
				metadata["at_rest"] = true
				var remarshalErr error
				metadataJSON, remarshalErr = json.Marshal(metadata)
				if remarshalErr != nil {
					return inserted, fmt.Errorf("marshal at-rest discovery metadata: %w", remarshalErr)
				}
			}

			result, err := tx.ExecContext(ctx, insertQuery,
				cloudDiscoveryReceiptID(tenantID, batchID, protocol, destIP, port, metadataJSON), systemSensorID, tenantID, batchID,
				// Canonical protocol_type spelling; empty stays empty, which
				// is what an at-rest resource honestly has.
				cryptoparse.NormalizeProtocol(protocol), destIP, port,
				0.8, metadataJSON, stringPtr(hostname),
				seen, now,
			)
			if err != nil {
				return inserted, fmt.Errorf("persist cloud discovery: %w", err)
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return inserted, err
			}
			inserted += int(affected)
		}
	}

	log.Printf("WriteSensorDiscoveries: inserted %d sensor_discoveries for batch %s (%d devices)", inserted, batchID, len(devices))
	return inserted, nil
}

// atRestDeviceTypes are the cloud resources whose cryptography is AT REST, not
// in transit: object storage, managed databases and key stores. They have no
// negotiated protocol and no port, so the TLS:443 fallback every other
// crypto-config-less device gets is a fabrication for them.
//
// Listed explicitly per provider rather than inferred, because getting this
// wrong in the other direction (marking a real endpoint as at-rest) would
// suppress a genuine TLS measurement.
// inventoryOnlyDeviceTypes are the enumerated resource kinds that make NO
// cryptographic statement at all — neither a negotiated protocol nor an at-rest
// encryption setting.
//
// They are distinct from atRestDeviceTypes below, and the distinction matters.
// An at-rest resource HAS a cryptographic posture (a bucket's default
// encryption, an RDS instance's storage key) and belongs in the findings
// pipeline carrying `at_rest: true`; it simply has no endpoint. An EC2
// instance, a VPC and a subnet have neither. Putting them through the findings
// pipeline would produce a row per resource that describes no measurement, and
// the pipeline's only honest reading of a protocol-less, at-rest-less row is
// the TLS:443 default, which is a fabrication.
//
// Their inventory identity is written by the identification engine instead
// (cloud_enumeration.go), which is where an asset that is only an asset belongs.
var inventoryOnlyDeviceTypes = map[string]bool{
	DeviceTypeAWSEC2Instance:     true,
	DeviceTypeAWSVPC:             true,
	DeviceTypeAWSSubnet:          true,
	DeviceTypeAzureVM:            true,
	DeviceTypeAzureVNet:          true,
	DeviceTypeAzureSubnet:        true,
	DeviceTypeGCPComputeInstance: true,
	DeviceTypeGCPNetwork:         true,
	DeviceTypeGCPSubnetwork:      true,
}

var atRestDeviceTypes = map[string]bool{
	"aws_s3_bucket":         true,
	"aws_rds_instance":      true,
	"aws_kms":               true,
	"azure_storage_account": true,
	"azure_sql_database":    true,
	"azure_keyvault_key":    true,
	"gcp_storage_bucket":    true,
	"gcp_cloudsql_instance": true,
	"gcp_kms_crypto_key":    true,
}

// atRestDiscoveryShape returns the protocol, port and at-rest flag to record for
// a device with no crypto configuration.
//
// An at-rest resource gets NO PROTOCOL, no port, and an explicit `at_rest: true`
// in the discovery metadata. Everything else keeps the historical TLS:443
// fallback.
//
// The "AT-REST" string this used to write in the protocol column is gone
// (phase 1, sub-task C). It was a sentinel in a column typed for protocols —
// "deliberately NOT a protocol", as its own comment had to keep insisting — and
// every consumer had to know the magic word to avoid materialising a phantom
// TLS endpoint from it. An explicit boolean says the same thing in a field
// whose type matches its meaning, and an empty protocol is independently
// correct: nothing was negotiated, so there is no protocol to name.
// inventory-service still recognises the old string for rows queued before this
// release (findingIsAtRest).
//
// B-22 history, worth keeping: the old comment asserted that inventory-service
// "routes these findings to crypto_applications by their resource_type before
// protocol normalization is ever reached." That is true only for the six device
// types whose collectors write a resource_type metadata key (s3_bucket,
// storage_account, gcs_bucket, rds_instance, sql_database, cloudsql_instance).
// The three key stores below write none, so they fell through to the TLS
// default and were materialized as phantom TLS endpoints. They are now dropped
// rather than fabricated; giving key stores a first-class at-rest posture is
// separate work (crypto_applications models whether a resource's DATA is
// encrypted and whose key, which does not describe a resource that IS the key).
func atRestDiscoveryShape(deviceType string) (protocol string, port int, atRest bool) {
	if atRestDeviceTypes[deviceType] {
		return "", 0, true
	}
	return "TLS", 443, false
}

// canonicalCertPEMs extracts the certificate PEMs from a canonical "certificates"
// array (as carried in a crypto config's metadata), ordered leaf-first by
// chain_order, ready for discovery.ClassifyCertChainFromPEMs. Accepts the
// untyped []interface{} of map[string]interface{} produced by the cloud
// interrogation path.
func canonicalCertPEMs(certs interface{}) []string {
	arr, ok := certs.([]interface{})
	if !ok {
		return nil
	}
	type entry struct {
		pem   string
		order int
	}
	var entries []entry
	for _, c := range arr {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		pem, _ := m["certificate_pem"].(string)
		if pem == "" {
			continue
		}
		order := 0
		switch o := m["chain_order"].(type) {
		case float64:
			order = int(o)
		case int:
			order = o
		}
		entries = append(entries, entry{pem: pem, order: order})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].order < entries[j].order })
	pems := make([]string, 0, len(entries))
	for _, e := range entries {
		pems = append(pems, e.pem)
	}
	return pems
}

// getStringFromMap safely extracts a string value from a map
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// extractCryptoConfigs pulls the crypto configs out of a device's metadata and
// normalises them to the shape every downstream reader assumes: plain JSON
// values ([]interface{} of map[string]interface{}, float64 numbers, no
// pointers).
//
// This is load-bearing, not cosmetic. The discovery functions build
// metadata["crypto_configs"] as a []map[string]interface{} holding *string /
// *int fields, and this device value is passed to WriteSensorDiscoveries
// IN MEMORY — it never round-trips through Postgres. The old
// `.([]interface{})` type assertion therefore always failed, so EVERY cloud
// discovery took the "no crypto configs" branch: one bare TLS/443 row per
// device with no protocol version, no cipher suite and no certificates. And
// even had the slice asserted, getStringFromMap would have returned "" for the
// *string protocol_version. Marshalling through JSON here reproduces exactly
// what a database round-trip would have produced, so the reader assumptions
// downstream (float64 ports, []interface{} certificates) hold.
func extractCryptoConfigs(metadata map[string]interface{}) []map[string]interface{} {
	if metadata == nil {
		return nil
	}
	raw, ok := metadata["crypto_configs"]
	if !ok || raw == nil {
		return nil
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		log.Printf("Warning: failed to normalize crypto_configs: %v", err)
		return nil
	}
	var configs []map[string]interface{}
	if err := json.Unmarshal(encoded, &configs); err != nil {
		log.Printf("Warning: failed to decode crypto_configs: %v", err)
		return nil
	}

	out := make([]map[string]interface{}, 0, len(configs))
	for _, cfg := range configs {
		if cfg != nil {
			out = append(out, cfg)
		}
	}
	return out
}

// cloudRegionForDevice resolves the region to stamp on a device's discoveries.
//
// Every regional discovery path already records metadata["region"]. Two AWS
// resource kinds are genuinely global and have no region: CloudFront
// distributions and (for the purposes of the bucket namespace) nothing else —
// S3 buckets DO have a home region and DiscoverS3BucketEncryption now resolves
// it per bucket. For the global ones we write the literal "global" rather than
// the integration's default region, which would claim the resource lives
// somewhere it does not.
func cloudRegionForDevice(device models.Device) string {
	if device.Metadata != nil {
		if region := getStringFromMap(map[string]interface{}(device.Metadata), "region"); region != "" {
			return region
		}
	}
	switch device.DeviceType {
	case "aws_cloudfront":
		return "global"
	}
	return ""
}

// Helper functions
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// upsertDeviceAsset resolves a discovered cloud resource to an asset and
// configures management on it, replacing the old
// findExistingDevice/insertDevice/updateDevice trio.
//
// Those three were the fourth of the four ad hoc dedupe keys ADR-0002 D3
// catalogues: they matched on `device_type` AND (hostname OR one of four
// metadata id fields), a key nothing else in the platform used. A bucket the
// cloud collector found and the same bucket named in a CMDB pull could never
// resolve to one row, and neither could a load balancer the sensor also saw on
// the wire.
//
// The engine's key is the provider's own resource id (cloud_resource_id), which
// is the strongest identifier a cloud resource ever has and sits at the top of
// the precedence list for every cloud class. resourceID is the collector's
// ARN / self-link / api id / distribution id; the device's metadata is searched
// as a fallback.
//
// On return device.ID is the ASSET id, so the caller's devices slice — which
// WriteSensorDiscoveries and the job result both read — carries asset ids.
func (s *CloudDiscoveryService) upsertDeviceAsset(ctx context.Context, device *models.Device, resourceID string) error {
	// No cloud network ref: the crypto/at-rest collectors record buckets, key
	// stores and load balancers, none of which the address-scoping question is
	// asked about. Enumeration is the one path that has one.
	//
	// The extra hook writes the resource's cloud ACCOUNT and REGION, which
	// enumeration already writes for instances, VPCs and subnets and this path
	// did not write at all — so a bucket or a distribution had nothing to be
	// grouped under on the map ( slice D). Built in cloud_enumeration.go
	// from the same two helpers enumeration uses, and nil when there is nothing
	// honest to write.
	return s.upsertDeviceAssetWith(ctx, device, resourceID, "", s.cloudScopeExtra(ctx, device))
}

// upsertDeviceAssetWith is upsertDeviceAsset with one more thing to do inside
// the SAME transaction as the resolution.
//
// `extra` is where an enumerated resource's facts and class attributes are
// written (cloud_enumeration.go). They belong in this transaction and not a
// later one: an asset created here whose facts landed separately and failed
// would keep its identity and lose its placement, and no later run would repair
// that — the next observation MATCHES the asset that exists and never takes the
// create path again.
//
// `extra` is NOT called on the contested outcome, because there is no asset to
// write about.
func (s *CloudDiscoveryService) upsertDeviceAssetWith(
	ctx context.Context,
	device *models.Device,
	resourceID string,
	cloudNetworkRef string,
	extra func(r *pgidentity.Repository, assetID uuid.UUID) error,
) error {
	now := device.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	receipt := device.ID.String()
	if device.ID == uuid.Nil {
		receipt = uuid.NewString()
	}

	// Which integration read this resource is PROVENANCE, and it used to be
	// recorded only as `asset_credentials.credential_id`. No credentials row is
	// written on this path any more (see the `Unmanaged` block below), so the
	// fact moves to the asset's own metadata rather than being dropped: it is
	// "this asset was read through integration X", not a credential reference,
	// and metadata is where the rest of the device's pipeline provenance lives.
	// Recorded BEFORE the observation is sealed so the contested path's replay
	// carries it too.
	if device.CredentialID != nil {
		if device.Metadata == nil {
			device.Metadata = models.JSONB{}
		}
		if _, ok := device.Metadata[cloudIntegrationIDKey]; !ok {
			device.Metadata[cloudIntegrationIDKey] = device.CredentialID.String()
		}
	}

	obs, err := s.devices.deviceObservation(ctx, device.TenantID, deviceObservationInput{
		DeviceType:      device.DeviceType,
		Hostname:        derefStr(device.Hostname),
		IPAddress:       derefStr(device.IPAddress),
		ManagementURL:   derefStr(device.ManagementURL),
		SerialNumber:    derefStr(device.SerialNumber),
		CloudResourceID: firstNonEmpty(resourceID, cloudResourceIDFromMetadata(device.Metadata)),
		CloudNetworkRef: cloudNetworkRef,
		DiscoveryMethod: device.DiscoveryMethod,
		Source:          cloudSource(device.Vendor),
		Admission:       identity.AdmissionEvidence{Authoritative: true, ReceiptID: receipt},
		ObservedAt:      now,
	})
	if err != nil {
		recordCloudOutcome(ctx, resourceID, identity.Resolution{}, false, err)
		return err
	}

	// NOTHING discovered through a cloud API is a managed device. Not a subnet,
	// not a VPC, not an EC2 instance, not a bucket, not a key store, not a load
	// balancer — nothing that reaches this funnel.
	//
	// This used to read "every cloud resource reached through an integration IS
	// managed", on the reasoning that the integration's credentials are what
	// asset_management records. That conflated two different questions, and the
	// owner's criterion for the Devices page settles it: the page lists
	// **API-accessible interfaces we pull inventory from**, not everything we
	// could conceivably hold a credential for. By that test a subnet was never a
	// device (there is no interface), and neither is an EC2 instance — an
	// instance is onboarded through the DEVICE AGENT, not through cloud
	// enumeration, so a management row minted here describes an onboarding that
	// did not happen. The rows it did mint claimed `connection_status =
	// 'connected'` for a connection nothing ever made, and the Devices page
	// greyed out every action on them because it already knew a cloud-discovered
	// row is not interrogable.
	//
	// What is suppressed is the management row and the credentials row. These
	// resources remain first-class ASSETS: identity, facts, class, class
	// attributes, endpoints and `contains` edges are all unchanged, and the
	// Inventory lenses are where they belong.
	//
	// **This is scoped to the cloud path on purpose, and that scoping is a
	// requirement rather than an implementation detail.** A cloud-hosted
	// appliance — a Palo Alto or FortiGate running as an instance — must still
	// be addable deliberately, with credentials, and interrogable. That happens
	// through DeviceService.CreateDevice, which does not set this flag and is
	// pinned by TestIntegration_ManualCloudApplianceKeepsManagement. Moving the
	// suppression down into applyDeviceFields, or keying it on the
	// client-settable `discovery_method` string, would take that away.
	fields := deviceFieldUpdate{
		DeviceType:       device.DeviceType,
		Hostname:         device.Hostname,
		IPAddress:        device.IPAddress,
		ManagementURL:    device.ManagementURL,
		Vendor:           device.Vendor,
		Model:            device.Model,
		FirmwareVersion:  device.FirmwareVersion,
		SerialNumber:     device.SerialNumber,
		ConnectionStatus: nonEmptyPtr(device.ConnectionStatus),
		CredentialID:     device.CredentialID,
		Metadata:         device.Metadata,
		Tags:             device.Tags,
		DiscoveryMethod:  device.DiscoveryMethod,
		CreateManagement: true,
		Unmanaged:        true,
	}

	pending := false
	res, err := s.devices.resolveObservation(ctx, obs, func(r *pgidentity.Repository, res identity.Resolution) error {
		if res.Asset.Zero() {
			// Every identifier this resource carries belongs to another asset.
			// A merge proposal is waiting in Approvals; creating a third asset
			// to hang the management row off would be the auto-merge ADR-0002
			// D5 forbids, from the other side.
			//
			// nil, NOT an error — see DeviceIdentityContestedError. The proposal
			// was written in this transaction and an error here would erase it.
			if err := s.devices.retainManagement(ctx, r, obs, res, fields); err != nil {
				return err
			}
			return s.retainCloudContext(ctx, r, obs, res, device)
		}
		assetID, parseErr := uuid.Parse(res.Asset.ID)
		if parseErr != nil {
			return fmt.Errorf("identification returned an unusable asset id %q: %w", res.Asset.ID, parseErr)
		}
		if err := r.Tx().QueryRowContext(ctx, `SELECT asset_status='pending_approval' FROM assets WHERE tenant_id=$1 AND id=$2`, device.TenantID, assetID).Scan(&pending); err != nil {
			return err
		}
		device.ID = assetID
		if err := s.devices.applyDeviceFields(ctx, r, device.TenantID, assetID, fields); err != nil {
			return err
		}
		if extra == nil {
			return nil
		}
		return extra(r, assetID)
	})
	recordCloudOutcome(ctx, firstNonEmpty(resourceID, cloudResourceIDFromMetadata(device.Metadata)), res, pending, err)
	if err != nil {
		return fmt.Errorf("failed to record cloud resource: %w", err)
	}
	if res.Asset.Zero() {
		if res.ObservationID != "" {
			return &identity.RetainedObservation{Result: res.IngestResult()}
		}
		return contestedFrom(res)
	}
	return nil
}

// cloudSource is the provenance of a cloud collector's observation: an ACTIVE
// measurement, because the provider's API answered about its own resource.
// `cloud:<provider>` is the producer shape ADR-0003 D3 names and the string the
// `observation` query target's `source` facet matches on.
func cloudSource(vendor *string) identity.Source {
	ref := "cloud"
	provider := cloudProviderForDevice(models.Device{Vendor: vendor})
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(derefStr(vendor)))
	}
	if provider != "" {
		ref = "cloud:" + provider
	}
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: identity.ModeActive}
}

// nonEmptyPtr returns a pointer to s, or nil when s is empty — the difference
// between "set this column" and "this call is not about that column".
func nonEmptyPtr(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// DiscoverAzureResources discovers Azure resources and creates devices
func (s *CloudDiscoveryService) DiscoverAzureResources(ctx context.Context, tenantID uuid.UUID, integrationID uuid.UUID, resourceTypes []string, resourceGroups []string) ([]models.Device, error) {
	if _, err := authorizeCloudIntegration(ctx, s.bypassDB, tenantID, integrationID, "azure"); err != nil {
		return nil, fmt.Errorf("azure integration not authorized: %w", err)
	}

	// Create Azure client
	azureClient, err := azureclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	var discoveredDevices []models.Device

	// Discover resources by type
	for _, resourceType := range resourceTypes {
		switch resourceType {
		case "application_gateway", "appgw":
			devices, err := s.discoverApplicationGateways(ctx, tenantID, azureClient, integrationID, resourceGroups)
			if err != nil {
				return nil, fmt.Errorf("failed to discover Application Gateways: %w", err)
			}
			discoveredDevices = append(discoveredDevices, devices...)
		case "load_balancer", "lb":
			devices, err := s.discoverAzureLoadBalancers(ctx, tenantID, azureClient, integrationID, resourceGroups)
			if err != nil {
				return nil, fmt.Errorf("failed to discover Load Balancers: %w", err)
			}
			discoveredDevices = append(discoveredDevices, devices...)
		case "key_vault", "keyvault", "kms":
			devices, err := s.discoverAzureKeyVaultKeys(ctx, tenantID, integrationID, azureClient)
			if err != nil {
				log.Printf("Warning: Azure Key Vault discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		case "storage_account", "storage", "blob":
			storageService := NewStorageEncryptionService(s.db, s.bypassDB, s.masterKey)
			devices, err := storageService.DiscoverAzureStorageAccounts(ctx, tenantID, azureClient)
			if err != nil {
				log.Printf("Warning: Azure Storage account discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		case "sql_database", "sql", "cloudsql":
			storageService := NewStorageEncryptionService(s.db, s.bypassDB, s.masterKey)
			devices, err := storageService.DiscoverAzureSQLDatabases(ctx, tenantID, azureClient)
			if err != nil {
				log.Printf("Warning: Azure SQL database discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		}
	}

	return discoveredDevices, nil
}

// discoverAzureKeyVaultKeys discovers Key Vault keys, persists them to the
// kms_keys table (provider "azure"), and returns device records for visibility —
// mirroring the AWS/GCP KMS paths.
func (s *CloudDiscoveryService) discoverAzureKeyVaultKeys(ctx context.Context, tenantID uuid.UUID, integrationID uuid.UUID, azClient *azureclient.Client) ([]models.Device, error) {
	kmsService := NewKMSDiscoveryService(s.db, s.bypassDB, s.masterKey)

	findings, err := kmsService.DiscoverAzureKeyVaultKeys(ctx, tenantID, integrationID, azClient)
	if err != nil {
		return nil, fmt.Errorf("discovering Azure Key Vault keys: %w", err)
	}

	if err := kmsService.StoreKMSKeyFindings(ctx, tenantID, integrationID, "azure", findings); err != nil {
		log.Printf("Warning: failed to store Azure Key Vault key findings: %v", err)
	}

	var devices []models.Device
	for _, f := range findings {
		metadata := keyStoreDeviceMetadata(f, "subscription_id")
		devices = append(devices, models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "azure_keyvault_key",
			Vendor:           stringPtr("Microsoft"),
			Hostname:         stringPtr(resourceShortName(f.KeyID)),
			DiscoveryMethod:  "cloud_api",
			ConnectionStatus: "discovered",
			Metadata:         models.JSONB(metadata),
		})
	}
	return devices, nil
}

// discoverApplicationGateways discovers Azure Application Gateways
func (s *CloudDiscoveryService) discoverApplicationGateways(ctx context.Context, tenantID uuid.UUID, azureClient *azureclient.Client, integrationID uuid.UUID, resourceGroups []string) ([]models.Device, error) {
	var devices []models.Device

	appGwClient, err := azureClient.GetApplicationGatewayClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Application Gateway client: %w", err)
	}

	// List all Application Gateways across all resource groups
	pager := appGwClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Application Gateways: %w", err)
		}

		for _, gw := range page.Value {
			if gw == nil || gw.ID == nil {
				continue
			}

			// Filter by resource groups if specified
			if len(resourceGroups) > 0 {
				gwResourceGroup := extractResourceGroupFromID(*gw.ID)
				matched := false
				for _, rg := range resourceGroups {
					if strings.EqualFold(gwResourceGroup, rg) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			// Check if gateway has HTTPS listeners (TLS)
			hasTLS := false
			var tlsConfigs []map[string]interface{}
			if gw.Properties != nil && gw.Properties.HTTPListeners != nil {
				for _, listener := range gw.Properties.HTTPListeners {
					if listener.Properties != nil && listener.Properties.Protocol != nil {
						if *listener.Properties.Protocol == "Https" {
							hasTLS = true
							// Extract TLS policy if available
							if gw.Properties.SSLPolicy != nil {
								tlsConfig := map[string]interface{}{
									"protocol":         "TLS",
									"protocol_version": getPtrValue(gw.Properties.SSLPolicy.MinProtocolVersion),
									"policy_type":      getPtrValue(gw.Properties.SSLPolicy.PolicyType),
									"policy_name":      getPtrValue(gw.Properties.SSLPolicy.PolicyName),
									"port":             443,
								}
								if gw.Properties.SSLPolicy.CipherSuites != nil {
									cipherSuites := make([]string, 0, len(gw.Properties.SSLPolicy.CipherSuites))
									for _, cs := range gw.Properties.SSLPolicy.CipherSuites {
										if cs != nil {
											cipherSuites = append(cipherSuites, string(*cs))
										}
									}
									tlsConfig["cipher_suites"] = cipherSuites
									if len(cipherSuites) > 0 {
										tlsConfig["cipher_suite"] = cipherSuites[0]
									}
								}
								tlsConfigs = append(tlsConfigs, tlsConfig)
							}
							break
						}
					}
				}
			}

			if !hasTLS {
				continue // Skip gateways without TLS
			}

			// Build metadata
			metadata := map[string]interface{}{
				"azure_resource_id":  *gw.ID,
				"resource_group":     extractResourceGroupFromID(*gw.ID),
				"subscription_id":    azureClient.GetSubscriptionID(),
				"location":           getPtrValue(gw.Location),
				"sku":                getGatewaySkuInfo(gw),
				"provisioning_state": getProvisioningState(gw),
			}

			hostname := ""
			if gw.Name != nil {
				hostname = *gw.Name + ".azure.com"
			}

			// Perform TLS handshake against the Application Gateway if it has a public IP
			if hostname != "" && len(tlsConfigs) > 0 {
				handshakeResult, hsErr := cloudTLSHandshake(ctx, hostname, 443)
				if hsErr != nil {
					log.Printf("Warning: TLS handshake error for Azure App Gateway %s: %v", hostname, hsErr)
				} else if handshakeResult != nil && handshakeResult.Success {
					// Enrich the first TLS config with handshake data
					tlsConfigs[0]["protocol_version"] = handshakeResult.TLSVersion
					tlsConfigs[0]["cipher_suite"] = handshakeResult.CipherSuite
					applyHandshakeKeyExchange(tlsConfigs[0], handshakeResult)
					tlsConfigs[0]["certificates"] = handshakeResult.Certificates
					tlsConfigs[0]["handshake_verified"] = true
				} else if handshakeResult != nil {
					tlsConfigs[0]["handshake_verified"] = false
					tlsConfigs[0]["handshake_error"] = handshakeResult.Error
					log.Printf("TLS handshake skipped for Azure App Gateway %s: %s", hostname, handshakeResult.Error)
				}
			}

			if len(tlsConfigs) > 0 {
				metadata["crypto_configs"] = tlsConfigs
			}

			// Extract public IP if available
			ipAddress := ""
			if gw.Properties != nil && gw.Properties.FrontendIPConfigurations != nil {
				for _, ipConfig := range gw.Properties.FrontendIPConfigurations {
					if ipConfig.Properties != nil && ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
						// Note: Would need to resolve the public IP address ID to get actual IP
						// For now, mark as having public IP
						metadata["has_public_ip"] = true
						break
					}
				}
			}

			device := models.Device{
				ID:               uuid.New(),
				TenantID:         tenantID,
				DeviceType:       "azure_application_gateway",
				Vendor:           stringPtr("Microsoft"),
				Hostname:         stringPtr(hostname),
				IPAddress:        stringPtrOrNil(ipAddress),
				DiscoveryMethod:  "cloud_api",
				CredentialID:     &integrationID,
				ConnectionStatus: "discovered",
				Metadata:         models.JSONB(metadata),
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			}

			if err := s.upsertDeviceAsset(ctx, &device, *gw.ID); err != nil {
				log.Printf("Warning: failed to record azure_application_gateway %s: %v", hostname, err)
				continue
			}

			devices = append(devices, device)
		}
	}

	return devices, nil
}

// discoverAzureLoadBalancers discovers Azure Load Balancers
func (s *CloudDiscoveryService) discoverAzureLoadBalancers(ctx context.Context, tenantID uuid.UUID, azureClient *azureclient.Client, integrationID uuid.UUID, resourceGroups []string) ([]models.Device, error) {
	var devices []models.Device

	lbClient, err := azureClient.GetLoadBalancerClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Load Balancer client: %w", err)
	}

	// List all Load Balancers
	pager := lbClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Load Balancers: %w", err)
		}

		for _, lb := range page.Value {
			if lb == nil || lb.ID == nil {
				continue
			}

			// Filter by resource groups if specified
			if len(resourceGroups) > 0 {
				lbResourceGroup := extractResourceGroupFromID(*lb.ID)
				matched := false
				for _, rg := range resourceGroups {
					if strings.EqualFold(lbResourceGroup, rg) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			// Check if load balancer has HTTPS probes or rules (indicating TLS usage)
			hasTLS := false
			if lb.Properties != nil {
				// Check for HTTPS probes
				if lb.Properties.Probes != nil {
					for _, probe := range lb.Properties.Probes {
						if probe.Properties != nil && probe.Properties.Protocol != nil {
							if *probe.Properties.Protocol == "Https" {
								hasTLS = true
								break
							}
						}
					}
				}
				// Check for port 443 in frontend configurations
				if lb.Properties.FrontendIPConfigurations != nil {
					for _, feConfig := range lb.Properties.FrontendIPConfigurations {
						if feConfig.Properties != nil && feConfig.Properties.InboundNatRules != nil {
							for _, rule := range feConfig.Properties.InboundNatRules {
								if rule.ID != nil && strings.Contains(*rule.ID, "443") {
									hasTLS = true
									break
								}
							}
						}
					}
				}
			}

			// Build metadata
			metadata := map[string]interface{}{
				"azure_resource_id": *lb.ID,
				"resource_group":    extractResourceGroupFromID(*lb.ID),
				"subscription_id":   azureClient.GetSubscriptionID(),
				"location":          getPtrValue(lb.Location),
				"has_tls":           hasTLS,
			}

			if lb.SKU != nil {
				metadata["sku_name"] = getPtrValue(lb.SKU.Name)
				metadata["sku_tier"] = getPtrValue(lb.SKU.Tier)
			}

			hostname := ""
			if lb.Name != nil {
				hostname = *lb.Name + ".azure.com"
			}

			device := models.Device{
				ID:               uuid.New(),
				TenantID:         tenantID,
				DeviceType:       "azure_load_balancer",
				Vendor:           stringPtr("Microsoft"),
				Hostname:         stringPtr(hostname),
				DiscoveryMethod:  "cloud_api",
				CredentialID:     &integrationID,
				ConnectionStatus: "discovered",
				Metadata:         models.JSONB(metadata),
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
			}

			if err := s.upsertDeviceAsset(ctx, &device, *lb.ID); err != nil {
				log.Printf("Warning: failed to record azure_load_balancer %s: %v", hostname, err)
				continue
			}

			devices = append(devices, device)
		}
	}

	return devices, nil
}

// DiscoverGCPResources discovers GCP resources and creates devices
func (s *CloudDiscoveryService) DiscoverGCPResources(ctx context.Context, tenantID uuid.UUID, integrationID uuid.UUID, resourceTypes []string) ([]models.Device, error) {
	if _, err := authorizeCloudIntegration(ctx, s.bypassDB, tenantID, integrationID, "gcp"); err != nil {
		return nil, fmt.Errorf("GCP integration not authorized: %w", err)
	}

	gcpCli, err := gcpclient.NewClient(ctx, s.bypassDB, integrationID, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP client: %w", err)
	}

	var discoveredDevices []models.Device

	var wantLB, wantSSL bool
	for _, rt := range resourceTypes {
		switch rt {
		case "load_balancer":
			wantLB = true
		case "ssl_proxy":
			wantSSL = true
		}
	}

	var sharedForwardingRules map[string]gcpclient.ForwardingRule
	if wantLB && wantSSL {
		m, err := s.buildGCPForwardingRuleMap(ctx, gcpCli)
		if err != nil {
			log.Printf("Warning: failed to list GCP forwarding rules: %v", err)
			sharedForwardingRules = map[string]gcpclient.ForwardingRule{}
		} else {
			sharedForwardingRules = m
		}
	}

	for _, resourceType := range resourceTypes {
		switch resourceType {
		case "load_balancer":
			devices, err := s.discoverGCPLoadBalancers(ctx, tenantID, gcpCli, integrationID, sharedForwardingRules)
			if err != nil {
				return nil, fmt.Errorf("failed to discover GCP load balancers: %w", err)
			}
			discoveredDevices = append(discoveredDevices, devices...)
		case "ssl_proxy":
			devices, err := s.discoverGCPSSLProxies(ctx, tenantID, gcpCli, integrationID, sharedForwardingRules)
			if err != nil {
				return nil, fmt.Errorf("failed to discover GCP SSL proxies: %w", err)
			}
			discoveredDevices = append(discoveredDevices, devices...)
		case "kms", "cloudkms":
			devices, err := s.discoverGCPKMSKeys(ctx, tenantID, integrationID, gcpCli)
			if err != nil {
				log.Printf("Warning: GCP KMS discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		case "storage", "gcs", "cloud_storage":
			storageService := NewStorageEncryptionService(s.db, s.bypassDB, s.masterKey)
			devices, err := storageService.DiscoverGCPStorageBuckets(ctx, tenantID, gcpCli)
			if err != nil {
				log.Printf("Warning: GCP Cloud Storage discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		case "cloudsql", "sql", "cloud_sql":
			storageService := NewStorageEncryptionService(s.db, s.bypassDB, s.masterKey)
			devices, err := storageService.DiscoverGCPCloudSQLInstances(ctx, tenantID, gcpCli)
			if err != nil {
				log.Printf("Warning: GCP Cloud SQL discovery failed: %v", err)
			} else {
				discoveredDevices = append(discoveredDevices, devices...)
			}
		}
	}

	return discoveredDevices, nil
}

// discoverGCPKMSKeys discovers Cloud KMS keys, persists them to the kms_keys
// table (provider "gcp"), and returns device records for visibility in the
// device list — mirroring the AWS discoverKMSKeys path.
func (s *CloudDiscoveryService) discoverGCPKMSKeys(ctx context.Context, tenantID uuid.UUID, integrationID uuid.UUID, gcpCli *gcpclient.Client) ([]models.Device, error) {
	kmsService := NewKMSDiscoveryService(s.db, s.bypassDB, s.masterKey)

	findings, err := kmsService.DiscoverGCPKMSKeys(ctx, tenantID, integrationID, gcpCli)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS key discovery failed: %w", err)
	}

	if err := kmsService.StoreKMSKeyFindings(ctx, tenantID, integrationID, "gcp", findings); err != nil {
		log.Printf("Warning: failed to store GCP KMS key findings: %v", err)
	}

	var devices []models.Device
	for _, f := range findings {
		metadata := keyStoreDeviceMetadata(f, "project_id")
		devices = append(devices, models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "gcp_kms_crypto_key",
			Vendor:           stringPtr("Google Cloud"),
			Hostname:         stringPtr(resourceShortName(f.KeyID)),
			DiscoveryMethod:  "cloud_api",
			ConnectionStatus: "discovered",
			Metadata:         models.JSONB(metadata),
		})
	}
	return devices, nil
}

// keyStoreDeviceMetadata is the device metadata for one managed key from a
// cloud key store (Azure Key Vault, GCP KMS). accountKey is what the provider
// calls the account the key lives in — `subscription_id` for Azure,
// `project_id` for GCP — and is the only thing that differed between the two
// hand-written copies this replaces.
//
// It exists to be TESTABLE. The identity line below is the whole point of the
// function, and while it sat inline inside a method that needs a live provider
// client, deleting it turned nothing red.
//
// AWS KMS does not use this: its collector writes a real `arn` (plus origin,
// region and aliases), which identity.CloudResourceIDKeys already reads.
func keyStoreDeviceMetadata(f KMSKeyFinding, accountKey string) map[string]interface{} {
	return map[string]interface{}{
		// The key's own identifier, under the canonical key.
		//
		// `key_id` carries the same value for these two providers, and it is
		// deliberately NOT in identity.CloudResourceIDKeys: that list is
		// consulted for every finding, cloud or not, and `key_id` is a generic
		// crypto-posture field name (shared/redact lists it as exactly that).
		// For AWS it is also a bare key UUID rather than a namespaced id.
		//
		// Without this the vault key was identified by its SHORT NAME alone —
		// resourceShortName of the key URI — which collides between two vaults
		// or two key rings holding a key of the same name.
		"cloud_resource_id": f.KeyARN,
		"key_id":            f.KeyID,
		"resource_name":     f.KeyARN,
		"key_state":         f.KeyState,
		"key_usage":         f.KeyUsage,
		"key_spec":          f.KeySpec,
		"protection_level":  f.Origin,
		"rotation_enabled":  f.RotationEnabled,
		"location":          f.Region,
		accountKey:          f.AccountID,
		"creation_date":     f.CreationDate,
	}
}

// resourceShortName returns the last path segment of a cloud resource name/ID.
func resourceShortName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 && i < len(name)-1 {
		return name[i+1:]
	}
	return name
}

// discoverGCPLoadBalancers discovers GCP HTTPS load balancers (target HTTPS proxies + forwarding rules).
// If prebuiltForwardingRules is non-nil, it is used instead of listing forwarding rules again.
func (s *CloudDiscoveryService) discoverGCPLoadBalancers(ctx context.Context, tenantID uuid.UUID, gcpCli *gcpclient.Client, integrationID uuid.UUID, prebuiltForwardingRules map[string]gcpclient.ForwardingRule) ([]models.Device, error) {
	var devices []models.Device

	// List target HTTPS proxies — these represent HTTPS load balancers
	proxies, err := gcpCli.ListTargetHTTPSProxies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list target HTTPS proxies: %w", err)
	}

	var forwardingRulesByTarget map[string]gcpclient.ForwardingRule
	if prebuiltForwardingRules != nil {
		forwardingRulesByTarget = prebuiltForwardingRules
	} else {
		forwardingRulesByTarget, err = s.buildGCPForwardingRuleMap(ctx, gcpCli)
		if err != nil {
			log.Printf("Warning: failed to list GCP forwarding rules: %v", err)
			forwardingRulesByTarget = map[string]gcpclient.ForwardingRule{}
		}
	}

	for _, proxy := range proxies {
		device, err := s.processGCPHTTPSProxy(ctx, tenantID, gcpCli, integrationID, proxy, forwardingRulesByTarget)
		if err != nil {
			log.Printf("Warning: failed to process GCP HTTPS proxy %s: %v", proxy.Name, err)
			continue
		}
		if device != nil {
			devices = append(devices, *device)
		}
	}

	return devices, nil
}

// discoverGCPSSLProxies discovers GCP SSL proxy load balancers.
// If prebuiltForwardingRules is non-nil, it is used instead of listing forwarding rules again.
func (s *CloudDiscoveryService) discoverGCPSSLProxies(ctx context.Context, tenantID uuid.UUID, gcpCli *gcpclient.Client, integrationID uuid.UUID, prebuiltForwardingRules map[string]gcpclient.ForwardingRule) ([]models.Device, error) {
	var devices []models.Device

	proxies, err := gcpCli.ListTargetSSLProxies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list target SSL proxies: %w", err)
	}

	var forwardingRulesByTarget map[string]gcpclient.ForwardingRule
	if prebuiltForwardingRules != nil {
		forwardingRulesByTarget = prebuiltForwardingRules
	} else {
		forwardingRulesByTarget, err = s.buildGCPForwardingRuleMap(ctx, gcpCli)
		if err != nil {
			log.Printf("Warning: failed to list GCP forwarding rules: %v", err)
			forwardingRulesByTarget = map[string]gcpclient.ForwardingRule{}
		}
	}

	for _, proxy := range proxies {
		device, err := s.processGCPSSLProxy(ctx, tenantID, gcpCli, integrationID, proxy, forwardingRulesByTarget)
		if err != nil {
			log.Printf("Warning: failed to process GCP SSL proxy %s: %v", proxy.Name, err)
			continue
		}
		if device != nil {
			devices = append(devices, *device)
		}
	}

	return devices, nil
}

// processGCPHTTPSProxy processes a single target HTTPS proxy into a device with crypto configs
func (s *CloudDiscoveryService) processGCPHTTPSProxy(
	ctx context.Context,
	tenantID uuid.UUID,
	gcpCli *gcpclient.Client,
	integrationID uuid.UUID,
	proxy gcpclient.TargetHTTPSProxy,
	forwardingRulesByTarget map[string]gcpclient.ForwardingRule,
) (*models.Device, error) {
	metadata := map[string]interface{}{
		"gcp_resource_id": proxy.SelfLink,
		"proxy_type":      "target_https_proxy",
		"project_id":      gcpCli.GetProjectID(),
		"url_map":         proxy.URLMap,
	}

	// Get SSL policy details
	var tlsConfigs []map[string]interface{}
	if proxy.SSLPolicy != "" {
		policy, err := gcpCli.GetSSLPolicy(ctx, proxy.SSLPolicy)
		if err != nil {
			log.Printf("Warning: failed to get SSL policy for %s: %v", proxy.Name, err)
		} else {
			tlsConfig := buildGCPTLSConfig(policy, "HTTPS")
			tlsConfigs = append(tlsConfigs, tlsConfig)
			metadata["ssl_policy_name"] = policy.Name
			metadata["ssl_policy_profile"] = policy.Profile
		}
	} else {
		// No explicit SSL policy means GCP default (COMPATIBLE profile, TLS 1.0 min)
		tlsConfigs = append(tlsConfigs, map[string]interface{}{
			"protocol":         "HTTPS",
			"protocol_version": "TLS 1.0",
			"port":             443,
			"metadata": map[string]interface{}{
				"ssl_policy": "GCP Default (COMPATIBLE)",
			},
		})
	}

	// Get certificate information
	if len(proxy.SSLCertificates) > 0 {
		certInfos := s.fetchGCPCertificateInfo(ctx, gcpCli, proxy.SSLCertificates)
		if len(certInfos) > 0 {
			metadata["certificates"] = certInfos
		}
	}

	// Find the forwarding rule to get the public IP
	hostname := proxy.Name + ".lb." + gcpCli.GetProjectID() + ".gcp"
	ipAddress := ""
	if fwRule, ok := forwardingRulesByTarget[proxy.SelfLink]; ok {
		ipAddress = fwRule.IPAddress
		metadata["forwarding_rule"] = fwRule.Name
		metadata["load_balancing_scheme"] = fwRule.LoadBalancingScheme
		metadata["port_range"] = fwRule.PortRange
		if ipAddress != "" {
			hostname = ipAddress
		}
	}

	// Perform TLS handshake if we have a reachable IP
	if ipAddress != "" && len(tlsConfigs) > 0 {
		handshakeResult, hsErr := cloudTLSHandshake(ctx, ipAddress, 443)
		if hsErr != nil {
			log.Printf("Warning: TLS handshake error for GCP LB %s (%s): %v", proxy.Name, ipAddress, hsErr)
		} else if handshakeResult != nil && handshakeResult.Success {
			tlsConfigs[0]["protocol_version"] = handshakeResult.TLSVersion
			tlsConfigs[0]["cipher_suite"] = handshakeResult.CipherSuite
			applyHandshakeKeyExchange(tlsConfigs[0], handshakeResult)
			tlsConfigs[0]["certificates"] = handshakeResult.Certificates
			tlsConfigs[0]["handshake_verified"] = true
		} else if handshakeResult != nil {
			tlsConfigs[0]["handshake_verified"] = false
			tlsConfigs[0]["handshake_error"] = handshakeResult.Error
			log.Printf("TLS handshake skipped for GCP LB %s: %s", proxy.Name, handshakeResult.Error)
		}
	}

	if len(tlsConfigs) > 0 {
		metadata["crypto_configs"] = tlsConfigs
	}

	device := models.Device{
		ID:               uuid.New(),
		TenantID:         tenantID,
		DeviceType:       "gcp_https_load_balancer",
		Vendor:           stringPtr("Google Cloud"),
		Hostname:         stringPtr(hostname),
		IPAddress:        stringPtrOrNil(ipAddress),
		DiscoveryMethod:  "cloud_api",
		CredentialID:     &integrationID,
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB(metadata),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := s.upsertDeviceAsset(ctx, &device, proxy.SelfLink); err != nil {
		return nil, fmt.Errorf("failed to record gcp_https_load_balancer: %w", err)
	}

	return &device, nil
}

// processGCPSSLProxy processes a single target SSL proxy into a device with crypto configs
func (s *CloudDiscoveryService) processGCPSSLProxy(
	ctx context.Context,
	tenantID uuid.UUID,
	gcpCli *gcpclient.Client,
	integrationID uuid.UUID,
	proxy gcpclient.TargetSSLProxy,
	forwardingRulesByTarget map[string]gcpclient.ForwardingRule,
) (*models.Device, error) {
	metadata := map[string]interface{}{
		"gcp_resource_id": proxy.SelfLink,
		"proxy_type":      "target_ssl_proxy",
		"project_id":      gcpCli.GetProjectID(),
		"backend_service": proxy.Service,
	}

	var tlsConfigs []map[string]interface{}
	if proxy.SSLPolicy != "" {
		policy, err := gcpCli.GetSSLPolicy(ctx, proxy.SSLPolicy)
		if err != nil {
			log.Printf("Warning: failed to get SSL policy for %s: %v", proxy.Name, err)
		} else {
			tlsConfig := buildGCPTLSConfig(policy, "TLS")
			tlsConfigs = append(tlsConfigs, tlsConfig)
			metadata["ssl_policy_name"] = policy.Name
			metadata["ssl_policy_profile"] = policy.Profile
		}
	} else {
		tlsConfigs = append(tlsConfigs, map[string]interface{}{
			"protocol":         "TLS",
			"protocol_version": "TLS 1.0",
			"port":             443,
			"metadata": map[string]interface{}{
				"ssl_policy": "GCP Default (COMPATIBLE)",
			},
		})
	}

	if len(proxy.SSLCertificates) > 0 {
		certInfos := s.fetchGCPCertificateInfo(ctx, gcpCli, proxy.SSLCertificates)
		if len(certInfos) > 0 {
			metadata["certificates"] = certInfos
		}
	}

	hostname := proxy.Name + ".sslproxy." + gcpCli.GetProjectID() + ".gcp"
	ipAddress := ""
	if fwRule, ok := forwardingRulesByTarget[proxy.SelfLink]; ok {
		ipAddress = fwRule.IPAddress
		metadata["forwarding_rule"] = fwRule.Name
		metadata["load_balancing_scheme"] = fwRule.LoadBalancingScheme
		metadata["port_range"] = fwRule.PortRange
		if ipAddress != "" {
			hostname = ipAddress
		}
	}

	if ipAddress != "" && len(tlsConfigs) > 0 {
		handshakeResult, hsErr := cloudTLSHandshake(ctx, ipAddress, 443)
		if hsErr != nil {
			log.Printf("Warning: TLS handshake error for GCP SSL Proxy %s (%s): %v", proxy.Name, ipAddress, hsErr)
		} else if handshakeResult != nil && handshakeResult.Success {
			tlsConfigs[0]["protocol_version"] = handshakeResult.TLSVersion
			tlsConfigs[0]["cipher_suite"] = handshakeResult.CipherSuite
			applyHandshakeKeyExchange(tlsConfigs[0], handshakeResult)
			tlsConfigs[0]["certificates"] = handshakeResult.Certificates
			tlsConfigs[0]["handshake_verified"] = true
		} else if handshakeResult != nil {
			tlsConfigs[0]["handshake_verified"] = false
			tlsConfigs[0]["handshake_error"] = handshakeResult.Error
		}
	}

	if len(tlsConfigs) > 0 {
		metadata["crypto_configs"] = tlsConfigs
	}

	device := models.Device{
		ID:               uuid.New(),
		TenantID:         tenantID,
		DeviceType:       "gcp_ssl_proxy",
		Vendor:           stringPtr("Google Cloud"),
		Hostname:         stringPtr(hostname),
		IPAddress:        stringPtrOrNil(ipAddress),
		DiscoveryMethod:  "cloud_api",
		CredentialID:     &integrationID,
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB(metadata),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := s.upsertDeviceAsset(ctx, &device, proxy.SelfLink); err != nil {
		return nil, fmt.Errorf("failed to record gcp_ssl_proxy: %w", err)
	}

	return &device, nil
}

// buildGCPForwardingRuleMap builds a map of forwarding rules keyed by their target resource URL
func (s *CloudDiscoveryService) buildGCPForwardingRuleMap(ctx context.Context, gcpCli *gcpclient.Client) (map[string]gcpclient.ForwardingRule, error) {
	rules, err := gcpCli.ListGlobalForwardingRules(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]gcpclient.ForwardingRule, len(rules))
	for _, rule := range rules {
		result[rule.Target] = rule
	}
	return result, nil
}

// buildGCPTLSConfig creates a TLS config from a GCP SSL policy. protocol is "HTTPS" for target HTTPS proxies and "TLS" for target SSL proxies (pass empty for "HTTPS").
func buildGCPTLSConfig(policy *gcpclient.SSLPolicy, protocol string) map[string]interface{} {
	if protocol == "" {
		protocol = "HTTPS"
	}
	tlsConfig := map[string]interface{}{
		"protocol":         protocol,
		"protocol_version": gcpclient.MinTLSVersionToString(policy.MinTLSVersion),
		"port":             443,
		"metadata": map[string]interface{}{
			"ssl_policy":         policy.Name,
			"ssl_policy_profile": policy.Profile,
		},
	}

	// Use enabled features (effective cipher suites) when available
	cipherSuites := policy.EnabledFeatures
	if len(cipherSuites) == 0 && policy.Profile == "CUSTOM" {
		cipherSuites = policy.CustomFeatures
	}

	if len(cipherSuites) > 0 {
		tlsConfig["cipher_suites"] = cipherSuites
		tlsConfig["cipher_suite"] = cipherSuites[0]
	}

	return tlsConfig
}

// fetchGCPCertificateInfo fetches certificate details for the given certificate URLs
func (s *CloudDiscoveryService) fetchGCPCertificateInfo(ctx context.Context, gcpCli *gcpclient.Client, certURLs []string) []map[string]interface{} {
	var certs []map[string]interface{}
	for _, certURL := range certURLs {
		cert, err := gcpCli.GetSSLCertificate(ctx, certURL)
		if err != nil {
			log.Printf("Warning: failed to get GCP SSL certificate %s: %v", certURL, err)
			continue
		}

		certInfo := map[string]interface{}{
			"name": cert.Name,
			"type": cert.Type,
		}
		if cert.ExpireTime != "" {
			certInfo["expire_time"] = cert.ExpireTime
		}
		if len(cert.SubjectAlternativeNames) > 0 {
			certInfo["subject_alternative_names"] = cert.SubjectAlternativeNames
			certInfo["primary_domain"] = cert.SubjectAlternativeNames[0]
		}
		if cert.Managed != nil {
			certInfo["managed"] = true
			certInfo["managed_status"] = cert.Managed.Status
			if len(cert.Managed.Domains) > 0 {
				certInfo["managed_domains"] = cert.Managed.Domains
			}
		} else {
			certInfo["managed"] = false
		}
		certs = append(certs, certInfo)
	}
	return certs
}

// Helper functions for Azure discovery

func extractResourceGroupFromID(resourceID string) string {
	// Azure resource IDs are in format:
	// /subscriptions/{sub}/resourceGroups/{rg}/providers/...
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func getPtrValue[T any](ptr *T) interface{} {
	if ptr == nil {
		return nil
	}
	return *ptr
}

func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func getGatewaySkuInfo(gw *armnetwork.ApplicationGateway) map[string]interface{} {
	if gw.Properties == nil || gw.Properties.SKU == nil {
		return nil
	}
	sku := map[string]interface{}{}
	if gw.Properties.SKU.Name != nil {
		sku["name"] = string(*gw.Properties.SKU.Name)
	}
	if gw.Properties.SKU.Tier != nil {
		sku["tier"] = string(*gw.Properties.SKU.Tier)
	}
	if gw.Properties.SKU.Capacity != nil {
		sku["capacity"] = *gw.Properties.SKU.Capacity
	}
	return sku
}

func getProvisioningState(gw *armnetwork.ApplicationGateway) string {
	if gw.Properties == nil || gw.Properties.ProvisioningState == nil {
		return "unknown"
	}
	return string(*gw.Properties.ProvisioningState)
}

// discoverKMSKeys discovers AWS KMS keys and creates device records
func (s *CloudDiscoveryService) discoverKMSKeys(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	awsClient *awsclient.Client,
	regions []string,
) ([]models.Device, error) {
	kmsService := NewKMSDiscoveryService(s.db, s.bypassDB, s.masterKey)

	findings, err := kmsService.DiscoverAWSKMSKeys(ctx, tenantID, integrationID, regions, awsClient)
	if err != nil {
		return nil, fmt.Errorf("KMS key discovery failed: %w", err)
	}

	// Store findings in the kms_keys table
	if err := kmsService.StoreKMSKeyFindings(ctx, tenantID, integrationID, "aws", findings); err != nil {
		log.Printf("Warning: failed to store KMS key findings: %v", err)
	}

	// Create device records for visibility in device list
	var devices []models.Device
	for _, f := range findings {
		keyName := f.KeyID
		if len(f.AliasNames) > 0 {
			keyName = f.AliasNames[0]
		}

		metadata := map[string]interface{}{
			"key_id":           f.KeyID,
			"arn":              f.KeyARN,
			"key_state":        f.KeyState,
			"key_usage":        f.KeyUsage,
			"key_spec":         f.KeySpec,
			"origin":           f.Origin,
			"rotation_enabled": f.RotationEnabled,
			"region":           f.Region,
			"creation_date":    f.CreationDate,
			"aliases":          f.AliasNames,
		}

		device := models.Device{
			ID:               uuid.New(),
			TenantID:         tenantID,
			DeviceType:       "aws_kms",
			Vendor:           stringPtr("AWS"),
			Hostname:         stringPtr(keyName),
			DiscoveryMethod:  "cloud_api",
			ConnectionStatus: "discovered",
			Metadata:         models.JSONB(metadata),
		}
		devices = append(devices, device)
	}

	log.Printf("Discovered %d AWS KMS keys across %d regions", len(findings), len(regions))
	return devices, nil
}
