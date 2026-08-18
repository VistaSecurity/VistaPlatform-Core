package services

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
)

// AWSInterrogationService handles detailed interrogation of AWS resources
type AWSInterrogationService struct {
	awsClient *awsclient.Client
}

// NewAWSInterrogationService creates a new AWS interrogation service
func NewAWSInterrogationService(awsClient *awsclient.Client) *AWSInterrogationService {
	return &AWSInterrogationService{awsClient: awsClient}
}

// InterrogateLoadBalancer extracts detailed crypto configurations from an AWS load balancer
func (s *AWSInterrogationService) InterrogateLoadBalancer(ctx context.Context, lbARN string) ([]CryptoConfig, error) {
	elbClient := s.awsClient.GetELBClient()

	// Get listeners
	listeners, err := elbClient.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: awsconfig.String(lbARN),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe listeners: %w", err)
	}

	var configs []CryptoConfig

	for _, listener := range listeners.Listeners {
		// Only process HTTPS/TLS listeners
		if listener.Protocol != elbv2types.ProtocolEnumHttps && listener.Protocol != elbv2types.ProtocolEnumTls {
			continue
		}

		port := 443
		if listener.Port != nil {
			port = int(*listener.Port)
		}

		config := CryptoConfig{
			Protocol: string(listener.Protocol),
			Port:     port,
			Hostname: awsconfig.ToString(listener.LoadBalancerArn),
			Metadata: make(map[string]interface{}),
		}

		// Get SSL policy
		if listener.SslPolicy != nil {
			config.Metadata["ssl_policy"] = *listener.SslPolicy

			// Get SSL policy details
			policyDetails, err := s.getSSLPolicyDetails(ctx, *listener.SslPolicy)
			if err == nil {
				config.Metadata["ssl_policy_details"] = policyDetails
				if protocols, ok := policyDetails["protocols"].([]string); ok && len(protocols) > 0 {
					// The full set the policy permits, in the canonical
					// "TLS 1.x" spelling. inventory-service's hasWeakTLSVersion
					// reads supported_tls_versions to flag legacy-TLS
					// endpoints, and it is fed from raw metadata
					// "tls_versions" (see discovery-processor's
					// extractCryptoDetails).
					config.Metadata["tls_versions"] = protocols

					// A single ProtocolVersion for a policy that permits
					// several must be the WEAKEST permitted version: that is
					// what an attacker can negotiate by downgrade, and it is
					// what isWeakProtocol/assessCrypto are asking about. The
					// strongest version is not a security property of the
					// endpoint — every modern client already gets it.
					if minVersion := weakestTLSVersion(protocols); minVersion != "" {
						config.ProtocolVersion = &minVersion
					}
				}
				if ciphers, ok := policyDetails["ciphers"].([]string); ok && len(ciphers) > 0 {
					cipherSuite := ciphers[0] // AWS returns ciphers in priority order
					config.CipherSuite = &cipherSuite
				}
			}
		}

		// Get certificates
		if len(listener.Certificates) > 0 {
			certs := make([]map[string]interface{}, 0)
			for _, cert := range listener.Certificates {
				certInfo := map[string]interface{}{
					"arn": awsconfig.ToString(cert.CertificateArn),
				}

				// Try to get certificate details if it's an ACM certificate
				if cert.CertificateArn != nil {
					certDetails, err := s.getCertificateDetails(ctx, *cert.CertificateArn)
					if err == nil {
						certInfo["details"] = certDetails
						if subject, ok := certDetails["subject"].(string); ok {
							config.Metadata["certificate_subject"] = subject
						}
						if issuer, ok := certDetails["issuer"].(string); ok {
							config.Metadata["certificate_issuer"] = issuer
						}
						if notAfter, ok := certDetails["not_after"].(string); ok {
							config.Metadata["certificate_expires"] = notAfter
						}
					}
				}

				certs = append(certs, certInfo)
			}
			config.Metadata["certificates"] = certs
		}

		// Get default actions (for ALB redirect rules)
		if len(listener.DefaultActions) > 0 {
			actions := make([]map[string]interface{}, 0)
			for _, action := range listener.DefaultActions {
				actionInfo := map[string]interface{}{
					"type": string(action.Type),
				}
				if action.RedirectConfig != nil {
					if action.RedirectConfig.Protocol != nil {
						actionInfo["redirect_protocol"] = *action.RedirectConfig.Protocol
					}
					if action.RedirectConfig.Port != nil {
						actionInfo["redirect_port"] = *action.RedirectConfig.Port
					}
				}
				actions = append(actions, actionInfo)
			}
			config.Metadata["default_actions"] = actions
		}

		configs = append(configs, config)
	}

	return configs, nil
}

// InterrogateAPIGateway extracts crypto configurations from an API Gateway v2
// API by way of the custom domain names mapped to it.
//
// TLS on API Gateway is a property of the DOMAIN, not the API: the domain
// name configuration carries the SecurityPolicy (TLS_1_0 / TLS_1_2) and the
// ACM certificate ARN. An API with no mapped custom domain is served only on
// the execute-api endpoint, whose TLS is AWS-managed and not tenant
// configuration — for those this returns an empty slice, matching the
// discovery path, which only keeps APIs that have a mapped custom domain.
//
// Required IAM: apigateway:GET (already required by cloud discovery).
func (s *AWSInterrogationService) InterrogateAPIGateway(ctx context.Context, apiID string) ([]CryptoConfig, error) {
	client := s.awsClient.GetAPIGatewayClient()

	configs := make([]CryptoConfig, 0)

	var nextToken *string
	for {
		domains, err := client.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("failed to list API Gateway domain names: %w", err)
		}

		for _, domain := range domains.Items {
			if domain.DomainName == nil {
				continue
			}

			// Only domains actually mapped to this API describe this API's TLS.
			mappings, err := client.GetApiMappings(ctx, &apigatewayv2.GetApiMappingsInput{
				DomainName: domain.DomainName,
			})
			if err != nil {
				continue
			}
			mapped := false
			var mappedStage string
			for _, m := range mappings.Items {
				if awsconfig.ToString(m.ApiId) == apiID {
					mapped = true
					mappedStage = awsconfig.ToString(m.Stage)
					break
				}
			}
			if !mapped {
				continue
			}

			for _, dnc := range domain.DomainNameConfigurations {
				// Explicit field allowlist. The DomainNameConfiguration is
				// projected rather than assigned wholesale so no future SDK
				// field can silently reach the database.
				meta := map[string]interface{}{
					"api_id":               apiID,
					"domain_name":          awsconfig.ToString(domain.DomainName),
					"resource_kind":        "api_gateway_domain",
					"security_policy":      string(dnc.SecurityPolicy),
					"endpoint_type":        string(dnc.EndpointType),
					"domain_name_status":   string(dnc.DomainNameStatus),
					"certificate_arn":      awsconfig.ToString(dnc.CertificateArn),
					"certificate_name":     awsconfig.ToString(dnc.CertificateName),
					"regional_domain_name": awsconfig.ToString(dnc.ApiGatewayDomainName),
				}
				if mappedStage != "" {
					meta["stage"] = mappedStage
				}

				cfg := CryptoConfig{
					Protocol: "HTTPS",
					Port:     443,
					Hostname: awsconfig.ToString(domain.DomainName),
					Metadata: meta,
				}

				// SecurityPolicy is a MINIMUM: "TLS_1_0" means TLS 1.0 is
				// still accepted. Report the minimum, for the same reason as
				// the ALB SSL policy above.
				if v := normalizeTLSVersion(string(dnc.SecurityPolicy)); v != "" {
					cfg.ProtocolVersion = &v
					// The permitted set implied by the minimum, so
					// hasWeakTLSVersion can see the legacy tail.
					cfg.Metadata["tls_versions"] = tlsVersionsAtLeast(v)
				}

				if arn := awsconfig.ToString(dnc.CertificateArn); arn != "" {
					certInfo := map[string]interface{}{"arn": arn}
					if certDetails, err := s.getCertificateDetails(ctx, arn); err == nil {
						certInfo["details"] = certDetails
					}
					cfg.Metadata["certificates"] = []map[string]interface{}{certInfo}
				}

				configs = append(configs, cfg)
			}
		}

		if domains.NextToken == nil || awsconfig.ToString(domains.NextToken) == "" {
			break
		}
		nextToken = domains.NextToken
	}

	return configs, nil
}

// InterrogateCloudFront extracts crypto configurations from a CloudFront
// distribution: one for the viewer (browser-facing) side and one per custom
// origin.
//
// The origin side is the valuable half. A distribution can serve viewers over
// TLS 1.2+ while talking to its origin over TLS 1.0 or plain HTTP, and nothing
// in a client-side handshake against the CloudFront domain can reveal that.
//
// Uses GetDistributionConfig rather than GetDistribution deliberately: it is
// the narrower response (no trusted-signer key material, no status/metrics),
// which is the "don't retrieve it" layer of the collect-posture-never-key-
// material rule.
//
// Required IAM: cloudfront:GetDistributionConfig (in addition to
// cloudfront:ListDistributions, which discovery already needs).
func (s *AWSInterrogationService) InterrogateCloudFront(ctx context.Context, distributionID string) ([]CryptoConfig, error) {
	client := s.awsClient.GetCloudFrontClient()

	out, err := client.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{
		Id: awsconfig.String(distributionID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get CloudFront distribution config for %s: %w", distributionID, err)
	}
	if out == nil || out.DistributionConfig == nil {
		return nil, fmt.Errorf("CloudFront distribution %s returned no configuration", distributionID)
	}
	dc := out.DistributionConfig

	configs := make([]CryptoConfig, 0, 2)

	// ---- viewer side ----
	viewerHostname := ""
	if dc.Aliases != nil && len(dc.Aliases.Items) > 0 {
		viewerHostname = dc.Aliases.Items[0]
	}

	viewerMeta := map[string]interface{}{
		"distribution_id": distributionID,
		"resource_kind":   "cloudfront_viewer",
	}
	if dc.DefaultCacheBehavior != nil {
		viewerMeta["viewer_protocol_policy"] = string(dc.DefaultCacheBehavior.ViewerProtocolPolicy)
	}

	viewer := CryptoConfig{
		Protocol: "HTTPS",
		Port:     443,
		Hostname: viewerHostname,
		Metadata: viewerMeta,
	}

	if vc := dc.ViewerCertificate; vc != nil {
		// Projected field allowlist — never the whole ViewerCertificate.
		viewerMeta["minimum_protocol_version"] = string(vc.MinimumProtocolVersion)
		viewerMeta["ssl_support_method"] = string(vc.SSLSupportMethod)
		// CertificateSource is deprecated in the CloudFront API; derive the same
		// answer from the three mutually exclusive fields that replaced it, so
		// the projected shape stays stable for consumers.
		viewerMeta["certificate_source"] = cloudFrontCertificateSource(vc)
		viewerMeta["cloudfront_default_certificate"] = awsconfig.ToBool(vc.CloudFrontDefaultCertificate)
		if arn := awsconfig.ToString(vc.ACMCertificateArn); arn != "" {
			viewerMeta["acm_certificate_arn"] = arn
			certInfo := map[string]interface{}{"arn": arn}
			if certDetails, err := s.getCertificateDetails(ctx, arn); err == nil {
				certInfo["details"] = certDetails
			}
			viewerMeta["certificates"] = []map[string]interface{}{certInfo}
		}
		if id := awsconfig.ToString(vc.IAMCertificateId); id != "" {
			viewerMeta["iam_certificate_id"] = id
		}

		// MinimumProtocolVersion is exactly that — a floor, not the
		// negotiated version.
		if v := normalizeTLSVersion(string(vc.MinimumProtocolVersion)); v != "" {
			viewer.ProtocolVersion = &v
			viewerMeta["tls_versions"] = tlsVersionsAtLeast(v)
		}
	}
	configs = append(configs, viewer)

	// ---- origin side ----
	if dc.Origins != nil {
		for _, origin := range dc.Origins.Items {
			custom := origin.CustomOriginConfig
			if custom == nil {
				// S3 origin (or OAC) — no tenant-controlled TLS settings.
				continue
			}

			originMeta := map[string]interface{}{
				"distribution_id":        distributionID,
				"resource_kind":          "cloudfront_origin",
				"origin_id":              awsconfig.ToString(origin.Id),
				"origin_domain_name":     awsconfig.ToString(origin.DomainName),
				"origin_protocol_policy": string(custom.OriginProtocolPolicy),
			}

			port := int(awsconfig.ToInt32(custom.HTTPSPort))
			if port == 0 {
				port = 443
			}
			protocol := "TLS"
			if custom.OriginProtocolPolicy == cloudfronttypes.OriginProtocolPolicyHttpOnly {
				// Honest reporting: CloudFront reaches this origin in
				// cleartext. Do not report a TLS version it does not use.
				protocol = "HTTP"
				port = int(awsconfig.ToInt32(custom.HTTPPort))
				if port == 0 {
					port = 80
				}
			}

			originCfg := CryptoConfig{
				Protocol: protocol,
				Port:     port,
				Hostname: awsconfig.ToString(origin.DomainName),
				Metadata: originMeta,
			}

			if protocol != "HTTP" && custom.OriginSslProtocols != nil {
				permitted := make([]string, 0, len(custom.OriginSslProtocols.Items))
				for _, p := range custom.OriginSslProtocols.Items {
					if v := normalizeTLSVersion(string(p)); v != "" {
						permitted = append(permitted, v)
					}
				}
				permitted = dedupeSortTLSVersions(permitted)
				if len(permitted) > 0 {
					originMeta["tls_versions"] = permitted
					weakest := weakestTLSVersion(permitted)
					originCfg.ProtocolVersion = &weakest
				}
			}

			configs = append(configs, originCfg)
		}
	}

	return configs, nil
}

// tlsVersionsAtLeast expands a MINIMUM protocol version into the set of
// versions it implies. AWS surfaces API Gateway's SecurityPolicy and
// CloudFront's MinimumProtocolVersion as a floor rather than a list, and the
// legacy tail is precisely what makes them risky: "TLS_1_0" means TLS 1.0 is
// still accepted, which is what hasWeakTLSVersion needs to see.
func tlsVersionsAtLeast(minVersion string) []string {
	minRank := tlsVersionRank(minVersion)
	if minRank < 0 {
		return nil
	}
	all := []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
	out := make([]string, 0, len(all))
	for _, v := range all {
		if tlsVersionRank(v) >= minRank {
			out = append(out, v)
		}
	}
	return out
}

// getSSLPolicyDetails gets details about an SSL policy.
//
// The protocol set comes from the policy's own SslProtocols field — the
// authoritative list of what the listener will negotiate. It is NOT inferred
// from the cipher list: an earlier version of this function set
// TLS 1.2 + TLS 1.3 for any policy that had any cipher, which reported the
// legacy ELBSecurityPolicy-TLS-1-0-2015-04 (which permits TLS 1.0) as
// modern-only. Reporting a weak protocol as strong is the worst failure this
// pipeline can have.
func (s *AWSInterrogationService) getSSLPolicyDetails(ctx context.Context, policyName string) (map[string]interface{}, error) {
	elbClient := s.awsClient.GetELBClient()

	// Describe SSL policies
	policies, err := elbClient.DescribeSSLPolicies(ctx, &elasticloadbalancingv2.DescribeSSLPoliciesInput{
		Names: []string{policyName},
	})
	if err != nil {
		return nil, err
	}

	if len(policies.SslPolicies) == 0 {
		return nil, fmt.Errorf("SSL policy not found")
	}

	return sslPolicyDetailsFromPolicy(policies.SslPolicies[0]), nil
}

// sslPolicyDetailsFromPolicy is the pure projection of an ELBv2 SslPolicy onto
// the detail map. Split out from getSSLPolicyDetails so it can be tested
// against real AWS policy definitions without an AWS client.
func sslPolicyDetailsFromPolicy(policy elbv2types.SslPolicy) map[string]interface{} {
	details := map[string]interface{}{
		"name":      awsconfig.ToString(policy.Name),
		"protocols": make([]string, 0),
		"ciphers":   make([]string, 0),
	}

	if policy.Name != nil {
		details["policy_name"] = *policy.Name
	}

	// Extract supported ciphers (AWS returns these in priority order).
	cipherList := details["ciphers"].([]string)
	for _, cipher := range policy.Ciphers {
		if cipher.Name != nil {
			cipherList = append(cipherList, *cipher.Name)
		}
	}
	details["ciphers"] = cipherList

	// Protocols the policy actually permits. Anything AWS reports that we
	// cannot map is surfaced verbatim under protocols_unrecognized rather
	// than silently dropped or guessed at.
	protocols := make([]string, 0, len(policy.SslProtocols))
	var unrecognized []string
	for _, raw := range policy.SslProtocols {
		if norm := normalizeTLSVersion(raw); norm != "" {
			protocols = append(protocols, norm)
		} else if strings.TrimSpace(raw) != "" {
			unrecognized = append(unrecognized, raw)
		}
	}
	protocols = dedupeSortTLSVersions(protocols)
	details["protocols"] = protocols
	details["protocols_raw"] = append([]string(nil), policy.SslProtocols...)
	if len(unrecognized) > 0 {
		details["protocols_unrecognized"] = unrecognized
	}
	if len(protocols) > 0 {
		details["min_protocol_version"] = protocols[0]
		details["max_protocol_version"] = protocols[len(protocols)-1]
	}

	return details
}

// tlsVersionRank orders canonical protocol-version strings from weakest to
// strongest. Unknown strings rank -1 and are never treated as a version.
func tlsVersionRank(v string) int {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "SSL 2.0":
		return 0
	case "SSL 3.0":
		return 1
	case "TLS 1.0":
		return 2
	case "TLS 1.1":
		return 3
	case "TLS 1.2":
		return 4
	case "TLS 1.3":
		return 5
	}
	return -1
}

// normalizeTLSVersion converts the several spellings AWS uses for a protocol
// version into the one spelling the rest of the discovery pipeline writes into
// protocol_version ("TLS 1.2"), as produced by TLSHandshakeService and as read
// by inventory-service's hasWeakTLSVersion.
//
// Accepted inputs:
//   - ELBv2 SslPolicy.SslProtocols:        "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"
//   - CloudFront MinimumProtocolVersion:   "SSLv3", "TLSv1", "TLSv1_2016",
//     "TLSv1.1_2016", "TLSv1.2_2021", "TLSv1.3_2025"  (the _<year> suffix is a
//     CloudFront policy vintage, not part of the protocol version)
//   - CloudFront OriginSslProtocols:       "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"
//   - API Gateway v2 SecurityPolicy:       "TLS_1_0", "TLS_1_2"
//
// Returns "" for anything it does not recognise. An empty string means NOT
// DETERMINED — callers must not substitute a default.
func normalizeTLSVersion(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// Strip a CloudFront policy vintage suffix ("TLSv1.2_2021" -> "TLSv1.2").
	// Only a 4-digit suffix is stripped, so API Gateway's "TLS_1_0" (suffix
	// "0") is left intact for the switch below.
	if i := strings.LastIndex(s, "_"); i != -1 {
		suffix := s[i+1:]
		if len(suffix) == 4 && strings.IndexFunc(suffix, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
			s = s[:i]
		}
	}

	switch strings.ToUpper(s) {
	case "TLS_1_0", "TLSV1", "TLSV1.0", "TLS1.0", "TLS 1.0":
		return "TLS 1.0"
	case "TLS_1_1", "TLSV1.1", "TLS1.1", "TLS 1.1":
		return "TLS 1.1"
	case "TLS_1_2", "TLSV1.2", "TLS1.2", "TLS 1.2":
		return "TLS 1.2"
	case "TLS_1_3", "TLSV1.3", "TLS1.3", "TLS 1.3":
		return "TLS 1.3"
	case "SSLV2", "SSL 2.0", "SSLV2.0":
		return "SSL 2.0"
	case "SSLV3", "SSL 3.0", "SSLV3.0":
		return "SSL 3.0"
	}
	return ""
}

// weakestTLSVersion returns the lowest-ranked recognised version in the list,
// or "" if none is recognised. See the call site in InterrogateLoadBalancer for
// why the minimum — not the maximum, and not an arbitrary map-iteration pick —
// is the security-relevant single answer.
func weakestTLSVersion(versions []string) string {
	best := ""
	bestRank := -1
	for _, v := range versions {
		r := tlsVersionRank(v)
		if r < 0 {
			continue
		}
		if bestRank == -1 || r < bestRank {
			best, bestRank = v, r
		}
	}
	return best
}

// dedupeSortTLSVersions returns the distinct recognised versions in ascending
// (weakest-first) order. Deterministic ordering matters: the previous code
// picked protocols[0] out of a Go map iteration, so the reported version was
// nondeterministic even when the set was right.
func dedupeSortTLSVersions(versions []string) []string {
	seen := make(map[string]bool, len(versions))
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		if tlsVersionRank(v) < 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return tlsVersionRank(out[i]) < tlsVersionRank(out[j]) })
	return out
}

// getCertificateDetails gets details about an ACM certificate
func (s *AWSInterrogationService) getCertificateDetails(ctx context.Context, certARN string) (map[string]interface{}, error) {
	acmClient := s.awsClient.GetACMClient()

	// Describe certificate
	result, err := acmClient.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: awsconfig.String(certARN),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe certificate: %w", err)
	}

	cert := result.Certificate
	details := map[string]interface{}{
		"arn": certARN,
	}

	// Extract certificate details
	if cert.DomainName != nil {
		details["domain_name"] = *cert.DomainName
	}

	if cert.SubjectAlternativeNames != nil && len(cert.SubjectAlternativeNames) > 0 {
		details["subject_alternative_names"] = cert.SubjectAlternativeNames
	}

	if cert.Issuer != nil {
		details["issuer"] = *cert.Issuer
	}

	// Status is an enum (value type, not pointer)
	details["status"] = string(cert.Status)

	// Type is an enum (value type, not pointer)
	details["type"] = string(cert.Type)

	// KeyAlgorithm is an enum (value type, not pointer)
	details["key_algorithm"] = string(cert.KeyAlgorithm)

	if cert.SignatureAlgorithm != nil {
		details["signature_algorithm"] = *cert.SignatureAlgorithm
	}

	if cert.NotBefore != nil {
		details["not_before"] = cert.NotBefore.Format("2006-01-02T15:04:05Z07:00")
	}

	if cert.NotAfter != nil {
		details["not_after"] = cert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
		if cert.NotBefore != nil {
			details["expires_in_days"] = int(cert.NotAfter.Sub(*cert.NotBefore).Hours() / 24)
		}
	}

	// RenewalEligibility is an enum (value type, not pointer)
	details["renewal_eligibility"] = string(cert.RenewalEligibility)

	if cert.InUseBy != nil && len(cert.InUseBy) > 0 {
		details["in_use_by"] = cert.InUseBy
	}

	// Extract domain validation options
	if cert.DomainValidationOptions != nil && len(cert.DomainValidationOptions) > 0 {
		validationOptions := make([]map[string]interface{}, 0)
		for _, opt := range cert.DomainValidationOptions {
			optMap := make(map[string]interface{})
			if opt.DomainName != nil {
				optMap["domain_name"] = *opt.DomainName
			}
			// ValidationStatus and ValidationMethod are enums (value types, not pointers)
			optMap["validation_status"] = string(opt.ValidationStatus)
			optMap["validation_method"] = string(opt.ValidationMethod)
			validationOptions = append(validationOptions, optMap)
		}
		details["domain_validation_options"] = validationOptions
	}

	// Extract certificate options
	if cert.Options != nil {
		options := make(map[string]interface{})
		// CertificateTransparencyLoggingPreference is an enum (value type, not pointer)
		options["certificate_transparency_logging"] = string(cert.Options.CertificateTransparencyLoggingPreference)
		details["options"] = options
	}

	return details, nil
}

// CryptoConfig represents a discovered cryptographic configuration
type CryptoConfig struct {
	Protocol        string
	ProtocolVersion *string
	CipherSuite     *string
	KeySize         *int
	HashAlgorithm   *string
	Port            int
	Hostname        string
	IPAddress       string
	Metadata        map[string]interface{}
}

// cloudFrontCertificateSource reports where a distribution's viewer certificate
// comes from: "cloudfront" for the default *.cloudfront.net certificate, "acm"
// for one issued/imported into ACM, or "iam" for a legacy IAM-uploaded server
// certificate. CloudFront's own CertificateSource field is deprecated, and the
// three replacement fields are mutually exclusive, so this reproduces the value
// without depending on the deprecated member. Returns "" when none is set,
// which is what an HTTP-only distribution looks like.
func cloudFrontCertificateSource(vc *cloudfronttypes.ViewerCertificate) string {
	if vc == nil {
		return ""
	}
	if awsconfig.ToBool(vc.CloudFrontDefaultCertificate) {
		return "cloudfront"
	}
	if awsconfig.ToString(vc.ACMCertificateArn) != "" {
		return "acm"
	}
	if awsconfig.ToString(vc.IAMCertificateId) != "" {
		return "iam"
	}
	return ""
}
