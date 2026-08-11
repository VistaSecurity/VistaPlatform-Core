package services

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
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
					protocolVersion := protocols[0] // Use first protocol version
					config.ProtocolVersion = &protocolVersion
				}
				if ciphers, ok := policyDetails["ciphers"].([]string); ok && len(ciphers) > 0 {
					cipherSuite := ciphers[0] // Use first cipher suite
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

// InterrogateAPIGateway extracts detailed crypto configurations from an AWS API Gateway
func (s *AWSInterrogationService) InterrogateAPIGateway(ctx context.Context, apiID string) ([]CryptoConfig, error) {
	// API Gateway v2 uses domain names for TLS
	// This would require additional API calls to get domain configurations
	// For now, return basic config
	config := CryptoConfig{
		Protocol: "HTTPS",
		Port:     443,
		Metadata: map[string]interface{}{
			"api_id": apiID,
		},
	}

	return []CryptoConfig{config}, nil
}

// InterrogateCloudFront extracts detailed crypto configurations from a CloudFront distribution
func (s *AWSInterrogationService) InterrogateCloudFront(ctx context.Context, distributionID string) ([]CryptoConfig, error) {
	// CloudFront uses viewer protocol policies
	// This would require additional API calls to get distribution details
	// For now, return basic config
	config := CryptoConfig{
		Protocol: "HTTPS",
		Port:     443,
		Metadata: map[string]interface{}{
			"distribution_id": distributionID,
		},
	}

	return []CryptoConfig{config}, nil
}

// getSSLPolicyDetails gets details about an SSL policy
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

	policy := policies.SslPolicies[0]
	details := map[string]interface{}{
		"name":      awsconfig.ToString(policy.Name),
		"protocols": make([]string, 0),
		"ciphers":   make([]string, 0),
	}

	// Note: MinProtocolVersion may not be available in all SDK versions
	if policy.Name != nil {
		// Extract min protocol from policy name if available
		details["policy_name"] = *policy.Name
	}

	// Extract supported ciphers
	cipherList := details["ciphers"].([]string)
	for _, cipher := range policy.Ciphers {
		if cipher.Name != nil {
			cipherList = append(cipherList, *cipher.Name)
		}
	}
	details["ciphers"] = cipherList

	// Extract protocol versions from ciphers
	protocols := make(map[string]bool)
	for _, cipher := range policy.Ciphers {
		if cipher.Name != nil {
			// Parse cipher name to extract protocol (e.g., "ECDHE-RSA-AES128-GCM-SHA256" -> TLS 1.2)
			// This is a simplified approach - actual parsing would be more complex
			protocols["TLS 1.2"] = true
			protocols["TLS 1.3"] = true
		}
	}
	protocolList := make([]string, 0, len(protocols))
	for p := range protocols {
		protocolList = append(protocolList, p)
	}
	details["protocols"] = protocolList

	return details, nil
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
