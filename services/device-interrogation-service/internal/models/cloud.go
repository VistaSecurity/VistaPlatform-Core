package models

import (
	"github.com/google/uuid"
)

// CloudProvider constants
const (
	CloudProviderAWS   = "aws"
	CloudProviderAzure = "azure"
	CloudProviderGCP   = "gcp"
)

// DiscoverCloudResourcesRequest represents a request to discover cloud resources
type DiscoverCloudResourcesRequest struct {
	IntegrationID  uuid.UUID `json:"integration_id" binding:"required"`
	CloudProvider  string    `json:"cloud_provider"`                    // Optional: aws, azure, gcp - auto-detected from integration if not specified
	ResourceTypes  []string  `json:"resource_types" binding:"required"` // e.g., alb, api_gateway, cloudfront for AWS; application_gateway, load_balancer for Azure
	Regions        []string  `json:"regions"`                           // For AWS: us-east-1, etc. For Azure: resource groups (optional)
	ResourceGroups []string  `json:"resource_groups"`                   // Azure-specific: filter by resource groups
}

// InterrogateCloudResourceRequest represents a request to interrogate a specific cloud resource
type InterrogateCloudResourceRequest struct {
	IntegrationID uuid.UUID `json:"integration_id" binding:"required"`
	CloudProvider string    `json:"cloud_provider"` // Optional: aws, azure, gcp - auto-detected from integration if not specified
	ResourceType  string    `json:"resource_type" binding:"required"`
	ResourceARN   string    `json:"resource_arn"` // AWS-specific identifier
	ResourceID    string    `json:"resource_id"`  // Azure/GCP-specific identifier
}
