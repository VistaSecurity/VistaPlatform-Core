package aws

// Tier-1 cloud classes (asset-inventory ADR-0009 D2; DCIM row 4.6): Lambda
// functions, EKS clusters, Secrets Manager secrets and Route 53 hosted zones.
//
// These four APIs are called over SigV4-signed REST with the integration's
// own resolved credentials rather than through four more SDK modules: each
// call is one paginated GET or POST, and the response is decoded straight
// into the projection structs below — the SAME projection boundary ec2.go
// keeps. Nothing outside these structs is ever decoded into a field.
//
// What is deliberately NOT retrieved or kept:
//
//   - A Lambda function's environment variable VALUES. ListFunctions returns
//     them (there is no narrower call), so the response type holds them only
//     as the keys of a map whose values are discarded on decode
//     (envNames.UnmarshalJSON); only the names are projected.
//   - A secret's value. ListSecrets never returns one, and GetSecretValue is
//     never called.
//   - An EKS cluster's certificate authority data and identity provider
//     configuration — the struct has no field for them.
//   - Route 53 record VALUES. Only the zone and its record-set count.
//
// IAM actions needed (all read-only, all in ReadOnlyAccess):
// lambda:ListFunctions, eks:ListClusters, eks:DescribeCluster,
// secretsmanager:ListSecrets, route53:ListHostedZones.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// maxTier1Pages bounds every pagination loop: a provider that keeps returning
// a next token cannot keep a run going for ever.
const maxTier1Pages = 200

// endpoint is the base URL for a service in a region. A configured
// BaseEndpoint (tests) wins.
func (c *Client) endpoint(service, region string) string {
	if c.config.BaseEndpoint != nil && *c.config.BaseEndpoint != "" {
		return strings.TrimRight(*c.config.BaseEndpoint, "/")
	}
	suffix := "amazonaws.com"
	if ARNPartition(region) == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	if service == "route53" {
		return "https://route53." + suffix
	}
	return "https://" + service + "." + region + "." + suffix
}

// signedDo sends one SigV4-signed request and returns the body, or the
// provider's error as a smithy.GenericAPIError carrying its own code (so
// SanitizeCloudFailure classifies it like any SDK error).
func (c *Client) signedDo(ctx context.Context, service, region, method, rawURL string, header http.Header, body []byte) ([]byte, error) {
	if c.config.Credentials == nil {
		return nil, fmt.Errorf("%s: no credentials", service)
	}
	creds, err := c.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: retrieve credentials: %w", service, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	sum := sha256.Sum256(body)
	signRegion := region
	if service == "route53" {
		signRegion = "us-east-1"
	}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), service, signRegion, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("%s: sign: %w", service, err)
	}
	var hc aws.HTTPClient = http.DefaultClient
	if c.config.HTTPClient != nil {
		hc = c.config.HTTPClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", service, region, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, restError(resp, out)
	}
	return out, nil
}

// restError projects a REST error response onto the provider's code and
// message — JSON (`__type` / `x-amzn-ErrorType`, `message`) or Route 53's XML.
func restError(resp *http.Response, body []byte) error {
	code := strings.TrimSpace(resp.Header.Get("X-Amzn-Errortype"))
	if i := strings.IndexAny(code, ":"); i > 0 {
		code = code[:i]
	}
	var j struct {
		Type     string `json:"__type"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		Message2 string `json:"Message"`
	}
	msg := ""
	if json.Unmarshal(body, &j) == nil {
		if code == "" {
			code = firstNonEmptyStr(j.Code, j.Type)
			if i := strings.LastIndex(code, "#"); i >= 0 {
				code = code[i+1:]
			}
		}
		msg = firstNonEmptyStr(j.Message, j.Message2)
	} else {
		var x struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		if xml.Unmarshal(body, &x) == nil {
			code = firstNonEmptyStr(code, x.Error.Code)
			msg = x.Error.Message
		}
	}
	if code == "" {
		code = "HTTP" + strconv.Itoa(resp.StatusCode)
	}
	return &smithy.GenericAPIError{Code: code, Message: msg}
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// lastSegment is the part of an ARN or path after the last "/".
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ---------------------------------------------------------------------------
// Lambda
// ---------------------------------------------------------------------------

// envNames decodes a map of environment variables keeping only the NAMES. The
// values are decoded as raw JSON and dropped before UnmarshalJSON returns.
type envNames []string

func (e *envNames) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	*e = names
	return nil
}

// Function is a Lambda function's projection.
type Function struct {
	ARN                string   `json:"arn"`
	Name               string   `json:"name"`
	Region             string   `json:"region"`
	Runtime            string   `json:"runtime,omitempty"`
	Handler            string   `json:"handler,omitempty"`
	MemoryMB           int      `json:"memory_mb,omitempty"`
	RoleName           string   `json:"role_name,omitempty"`
	State              string   `json:"state,omitempty"`
	EnvironmentVarKeys []string `json:"environment_variable_names,omitempty"`
}

// ListFunctions lists every Lambda function in one region.
func (c *Client) ListFunctions(ctx context.Context, region string) ([]Function, error) {
	var out []Function
	marker := ""
	for page := 0; page < maxTier1Pages; page++ {
		u := c.endpoint("lambda", region) + "/2015-03-31/functions/?MaxItems=50"
		if marker != "" {
			u += "&Marker=" + url.QueryEscape(marker)
		}
		body, err := c.signedDo(ctx, "lambda", region, http.MethodGet, u, nil, nil)
		if err != nil {
			return out, err
		}
		var resp struct {
			Functions []struct {
				FunctionName string `json:"FunctionName"`
				FunctionArn  string `json:"FunctionArn"`
				Runtime      string `json:"Runtime"`
				Handler      string `json:"Handler"`
				MemorySize   int    `json:"MemorySize"`
				Role         string `json:"Role"`
				State        string `json:"State"`
				Environment  *struct {
					Variables envNames `json:"Variables"`
				} `json:"Environment"`
			} `json:"Functions"`
			NextMarker string `json:"NextMarker"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return out, fmt.Errorf("lambda %s: decode: %w", region, err)
		}
		for _, f := range resp.Functions {
			if f.FunctionArn == "" {
				continue
			}
			fn := Function{
				ARN: f.FunctionArn, Name: f.FunctionName, Region: region, Runtime: f.Runtime,
				Handler: f.Handler, MemoryMB: f.MemorySize, RoleName: lastSegment(f.Role), State: f.State,
			}
			if f.Environment != nil {
				fn.EnvironmentVarKeys = []string(f.Environment.Variables)
			}
			out = append(out, fn)
		}
		if resp.NextMarker == "" {
			return out, nil
		}
		marker = resp.NextMarker
	}
	return out, fmt.Errorf("lambda %s: more than %d pages", region, maxTier1Pages)
}

// ---------------------------------------------------------------------------
// EKS
// ---------------------------------------------------------------------------

// Cluster is an EKS cluster's projection.
type Cluster struct {
	ARN              string   `json:"arn"`
	Name             string   `json:"name"`
	Region           string   `json:"region"`
	Version          string   `json:"version,omitempty"`
	Status           string   `json:"status,omitempty"`
	EndpointPublic   bool     `json:"endpoint_public"`
	EndpointPrivate  bool     `json:"endpoint_private"`
	SecurityGroupIDs []string `json:"security_group_ids,omitempty"`
	RoleName         string   `json:"role_name,omitempty"`
}

// ListClusters lists and describes every EKS cluster in one region.
func (c *Client) ListClusters(ctx context.Context, region string) ([]Cluster, error) {
	var names []string
	token := ""
	for page := 0; page < maxTier1Pages; page++ {
		u := c.endpoint("eks", region) + "/clusters?maxResults=100"
		if token != "" {
			u += "&nextToken=" + url.QueryEscape(token)
		}
		body, err := c.signedDo(ctx, "eks", region, http.MethodGet, u, nil, nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Clusters  []string `json:"clusters"`
			NextToken string   `json:"nextToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("eks %s: decode: %w", region, err)
		}
		names = append(names, resp.Clusters...)
		if resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	var out []Cluster
	for _, name := range names {
		body, err := c.signedDo(ctx, "eks", region, http.MethodGet, c.endpoint("eks", region)+"/clusters/"+url.PathEscape(name), nil, nil)
		if err != nil {
			return out, err
		}
		var resp struct {
			Cluster struct {
				Name               string `json:"name"`
				Arn                string `json:"arn"`
				Version            string `json:"version"`
				Status             string `json:"status"`
				RoleArn            string `json:"roleArn"`
				ResourcesVpcConfig struct {
					EndpointPublicAccess   bool     `json:"endpointPublicAccess"`
					EndpointPrivateAccess  bool     `json:"endpointPrivateAccess"`
					SecurityGroupIDs       []string `json:"securityGroupIds"`
					ClusterSecurityGroupID string   `json:"clusterSecurityGroupId"`
				} `json:"resourcesVpcConfig"`
			} `json:"cluster"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return out, fmt.Errorf("eks %s: decode %s: %w", region, name, err)
		}
		cl := resp.Cluster
		if cl.Arn == "" {
			continue
		}
		sgs := append([]string(nil), cl.ResourcesVpcConfig.SecurityGroupIDs...)
		if id := cl.ResourcesVpcConfig.ClusterSecurityGroupID; id != "" {
			sgs = append(sgs, id)
		}
		out = append(out, Cluster{
			ARN: cl.Arn, Name: cl.Name, Region: region, Version: cl.Version, Status: cl.Status,
			EndpointPublic: cl.ResourcesVpcConfig.EndpointPublicAccess, EndpointPrivate: cl.ResourcesVpcConfig.EndpointPrivateAccess,
			SecurityGroupIDs: sgs, RoleName: lastSegment(cl.RoleArn),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Secrets Manager
// ---------------------------------------------------------------------------

// Secret is a Secrets Manager secret's projection: metadata only.
type Secret struct {
	ARN             string            `json:"arn"`
	Name            string            `json:"name"`
	Region          string            `json:"region"`
	RotationEnabled bool              `json:"rotation_enabled"`
	LastRotated     string            `json:"last_rotated,omitempty"`
	KMSKeyID        string            `json:"kms_key_id,omitempty"`
	PendingDeletion bool              `json:"pending_deletion,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// ListSecrets lists every secret's metadata in one region. It never asks for
// a value; ListSecrets does not return one.
func (c *Client) ListSecrets(ctx context.Context, region string) ([]Secret, error) {
	var out []Secret
	token := ""
	h := http.Header{}
	h.Set("Content-Type", "application/x-amz-json-1.1")
	h.Set("X-Amz-Target", "secretsmanager.ListSecrets")
	for page := 0; page < maxTier1Pages; page++ {
		req := map[string]any{"MaxResults": 100, "IncludePlannedDeletion": true}
		if token != "" {
			req["NextToken"] = token
		}
		b, _ := json.Marshal(req)
		body, err := c.signedDo(ctx, "secretsmanager", region, http.MethodPost, c.endpoint("secretsmanager", region)+"/", h, b)
		if err != nil {
			return out, err
		}
		var resp struct {
			SecretList []struct {
				ARN             string   `json:"ARN"`
				Name            string   `json:"Name"`
				RotationEnabled bool     `json:"RotationEnabled"`
				LastRotatedDate *float64 `json:"LastRotatedDate"`
				KmsKeyID        string   `json:"KmsKeyId"`
				DeletedDate     *float64 `json:"DeletedDate"`
				Tags            []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
			} `json:"SecretList"`
			NextToken string `json:"NextToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return out, fmt.Errorf("secretsmanager %s: decode: %w", region, err)
		}
		for _, sec := range resp.SecretList {
			if sec.ARN == "" {
				continue
			}
			s := Secret{ARN: sec.ARN, Name: sec.Name, Region: region, RotationEnabled: sec.RotationEnabled,
				KMSKeyID: sec.KmsKeyID, PendingDeletion: sec.DeletedDate != nil}
			if sec.LastRotatedDate != nil {
				s.LastRotated = time.Unix(int64(*sec.LastRotatedDate), 0).UTC().Format(time.RFC3339)
			}
			if len(sec.Tags) > 0 {
				s.Tags = map[string]string{}
				for _, t := range sec.Tags {
					if k := strings.TrimSpace(t.Key); k != "" {
						s.Tags[k] = redact.String(k, t.Value)
					}
				}
			}
			out = append(out, s)
		}
		if resp.NextToken == "" {
			return out, nil
		}
		token = resp.NextToken
	}
	return out, fmt.Errorf("secretsmanager %s: more than %d pages", region, maxTier1Pages)
}

// ---------------------------------------------------------------------------
// Route 53
// ---------------------------------------------------------------------------

// HostedZone is a Route 53 hosted zone's projection.
type HostedZone struct {
	ARN         string `json:"arn"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Private     bool   `json:"private"`
	RecordCount int    `json:"record_count"`
}

// ListHostedZones lists every hosted zone in the account (Route 53 is global).
func (c *Client) ListHostedZones(ctx context.Context) ([]HostedZone, error) {
	var out []HostedZone
	marker := ""
	partition := ARNPartition(c.region)
	for page := 0; page < maxTier1Pages; page++ {
		u := c.endpoint("route53", c.region) + "/2013-04-01/hostedzone?maxitems=100"
		if marker != "" {
			u += "&marker=" + url.QueryEscape(marker)
		}
		body, err := c.signedDo(ctx, "route53", c.region, http.MethodGet, u, nil, nil)
		if err != nil {
			return out, err
		}
		var resp struct {
			HostedZones []struct {
				ID     string `xml:"Id"`
				Name   string `xml:"Name"`
				Config struct {
					PrivateZone bool `xml:"PrivateZone"`
				} `xml:"Config"`
				Count int `xml:"ResourceRecordSetCount"`
			} `xml:"HostedZones>HostedZone"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextMarker  string `xml:"NextMarker"`
		}
		if err := xml.Unmarshal(body, &resp); err != nil {
			return out, fmt.Errorf("route53: decode: %w", err)
		}
		for _, z := range resp.HostedZones {
			id := lastSegment(z.ID)
			if id == "" {
				continue
			}
			out = append(out, HostedZone{
				ARN: "arn:" + partition + ":route53:::hostedzone/" + id, ID: id,
				Name: strings.TrimSuffix(z.Name, "."), Private: z.Config.PrivateZone, RecordCount: z.Count,
			})
		}
		if !resp.IsTruncated || resp.NextMarker == "" {
			return out, nil
		}
		marker = resp.NextMarker
	}
	return out, fmt.Errorf("route53: more than %d pages", maxTier1Pages)
}
