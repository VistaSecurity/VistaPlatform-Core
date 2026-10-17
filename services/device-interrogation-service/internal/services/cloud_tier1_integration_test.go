package services

// The Tier-1 classes (asset-inventory ADR-0009 D2) through the REAL funnel:
//
//   - a security group is an asset of class security_group, and the instance
//     in it has a `member_of` edge to it (D4);
//   - the AWS collectors, driven against a local fake of the provider APIs,
//     record a Lambda function, a secret and a hosted zone as assets of their
//     classes, a refused type as a failed grid row, a zone's certificate names
//     from the tenant's certificate inventory — and a planted environment
//     variable value and secret-named tag reach no tenant table.
//
// MUTATION-VERIFIED (see the PR): remove linkMemberOf from
// recordCloudResource and the edge assertion goes red; decode Lambda's
// Variables into a value-keeping map and project it, and the planted value is
// found.
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func classOf(t *testing.T, db *sql.DB, tenantID uuid.UUID, resourceID string) (uuid.UUID, string) {
	t.Helper()
	id := assetIDForCloudResource(t, db, tenantID, resourceID)
	var class string
	if err := db.QueryRow(`SELECT class_key FROM assets WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&class); err != nil {
		t.Fatal(err)
	}
	return id, class
}

func TestIntegration_CloudTier1_SecurityGroupIsAnAssetWithMemberOf(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	plan := awsEnumerationPlanForTest(t)
	account := plan.Instances[0].Facts["cloud.account_id"].(string)
	integ := seedAccountIntegration(t, owner, tenantID, account, true)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)

	groups := plan.Instances[0].Facts["cloud.security_groups"].([]map[string]any)
	sgID := groups[0]["id"].(string)
	awsSecurityGroups(&plan, []awsclient.SecurityGroup{{GroupID: sgID, GroupName: "web", VPCID: "vpc-01", AccountID: account, Region: "us-east-1"}}, "us-east-1")

	ctx := svc.beginCloudRun(context.Background(), tenantID, integ, "aws")
	if _, _, err := svc.recordEnumeration(ctx, tenantID, integ, "production", plan); err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}

	sgARN := awsclient.EC2ResourceARN("us-east-1", account, "security-group", sgID)
	sgAsset, class := classOf(t, owner, tenantID, sgARN)
	if class != "security_group" {
		t.Fatalf("security group class = %q, want security_group", class)
	}
	instance := assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID)
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND from_asset_id = $2 AND to_asset_id = $3 AND type = 'member_of'`,
		tenantID, instance, sgAsset).Scan(&n); err != nil || n != 1 {
		t.Errorf("member_of instance → security group edges = %d, %v; want 1", n, err)
	}
	var providerType string
	_ = owner.QueryRow(`SELECT coalesce(attributes->>'provider_type','') FROM assets WHERE id = $1`, sgAsset).Scan(&providerType)
	if providerType != "AWS::EC2::SecurityGroup" {
		t.Errorf("provider_type = %q, want AWS::EC2::SecurityGroup", providerType)
	}
}

const (
	plantedEnvValue = "PlantedLambdaEnvValue-8842-wJalrXUtnFEMI"
	plantedTagValue = "PlantedSecretTagValue-5521"
)

func TestIntegration_CloudTier1_AWSCollectorsRecordClassesAndNeverSecrets(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	suffix := uuid.New().String()[:8]
	account := "4444" + "55556666"
	integ := seedAccountIntegration(t, owner, tenantID, account, true)
	svc := NewCloudDiscoveryService(app, owner, testMasterKey)
	zone := "zone-" + suffix + ".example.test"
	if _, err := owner.Exec(`INSERT INTO certificates (tenant_id, subject_dn, issuer_dn, fingerprint_sha256, common_name, subject_alternative_names)
		VALUES ($1, 'CN=api.'||$2, 'CN=Example CA', $3, 'api.'||$2, ARRAY['www.'||$2, 'other.example.org'])`,
		tenantID, zone, strings.Repeat("a", 56)+suffix); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	fnARN := "arn:aws:lambda:us-east-1:" + account + ":function:fn-" + suffix
	secARN := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:db-" + suffix
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/2015-03-31/functions"):
			_ = json.NewEncoder(w).Encode(map[string]any{"Functions": []any{map[string]any{
				"FunctionName": "fn-" + suffix, "FunctionArn": fnARN, "Runtime": "python3.12", "Handler": "app.handler",
				"MemorySize": 256, "Role": "arn:aws:iam::" + account + ":role/fn-exec",
				"Environment": map[string]any{"Variables": map[string]string{"DB_PASSWORD": plantedEnvValue, "STAGE": "prod"}},
			}}})
		case strings.HasPrefix(r.URL.Path, "/clusters"):
			w.Header().Set("X-Amzn-Errortype", "AccessDeniedException:http://internal.amazon.com/coral/")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "not authorized to perform: eks:ListClusters"})
		case r.Header.Get("X-Amz-Target") == "secretsmanager.ListSecrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretList": []any{map[string]any{
				"ARN": secARN, "Name": "db-" + suffix, "RotationEnabled": true, "LastRotatedDate": 1760000000, "KmsKeyId": "alias/db",
				"Tags": []any{map[string]string{"Key": "password", "Value": plantedTagValue}},
			}}})
		case strings.HasPrefix(r.URL.Path, "/2013-04-01/hostedzone"):
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z` + strings.ToUpper(suffix) +
				`</Id><Name>` + zone + `.</Name><Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>7</ResourceRecordSetCount></HostedZone></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	client := awsclient.NewClientFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDEXAMPLETESTONLY", "example-secret-test-only", ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
	}, account, "us-east-1")

	types := []string{CloudTypeServerlessFunctions, CloudTypeContainerClusters, CloudTypeSecretStores, CloudTypeDNSZones}
	rec := NewCloudOutcomeRecorder(types)
	ctx := WithCloudOutcomes(svc.beginCloudRun(context.Background(), tenantID, integ, "aws"), rec)
	devices := runCloudCollectors(ctx, types, []string{"us-east-1"}, awsTier1Collectors(svc, tenantID, integ, client))
	if len(devices) != 3 {
		t.Fatalf("recorded %d resources, want function + secret + zone", len(devices))
	}

	got := outcomesByType(rec)
	if o := got[CloudTypeContainerClusters]; o.Status != CloudTypeFailed || len(o.Regions) != 1 || o.Regions[0].Failure == nil || o.Regions[0].Failure.Code != "AccessDeniedException" {
		t.Errorf("container_clusters = %+v, want a failed us-east-1 row with AccessDeniedException", o)
	}
	for _, rt := range []string{CloudTypeServerlessFunctions, CloudTypeSecretStores, CloudTypeDNSZones} {
		if o := got[rt]; o.Status != CloudTypeSucceeded || o.Found != 1 {
			t.Errorf("%s = %+v, want succeeded with 1", rt, o)
		}
	}

	zoneARN := "arn:aws:route53:::hostedzone/Z" + strings.ToUpper(suffix)
	for rid, want := range map[string]string{fnARN: "serverless_function", secARN: "secret_store", zoneARN: "dns_zone"} {
		if _, class := classOf(t, owner, tenantID, rid); class != want {
			t.Errorf("%s class = %q, want %q", rid, class, want)
		}
	}
	fnAsset := assetIDForCloudResource(t, owner, tenantID, fnARN)
	var envNames, roles string
	_ = owner.QueryRow(`SELECT attributes->>'environment_variable_names', attributes->>'role_names' FROM assets WHERE id = $1`, fnAsset).Scan(&envNames, &roles)
	if !strings.Contains(envNames, "DB_PASSWORD") || !strings.Contains(envNames, "STAGE") || !strings.Contains(roles, "fn-exec") {
		t.Errorf("function attributes: env names %s, roles %s", envNames, roles)
	}
	zoneAsset := assetIDForCloudResource(t, owner, tenantID, zoneARN)
	var certNames string
	_ = owner.QueryRow(`SELECT coalesce(attributes->>'certificate_names','') FROM assets WHERE id = $1`, zoneAsset).Scan(&certNames)
	if !strings.Contains(certNames, "api."+zone) || !strings.Contains(certNames, "www."+zone) || strings.Contains(certNames, "example.org") {
		t.Errorf("zone certificate_names = %s", certNames)
	}

	// The planted values reach no tenant table.
	rows, err := owner.Query(`SELECT c.table_name FROM information_schema.columns c
		JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
		WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' AND tb.table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		tables = append(tables, name)
	}
	_ = rows.Close()
	for _, table := range tables {
		for _, secret := range []string{plantedEnvValue, plantedTagValue} {
			var n int
			if err := owner.QueryRow(`SELECT count(*) FROM public."`+table+`" t WHERE t.tenant_id = $1 AND strpos(to_jsonb(t)::text, $2) > 0`,
				tenantID, secret).Scan(&n); err != nil {
				t.Fatalf("searching %s: %v", table, err)
			}
			if n > 0 {
				t.Errorf("planted secret %q reached %d row(s) of %s", secret, n, table)
			}
		}
	}
}
