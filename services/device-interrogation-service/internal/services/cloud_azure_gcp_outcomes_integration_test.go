package services

// Azure and GCP runs: one collector failing no longer aborts the run, and no
// failure is swallowed (integrations review M7).
//
// The REAL DiscoverResourceEvidence runs against the REAL provider clients,
// built from a stored integration row and pointed (through their test-only
// Option) at a local fake of the provider API. The fake refuses some resource
// types and answers the rest, and the run must keep what answered and record
// what did not — per type, with the provider's own error code.
//
// MUTATION-VERIFIED (see the PR): restoring either provider's switch dispatch
// fails its test — the refused load-balancer-family type aborts the whole run
// (the storage resource is lost), and the refused key store reads as a
// success.
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/google/uuid"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const (
	outcomeTestSubscription = "00000000-0000-4000-8000-00000000f001"
	outcomeTestProject      = "example-outcomes-project"
)

func seedEncryptedCloudIntegration(t *testing.T, owner *sql.DB, tenant uuid.UUID, provider, accountID string, plain, secret map[string]string) uuid.UUID {
	t.Helper()
	enc, err := encryption.NewService(testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]interface{}{EnumerateComputeConfigKey: false}
	for k, v := range plain {
		config[k] = v
	}
	for k, v := range secret {
		ct, err := enc.Encrypt(v)
		if err != nil {
			t.Fatal(err)
		}
		config[k] = ct
	}
	raw, _ := json.Marshal(config)
	id := uuid.New()
	if _, err := owner.Exec(`INSERT INTO platform_integrations(id,tenant_id,integration_name,integration_type,provider,config,account_id,is_active,is_enabled,status)
		VALUES($1,$2,$3,$4,'cloud',$5,$6,true,true,'connected')`, id, tenant, "outcomes "+provider, provider, string(raw), accountID); err != nil {
		t.Fatalf("seed %s integration: %v", provider, err)
	}
	return id
}

func armError(w http.ResponseWriter, status int, code, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": code, "message": message}})
}

func outcomesByType(rec *CloudOutcomeRecorder) map[string]CloudResourceTypeOutcome {
	out := map[string]CloudResourceTypeOutcome{}
	for _, o := range rec.Outcomes() {
		out[o.ResourceType] = o
	}
	return out
}

func TestIntegration_AzureDiscovery_OneCollectorFailingDoesNotAbortTheRun(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/.well-known/openid-configuration"):
			base := srv.URL + "/" + fakeAzureTenant
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": base + "/oauth2/v2.0/token", "authorization_endpoint": base + "/oauth2/v2.0/authorize", "issuer": base + "/v2.0"})
		case strings.HasSuffix(p, "/oauth2/v2.0/token"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
		case strings.HasSuffix(p, "/providers/Microsoft.Network/applicationGateways"):
			armError(w, http.StatusForbidden, "AuthorizationFailed", "The client does not have authorization to perform action 'Microsoft.Network/applicationGateways/read'.")
		case strings.HasSuffix(p, "/providers/Microsoft.KeyVault/vaults"):
			armError(w, http.StatusForbidden, "AuthorizationFailed", "The client does not have authorization to perform action 'Microsoft.KeyVault/vaults/read'.")
		case strings.HasSuffix(p, "/providers/Microsoft.Storage/storageAccounts"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{map[string]interface{}{
				"id":       "/subscriptions/" + outcomeTestSubscription + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/exampleoutcomes",
				"name":     "exampleoutcomes",
				"location": "eastus",
				"properties": map[string]interface{}{"encryption": map[string]interface{}{
					"keySource": "Microsoft.Storage",
					"services":  map[string]interface{}{"blob": map[string]interface{}{"enabled": true}},
				}},
			}}})
		case strings.HasSuffix(p, "/providers/Microsoft.Network/loadBalancers"), strings.HasSuffix(p, "/providers/Microsoft.Sql/servers"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	integration := seedEncryptedCloudIntegration(t, owner, tenant, "azure", outcomeTestSubscription,
		map[string]string{"tenant_id": fakeAzureTenant, "subscription_id": outcomeTestSubscription},
		map[string]string{"client_id": "00000000-0000-4000-8000-00000000f002", "client_secret": "fake-secret"})

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	svc.azureOptions = []azureclient.Option{azureclient.WithCloud(cloud.Configuration{
		ActiveDirectoryAuthorityHost: srv.URL + "/",
		Services:                     map[cloud.ServiceName]cloud.ServiceConfiguration{cloud.ResourceManager: {Audience: srv.URL, Endpoint: srv.URL}},
	}, srv.Client())}

	types := []string{"application_gateway", "load_balancer", "key_vault", "storage_account", "sql_database"}
	rec := NewCloudOutcomeRecorder(types)
	out, err := svc.DiscoverResourceEvidence(WithCloudOutcomes(context.Background(), rec), tenant, integration, "azure", types, nil, nil)
	if err != nil {
		t.Fatalf("one refused collector aborted the Azure run: %v", err)
	}
	if len(out.Devices) != 1 || out.Devices[0].DeviceType != "azure_storage_account" {
		t.Fatalf("devices = %+v, want the storage account the answering collector found", out.Devices)
	}

	got := outcomesByType(rec)
	for _, rt := range []string{"application_gateway", "key_vault"} {
		o := got[rt]
		if o.Status != CloudTypeFailed || len(o.Failures) == 0 || o.Failures[0].Reason != CloudFailureAccessDenied || o.Failures[0].Code != "AuthorizationFailed" {
			t.Errorf("%s outcome = %+v, want failed / access_denied / AuthorizationFailed", rt, o)
		}
	}
	for rt, found := range map[string]int{"load_balancer": 0, "storage_account": 1, "sql_database": 0} {
		if o := got[rt]; o.Status != CloudTypeSucceeded || o.Found != found {
			t.Errorf("%s outcome = %+v, want succeeded with %d found", rt, o, found)
		}
	}
	if rec.Verdict() != CloudRunPartial {
		t.Errorf("verdict = %s, want partial", rec.Verdict())
	}
}

// fakeAzureTenant is the directory id the fake Entra ID serves.
const fakeAzureTenant = "00000000-0000-4000-8000-00000000f003"

func TestIntegration_GCPDiscovery_OneCollectorFailingDoesNotAbortTheRun(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)

	denied := func(w http.ResponseWriter, perm string) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{"code": 403, "status": "PERMISSION_DENIED", "message": "Required '" + perm + "' permission"}})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/token":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
		case strings.HasSuffix(p, "/global/targetHttpsProxies"):
			denied(w, "compute.targetHttpsProxies.list")
		case strings.HasSuffix(p, "/locations"):
			denied(w, "cloudkms.locations.list")
		case p == "/b":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{map[string]interface{}{"name": "example-outcomes-bucket", "location": "US"}}})
		case strings.HasSuffix(p, "/global/targetSslProxies"), strings.HasSuffix(p, "/global/forwardingRules"), strings.HasSuffix(p, "/instances"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	saKey, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": outcomeTestProject, "private_key_id": "k1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "scanner@" + outcomeTestProject + ".iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
	})
	integration := seedEncryptedCloudIntegration(t, owner, tenant, "gcp", outcomeTestProject,
		map[string]string{"project_id": outcomeTestProject}, map[string]string{"service_account_key": string(saKey)})

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	svc.gcpOptions = []gcpclient.Option{gcpclient.WithEndpoints(srv.Client(), srv.URL+"/token", srv.URL)}

	types := []string{"load_balancer", "ssl_proxy", "kms", "storage", "cloudsql"}
	rec := NewCloudOutcomeRecorder(types)
	out, err := svc.DiscoverResourceEvidence(WithCloudOutcomes(context.Background(), rec), tenant, integration, "gcp", types, nil, nil)
	if err != nil {
		t.Fatalf("one refused collector aborted the GCP run: %v", err)
	}
	if len(out.Devices) != 1 || out.Devices[0].DeviceType != "gcp_storage_bucket" {
		t.Fatalf("devices = %+v, want the bucket the answering collector found", out.Devices)
	}
	got := outcomesByType(rec)
	for _, rt := range []string{"load_balancer", "kms"} {
		o := got[rt]
		if o.Status != CloudTypeFailed || len(o.Failures) == 0 || o.Failures[0].Reason != CloudFailureAccessDenied || o.Failures[0].Code != "PERMISSION_DENIED" {
			t.Errorf("%s outcome = %+v, want failed / access_denied / PERMISSION_DENIED", rt, o)
		}
	}
	for rt, found := range map[string]int{"ssl_proxy": 0, "storage": 1, "cloudsql": 0} {
		if o := got[rt]; o.Status != CloudTypeSucceeded || o.Found != found {
			t.Errorf("%s outcome = %+v, want succeeded with %d found", rt, o, found)
		}
	}
	if rec.Verdict() != CloudRunPartial {
		t.Errorf("verdict = %s, want partial", rec.Verdict())
	}
}
