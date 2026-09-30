package handlers

// Test Connection contacts the provider (integrations review M4), and a
// credential the platform can no longer read is reported as such (cloud
// MINOR). Every test drives the REAL TestConnection handler over the stored
// row the real encryptConfig produced; the provider is an httptest server the
// real Azure / GCP clients are pointed at through their test-only Option.
//
// MUTATION-VERIFIED (see the PR):
//   - testStoredAzureConnection back to the pre-fix stub (any three strings →
//     "validated") → AzureWrongSecret and AzureSubscriptionDenied go red.
//   - testStoredGCPConnection back to parsing the key JSON only → GCPRevokedKey
//     and GCPProjectDenied go red.
//   - TestConnection back to the lenient handler decrypt → the three
//     RetiredCredential cases go red (the ciphertext is sent to the provider).
//   - tokenEndpoint accepting any token_uri → GCPForeignTokenURI goes red.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

const (
	fakeTenant       = "00000000-0000-4000-8000-0000000000aa"
	fakeSubscription = "00000000-0000-4000-8000-0000000000bb"
	deniedSub        = "00000000-0000-4000-8000-0000000000cc"
	goodSecret       = "correct-client-secret-value"
	fakeAccessToken  = "fake-access-token"
)

// retiredCiphertext is what a v0/v1 ciphertext looks like to the current key:
// valid base64 whose version byte is not v2.
func retiredCiphertext() string {
	buf := make([]byte, 29)
	buf[0] = 0x01
	_, _ = rand.Read(buf[1:])
	return base64.StdEncoding.EncodeToString(buf)
}

// storedConfig is what CreateIntegration writes for a UI config.
func storedConfig(t *testing.T, h *IntegrationHandlers, config map[string]interface{}) string {
	t.Helper()
	enc, err := h.encryptConfig(config)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	raw, _ := json.Marshal(enc)
	return string(raw)
}

func runTestConnection(t *testing.T, h *IntegrationHandlers) connectionTestResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", deviceTestTenant); c.Next() })
	r.POST("/integrations/:id/test", h.TestConnection)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/integrations/"+aUUID+"/test", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var res connectionTestResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return res
}

// --- Azure -----------------------------------------------------------------

type fakeAzure struct {
	srv          *httptest.Server
	mu           sync.Mutex
	tokenCalls   int
	subReads     []string
	sawBadBearer bool
}

func newFakeAzure(t *testing.T) *fakeAzure {
	t.Helper()
	f := &fakeAzure{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			base := f.srv.URL + "/" + fakeTenant
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token_endpoint":         base + "/oauth2/v2.0/token",
				"authorization_endpoint": base + "/oauth2/v2.0/authorize",
				"issuer":                 base + "/v2.0",
			})
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			f.mu.Lock()
			f.tokenCalls++
			f.mu.Unlock()
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != goodSecret {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_client",
					"error_description": "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value.\r\nTrace ID: 1111 Correlation ID: 2222",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": fakeAccessToken, "token_type": "Bearer", "expires_in": 3600})
		case strings.HasPrefix(r.URL.Path, "/subscriptions/"):
			sub := strings.TrimPrefix(r.URL.Path, "/subscriptions/")
			f.mu.Lock()
			f.subReads = append(f.subReads, sub)
			if r.Header.Get("Authorization") != "Bearer "+fakeAccessToken {
				f.sawBadBearer = true
			}
			f.mu.Unlock()
			if sub == deniedSub {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{
					"code":    "AuthorizationFailed",
					"message": "The client does not have authorization to perform action 'Microsoft.Resources/subscriptions/read' over scope '/subscriptions/" + deniedSub + "'.",
				}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"subscriptionId": sub, "displayName": "Example Production", "state": "Enabled"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAzure) handlers(t *testing.T, secret, subscription string) (*IntegrationHandlers, *stubIntegrationStore) {
	t.Helper()
	store := &stubIntegrationStore{testFound: true, testType: "azure", testAcct: subscription}
	h := &IntegrationHandlers{store: store, encryptionKey: testEncryptionKey,
		azureOptions: []azureclient.Option{azureclient.WithCloud(cloud.Configuration{
			ActiveDirectoryAuthorityHost: f.srv.URL + "/",
			Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Audience: f.srv.URL, Endpoint: f.srv.URL},
			},
		}, f.srv.Client())}}
	// Exactly the config the Connect modal sends for Azure.
	store.testConfig = storedConfig(t, h, map[string]interface{}{
		"tenant_id": fakeTenant, "client_id": "00000000-0000-4000-8000-0000000000dd", "client_secret": secret, "subscription_id": subscription,
	})
	return h, store
}

func TestTestConnection_AzureValidCredentialsReadTheSubscription(t *testing.T) {
	f := newFakeAzure(t)
	h, store := f.handlers(t, goodSecret, fakeSubscription)
	res := runTestConnection(t, h)
	if !res.Success {
		t.Fatalf("valid credentials failed: %q", res.Message)
	}
	if f.tokenCalls == 0 || len(f.subReads) != 1 || f.subReads[0] != fakeSubscription || f.sawBadBearer {
		t.Errorf("the test did not authenticate and read the subscription: tokens=%d reads=%v badBearer=%v", f.tokenCalls, f.subReads, f.sawBadBearer)
	}
	if res.Details["subscription_name"] != "Example Production" {
		t.Errorf("details = %v, want the subscription's display name", res.Details)
	}
	if store.testStatus != "connected" {
		t.Errorf("integration status = %q, want connected", store.testStatus)
	}
}

func TestTestConnection_AzureWrongSecret(t *testing.T) {
	f := newFakeAzure(t)
	h, store := f.handlers(t, "not-the-secret", fakeSubscription)
	res := runTestConnection(t, h)
	if res.Success {
		t.Fatal("a wrong client secret tested green")
	}
	if !strings.Contains(res.Message, "AADSTS7000215") {
		t.Errorf("message %q does not carry Entra ID's own error", res.Message)
	}
	if strings.Contains(res.Message, "Trace ID") || strings.Contains(res.Message, "not-the-secret") {
		t.Errorf("message %q carries trace noise or the secret", res.Message)
	}
	if len(f.subReads) != 0 {
		t.Error("the subscription was read without a token")
	}
	if store.testStatus != "error" {
		t.Errorf("integration status = %q, want error", store.testStatus)
	}
}

func TestTestConnection_AzureSubscriptionDenied(t *testing.T) {
	f := newFakeAzure(t)
	h, _ := f.handlers(t, goodSecret, deniedSub)
	res := runTestConnection(t, h)
	if res.Success {
		t.Fatal("a subscription the principal cannot read tested green")
	}
	if !strings.Contains(res.Message, "AuthorizationFailed") || !strings.Contains(res.Message, "403") {
		t.Errorf("message %q does not carry ARM's refusal", res.Message)
	}
}

// --- GCP -------------------------------------------------------------------

type fakeGCP struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	revokedKeyID string
	mu           sync.Mutex
	tokenCalls   int
	projectReads []string
}

func newFakeGCP(t *testing.T) *fakeGCP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGCP{key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token":
			f.mu.Lock()
			f.tokenCalls++
			f.mu.Unlock()
			_ = r.ParseForm()
			// The real exchange: the assertion must be signed by the key's
			// private half, as Google verifies it.
			claims := jwt.MapClaims{}
			_, perr := jwt.ParseWithClaims(r.Form.Get("assertion"), claims, func(*jwt.Token) (interface{}, error) { return &f.key.PublicKey, nil })
			if perr != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || claims["iss"] == f.revokedKeyID {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": fakeAccessToken, "expires_in": 3600, "token_type": "Bearer"})
		case strings.HasPrefix(r.URL.Path, "/projects/"):
			project := strings.Split(strings.TrimPrefix(r.URL.Path, "/projects/"), "/")[0]
			f.mu.Lock()
			f.projectReads = append(f.projectReads, project)
			f.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+fakeAccessToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if project == "denied-project" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{
					"code": 403, "message": "Required 'compute.sslPolicies.list' permission for 'projects/denied-project'", "status": "PERMISSION_DENIED",
				}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGCP) keyJSON(t *testing.T, email, project, tokenURI string) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	key := map[string]string{
		"type": "service_account", "project_id": project, "private_key_id": "k1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": email, "client_id": "1", "token_uri": tokenURI,
	}
	raw, _ := json.Marshal(key)
	return string(raw)
}

func (f *fakeGCP) handlers(t *testing.T, email, project, tokenURI string, tokenOverride bool) (*IntegrationHandlers, *stubIntegrationStore) {
	t.Helper()
	store := &stubIntegrationStore{testFound: true, testType: "gcp"}
	override := ""
	if tokenOverride {
		override = f.srv.URL + "/token"
	}
	h := &IntegrationHandlers{store: store, encryptionKey: testEncryptionKey,
		gcpOptions: []gcpclient.Option{gcpclient.WithEndpoints(f.srv.Client(), override, f.srv.URL)}}
	store.testConfig = storedConfig(t, h, map[string]interface{}{
		"project_id": project, "service_account_key": f.keyJSON(t, email, project, tokenURI),
	})
	return h, store
}

func TestTestConnection_GCPValidKeyReadsTheProject(t *testing.T) {
	f := newFakeGCP(t)
	h, store := f.handlers(t, "scanner@example-project.iam.gserviceaccount.com", "example-project", "https://oauth2.googleapis.com/token", true)
	res := runTestConnection(t, h)
	if !res.Success {
		t.Fatalf("a valid key failed: %q", res.Message)
	}
	if f.tokenCalls != 1 || len(f.projectReads) != 1 || f.projectReads[0] != "example-project" {
		t.Errorf("the test did not exchange the key and read the project: tokens=%d reads=%v", f.tokenCalls, f.projectReads)
	}
	if store.testStatus != "connected" {
		t.Errorf("integration status = %q, want connected", store.testStatus)
	}
}

func TestTestConnection_GCPRevokedKey(t *testing.T) {
	f := newFakeGCP(t)
	f.revokedKeyID = "revoked@example-project.iam.gserviceaccount.com"
	h, _ := f.handlers(t, f.revokedKeyID, "example-project", "https://oauth2.googleapis.com/token", true)
	res := runTestConnection(t, h)
	if res.Success {
		t.Fatal("a key Google refuses tested green")
	}
	if !strings.Contains(res.Message, "invalid_grant") {
		t.Errorf("message %q does not carry Google's refusal", res.Message)
	}
	if len(f.projectReads) != 0 {
		t.Error("the project was read without a token")
	}
}

func TestTestConnection_GCPProjectDenied(t *testing.T) {
	f := newFakeGCP(t)
	h, _ := f.handlers(t, "scanner@example-project.iam.gserviceaccount.com", "denied-project", "https://oauth2.googleapis.com/token", true)
	res := runTestConnection(t, h)
	if res.Success {
		t.Fatal("a project the account cannot read tested green")
	}
	for _, want := range []string{"PERMISSION_DENIED", "compute.sslPolicies.list", "roles/compute.viewer"} {
		if !strings.Contains(res.Message, want) {
			t.Errorf("message %q lacks %q", res.Message, want)
		}
	}
}

// The key is tenant-supplied JSON; the platform must not POST a signed
// assertion — or report the answer — to whatever token_uri it names.
func TestTestConnection_GCPForeignTokenURI(t *testing.T) {
	f := newFakeGCP(t)
	foreign := f.srv.URL + "/token" // a URL the platform can reach, but not Google's
	h, _ := f.handlers(t, "scanner@example-project.iam.gserviceaccount.com", "example-project", foreign, false)
	res := runTestConnection(t, h)
	if res.Success {
		t.Fatal("a key naming a non-Google token endpoint tested green")
	}
	if f.tokenCalls != 0 {
		t.Errorf("the platform posted the assertion to the key's foreign token_uri (%d call(s))", f.tokenCalls)
	}
	if !strings.Contains(res.Message, "token_uri") {
		t.Errorf("message %q does not say why", res.Message)
	}
}

// --- a credential the platform can no longer read --------------------------

// Test Connection used to decrypt leniently and hand a retired ciphertext to
// the provider as the secret. Discovery says "re-enter the credential"; so
// must the test, and nothing may reach the provider.
func TestTestConnection_RetiredCredential(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		isolateAWSAuthEnv(t)
		store := &stubIntegrationStore{testFound: true, testType: "aws"}
		h := &IntegrationHandlers{store: store, encryptionKey: testEncryptionKey}
		cfg, _ := json.Marshal(map[string]interface{}{"access_key_id": retiredCiphertext(), "secret_access_key": retiredCiphertext(), "region": "us-east-1"})
		store.testConfig = string(cfg)
		res := runTestConnection(t, h)
		if res.Success || !strings.Contains(res.Message, "Re-enter the credential") {
			t.Errorf("retired AWS credential: %+v, want a re-enter instruction", res)
		}
	})
	t.Run("azure", func(t *testing.T) {
		f := newFakeAzure(t)
		h, store := f.handlers(t, goodSecret, fakeSubscription)
		var cfg map[string]interface{}
		_ = json.Unmarshal([]byte(store.testConfig), &cfg)
		cfg["client_secret"] = retiredCiphertext()
		raw, _ := json.Marshal(cfg)
		store.testConfig = string(raw)
		res := runTestConnection(t, h)
		if res.Success || !strings.Contains(res.Message, "Re-enter the credential") {
			t.Errorf("retired Azure credential: %+v, want a re-enter instruction", res)
		}
		if f.tokenCalls != 0 {
			t.Error("the retired ciphertext was sent to Microsoft Entra ID as the client secret")
		}
	})
	t.Run("gcp", func(t *testing.T) {
		f := newFakeGCP(t)
		h, store := f.handlers(t, "scanner@example-project.iam.gserviceaccount.com", "example-project", "https://oauth2.googleapis.com/token", true)
		var cfg map[string]interface{}
		_ = json.Unmarshal([]byte(store.testConfig), &cfg)
		cfg["service_account_key"] = retiredCiphertext()
		raw, _ := json.Marshal(cfg)
		store.testConfig = string(raw)
		res := runTestConnection(t, h)
		if res.Success || !strings.Contains(res.Message, "Re-enter the credential") {
			t.Errorf("retired GCP credential: %+v, want a re-enter instruction", res)
		}
		if f.tokenCalls != 0 {
			t.Error("a token exchange was attempted with an unreadable key")
		}
	})
}

// --- a partial edit keeps what it does not touch ---------------------------

// MUTATION-VERIFIED: restore the lenient decrypt-everything/encrypt-everything
// merge and the retired secret comes back as a NEW ciphertext (of the old
// ciphertext), and the untouched client_id changes bytes.
func TestUpdateIntegration_PartialEditKeepsStoredCredentials(t *testing.T) {
	h := &IntegrationHandlers{encryptionKey: testEncryptionKey}
	retired := retiredCiphertext()
	stored := storedConfig(t, h, map[string]interface{}{"tenant_id": fakeTenant, "client_id": "app-id", "subscription_id": fakeSubscription})
	var existing map[string]interface{}
	_ = json.Unmarshal([]byte(stored), &existing)
	existing["client_secret"] = retired
	// A GCP-style legacy plaintext value in a sensitive key (not base64).
	existing["service_account_json"] = `{"type":"service_account"}`
	raw, _ := json.Marshal(existing)

	store := &stubIntegrationStore{updFound: true, updType: "azure", updConfig: string(raw)}
	h.store = store
	eng := newIntegrationEngine(store)
	w := do(eng, http.MethodPut, base+"/integrations/"+aUUID, strings.NewReader(`{"config":{"enumerate_compute":false}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var written map[string]interface{}
	if err := json.Unmarshal([]byte(fmt.Sprint(store.updFields["config"])), &written); err != nil {
		t.Fatalf("written config: %v", err)
	}
	if written["client_secret"] != retired {
		t.Errorf("an edit that did not touch client_secret rewrote it: %v -> %v", retired, written["client_secret"])
	}
	if written["client_id"] != existing["client_id"] {
		t.Error("an edit that did not touch client_id rewrote it")
	}
	if written["enumerate_compute"] != false {
		t.Errorf("enumerate_compute = %v, want false", written["enumerate_compute"])
	}
	// Legacy plaintext is still migrated to ciphertext on the next edit.
	legacy, _ := written["service_account_json"].(string)
	if legacy == `{"type":"service_account"}` {
		t.Error("legacy plaintext in a sensitive key was left in the clear")
	}
	if dec, err := h.decryptConfig(map[string]interface{}{"service_account_json": legacy}); err != nil || dec["service_account_json"] != `{"type":"service_account"}` {
		t.Errorf("migrated legacy value does not decrypt back: %v %v", dec, err)
	}
}
