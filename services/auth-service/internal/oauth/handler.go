package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/apitokens"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

const (
	authCodeTTL    = 10 * time.Minute
	mcpTokenName   = "MCP OAuth"
	mcpTokenExpiry = 90 // days
)

// mcpScopes are the read-only permissions issued to every MCP OAuth token.
var mcpScopes = []string{"assets.read", "compliance.read", "reports.read"}

// Handler holds the dependencies for all OAuth endpoints.
type Handler struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the token
	// endpoint: it resolves the tenant FROM the presented auth code's hash
	// (the client is unauthenticated at that point) and marks the code used by
	// the same hash. Pre-flip it resolves to the same connection as db.
	bypassDB   *sql.DB
	jwtService *auth.JWTService
	patService *apitokens.Service
	cfg        *config.Config
}

func NewHandler(db *sql.DB, bypassDB *sql.DB, jwtService *auth.JWTService, cfg *config.Config) *Handler {
	return &Handler{
		db:         db,
		bypassDB:   bypassDB,
		jwtService: jwtService,
		patService: apitokens.NewService(db, bypassDB),
		cfg:        cfg,
	}
}

// WellKnown serves the RFC 8414 authorization server metadata.
// GET /.well-known/oauth-authorization-server
func (h *Handler) WellKnown(c *gin.Context) {
	base := getIssuer(h.cfg)
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                base,
		"authorization_endpoint":                base + "/api/v1/auth-service/oauth/authorize",
		"token_endpoint":                        base + "/api/v1/auth-service/oauth/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// Authorize handles the authorization endpoint (GET = show consent, POST = decision).
// GET /api/v1/auth-service/oauth/authorize
func (h *Handler) AuthorizeGET(c *gin.Context) {
	params, errMsg := validateAuthorizeParams(c)
	if errMsg != "" {
		// RFC 6749 §4.1.2.1: never redirect on bad client_id or redirect_uri.
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	// Check for a valid session cookie.
	claims, err := h.sessionFromCookie(c)
	if err != nil {
		// Not logged in — redirect to web-ui login with ?next= pointing back here.
		loginURL := h.loginRedirectURL(c.Request.URL.String())
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	client, _ := LookupClient(params.clientID)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	renderConsent(c.Writer, consentData{
		ClientName:  client.Name,
		UserEmail:   claims.Email,
		Scopes:      mcpScopes,
		ClientID:    params.clientID,
		RedirectURI: params.redirectURI,
		State:       params.state,
		Challenge:   params.codeChallenge,
	})
}

// AuthorizePOST handles the user's Allow / Deny decision.
// POST /api/v1/auth-service/oauth/authorize
func (h *Handler) AuthorizePOST(c *gin.Context) {
	params, errMsg := validateAuthorizeParams(c)
	if errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	claims, err := h.sessionFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
		return
	}

	decision := c.PostForm("decision")
	if decision != "allow" {
		redirectWithError(c, params.redirectURI, "access_denied", "user denied access", params.state)
		return
	}

	// Mint an auth code and store its hash.
	rawCode, codeHash, err := generateCode()
	if err != nil {
		redirectWithError(c, params.redirectURI, "server_error", "failed to generate code", params.state)
		return
	}

	// RLS-scoped write: oauth_authorization_codes carries a tenant_isolation
	// policy and the tenant is known from the authenticated session (claims),
	// so the INSERT runs inside WithTenantTx — app.tenant_id satisfies WITH CHECK.
	err = shareddatabase.WithTenantTx(c.Request.Context(), h.db, claims.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(c.Request.Context(), `
			INSERT INTO oauth_authorization_codes
				(code_hash, client_id, redirect_uri, user_id, tenant_id, code_challenge, scopes, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			codeHash,
			params.clientID,
			params.redirectURI,
			claims.UserID,
			claims.TenantID,
			params.codeChallenge,
			mcpScopes,
			time.Now().UTC().Add(authCodeTTL),
		)
		return e
	})
	if err != nil {
		redirectWithError(c, params.redirectURI, "server_error", "failed to store code", params.state)
		return
	}

	dest, _ := url.Parse(params.redirectURI)
	q := dest.Query()
	q.Set("code", rawCode)
	if params.state != "" {
		q.Set("state", params.state)
	}
	dest.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, dest.String())
}

// Token handles the token endpoint: exchanges an auth code for a PAT.
// POST /api/v1/auth-service/oauth/token
func (h *Handler) Token(c *gin.Context) {
	clientID := strings.TrimSpace(c.PostForm("client_id"))
	redirectURI := strings.TrimSpace(c.PostForm("redirect_uri"))
	rawCode := strings.TrimSpace(c.PostForm("code"))
	codeVerifier := strings.TrimSpace(c.PostForm("code_verifier"))
	grantType := strings.TrimSpace(c.PostForm("grant_type"))

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	if grantType != "authorization_code" {
		tokenError(c, "unsupported_grant_type", "")
		return
	}
	if clientID == "" || redirectURI == "" || rawCode == "" || codeVerifier == "" {
		tokenError(c, "invalid_request", "missing required parameters")
		return
	}

	client, ok := LookupClient(clientID)
	if !ok || !client.ValidateRedirectURI(redirectURI) {
		tokenError(c, "invalid_client", "")
		return
	}

	codeHash := hashCode(rawCode)

	var (
		storedChallenge string
		userID          uuid.UUID
		tenantID        uuid.UUID
		expiresAt       time.Time
		usedAt          sql.NullTime
	)
	// RLS: cross-tenant — runs on the bypass role (Phase 4). The token endpoint
	// resolves the tenant FROM the presented auth code's hash; the tenant is the
	// query OUTPUT (the client is unauthenticated at this point). Wrapping would
	// fail closed. The follow-up "mark used" UPDATE is keyed by the same hash.
	err := h.bypassDB.QueryRowContext(c.Request.Context(), `
		SELECT code_challenge, user_id, tenant_id, expires_at, used_at
		FROM oauth_authorization_codes
		WHERE code_hash = $1 AND client_id = $2 AND redirect_uri = $3`,
		codeHash, clientID, redirectURI,
	).Scan(&storedChallenge, &userID, &tenantID, &expiresAt, &usedAt)
	if err == sql.ErrNoRows {
		tokenError(c, "invalid_grant", "")
		return
	}
	if err != nil {
		tokenError(c, "server_error", "")
		return
	}
	if usedAt.Valid {
		tokenError(c, "invalid_grant", "code already used")
		return
	}
	if time.Now().UTC().After(expiresAt) {
		tokenError(c, "invalid_grant", "code expired")
		return
	}
	if !verifyPKCE(codeVerifier, storedChallenge) {
		tokenError(c, "invalid_grant", "PKCE verification failed")
		return
	}

	// Mark the code as used before minting the token (prevents replay on error).
	_, err = h.bypassDB.ExecContext(c.Request.Context(),
		`UPDATE oauth_authorization_codes SET used_at = now() WHERE code_hash = $1`,
		codeHash,
	)
	if err != nil {
		tokenError(c, "server_error", "")
		return
	}

	_, plaintext, err := h.patService.Create(tenantID, userID, mcpTokenName, mcpScopes, mcpTokenExpiry)
	if err != nil {
		tokenError(c, "server_error", "failed to mint token")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": plaintext,
		"token_type":   "Bearer",
		"expires_in":   mcpTokenExpiry * 24 * 60 * 60,
	})
}

// --- helpers ---

type authorizeParams struct {
	clientID      string
	redirectURI   string
	state         string
	codeChallenge string
}

func validateAuthorizeParams(c *gin.Context) (authorizeParams, string) {
	var p authorizeParams
	// Support both GET query params and POST form values.
	get := func(k string) string {
		if v := c.Query(k); v != "" {
			return v
		}
		return c.PostForm(k)
	}

	p.clientID = strings.TrimSpace(get("client_id"))
	p.redirectURI = strings.TrimSpace(get("redirect_uri"))
	p.state = get("state")
	p.codeChallenge = strings.TrimSpace(get("code_challenge"))
	method := strings.TrimSpace(get("code_challenge_method"))
	responseType := strings.TrimSpace(get("response_type"))

	client, ok := LookupClient(p.clientID)
	if !ok {
		return p, "unknown client_id"
	}
	if !client.ValidateRedirectURI(p.redirectURI) {
		return p, "redirect_uri not allowed for this client"
	}
	if responseType != "code" {
		return p, "response_type must be 'code'"
	}
	if p.codeChallenge == "" {
		return p, "code_challenge is required (PKCE)"
	}
	if method != "S256" {
		return p, "code_challenge_method must be S256"
	}
	return p, ""
}

func (h *Handler) sessionFromCookie(c *gin.Context) (*auth.JWTClaims, error) {
	token, err := c.Cookie("access_token")
	if err != nil || token == "" {
		return nil, http.ErrNoCookie
	}
	return h.jwtService.ValidateToken(token)
}

func (h *Handler) loginRedirectURL(nextURL string) string {
	frontendBase := getFrontendURL(h.cfg)
	return frontendBase + "/login?next=" + url.QueryEscape(nextURL)
}

func generateCode() (raw, hashed string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hashed = hashCode(raw)
	return
}

func hashCode(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

func redirectWithError(c *gin.Context, redirectURI, errCode, desc, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errCode)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func tokenError(c *gin.Context, errCode, desc string) {
	body := gin.H{"error": errCode}
	if desc != "" {
		body["error_description"] = desc
	}
	status := http.StatusBadRequest
	if errCode == "server_error" {
		status = http.StatusInternalServerError
	}
	c.JSON(status, body)
}

// getIssuer returns the public base URL used as the OAuth issuer identifier.
// Reuses the same logic as getBaseURL in api/base_url.go (cfg.OAuthCallbackBaseURL or
// CORSOrigins[0]).
func getIssuer(cfg *config.Config) string {
	if base := strings.TrimSpace(cfg.OAuthCallbackBaseURL); base != "" {
		return strings.TrimRight(base, "/")
	}
	if len(cfg.CORSOrigins) > 0 {
		return strings.TrimRight(cfg.CORSOrigins[0], "/")
	}
	return ""
}

// getFrontendURL returns the web-ui origin (CORSOrigins[0]) for login redirects.
func getFrontendURL(cfg *config.Config) string {
	if len(cfg.CORSOrigins) > 0 {
		return strings.TrimRight(cfg.CORSOrigins[0], "/")
	}
	return ""
}

// consentData is passed to renderConsent.
type consentData struct {
	ClientName  string
	UserEmail   string
	Scopes      []string
	ClientID    string
	RedirectURI string
	State       string
	Challenge   string
}

// renderConsent writes the consent HTML page directly to w. Kept as a
// server-rendered template (no React build dependency) so it works even if
// the web-ui container is unhealthy.
func renderConsent(w http.ResponseWriter, d consentData) {
	scopeLabels := map[string]string{
		"assets.read":     "Read your cryptographic asset inventory",
		"compliance.read": "Read your compliance posture and framework scores",
		"reports.read":    "Read your CBOM artifacts and reports",
	}

	scopeItems := ""
	for _, s := range d.Scopes {
		label := scopeLabels[s]
		if label == "" {
			label = s
		}
		scopeItems += `<li>` + escapeHTML(label) + `</li>`
	}

	// Hidden fields carry the validated params through the POST decision.
	hidden := ``
	for k, v := range map[string]string{
		"client_id":             d.ClientID,
		"redirect_uri":          d.RedirectURI,
		"state":                 d.State,
		"code_challenge":        d.Challenge,
		"code_challenge_method": "S256",
		"response_type":         "code",
	} {
		hidden += `<input type="hidden" name="` + escapeHTML(k) + `" value="` + escapeHTML(v) + `">`
	}

	page := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize access — Vista</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8fafc;color:#1e293b;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
  .card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:2.5rem;max-width:420px;width:100%}
  .logo{font-size:1.1rem;font-weight:700;color:#6366f1;margin-bottom:1.5rem}
  h1{font-size:1.25rem;font-weight:600;margin-bottom:.5rem}
  .sub{color:#64748b;font-size:.9rem;margin-bottom:1.5rem}
  ul{list-style:none;margin-bottom:1.75rem}
  li{padding:.5rem 0;border-bottom:1px solid #f1f5f9;font-size:.9rem;display:flex;gap:.5rem}
  li::before{content:"✓";color:#10b981;font-weight:700;flex-shrink:0}
  .readonly{font-size:.8rem;color:#64748b;margin-bottom:1.5rem;padding:.75rem;background:#f8fafc;border-radius:6px}
  .actions{display:flex;gap:.75rem}
  .btn{flex:1;padding:.7rem;border-radius:8px;font-size:.95rem;font-weight:600;cursor:pointer;border:none;transition:opacity .15s}
  .btn-allow{background:#6366f1;color:#fff}
  .btn-allow:hover{opacity:.9}
  .btn-deny{background:#f1f5f9;color:#475569}
  .btn-deny:hover{background:#e2e8f0}
  .user{font-size:.8rem;color:#94a3b8;margin-top:1.5rem;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Vista</div>
  <h1>` + escapeHTML(d.ClientName) + ` wants access</h1>
  <p class="sub">This will allow <strong>` + escapeHTML(d.ClientName) + `</strong> to read your Vista data.</p>
  <ul>` + scopeItems + `</ul>
  <p class="readonly">Access is <strong>read-only</strong>. ` + escapeHTML(d.ClientName) + ` cannot modify anything in your account.</p>
  <form method="POST">
    ` + hidden + `
    <div class="actions">
      <button class="btn btn-deny" name="decision" value="deny" type="submit">Deny</button>
      <button class="btn btn-allow" name="decision" value="allow" type="submit">Allow</button>
    </div>
  </form>
  <p class="user">Signed in as ` + escapeHTML(d.UserEmail) + `</p>
</div>
</body>
</html>`

	_, _ = w.Write([]byte(page))
}

// escapeHTML replaces the five characters that need escaping in HTML contexts.
func escapeHTML(s string) string {
	b, _ := json.Marshal(s)
	s = string(b[1 : len(b)-1]) // strip JSON quotes
	r := strings.NewReplacer(
		`&`, "&amp;",
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&#34;",
		`'`, "&#39;",
	)
	return r.Replace(s)
}
