package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// fingerprintLen is how much of the token hash is recorded on auth events —
// enough to correlate a credential across events, far too little to reverse.
const fingerprintLen = 16

// cacheKey derives the grant-cache key from the PAT without retaining the
// plaintext in memory beyond the request.
func cacheKey(pat string) string {
	sum := sha256.Sum256([]byte(pat))
	return hex.EncodeToString(sum[:])
}

// exchangeSafety is how long before JWT expiry a cached grant is considered
// stale — generous enough that a grant never expires mid tool-call fan-out.
const exchangeSafety = 2 * time.Minute

// maxCacheEntries bounds the grant cache; beyond it the cache is dropped
// wholesale (simple and sufficient — entries self-expire in minutes).
const maxCacheEntries = 10000

// Exchanger resolves API tokens (PATs) to Grants via auth-service's
// HMAC-guarded /internal/api-tokens/exchange endpoint, caching the resulting
// short-lived JWT until just before expiry so the hot path costs one map hit.
type Exchanger struct {
	authBaseURL string
	httpc       *http.Client
	audit       *auditlog.Recorder

	mu    sync.Mutex
	cache map[string]*Grant // key: SHA-256 of the PAT (never the plaintext)
}

func NewExchanger(authBaseURL string, httpc *http.Client, rec *auditlog.Recorder) *Exchanger {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exchanger{
		authBaseURL: authBaseURL,
		httpc:       httpc,
		audit:       rec,
		cache:       map[string]*Grant{},
	}
}

type exchangeResponse struct {
	AccessToken string   `json:"access_token"`
	ExpiresAt   string   `json:"expires_at"`
	TenantID    string   `json:"tenant_id"`
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// Exchange resolves the plaintext PAT to a Grant, consulting the cache first.
// Any auth-service rejection surfaces as ErrUnauthorized.
//
// Audit: every credential decision auth-service actually makes is recorded —
// the fresh exchange that accepted a token, and every rejection or backend
// failure. A cache hit records nothing, because no decision was taken; the
// identity is still on every tool-call record, so no read is left unattributed.
func (e *Exchanger) Exchange(ctx context.Context, pat string) (*Grant, error) {
	key := cacheKey(pat)
	fingerprint := key[:fingerprintLen]

	e.mu.Lock()
	if g, ok := e.cache[key]; ok && time.Until(g.ExpiresAt) > exchangeSafety {
		e.mu.Unlock()
		return g, nil
	}
	e.mu.Unlock()

	body, err := json.Marshal(map[string]string{"token": pat})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.authBaseURL+"/api/v1/auth-service/internal/api-tokens/exchange", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(req)

	resp, err := e.httpc.Do(req)
	if err != nil {
		err = fmt.Errorf("auth-service unreachable: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusUnauthorized, http.StatusBadRequest:
		e.recordAuth(ctx, auditlog.OutcomeTokenRejected, fingerprint, Grant{}, ErrUnauthorized)
		return nil, ErrUnauthorized
	default:
		err := fmt.Errorf("auth-service exchange returned %d", resp.StatusCode)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}

	var er exchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		err = fmt.Errorf("failed to decode exchange response: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, er.ExpiresAt)
	if err != nil {
		err = fmt.Errorf("failed to parse exchange expiry: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}

	g := &Grant{
		AccessToken: er.AccessToken,
		ExpiresAt:   expiresAt,
		TenantID:    er.TenantID,
		UserID:      er.UserID,
		Email:       er.Email,
		Role:        er.Role,
		Permissions: er.Permissions,
	}

	e.mu.Lock()
	if len(e.cache) >= maxCacheEntries {
		e.cache = map[string]*Grant{}
	}
	e.cache[key] = g
	e.mu.Unlock()

	e.recordAuth(ctx, auditlog.OutcomeTokenExchanged, fingerprint, *g, nil)

	return g, nil
}

// recordAuth writes one authentication decision to the shared audit path.
func (e *Exchanger) recordAuth(ctx context.Context, outcome, fingerprint string, g Grant, err error) {
	e.audit.RecordAuth(ctx, auditlog.AuthEvent{
		Outcome:          outcome,
		Identity:         g.Identity(),
		Request:          RequestContextFrom(ctx),
		TokenFingerprint: fingerprint,
		Err:              err,
	})
}
