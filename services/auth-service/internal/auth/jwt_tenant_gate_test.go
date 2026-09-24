package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// TestJWTService_TenantGateCoversEveryTenantMint pins that the gate sits on
// EVERY function that mints a tenant session — password login, refresh, both
// SSO callbacks and invitation acceptance all use GenerateTokens*, the PAT
// exchange uses GenerateScopedAccessTokenWithTTL — so no sign-in path can hand
// a suspended tenant a token. Mutation: drop checkTenant from any one of the
// three mint functions and its row fails.
//
// Impersonation is deliberately NOT gated (platform support may look at a
// suspended tenant), and platform sessions (no tenant) never consult the gate.
func TestJWTService_TenantGateCoversEveryTenantMint(t *testing.T) {
	blocked := uuid.New()
	calls := 0
	j := NewJWTService("test-secret-for-tenant-gate", time.Hour, time.Hour)
	j.SetTenantGate(func(_ context.Context, id uuid.UUID) error {
		calls++
		if id == blocked {
			return &tenantstate.BlockedError{Code: tenantstate.CodeSuspended}
		}
		return nil
	})

	mints := map[string]func(tenant uuid.UUID) error{
		"GenerateTokens (login/refresh/SSO/invite)": func(tenant uuid.UUID) error {
			_, _, err := j.GenerateTokens(uuid.New(), tenant, "u@example.test", "viewer")
			return err
		},
		"GenerateTokensWithPasswordChange": func(tenant uuid.UUID) error {
			_, _, err := j.GenerateTokensWithPasswordChange(uuid.New(), tenant, "u@example.test", "viewer", time.Hour, true)
			return err
		},
		"GenerateAccessTokenWithTTL": func(tenant uuid.UUID) error {
			_, _, _, err := j.GenerateAccessTokenWithTTL(uuid.New(), tenant, "u@example.test", "viewer", time.Minute)
			return err
		},
		"GenerateScopedAccessTokenWithTTL (PAT exchange)": func(tenant uuid.UUID) error {
			_, _, _, err := j.GenerateScopedAccessTokenWithTTL(uuid.New(), tenant, "u@example.test", "viewer", []string{"assets.read"}, time.Minute)
			return err
		},
	}
	for name, mint := range mints {
		if be, ok := tenantstate.AsBlocked(mint(blocked)); !ok || be.Code != tenantstate.CodeSuspended {
			t.Errorf("%s minted a session for a suspended tenant", name)
		}
		if err := mint(uuid.New()); err != nil {
			t.Errorf("%s refused a live tenant: %v", name, err)
		}
	}

	calls = 0
	if _, _, err := j.GenerateTokens(uuid.New(), uuid.Nil, "admin@example.test", "super_admin"); err != nil {
		t.Fatalf("platform session refused: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a platform session consulted the tenant gate (%d calls)", calls)
	}
	if _, _, _, err := j.GenerateImpersonationToken(uuid.New(), blocked, "u@example.test", "viewer",
		uuid.NewString(), "admin@example.test", "support", "203.0.113.1", "ua", time.Minute); err != nil {
		t.Fatalf("impersonation of a suspended tenant refused: %v (platform support access is allowed)", err)
	}
}

func TestJWTService_TokensCarryTenantSessionVersion(t *testing.T) {
	tenantID := uuid.New()
	j := NewJWTService("test-secret-for-session-version", time.Hour, time.Hour)
	j.SetTenantVersionGate(func(_ context.Context, id uuid.UUID) (int64, error) {
		if id != tenantID {
			t.Fatalf("gate tenant = %s, want %s", id, tenantID)
		}
		return 7, nil
	})

	access, refresh, err := j.GenerateTokens(uuid.New(), tenantID, "u@example.test", "viewer")
	if err != nil {
		t.Fatalf("GenerateTokens: %v", err)
	}
	for name, token := range map[string]string{"access": access, "refresh": refresh} {
		claims, err := j.ValidateToken(token)
		if err != nil {
			t.Fatalf("ValidateToken(%s): %v", name, err)
		}
		if claims.TenantSessionVersion != 7 {
			t.Errorf("%s tenant_session_version = %d, want 7", name, claims.TenantSessionVersion)
		}
	}
}
