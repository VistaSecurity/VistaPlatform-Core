package edition

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// TenantProviderFeature is the entitlement that lets a tenant connect its own
// model provider. Enterprise-gated (shared/entitlements/editions.go): on for
// every tenant under an Enterprise licence, decided per plan under an MSP one,
// and never on in Core — which has no model clients to connect to anyway.
const TenantProviderFeature = "ai_tenant_provider"

// NewProviderResolver builds the process's [ai.Resolver]: stored providers from
// db, credentials under ENCRYPTION_MASTER_KEY, and the tenant gate from the
// entitlements resolver. Build one per process and hand it to every seam.
//
// A nil db yields a resolver that knows only the environment.
func NewProviderResolver(db *sql.DB) *ai.Resolver {
	if db == nil {
		return ai.NewResolver(nil, ai.KeyCipherFromEnv(), denyAll)
	}
	return ai.NewResolver(db, ai.KeyCipherFromEnv(), TenantProviderGate(entitlements.NewPostgresResolver(db)))
}

// TenantProviderGate adapts an entitlements resolver to [ai.TenantGate].
//
// An item the catalogue does not know is "no", not an error: that is a
// database seeded before this capability existed, and the honest answer for it
// is that no plan there includes it. Every other failure is returned, because
// the resolver must not guess whether a tenant that HAS a provider may use it.
func TenantProviderGate(r entitlements.Resolver) ai.TenantGate {
	return func(ctx context.Context, tenantID uuid.UUID) (bool, error) {
		ok, err := entitlements.IsEnabled(ctx, r, tenantID, TenantProviderFeature)
		if errors.Is(err, entitlements.ErrUnknownItem) {
			return false, nil
		}
		return ok, err
	}
}

func denyAll(context.Context, uuid.UUID) (bool, error) { return false, nil }
