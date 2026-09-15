package identity_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestResolveDependent(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	ctx := context.Background()
	host := identity.AssetRef{TenantID: tenant, ID: "asset-001"}
	tenantOnly := identity.AssetRef{TenantID: tenant}

	t.Run("an endpoint is keyed under its asset", func(t *testing.T) {
		got, err := e.ResolveDependent(ctx, identity.DependentEndpoint, host, identity.EndpointKey("192.0.2.10", 443, "tcp"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		if !strings.Contains(got.Canonical, host.ID) {
			t.Errorf("canonical %q does not name the parent asset", got.Canonical)
		}
		// The same endpoint under a different host is a different thing.
		other, err := e.ResolveDependent(ctx, identity.DependentEndpoint, identity.AssetRef{TenantID: tenant, ID: "asset-002"}, identity.EndpointKey("192.0.2.10", 443, "tcp"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		if other.Canonical == got.Canonical {
			t.Errorf("two hosts produced one endpoint key: %q", got.Canonical)
		}
	})

	t.Run("an application is keyed by product and instance under its host", func(t *testing.T) {
		a, err := e.ResolveDependent(ctx, identity.DependentApplication, host, identity.ApplicationKey("postgres", "main"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		b, err := e.ResolveDependent(ctx, identity.DependentApplication, host, identity.ApplicationKey("postgres", "replica"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		if a.Canonical == b.Canonical {
			t.Errorf("two instances of one product produced one key: %q", a.Canonical)
		}
	})

	t.Run("a service is keyed by name within the tenant", func(t *testing.T) {
		got, err := e.ResolveDependent(ctx, identity.DependentService, tenantOnly, identity.ServiceKey("Payments"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		if !strings.Contains(got.Canonical, tenant) {
			t.Errorf("canonical %q does not name the tenant", got.Canonical)
		}
		// Case-insensitive: "Payments" and "payments" are one service.
		same, err := e.ResolveDependent(ctx, identity.DependentService, tenantOnly, identity.ServiceKey("payments"))
		if err != nil {
			t.Fatalf("ResolveDependent: %v", err)
		}
		if same.Canonical != got.Canonical {
			t.Errorf("%q and %q are the same service but produced different keys", got.Canonical, same.Canonical)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name   string
			kind   identity.DependentKind
			parent identity.AssetRef
			key    string
			want   string
		}{
			{"unknown kind", identity.DependentKind("widget"), host, "k", "unknown dependent kind"},
			{"empty key", identity.DependentEndpoint, host, "  ", "empty key"},
			{"no tenant", identity.DependentEndpoint, identity.AssetRef{ID: "asset-001"}, "k", "no tenant"},
			{"endpoint with no parent", identity.DependentEndpoint, tenantOnly, "k", "needs a parent asset"},
			{"application with no parent", identity.DependentApplication, tenantOnly, "k", "needs a parent asset"},
			{"service with a parent", identity.DependentService, host, "k", "must not have a parent asset"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := e.ResolveDependent(ctx, tc.kind, tc.parent, tc.key)
				if err == nil {
					t.Fatalf("ResolveDependent accepted %s", tc.name)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.want)
				}
			})
		}
	})
}

func TestDependentKindValid(t *testing.T) {
	for _, k := range []identity.DependentKind{identity.DependentEndpoint, identity.DependentApplication, identity.DependentService} {
		if !k.Valid() {
			t.Errorf("%s.Valid() = false", k)
		}
	}
	if identity.DependentKind("certificate").Valid() {
		t.Error("an invented dependent kind reported itself valid")
	}
	if identity.DependentService.NeedsParent() {
		t.Error("a service must not need a parent asset: it is identified by (tenant, name)")
	}
}

func TestEndpointKeyIsTheOneSpelling(t *testing.T) {
	// The struct method and the exported helper must agree — two spellings of
	// a dedupe key is exactly the failure the engine exists to end.
	ep := identity.EndpointObservation{Address: "192.0.2.10", Port: 443, Transport: "TCP"}
	if got, want := ep.Key(), identity.EndpointKey("192.0.2.10", 443, "tcp"); got != want {
		t.Fatalf("EndpointObservation.Key() = %q, EndpointKey() = %q", got, want)
	}

	// An endpoint known only by name keys on the name.
	byName := identity.EndpointObservation{FQDN: "api.example.com", Port: 443, Transport: "tcp"}
	if got, want := byName.Key(), identity.EndpointKey("api.example.com", 443, "tcp"); got != want {
		t.Fatalf("name-only endpoint key = %q, want %q", got, want)
	}

	// An at-rest endpoint (no port, no transport) is distinguishable from a
	// port-0 socket only by its transport, which is why "" becomes "none".
	atRest := identity.EndpointObservation{Address: "192.0.2.10"}
	if got := atRest.Key(); !strings.HasSuffix(got, "|none") {
		t.Errorf("at-rest endpoint key = %q, want a 'none' transport", got)
	}
}
