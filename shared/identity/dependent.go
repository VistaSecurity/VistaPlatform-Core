package identity

import (
	"context"
	"fmt"
	"strings"
)

// DependentKind names a thing with no independent identity: it is identified
// by its position under something else, never on its own (ADR-0002 D3, which
// borrows ServiceNow's term).
type DependentKind string

const (
	// DependentEndpoint — an endpoint, keyed (asset, address|fqdn, port,
	// transport). Build the key with [EndpointKey].
	DependentEndpoint DependentKind = "endpoint"
	// DependentApplication — an application, keyed (host asset, product,
	// instance name). Build the key with [ApplicationKey].
	DependentApplication DependentKind = "application"
	// DependentService — a business or technical service, keyed (tenant,
	// name): it is declared, never discovered, and has no host. Build the key
	// with [ServiceKey].
	DependentService DependentKind = "service"
)

// Valid reports whether k is one of the three dependent kinds.
func (k DependentKind) Valid() bool {
	switch k {
	case DependentEndpoint, DependentApplication, DependentService:
		return true
	default:
		return false
	}
}

// NeedsParent reports whether this kind is identified under a parent asset.
// Services are not: they are tenant-scoped by name.
func (k DependentKind) NeedsParent() bool {
	return k == DependentEndpoint || k == DependentApplication
}

// DependentIdentity is the resolved dedupe key of a dependent thing.
type DependentIdentity struct {
	Kind   DependentKind `json:"kind"`
	Parent AssetRef      `json:"parent,omitzero"`
	// Key is the natural key as supplied.
	Key string `json:"key"`
	// Canonical is the full key including the scope it is unique within: the
	// parent asset for an endpoint or application, the tenant for a service.
	// This is the string an upsert deduplicates on.
	Canonical string `json:"canonical"`
}

// ResolveDependent derives the identity of a thing that has none of its own.
//
// It is the one place the dependent-identity rules of ADR-0002 D3 are written
// down, so the phase-1 upserts (workstream 1.2) share a spelling of each key
// instead of each inventing one — which is exactly how six intake paths came
// to use four different dedupe keys.
//
// It derives; it does not query. There is no repository method behind it
// because the tables it keys into (`asset_endpoints`, and the application and
// service rows) are phase-1 shapes, and inventing a reader for them now would
// be an interface with no implementation on either side. Callers use the
// returned Canonical as the conflict target of their upsert.
//
// The `key` argument is the kind's natural key, built by [EndpointKey],
// [ApplicationKey] or [ServiceKey]. Pass the tenant in `parent` for a service,
// whose parent is the tenant and not an asset.
func (e *Engine) ResolveDependent(ctx context.Context, kind DependentKind, parent AssetRef, key string) (DependentIdentity, error) {
	_ = ctx // no lookup: see the doc comment.

	if !kind.Valid() {
		return DependentIdentity{}, fmt.Errorf("identity: unknown dependent kind %q", string(kind))
	}
	k := strings.TrimSpace(key)
	if k == "" {
		return DependentIdentity{}, fmt.Errorf("identity: %s: empty key", kind)
	}
	if strings.TrimSpace(parent.TenantID) == "" {
		return DependentIdentity{}, fmt.Errorf("identity: %s: no tenant", kind)
	}
	if kind.NeedsParent() && parent.ID == "" {
		return DependentIdentity{}, fmt.Errorf("identity: %s: needs a parent asset; a %s is identified under its host, never on its own", kind, kind)
	}
	if !kind.NeedsParent() && parent.ID != "" {
		// A service keyed under an asset would be a different service per
		// host, which is the opposite of what a business service is.
		return DependentIdentity{}, fmt.Errorf("identity: %s: must not have a parent asset; it is identified by (tenant, name)", kind)
	}

	scope := parent.TenantID
	if kind.NeedsParent() {
		scope = parent.ID
	}
	return DependentIdentity{
		Kind:      kind,
		Parent:    parent,
		Key:       k,
		Canonical: string(kind) + ":" + scope + ":" + k,
	}, nil
}
