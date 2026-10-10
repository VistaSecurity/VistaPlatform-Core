// Package sightingserver is a REFERENCE implementation of inventory-service's
// internal sightings route (sightingclient.Path), for the tests of services
// that post sightings rather than resolve them (platform ADR-0003 D3).
//
// It does what that route is specified to do, over a real Postgres through
// shared/identity/postgres: per sighting, one transaction that reads the
// tenant's auto-accept threshold and rule-merge switch, runs identity.Intake
// and the engine (configured as inventory-service configures its own, with
// ProvisionalInventory on), writes the Intake's withheld attribute evidence
// onto the resolved asset, gives a settled asset its own segment's location
// when it records none, and projects a first-hand sighting's segment onto the
// asset's location; one retry on ErrIdentifierConflict.
//
// It is NOT inventory-service's handler, and a collector's test passing here
// says only that the collector speaks the contract. The end-to-end proof is
// the same test run against inventory-service once its route ships; until
// then this keeps every device-interrogation-service test exercising a real
// HTTP hop, a real HMAC signature and a real resolution.
package sightingserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// Secret is the INTERNAL_AUTH_SECRET the test server verifies against; the
// client from [Start] signs with it.
const Secret = "sightingserver-test-secret"

// Resolver resolves sightings over one database.
type Resolver struct {
	repo *pgidentity.Repository
	eng  *identity.Engine
	in   *identity.Intake

	// URL is the test server's base URL once [Start] has started one.
	URL string

	mu    sync.Mutex
	calls int
}

// NewResolver builds the reference resolution over db (an owner or app-role
// connection; tenant scoping is the repository's).
func NewResolver(db *sql.DB) (*Resolver, error) {
	repo := pgidentity.New(db)
	eng, err := identity.New(identity.Config{
		AdmissionEnabled:     identity.AvailableCapabilities().Admission,
		Repo:                 repo,
		ProvisionalInventory: true,
	})
	if err != nil {
		return nil, err
	}
	in, err := identity.NewIntake(repo)
	if err != nil {
		return nil, err
	}
	return &Resolver{repo: repo, eng: eng, in: in}, nil
}

// Calls is how many sightings have been resolved, so a test can tell a path
// that posted from one that wrote around the route.
func (r *Resolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// Resolve is one sighting's resolution.
func (r *Resolver) Resolve(ctx context.Context, s identity.Sighting) sightingclient.Result {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	var res identity.Resolution
	run := func() error {
		return r.repo.RunInTx(ctx, s.TenantID, func(b *pgidentity.Repository) error {
			assessed, err := r.in.Assess(ctx, s)
			if err != nil {
				return err
			}
			obs := assessed.Observation
			threshold, err := identitysettings.ReadAutoAcceptThresholdFor(ctx, b.Tx(), s.TenantID)
			if err != nil {
				return err
			}
			autoMerge, err := identitysettings.ReadAutoMergeExistingFor(ctx, b.Tx(), s.TenantID)
			if err != nil {
				return err
			}
			res, err = r.eng.WithAutoAcceptThreshold(threshold).WithAutoMergeExisting(autoMerge).WithRepository(b).Resolve(ctx, obs)
			if err != nil {
				return err
			}
			if res.Asset.Zero() {
				return nil
			}
			// As the route: any settled resolution keeps the asset's placement
			// consistent with the segment it is already in.
			if res.Outcome != identity.OutcomeConflict {
				if err := b.InheritSegmentLocation(ctx, res.Asset, obs.Source); err != nil {
					return err
				}
			}
			for key, values := range assessed.AttributeEvidence {
				limit := attrlist.MaxAddressEvidence
				if key == attrlist.KeySyntheticNames {
					limit = hostnamequality.MaxSyntheticNames
				}
				if err := attrlist.Record(ctx, b.Tx(), s.TenantID, res.Asset.ID, key, values, limit); err != nil {
					return err
				}
			}
			// A claimed-address sighting describes a network the device
			// serves, not where it stands: it places nothing.
			if s.Channel == identity.ChannelAuthenticatedSession && res.Outcome != identity.OutcomeConflict && !s.ClaimsAddresses() {
				return b.ProjectSegmentLocation(ctx, res.Asset, obs.Network.SegmentID, obs.Source)
			}
			return nil
		})
	}
	err := run()
	if errors.Is(err, identity.ErrIdentifierConflict) {
		err = run()
	}
	switch {
	case errors.Is(err, identity.ErrNoUsableIdentifier):
		return sightingclient.Result{Outcome: sightingclient.OutcomeRejected, Reasons: []string{sightingclient.ReasonNoUsableIdentifier}}
	case err != nil:
		// inventory-service answers a store failure with a 500 for the whole
		// batch; the reference folds every other refusal into `invalid`.
		return sightingclient.Result{Outcome: sightingclient.OutcomeRejected, Reasons: []string{sightingclient.ReasonInvalid}}
	}
	out := sightingclient.Result{
		Outcome: res.Outcome, AssetID: res.Asset.ID, ObservationID: res.ObservationID, ProposalID: res.Proposal.ID,
		EvidenceHeld: res.EvidenceHeld, EndpointsClosed: res.EndpointsClosed,
	}
	if res.AdmissionReason != "" {
		out.Reasons = []string{res.AdmissionReason}
	}
	return out
}

// DeclareFor is a declaration for a named asset: Intake, then
// Engine.ResolveDeclaredFor on one transaction. A conflict with another owner
// opens a merge proposal on its own transaction, as inventory-service's
// identifier edit does.
func (r *Resolver) DeclareFor(ctx context.Context, s identity.Sighting, target string) sightingclient.Result {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	rejected := func(reason string) sightingclient.Result {
		return sightingclient.Result{Outcome: sightingclient.OutcomeRejected, Reasons: []string{reason}}
	}
	ref := identity.AssetRef{TenantID: s.TenantID, ID: target}
	if summaries, err := r.repo.LoadSummaries(ctx, s.TenantID, []string{target}); err != nil || len(summaries) == 0 {
		return rejected(sightingclient.ReasonUnknownTarget)
	}
	assessed, err := r.in.Assess(ctx, s)
	if err != nil {
		return rejected(sightingclient.ReasonInvalid)
	}
	err = r.repo.RunInTx(ctx, s.TenantID, func(b *pgidentity.Repository) error {
		_, rerr := r.eng.WithRepository(b).ResolveDeclaredFor(ctx, assessed.Observation, ref)
		return rerr
	})
	var conflict *identity.DeclaredTargetConflict
	switch {
	case errors.As(err, &conflict) && conflict.Singleton:
		return sightingclient.Result{Outcome: identity.OutcomeConflict, AssetID: target, Reasons: []string{sightingclient.ReasonDeclaredSingletonConflict}}
	case errors.As(err, &conflict):
		proposal, perr := r.repo.OpenMergeProposal(ctx, s.TenantID, identity.MergeProposal{
			ObservationAssetID: target,
			Candidates:         []identity.MergeCandidate{{Ref: conflict.Owner, MatchedIdentifiers: []identity.Identifier{conflict.Identifier}, Reason: "a person declared this identifier on another asset"}},
			Source:             s.Source, Reason: "declared identifier already belongs to another asset", PreserveObservationStatus: true,
		})
		if perr != nil {
			return rejected(sightingclient.ReasonInvalid)
		}
		return sightingclient.Result{Outcome: identity.OutcomeConflict, AssetID: target, ProposalID: proposal.ID, Reasons: []string{sightingclient.ReasonDeclaredIdentifierConflict}}
	case err != nil:
		return rejected(sightingclient.ReasonInvalid)
	}
	return sightingclient.Result{Outcome: identity.OutcomeMatched, AssetID: target}
}

// Handler serves sightingclient.Path, verifying the HMAC and the signed
// tenant header as inventory-service's internal routes do.
func (r *Resolver) Handler() http.Handler {
	gin.SetMode(gin.TestMode)
	verifier := serviceauth.NewVerifier(Secret)
	engine := gin.New()
	engine.POST(sightingclient.Path, func(c *gin.Context) {
		if !verifier.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "service authentication required"})
			return
		}
		tenant := c.GetHeader(serviceauth.HeaderTenantID)
		var body sightingclient.Request
		if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
			return
		}
		out := sightingclient.Response{Results: make([]sightingclient.Result, 0, len(body.Sightings))}
		for _, s := range body.Sightings {
			if s.TenantID != tenant {
				out.Results = append(out.Results, sightingclient.Result{Outcome: sightingclient.OutcomeRejected, Reasons: []string{sightingclient.ReasonTenantMismatch}})
				continue
			}
			if s.TargetAssetID != "" {
				out.Results = append(out.Results, r.DeclareFor(c.Request.Context(), s.Sighting, s.TargetAssetID))
				continue
			}
			out.Results = append(out.Results, r.Resolve(c.Request.Context(), s.Sighting))
		}
		c.JSON(http.StatusOK, out)
	})
	// The gateway-links route: the same reconcile inventory-service's
	// route runs, so it is the shared function, not a second copy of it.
	engine.POST(sightingclient.GatewayLinksPath, func(c *gin.Context) {
		if !verifier.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "service authentication required"})
			return
		}
		tenant := c.GetHeader(serviceauth.HeaderTenantID)
		var body sightingclient.GatewayLinksRequest
		if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
			return
		}
		res, err := r.repo.ReconcileGatewayLinks(c.Request.Context(), tenant, body.AssetID, body.SourceRef, body.ObservedAt, body.Addresses)
		switch {
		case errors.Is(err, pgidentity.ErrGatewayAssetUnknown):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)
	})
	return engine
}

// Start serves the reference route over db for the life of the test and
// returns a client that posts to it, signed with [Secret].
func Start(t testing.TB, db *sql.DB) (*sightingclient.Client, *Resolver) {
	t.Helper()
	r, err := NewResolver(db)
	if err != nil {
		t.Fatalf("sightingserver: %v", err)
	}
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	r.URL = srv.URL
	signer := serviceauth.NewSigner(Secret)
	return sightingclient.New(srv.URL, srv.Client(), sightingclient.WithSigner(signer.SignRequest)), r
}

var (
	forDBMu sync.Mutex
	forDB   = map[*sql.DB]*sightingclient.Client{}
)

// ForDB is [Start] for code with no testing.TB at hand — a package's init()
// installing a poster factory for every test in the package. One server per
// database handle, for the life of the test binary.
func ForDB(db *sql.DB) *sightingclient.Client {
	forDBMu.Lock()
	defer forDBMu.Unlock()
	if c, ok := forDB[db]; ok {
		return c
	}
	r, err := NewResolver(db)
	if err != nil {
		panic("sightingserver: " + err.Error())
	}
	srv := httptest.NewServer(r.Handler())
	r.URL = srv.URL
	signer := serviceauth.NewSigner(Secret)
	c := sightingclient.New(srv.URL, srv.Client(), sightingclient.WithSigner(signer.SignRequest), sightingclient.WithRetry(1, 0))
	forDB[db] = c
	return c
}

var (
	ownURLMu sync.Mutex
	ownURL   = map[string]*sightingclient.Client{}
)

// ForURL is [ForDB] over a connection pool of its OWN, opened from dsn —
// what inventory-service has in production. A test whose intake runs on a
// pool of one connection (SetMaxOpenConns(1)) and holds it across the post
// would otherwise wait on itself.
func ForURL(dsn string) *sightingclient.Client {
	ownURLMu.Lock()
	defer ownURLMu.Unlock()
	if c, ok := ownURL[dsn]; ok {
		return c
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic("sightingserver: " + err.Error())
	}
	c := ForDB(db)
	ownURL[dsn] = c
	return c
}
