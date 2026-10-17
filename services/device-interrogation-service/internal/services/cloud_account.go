package services

// The cloud account as an asset, and account-level auto-approval
// (asset-inventory ADR-0009 D1 and D5).
//
// Two things happen here, both derived from platform_integrations, which this
// service owns:
//
//  1. Every account a tenant connected through a cloud integration is a
//     DECLARED `cloud_account` asset, keyed `cloud_resource_id =
//     <provider>:<account>` (shared/cloudaccount). It is approved by the act
//     of adding the integration — a person said "this account is ours" — and
//     several integrations may read one account. Deleting an integration does
//     NOT delete the asset: it stops being refreshed and goes stale by the
//     tenant's policy, like anything else nobody observes any more.
//  2. Each account gets ONE discovery_auto_approval_rules row,
//     `source:cloud and cloud.account_id="<account>"`, active while any
//     enabled integration for that account has auto_approve_resources on.
//     shared/approval evaluates it like every other rule; the cloud intake
//     (cloudResourceRecorded below, and inventory-service for the findings it
//     ingests) only supplies the account on the observation.
//
// Both are recomputed from the integrations table by SyncTenant — on every
// integration write and at the start of every cloud run — rather than being
// maintained incrementally. A derived row that is rebuilt from its source on
// every touch cannot drift from it.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/cloudaccount"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// CloudAccountService declares account assets and derives account approval
// rules.
type CloudAccountService struct {
	db      *sql.DB
	devices *DeviceService
}

// NewCloudAccountService builds the service over the tenant-scoped (RLS)
// connection.
func NewCloudAccountService(db *sql.DB, masterKey string) *CloudAccountService {
	return &CloudAccountService{db: db, devices: NewDeviceServiceWithKey(db, masterKey)}
}

// accountKey is one (provider, account) pair.
type accountKey struct{ provider, account string }

// accountGroup is everything the tenant's integrations say about one account.
type accountGroup struct {
	key            accountKey
	name           string
	integrationIDs []string
	// autoApprove: some ENABLED integration for this account has
	// auto_approve_resources on.
	autoApprove bool
}

// SyncTenant brings the tenant's account assets and account approval rules in
// line with its cloud integrations. It returns the account asset id per
// `<provider>:<account>`.
func (s *CloudAccountService) SyncTenant(ctx context.Context, tenantID uuid.UUID) (map[string]uuid.UUID, error) {
	groups, err := s.accountGroups(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	assets := make(map[string]uuid.UUID, len(groups))
	var firstErr error
	for _, g := range groups {
		id, err := s.ensureAccountAsset(ctx, tenantID, g)
		if err != nil {
			// One account that cannot be declared must not stop the others,
			// nor the rules below — but it is reported, never swallowed.
			log.Printf("[cloud account] %s for tenant %s not declared: %v", cloudaccount.ResourceID(g.key.provider, g.key.account), tenantID, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		assets[cloudaccount.ResourceID(g.key.provider, g.key.account)] = id
	}
	if err := s.syncApprovalRules(ctx, tenantID, groups); err != nil {
		return assets, err
	}
	return assets, firstErr
}

// accountGroups reads the tenant's own live cloud integrations, grouped by
// account. Shared platform integrations (tenant_id NULL) declare nothing: the
// account they read is not the tenant's to own.
func (s *CloudAccountService) accountGroups(ctx context.Context, tenantID uuid.UUID) ([]accountGroup, error) {
	byKey := map[accountKey]*accountGroup{}
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, integration_type, coalesce(account_id, ''), integration_name,
			       coalesce(is_enabled, true), auto_approve_resources
			  FROM platform_integrations
			 WHERE tenant_id = $1 AND deleted_at IS NULL AND coalesce(is_active, true)
			   AND integration_type IN ('aws', 'azure', 'gcp')
			 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return fmt.Errorf("list cloud integrations: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				id                   uuid.UUID
				provider, acct, name string
				enabled, autoApprove bool
			)
			if err := rows.Scan(&id, &provider, &acct, &name, &enabled, &autoApprove); err != nil {
				return err
			}
			k := accountKey{cloudaccount.NormalizeProvider(provider), strings.TrimSpace(acct)}
			if k.provider == "" || k.account == "" {
				// An integration that names no account declares none. AWS
				// learns its account on the first successful connection test.
				continue
			}
			g := byKey[k]
			if g == nil {
				g = &accountGroup{key: k, name: strings.TrimSpace(name)}
				byKey[k] = g
			}
			g.integrationIDs = append(g.integrationIDs, id.String())
			if enabled && autoApprove {
				g.autoApprove = true
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := make([]accountGroup, 0, len(byKey))
	for _, g := range byKey {
		sort.Strings(g.integrationIDs)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		return cloudaccount.ResourceID(out[i].key.provider, out[i].key.account) < cloudaccount.ResourceID(out[j].key.provider, out[j].key.account)
	})
	return out, nil
}

// accountSource is the provenance of an account declaration: a person added
// an integration naming it.
func accountSource(integrationID string) identity.Source {
	return identity.Source{Kind: identity.SourceDeclared, Ref: "integration:" + integrationID}
}

// ensureAccountAsset resolves the account's declared sighting through the one
// identity engine — so a second integration for the same account MATCHES the
// asset the first created — then, in one transaction, approves it, records
// its attributes and its two cloud facts.
func (s *CloudAccountService) ensureAccountAsset(ctx context.Context, tenantID uuid.UUID, g accountGroup) (uuid.UUID, error) {
	rid := cloudaccount.ResourceID(g.key.provider, g.key.account)
	source := accountSource(g.integrationIDs[0])
	name := g.name
	if name == "" {
		name = cloudaccount.DisplayName(g.key.provider, g.key.account)
	}
	sighting := identity.Sighting{
		TenantID: tenantID.String(),
		Source:   source,
		// The integration is the tenant's authenticated provider-API connection;
		// its account scope is authoritative even though the provenance remains
		// declared (a person added the connection). Treat it like the rest of the
		// cloud collector's API evidence so identity admission can establish the
		// account from its cloud_resource_id. ChannelPerson made the declaration
		// unresolved when admission enforcement was enabled, leaving no account
		// asset or site even though discovery itself succeeded.
		Channel:     identity.ChannelAPI,
		ObservedAt:  time.Now().UTC(),
		ReceiptID:   "cloud-account:" + rid,
		ClassHint:   cloudaccount.ClassKey,
		DisplayName: name,
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindCloudResourceID, Value: rid}},
	}
	var assetID uuid.UUID
	res, err := s.devices.resolveSighting(ctx, sighting, func(r *pgidentity.Repository, res identity.Resolution) error {
		if res.Asset.Zero() {
			// The identifier belongs to more than one asset and a merge
			// proposal is waiting. Not resolved here: auto-merging is what
			// ADR-0002 D5 forbids.
			return nil
		}
		id, err := uuid.Parse(res.Asset.ID)
		if err != nil {
			return fmt.Errorf("identification returned an unusable asset id %q: %w", res.Asset.ID, err)
		}
		assetID = id
		if _, err := cloudaccount.ApproveAsset(ctx, r, tenantID, id, source,
			map[string]any{"reason": "cloud integration added for this account"}); err != nil {
			return err
		}
		// The account's site (DCIM row 2.1): one per account, named by it,
		// facility = provider. Its regions become locations there as the
		// enumeration finds resources in them.
		if _, err := cloudaccount.EnsureSite(ctx, r, tenantID, id, g.key.provider, g.key.account, name); err != nil {
			return fmt.Errorf("placing the account in its site: %w", err)
		}
		attrs := filterClassAttributes(cloudaccount.ClassKey, map[string]any{
			"provider":        g.key.provider,
			"account_id":      g.key.account,
			"integration_ids": g.integrationIDs,
		}, "")
		if err := mergeAssetAttributes(ctx, r.Tx(), tenantID, id, attrs); err != nil {
			return fmt.Errorf("writing account attributes: %w", err)
		}
		rows := cloudFactRows(map[string]any{
			facts.KeyCloudProvider:  g.key.provider,
			facts.KeyCloudAccountID: g.key.account,
		}, source, time.Now().UTC())
		if len(rows) > 0 {
			ref := identity.AssetRef{TenantID: tenantID.String(), ID: id.String()}
			if err := r.UpsertFacts(ctx, ref, facts.ProducerCloudCollector, rows); err != nil {
				return fmt.Errorf("writing account facts: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	if res.Asset.Zero() {
		if res.ObservationID != "" {
			return uuid.Nil, &identity.RetainedObservation{Result: res.IngestResult()}
		}
		return uuid.Nil, contestedFrom(res)
	}
	return assetID, nil
}

// accountRuleName is the rule's human label.
func accountRuleName(g accountGroup) string {
	return fmt.Sprintf("Auto-approve cloud resources: %s", cloudaccount.DisplayName(g.key.provider, g.key.account))
}

// syncApprovalRules makes the tenant's account rules match its integrations:
// one rule per account, active iff some enabled integration for the account
// auto-approves; a rule whose account no integration names any more is
// deactivated (never deleted — rules are referenced by the discoveries they
// approved).
//
// Which rule belongs to which account is read out of the rule's query
// (approval.CloudAccountIDFromQuery), the same way segment rules are found by
// their segment id, so this never touches a segment's rule.
func (s *CloudAccountService) syncApprovalRules(ctx context.Context, tenantID uuid.UUID, groups []accountGroup) error {
	want := map[string]accountGroup{}
	for _, g := range groups {
		want[g.key.account] = g
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// SyncTenant runs from every integration write AND at the start of
		// every cloud run, so two syncs for one tenant can overlap. Without
		// this lock both read "no rule for the account" and both insert one;
		// the duplicate then outlives the switch being turned off. Held to
		// the end of this transaction, per tenant.
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('cloud-account-rules:' || $1::text, 0))`, tenantID.String()); err != nil {
			return fmt.Errorf("lock account rules: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT id, query FROM discovery_auto_approval_rules WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return fmt.Errorf("read approval rules: %w", err)
		}
		// Every rule per account, oldest first. Normally one; more than one
		// is what an earlier race (or a hand-written copy) leaves, and every
		// one of them can approve the account's resources, so every one is
		// governed below — the oldest is kept, the rest are switched off.
		existing := map[string][]uuid.UUID{}
		for rows.Next() {
			var id uuid.UUID
			var q string
			if err := rows.Scan(&id, &q); err != nil {
				_ = rows.Close()
				return err
			}
			if _, isPrefix := approval.PrefixIDFromQuery(q); isPrefix {
				continue
			}
			if acct, ok := approval.CloudAccountIDFromQuery(q); ok {
				existing[acct] = append(existing[acct], id)
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}

		for acct, g := range want {
			q, err := approval.ValidateRuleQuery(approval.CloudAccountApprovalQuery(acct))
			if err != nil {
				// Our generator produced something the language refuses: OUR
				// bug, so loud, and no rule nothing could read is written.
				return fmt.Errorf("BUG: generated cloud account rule for %s does not validate: %w", acct, err)
			}
			desc := fmt.Sprintf("Resources discovered in %s are approved automatically (the cloud integration's \"Auto-approve resources\" setting).",
				cloudaccount.DisplayName(g.key.provider, g.key.account))
			if ids := existing[acct]; len(ids) > 0 {
				if _, err := tx.ExecContext(ctx, `
					UPDATE discovery_auto_approval_rules
					   SET name = $1, description = $2, query = $3, is_active = $4, updated_at = now()
					 WHERE id = $5`, accountRuleName(g), desc, q, g.autoApprove, ids[0]); err != nil {
					return fmt.Errorf("update account rule %s: %w", acct, err)
				}
				for _, dup := range ids[1:] {
					if _, err := tx.ExecContext(ctx, `
						UPDATE discovery_auto_approval_rules SET is_active = false, updated_at = now()
						 WHERE id = $1 AND is_active`, dup); err != nil {
						return fmt.Errorf("deactivate duplicate account rule %s: %w", acct, err)
					}
				}
				continue
			}
			if !g.autoApprove {
				// No rule needed until somebody turns it on.
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO discovery_auto_approval_rules
					(tenant_id, name, description, query, is_active, created_at, updated_at)
				VALUES ($1, $2, $3, $4, true, now(), now())`,
				tenantID, accountRuleName(g), desc, q); err != nil {
				return fmt.Errorf("create account rule %s: %w", acct, err)
			}
		}
		for acct, ids := range existing {
			if _, still := want[acct]; still {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE discovery_auto_approval_rules SET is_active = false, updated_at = now()
				 WHERE id = ANY($1) AND is_active`, pq.Array(ids)); err != nil {
				return fmt.Errorf("deactivate account rule %s: %w", acct, err)
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// The cloud intake half: every resource a collector records
// ---------------------------------------------------------------------------

// cloudApprovalKey carries one run's lazily loaded approval rules.
type cloudApprovalKey struct{}

// cloudApprovalRules loads the tenant's active rules once per run.
type cloudApprovalRules struct {
	once  sync.Once
	rules []*approval.Rule
	err   error
}

func withCloudApprovalRules(ctx context.Context) context.Context {
	if _, ok := ctx.Value(cloudApprovalKey{}).(*cloudApprovalRules); ok {
		return ctx
	}
	return context.WithValue(ctx, cloudApprovalKey{}, &cloudApprovalRules{})
}

func (s *CloudDiscoveryService) approvalRules(ctx context.Context, tenantID uuid.UUID) ([]*approval.Rule, error) {
	load := func() ([]*approval.Rule, error) { return approval.NewService(s.db).GetActiveRulesForTenant(tenantID) }
	cache, ok := ctx.Value(cloudApprovalKey{}).(*cloudApprovalRules)
	if !ok {
		return load()
	}
	cache.once.Do(func() { cache.rules, cache.err = load() })
	return cache.rules, cache.err
}

// cloudResourceAccount decides which account a recorded resource is in: the
// account its own metadata states, else the one its resource id states, else
// the run's integration account.
func cloudResourceAccount(ctx context.Context, device *models.Device, resourceID string) (provider, account string) {
	scope, _ := ctx.Value(cloudScopeKey{}).(cloudScope)
	provider = cloudaccount.NormalizeProvider(firstNonEmpty(cloudProviderForDevice(*device), scope.Provider))
	stated := ""
	if device.Metadata != nil {
		stated = firstNonEmpty(getStringFromMap(map[string]interface{}(device.Metadata), "cloud_account_id"),
			getStringFromMap(map[string]interface{}(device.Metadata), "account_id"))
	}
	if res, ok := ctx.Value(cloudEnumerationContextKey{}).(*cloudEnumResource); ok && res != nil {
		if v, ok := res.Facts[facts.KeyCloudAccountID].(string); ok && stated == "" {
			stated = v
		}
	}
	return provider, cloudaccount.Resolve(provider, stated, resourceID, scope.AccountID)
}

// cloudResourceApprovalInput projects a recorded resource onto the
// `observation` target: source cloud, the account, what it is and what it is
// called. Kind is left empty — an inventory listing is neither a crypto
// measurement nor a passive host observation, and absent is the honest answer.
func cloudResourceApprovalInput(tenantID uuid.UUID, device *models.Device, account string, at time.Time) approval.Discovery {
	d := approval.Discovery{
		TenantID:       tenantID,
		Metadata:       []byte(`{"source":"cloud_discovery","discovery_method":"cloud_api"}`),
		Hostname:       derefStr(device.Hostname),
		Address:        derefStr(device.IPAddress),
		FirstSeen:      at,
		CloudAccountID: account,
	}
	if c, ok := assetclass.Get(DeviceTypeClassKey(device.DeviceType)); ok {
		d.ClassPath = c.Path
	}
	return d
}

// cloudResourceRecorded is the account half of the cloud intake, run inside
// the resolution's own transaction for every resource any collector records
// through upsertDeviceAssetWith (enumeration and the crypto collectors alike):
//
//  1. a PENDING resource is offered to the tenant's auto-approval rules with
//     its account on the observation; an account rule that matches approves
//     it (shared/approval decides — there is no second evaluator);
//  2. the measured `hosted_on` edge to the account asset is written, AFTER
//     the approval, so an approved resource's edge enters `active`.
//
// It never runs on a contested resolution: there is no asset, the merge
// proposal stands, and auto-approval never auto-merges.
func (s *CloudDiscoveryService) cloudResourceRecorded(ctx context.Context, r *pgidentity.Repository, device *models.Device, assetID uuid.UUID, resourceID string, pending *bool) error {
	provider, account := cloudResourceAccount(ctx, device, resourceID)
	now := time.Now().UTC()
	source := cloudSource(device.Vendor)

	if *pending {
		rules, err := s.approvalRules(ctx, device.TenantID)
		if err != nil {
			// Fail closed: a resource nobody could evaluate stays in Approvals.
			log.Printf("[cloud account] approval rules for tenant %s unreadable; %s stays pending: %v", device.TenantID, resourceID, err)
		} else if len(rules) > 0 {
			ok, ruleID, evalErr := approval.NewService(s.db).EvaluateAutoApprovalWithRules(rules,
				cloudResourceApprovalInput(device.TenantID, device, account, now),
				&approval.Classification{Ownership: identity.OwnershipInternal})
			if evalErr != nil {
				log.Printf("[cloud account] auto-approval for %s failed: %v", resourceID, evalErr)
			}
			if ok && ruleID != nil {
				changed, err := cloudaccount.ApproveAsset(ctx, r, device.TenantID, assetID, source,
					map[string]any{"auto_approval_rule_id": ruleID.String(), "cloud_account_id": account})
				if err != nil {
					return err
				}
				if changed {
					*pending = false
				}
			}
		}
	}

	if account == "" {
		return nil
	}
	if _, err := cloudaccount.LinkHostedOn(ctx, r, device.TenantID.String(), assetID.String(), provider, account, source, now); err != nil {
		return fmt.Errorf("hosted_on edge to account %s: %w", account, err)
	}
	// Placement (DCIM row 2.1): the account's site and the region's location
	// in it. A CloudFront distribution's "global" is not a place.
	if region := strings.TrimSpace(cloudRegionForDevice(*device)); region != "" && !strings.EqualFold(region, "global") {
		if _, err := cloudaccount.PlaceInRegion(ctx, r, device.TenantID, assetID, provider, account, region); err != nil {
			return fmt.Errorf("placing %s in %s: %w", resourceID, region, err)
		}
	}
	return nil
}
