package entitlements

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// License is the licence an install runs under, as admin-service recorded it in
// platform_license after verifying the signed token. A nil *License means the
// install has no licence: it is Core.
//
// This package never verifies a token. Verification (signature, issuer, expiry,
// install binding) happens once, in admin-service/ee/edition, which then writes
// the one platform_license row — or deletes it when the token is missing or
// invalid. Every other service only reads that row, which is why Core services
// need no key material and no Enterprise code to enforce the boundary.
type License struct {
	Edition   Edition
	ExpiresAt time.Time
	// Licensee is the organisation the licence was issued to, as recorded in
	// platform_license.licensee. Presentation only (the plan block, the
	// License & Usage page); nothing gates on it.
	Licensee string
	// RetentionMaxDays is the platform data-retention cap an Enterprise install
	// applies to every tenant (platform_settings "retention.max_days"). nil
	// means unlimited, which is also the answer when the setting was never
	// written. Only read for an Enterprise licence: on MSP retention is a plan
	// value and on Core it is unchanged, so the field stays nil there.
	RetentionMaxDays *int
}

// Active reports whether the licence grants anything at `now`: it exists, it
// names a paid edition, and it has not expired. The expiry is checked here, at
// resolve time, rather than trusted to the reconcile loop, so an expired licence
// stops granting the moment it lapses even if admin-service is down.
func (l *License) Active(now time.Time) bool {
	if l == nil {
		return false
	}
	if l.Edition != EditionEnterprise && l.Edition != EditionMSP {
		return false
	}
	return now.Before(l.ExpiresAt)
}

// LicenseSource returns the install's licence, or nil for Core.
type LicenseSource func(ctx context.Context) (*License, error)

// LicenseCacheTTL bounds how stale a service's view of platform_license can be.
// The row changes at most once per admin-service reconcile (10 minutes by
// default), and the resolver sits on hot paths (every RequireFeature request),
// so a short cache removes a query per request while keeping a licence install
// or removal visible within half a minute.
const LicenseCacheTTL = 30 * time.Second

type licenseCacheEntry struct {
	license *License
	fetched time.Time
}

// licenseCache is keyed by the pool the licence was read through. One process
// normally holds one or two pools on one database; keying by pool rather than
// holding a single process-wide value means a test binary that talks to two
// databases cannot read one database's licence through the other's handle.
var licenseCache = struct {
	sync.Mutex
	entries map[*sql.DB]licenseCacheEntry
}{entries: map[*sql.DB]licenseCacheEntry{}}

// FlushLicenseCache forgets every cached licence, so the next resolution reads
// platform_license again. Production code has no reason to call it; tests that
// install or remove a licence call it so they do not wait out the TTL.
func FlushLicenseCache() {
	licenseCache.Lock()
	defer licenseCache.Unlock()
	licenseCache.entries = map[*sql.DB]licenseCacheEntry{}
}

// LoadLicense returns the licence recorded in platform_license, read through db
// and cached for LicenseCacheTTL. Safe for concurrent use.
//
// Errors are returned, not cached, and not converted to "no licence": the
// callers are gates, and every gate already fails closed on a resolver error.
// Treating a failed read as Core would be fail-closed too, but it would do so
// silently. The one exception is a database with no platform_license table at
// all (undefined_table, before the schema migration has run): that is Core by
// definition, and is logged once — see readLicense.
func LoadLicense(ctx context.Context, db *sql.DB) (*License, error) {
	now := time.Now()
	licenseCache.Lock()
	if e, ok := licenseCache.entries[db]; ok && now.Sub(e.fetched) < LicenseCacheTTL {
		licenseCache.Unlock()
		return e.license, nil
	}
	licenseCache.Unlock()

	lic, err := readLicense(ctx, db)
	if err != nil {
		return nil, err
	}

	licenseCache.Lock()
	licenseCache.entries[db] = licenseCacheEntry{license: lic, fetched: now}
	licenseCache.Unlock()
	return lic, nil
}

// rowQueryer is satisfied by *sql.DB, *sql.Conn and *sql.Tx.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// selectLicenseSQL reads the single platform_license row. The table is global
// (no tenant_id, no RLS), like subscription_tiers, so it answers identically on
// the RLS-scoped application pool and the bypass pool.
const selectLicenseSQL = `SELECT edition, expires_at, licensee FROM platform_license LIMIT 1`

// sqlStateUndefinedTable is Postgres's undefined_table (42P01).
const sqlStateUndefinedTable = "42P01"

// missingTableLogged makes the "no platform_license table" line once per
// process rather than once per resolution (the resolver sits on hot paths).
var missingTableLogged sync.Once

// licenseTableSeen records that platform_license has been read successfully in
// this process. The table is never dropped once created, so after that the
// transaction path (readLicenseInTx) can skip its existence probe.
var licenseTableSeen atomic.Bool

func logMissingLicenseTable(cause string) {
	missingTableLogged.Do(func() {
		log.Printf("[entitlements] platform_license does not exist yet (%s) — resolving as Core until the schema migration creates it", cause)
	})
}

// readLicenseInTx is readLicense on the caller's transaction (GetQuantityInTx).
// It cannot simply map undefined_table the way readLicense does: in a
// transaction the failed SELECT has already ABORTED the caller's transaction,
// so "Core" would come back with a transaction on which every later statement
// fails. It asks whether the table exists first instead — once per process,
// since after the first successful read it always will.
func readLicenseInTx(ctx context.Context, tx *sql.Tx) (*License, error) {
	if !licenseTableSeen.Load() {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass('platform_license') IS NOT NULL`).Scan(&exists); err != nil {
			return nil, fmt.Errorf("entitlements: probe platform_license: %w", err)
		}
		if !exists {
			logMissingLicenseTable("to_regclass found no platform_license")
			return nil, nil
		}
	}
	return readLicense(ctx, tx)
}

// isUndefinedTable reports whether err is Postgres's undefined_table. Matched
// through the SQLState() method both lib/pq and pgx errors implement, so this
// package does not import a driver.
func isUndefinedTable(err error) bool {
	var coded interface{ SQLState() string }
	return errors.As(err, &coded) && coded.SQLState() == sqlStateUndefinedTable
}

func readLicense(ctx context.Context, q rowQueryer) (*License, error) {
	var (
		edition  string
		expires  time.Time
		licensee string
	)
	err := q.QueryRowContext(ctx, selectLicenseSQL).Scan(&edition, &expires, &licensee)
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		licenseTableSeen.Store(true)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if isUndefinedTable(err) {
		// The database predates the licence model: a new service image is
		// running before the schema-migration Job has created the table (a
		// rolling upgrade, or a compose stack whose volume was initialised
		// from an older schema.sql). No table can hold no licence, so this is
		// Core — the same answer as an empty table — not an error that would
		// fail every gate closed and 500 every feature check until the Job
		// runs. Logged once, since it is expected to be transient. (Safe on a
		// pool: the failed statement was its own implicit transaction. The
		// transaction path goes through readLicenseInTx, which never lets the
		// SELECT fail.)
		logMissingLicenseTable(err.Error())
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("entitlements: read platform_license: %w", err)
	}
	lic := &License{Edition: Edition(edition), ExpiresAt: expires, Licensee: licensee}
	if lic.Edition == EditionEnterprise {
		capDays, err := readRetentionCap(ctx, q)
		if err != nil {
			return nil, err
		}
		lic.RetentionMaxDays = capDays
	}
	return lic, nil
}

var (
	disabledValue  = json.RawMessage(`{"enabled": false}`)
	enabledValue   = json.RawMessage(`{"enabled": true}`)
	zeroQuantity   = json.RawMessage(`{"quantity": 0}`)
	unlimitedValue = json.RawMessage(`{"quantity": null}`)
)

// applyLicense is the licence step. It runs on every resolved entitlement,
// after the override > tier > default query, and is the ONLY place the edition
// boundary is enforced. The rules (edition-licensing spec §3):
//
// Edition-gated items (EditionFor != Core):
//
//   - No active licence, or a licence whose edition does not cover the item
//     (EditionCovers): denied, Source = edition, whatever any tier or override
//     says. This is what makes a Core install safe even though seed.sql, the
//     tier editor and the override API all ship in the open-source tree: none
//     of them can switch on a capability the licence does not cover.
//   - Enterprise licence: enabled for every tenant, Source = edition, UNLESS a
//     per-tenant override is in force — the platform admin switching a
//     contractor or due-diligence tenant off. Tiers are ignored: an Enterprise
//     install has no plans.
//   - MSP licence: the ordinary override > tier > default result stands. The
//     MSP's plans decide which of its customers get the capability.
//
// Items that are not edition-gated:
//
//   - Enterprise licence: numeric capacity (numeric_cap, numeric_metered)
//     resolves to unlimited unless a per-tenant override is in force — except
//     retention_days, which resolves to the platform retention cap
//     (License.RetentionMaxDays; unlimited when unset).
//   - Core and MSP: unchanged.
//
// Only boolean and numeric kinds are rewritten. Every gated item in the
// catalogue today is boolean; an enum_choice item has no generic "denied"
// value, so one is left as resolved.
func applyLicense(ent *EffectiveEntitlement, lic *License, now time.Time) {
	if ent == nil {
		return
	}
	key := ent.Item.Key
	gated := IsEditionGated(key)
	active := lic.Active(now)

	if gated && (!active || !EditionCovers(lic.Edition, key)) {
		switch ent.Item.Kind {
		case KindBoolean:
			setEditionValue(ent, disabledValue)
		case KindNumericCap, KindNumericMetered:
			setEditionValue(ent, zeroQuantity)
		}
		return
	}
	if !active || lic.Edition != EditionEnterprise {
		return // Core (ungated items) and MSP: the tenant's own rows decide.
	}

	// Enterprise. A per-tenant override is the platform admin's explicit
	// exception and is honoured exactly as written — a switched-off capability
	// stays off, a capped capacity stays capped.
	if ent.Source == SourceOverride {
		return
	}
	switch ent.Item.Kind {
	case KindBoolean:
		if gated {
			setEditionValue(ent, enabledValue)
		}
	case KindNumericCap, KindNumericMetered:
		if key == RetentionItemKey {
			setEditionValue(ent, retentionValue(lic.RetentionMaxDays))
			return
		}
		setEditionValue(ent, unlimitedValue)
	}
}

func setEditionValue(ent *EffectiveEntitlement, v json.RawMessage) {
	ent.Value = append(json.RawMessage(nil), v...)
	ent.Source = SourceEdition
	// The tier's metering metadata and an override's expiry describe the value
	// that was just replaced; carrying them over would attach them to a value
	// they do not belong to (a "trial ends" date on an Enterprise grant).
	ent.OveragePriceCents = nil
	ent.OverageUnitSize = nil
	ent.ExpiresAt = nil
}
