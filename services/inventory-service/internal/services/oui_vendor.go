package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// OUI vendor resolution: hw.vendor from the MAC prefix, decided on the platform.
//
// The sensor used to look the vendor up in a ~500-prefix curated table compiled
// into its own binary and ship the answer as `hw.vendor`. It no longer does
// (shared/hostobs's Finalize leaves Vendor empty): the platform resolves the
// manufacturer here, at ingestion, from the full IEEE registry in
// shared/ouiregistry. The registry is complete and current on the platform; a
// sensor's table is whatever it was built with, and an older sensor binary in
// the field keeps sending that answer. So when the registry has an answer it
// wins, and a carried vendor is only the fallback for a prefix the registry
// does not determine.
//
// # Provenance and precedence
//
// The resolved vendor is written as the `enricher` producer — a platform-side
// catalogue resolution, the same shape as the EOL and CPE lookups — with
// source_kind `imported` (it was read out of a catalogue, not measured off the
// device, and not inferred by a model) under the single source_ref
// [ouiVendorSourceRef].
//
// asset_facts keeps one row per (asset, key, source_ref) and its readers pick a
// winner by source kind (ADR-0002 D4: identity.Reconcile, the query language's
// fact ordering) or by recency. None of them knows the producer, and on D4's
// ladder a passive sensor's `measured` row outranks an `imported` one — which
// is backwards for a vendor the sensor itself only ever read out of a stale
// table. So the precedence this lookup needs is realised at WRITE time, by
// [applyRegistryVendorFact]:
//
//   - a `hw.vendor` row from a device-identity source (device agent, device
//     interrogation, a connector, an import — anything that is not the passive
//     sensors or this lookup) means the device or a system of record named its
//     own manufacturer. The OUI answer is then NOT written, and an earlier one
//     is retracted, so no reader can prefer it;
//   - otherwise the OUI answer supersedes the passive sensors' rows for the
//     key (`sensor`, `sensor:<id>`, `sensor:pcap…`): those were the old
//     table's answer to the same question, and are deleted when the registry
//     writes its own.
const ouiVendorSourceRef = "catalog:oui"

// passiveSensorFactRefSQL matches the source_ref of a fact the passive sensors
// wrote: hostObservationSource's "sensor", "sensor:<id>", "sensor:pcap" and
// "sensor:pcap:<id>".
const passiveSensorFactRefSQL = `(source_ref = 'sensor' OR source_ref LIKE 'sensor:%')`

// registryVendorForObservation is the IEEE registry's manufacturer for the
// observation's SUBJECT MAC, or "" when the registry does not determine one.
//
// OtherMACs are deliberately not consulted: they are a self-report's other
// NICs (or, on other paths, relayed addresses), and a vendor resolved from a
// secondary MAC is not a statement about the subject's own hardware.
func registryVendorForObservation(ho *hostobs.HostObservation) string {
	if ho == nil || ho.MAC == "" {
		return ""
	}
	return ouiregistry.VendorForMAC(ho.MAC)
}

// resolveHostObservationVendor makes the platform's answer the vendor every
// later reader of ho sees — the class evidence (hostObservationClassEvidence
// reads ho.Vendor) and the fact writer — and returns it ("" when the registry
// does not determine one, in which case ho is left exactly as it arrived).
//
// When the registry answers, `hw.vendor` is removed from the payload's own
// fact map: the value is written once, as the enricher's fact
// (applyRegistryVendorFact), not a second time under the sensor's producer.
func resolveHostObservationVendor(ho *hostobs.HostObservation) string {
	v := registryVendorForObservation(ho)
	if v == "" {
		return ""
	}
	ho.Vendor = v
	if ho.Facts != nil {
		delete(ho.Facts, facts.KeyHWVendor)
		if len(ho.Facts) == 0 {
			ho.Facts = nil
		}
	}
	return v
}

// factTx is the slice of *sql.Tx / *sqlx.Tx the vendor writer needs, so the
// ingest path (an engine transaction) and the backfill (its own batch
// transaction) share one implementation.
type factTx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// applyRegistryVendorFact writes vendor as the asset's OUI-resolved hw.vendor,
// under the write-time precedence documented on [ouiVendorSourceRef]. It
// reports whether the fact was written (false: a device-identity source holds
// the key, and any earlier OUI row was retracted instead).
//
// tx must be the tenant-scoped transaction repo is bound to, so the check, the
// supersession and the upsert are one atomic decision.
func applyRegistryVendorFact(ctx context.Context, repo *pgidentity.Repository, tx factTx, asset identity.AssetRef, vendor string, observedAt time.Time) (bool, error) {
	if vendor == "" {
		return false, nil
	}
	var identityHeld bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM asset_facts
		    WHERE tenant_id = $1 AND asset_id = $2 AND key = $3
		      AND source_ref <> $4 AND NOT `+passiveSensorFactRefSQL+`)`,
		asset.TenantID, asset.ID, facts.KeyHWVendor, ouiVendorSourceRef).Scan(&identityHeld); err != nil {
		return false, fmt.Errorf("checking hw.vendor provenance: %w", err)
	}
	if identityHeld {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_facts
			WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND source_ref = $4`,
			asset.TenantID, asset.ID, facts.KeyHWVendor, ouiVendorSourceRef); err != nil {
			return false, fmt.Errorf("retracting the OUI hw.vendor: %w", err)
		}
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND `+passiveSensorFactRefSQL,
		asset.TenantID, asset.ID, facts.KeyHWVendor); err != nil {
		return false, fmt.Errorf("superseding the sensor's hw.vendor: %w", err)
	}
	if err := repo.UpsertFacts(ctx, asset, facts.ProducerEnricher, []pgidentity.Fact{{
		Key:   facts.KeyHWVendor,
		Value: vendor,
		// Read out of the IEEE registry the platform carries: a catalogue
		// lookup, like the EOL facts' `catalog:eol:<row>`. Not measured (the
		// device said nothing) and not inferred (no model judged anything).
		SourceKind: identity.SourceImported,
		SourceRef:  ouiVendorSourceRef,
		ObservedAt: observedAt,
	}}); err != nil {
		return false, fmt.Errorf("writing the OUI hw.vendor: %w", err)
	}
	return true, nil
}
