package services

// The asset commercial lifecycle (DCIM gap 4; DATA_MODEL §2 "commercial
// lifecycle"): the eleven declared commercial columns on `assets`, the
// end-of-sale / end-of-support / end-of-life dates on `device_types` and
// `platforms`, and the computed `lifecycle` block every asset read carries.
//
// # One rule, one function
//
// ComputeAssetLifecycle is the only place the warranty and end-of-support
// states are decided. The list, the single-asset read and the Hardware tab's
// view all call it; the query language's `end_of_support` field reads the same
// effective date through shared/query/sql's AssetEffectiveEndOfSupportSQL, and
// TestIntegration_AssetLifecycle_EffectiveDateMatchesQueryLanguage holds the two
// to the same answer.
//
// # Effective end of support
//
// A device type's or a platform's effective end of support is its DECLARED
// end_of_support when one is set, else the eol_date of the end-of-life
// catalogue entry it is linked to (eol_catalogue_id). The asset's effective end
// of support is the EARLIER of the two: an asset whose hardware is supported
// until 2030 on an operating system that lost support last year is past end of
// support. Nothing recorded on either is "unknown", never "supported".

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// isoDate is the wire and column form of every lifecycle date.
const isoDate = "2006-01-02"

// WarrantyExpiringDays is how far ahead an ending warranty is "expiring".
const WarrantyExpiringDays = 90

// EOSWarningMonths is how far ahead an end of support is "within 12 months".
const EOSWarningMonths = 12

// EOSCandidate is one catalogue object's end-of-support inputs: the declared
// date and the linked end-of-life catalogue entry's date, either may be nil.
type EOSCandidate struct {
	Declared  *time.Time
	Catalogue *time.Time
}

// effective returns the candidate's effective date and where it came from.
func (c EOSCandidate) effective() (*time.Time, string) {
	if c.Declared != nil {
		return c.Declared, models.EOSSourceDecl
	}
	if c.Catalogue != nil {
		return c.Catalogue, models.EOSSourceCat
	}
	return nil, models.EOSSourceNone
}

// LifecycleInputs is everything ComputeAssetLifecycle reads.
type LifecycleInputs struct {
	WarrantyEnd *time.Time
	DeviceType  EOSCandidate
	Platform    EOSCandidate
}

// ComputeAssetLifecycle decides an asset's warranty and end-of-support states
// as of `today` (a calendar date; the time of day is ignored).
//
//   - warranty: expired when warranty_end is before today; expiring_90 from
//     today through today + 90 days (inclusive — a warranty ending today still
//     covers today); active beyond that; unknown when no warranty_end.
//   - end of support: past_eos when the effective date is before today;
//     eos_within_12m from today through today + 12 months (inclusive); supported
//     beyond that; unknown when neither the device type nor the platform has a
//     date.
func ComputeAssetLifecycle(in LifecycleInputs, today time.Time) models.AssetLifecycle {
	day := dateOnly(today)
	out := models.AssetLifecycle{WarrantyState: models.WarrantyUnknown, EOSState: models.EOSUnknown, Source: models.EOSSourceNone}

	if in.WarrantyEnd != nil {
		end := dateOnly(*in.WarrantyEnd)
		switch {
		case end.Before(day):
			out.WarrantyState = models.WarrantyExpired
		case !end.After(day.AddDate(0, 0, WarrantyExpiringDays)):
			out.WarrantyState = models.WarrantyExpiring90
		default:
			out.WarrantyState = models.WarrantyActive
		}
	}

	dt, dtSrc := in.DeviceType.effective()
	pl, plSrc := in.Platform.effective()
	var (
		eos     *time.Time
		src     = models.EOSSourceNone
		subject string
	)
	switch {
	case dt != nil && (pl == nil || !pl.Before(*dt)):
		// The earlier wins; on a tie the device type's (hardware) is named.
		eos, src, subject = dt, dtSrc, models.EOSSubjectDT
	case pl != nil:
		eos, src, subject = pl, plSrc, models.EOSSubjectPlat
	}
	if eos == nil {
		return out
	}
	end := dateOnly(*eos)
	s := end.Format(isoDate)
	out.EffectiveEndOfSupport, out.Source, out.Subject = &s, src, &subject
	switch {
	case end.Before(day):
		out.EOSState = models.EOSPastEOS
	case !end.After(day.AddDate(0, EOSWarningMonths, 0)):
		out.EOSState = models.EOSWithin12m
	default:
		out.EOSState = models.EOSSupported
	}
	return out
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// parseISODate reads a "YYYY-MM-DD" (a jsonb-rendered date); nil for nil or "".
func parseISODate(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(isoDate, (*s)[:min(len(*s), len(isoDate))])
	if err != nil {
		return nil
	}
	return &t
}

// assetLifecycleSQL is one text column, a jsonb object of the asset's eleven
// commercial columns and the four end-of-support inputs. It is a correlated
// sub-select over `a` so the list and single reads add one column, not four
// joins to their FROM.
const assetLifecycleSQL = `(SELECT jsonb_build_object(
		'purchase_date', a.purchase_date, 'warranty_start', a.warranty_start, 'warranty_end', a.warranty_end,
		'purchase_cost', a.purchase_cost, 'purchase_currency', a.purchase_currency, 'purchase_order', a.purchase_order,
		'vendor', a.vendor, 'support_contract', a.support_contract, 'support_contract_end', a.support_contract_end,
		'installed_at', a.installed_at, 'decommissioned_at', a.decommissioned_at,
		'dt_end_of_support', lc_dt.end_of_support, 'dt_catalogue_end_of_support', lc_dte.eol_date,
		'pl_end_of_support', lc_pl.end_of_support, 'pl_catalogue_end_of_support', lc_ple.eol_date)
	  FROM (SELECT 1) lc_one
	  LEFT JOIN device_types lc_dt ON lc_dt.id = a.device_type_id
	  LEFT JOIN eol_catalogue lc_dte ON lc_dte.id = lc_dt.eol_catalogue_id
	  LEFT JOIN platforms lc_pl ON lc_pl.id = a.platform_id
	  LEFT JOIN eol_catalogue lc_ple ON lc_ple.id = lc_pl.eol_catalogue_id)::text`

// assetLifecycleRow is assetLifecycleSQL's object.
type assetLifecycleRow struct {
	models.AssetCommercial
	DTEndOfSupport          *string `json:"dt_end_of_support"`
	DTCatalogueEndOfSupport *string `json:"dt_catalogue_end_of_support"`
	PLEndOfSupport          *string `json:"pl_end_of_support"`
	PLCatalogueEndOfSupport *string `json:"pl_catalogue_end_of_support"`
}

func (r assetLifecycleRow) inputs() LifecycleInputs {
	return LifecycleInputs{
		WarrantyEnd: parseISODate(r.WarrantyEnd),
		DeviceType:  EOSCandidate{Declared: parseISODate(r.DTEndOfSupport), Catalogue: parseISODate(r.DTCatalogueEndOfSupport)},
		Platform:    EOSCandidate{Declared: parseISODate(r.PLEndOfSupport), Catalogue: parseISODate(r.PLCatalogueEndOfSupport)},
	}
}

// lifecycleNow is the clock the reads compute against (tests pin it).
var lifecycleNow = time.Now

// applyAssetLifecycle decodes assetLifecycleSQL's text onto the asset: the
// commercial fields and the computed block. An undecodable or empty value
// leaves the fields nil and the block unknown — never a guess.
func applyAssetLifecycle(asset *models.Asset, text string) {
	var row assetLifecycleRow
	if text != "" {
		_ = json.Unmarshal([]byte(text), &row)
	}
	asset.AssetCommercial = row.AssetCommercial
	lc := ComputeAssetLifecycle(row.inputs(), lifecycleNow())
	asset.Lifecycle = &lc
}

// EOLCatalogueEntries lists end-of-life catalogue entries a device type
// (`hardware`) or platform (`os`) may be linked to, for the catalogue forms'
// picker: `kind` is required, `q` matches the vendor, product or cycle
// (case-insensitive substring), at most `limit` rows ordered by vendor,
// product and cycle. The catalogue is platform-scoped and carries no tenant_id;
// the read still runs in the tenant's transaction like every other.
func (s *CatalogueService) EOLCatalogueEntries(ctx context.Context, tenant uuid.UUID, kind, q string, limit int) ([]EOLCatalogueRef, error) {
	if kind != "hardware" && kind != "os" {
		return nil, ipamInvalid("product_kind must be hardware or os")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	out := []EOLCatalogueRef{}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pattern := "%" + escapeLike(strings.ToLower(strings.TrimSpace(q))) + "%"
		rows, err := tx.QueryContext(ctx, `
			SELECT id, product_kind, vendor, product, cycle, eol_date::text, extended_support_date::text
			  FROM public.eol_catalogue
			 WHERE product_kind = $1
			   AND (lower(COALESCE(vendor, '')) LIKE $2 OR lower(product) LIKE $2 OR lower(cycle) LIKE $2)
			 ORDER BY lower(COALESCE(vendor, '')), lower(product), cycle, id
			 LIMIT $3`, kind, pattern, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r EOLCatalogueRef
			var vendor, eol, ext sql.NullString
			if err := rows.Scan(&r.ID, &r.ProductKind, &vendor, &r.Product, &r.Cycle, &eol, &ext); err != nil {
				return err
			}
			r.Vendor, r.EOLDate, r.ExtendedSupportDate = ifaceStrPtr(vendor), ifaceStrPtr(eol), ifaceStrPtr(ext)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
