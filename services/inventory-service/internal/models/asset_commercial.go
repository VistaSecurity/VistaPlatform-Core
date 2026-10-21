package models

// The asset commercial lifecycle (DCIM gap 4; DATA_MODEL §2 "commercial
// lifecycle"): what an asset cost, who sold it, its warranty and support
// contract, when it went in and came out — and, computed from those and its
// device type's and platform's end-of-support dates, two states a list can
// filter and a badge can show.
//
// Every field is DECLARED (a person or an import wrote it); nothing measures a
// purchase order. A nil field is "not recorded" and is serialised as null,
// never as a zero value: an asset with no warranty_end has an UNKNOWN
// warranty, not an expired one and not an active one.

// AssetCommercial is the eleven commercial columns of an asset. Dates are
// ISO 8601 calendar dates ("").
type AssetCommercial struct {
	PurchaseDate  *string `json:"purchase_date" db:"purchase_date"`
	WarrantyStart *string `json:"warranty_start" db:"warranty_start"`
	WarrantyEnd   *string `json:"warranty_end" db:"warranty_end"`
	// PurchaseCost is numeric(14,2) in the column; PurchaseCurrency is its
	// ISO 4217 code (upper-case, three letters, CHECKed).
	PurchaseCost     *float64 `json:"purchase_cost" db:"purchase_cost"`
	PurchaseCurrency *string  `json:"purchase_currency" db:"purchase_currency"`
	PurchaseOrder    *string  `json:"purchase_order" db:"purchase_order"`
	// Vendor is the SELLER (a reseller, a distributor), which is not the
	// manufacturer — that is the device type's.
	Vendor             *string `json:"vendor" db:"vendor"`
	SupportContract    *string `json:"support_contract" db:"support_contract"`
	SupportContractEnd *string `json:"support_contract_end" db:"support_contract_end"`
	InstalledAt        *string `json:"installed_at" db:"installed_at"`
	DecommissionedAt   *string `json:"decommissioned_at" db:"decommissioned_at"`
}

// Warranty states. WarrantyUnknown is the answer when no warranty_end is
// recorded; it is never defaulted to active.
const (
	WarrantyActive     = "active"
	WarrantyExpiring90 = "expiring_90"
	WarrantyExpired    = "expired"
	WarrantyUnknown    = "unknown"
)

// End-of-support states. EOSUnknown is the answer when neither the device type
// nor the platform has an end-of-support date, declared or from the end-of-life
// catalogue; it is never defaulted to supported.
const (
	EOSSupported   = "supported"
	EOSWithin12m   = "eos_within_12m"
	EOSPastEOS     = "past_eos"
	EOSUnknown     = "unknown"
	EOSSourceDecl  = "declared"
	EOSSourceCat   = "catalogue"
	EOSSourceNone  = "none"
	EOSSubjectDT   = "device_type"
	EOSSubjectPlat = "platform"
)

// AssetLifecycle is the computed, read-only lifecycle block on an asset.
type AssetLifecycle struct {
	WarrantyState string `json:"warranty_state"`
	EOSState      string `json:"eos_state"`
	// EffectiveEndOfSupport is the earlier of the device type's and the
	// platform's effective end-of-support dates (declared, else the linked
	// end-of-life catalogue entry's eol_date); nil when neither has one.
	EffectiveEndOfSupport *string `json:"effective_end_of_support"`
	// Source says where EffectiveEndOfSupport came from: declared, catalogue,
	// or none when there is no date.
	Source string `json:"source"`
	// Subject is which catalogue object the date belongs to: device_type or
	// platform; nil when there is no date.
	Subject *string `json:"subject"`
}
