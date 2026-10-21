package sql

// AssetEffectiveEndOfSupportSQL is the asset's effective end of support (DCIM
// gap 4) as a scalar date expression over the asset alias `asset`: the EARLIER
// of its device type's and its platform's effective end of support, where each
// is the declared end_of_support or, when that is NULL, the eol_date of the
// end-of-life catalogue entry the type or platform is linked to. NULL when
// neither has a date — UNKNOWN to every comparison, so `end_of_support < now`
// never matches an asset nobody recorded a date for.
//
// LEAST ignores NULLs, which is what makes "the earlier of the two, or the one
// there is" a single expression. inventory-service's ComputeAssetLifecycle is
// the Go side of the same rule; an integration test there holds the two to the
// same date.
func AssetEffectiveEndOfSupportSQL(asset string, alias func(string) string) string {
	dt, dte, pl, ple := alias("eosdt"), alias("eosdte"), alias("eospl"), alias("eosple")
	return "LEAST(" +
		"(SELECT COALESCE(" + dt + ".end_of_support, " + dte + ".eol_date) FROM device_types " + dt +
		" LEFT JOIN eol_catalogue " + dte + " ON " + dte + ".id = " + dt + ".eol_catalogue_id" +
		" WHERE " + dt + ".id = " + asset + ".device_type_id), " +
		"(SELECT COALESCE(" + pl + ".end_of_support, " + ple + ".eol_date) FROM platforms " + pl +
		" LEFT JOIN eol_catalogue " + ple + " ON " + ple + ".id = " + pl + ".eol_catalogue_id" +
		" WHERE " + pl + ".id = " + asset + ".platform_id))"
}
