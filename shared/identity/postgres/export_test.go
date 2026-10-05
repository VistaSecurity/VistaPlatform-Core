package postgres

// HostnameCardinalitySQL exposes the query to the external test package, which
// EXPLAINs it to prove it rides asset_identifiers_value_uniq.
const HostnameCardinalitySQL = hostnameCardinalitySQL

// SourceRankSQL exposes the upsert's rank expression so the external test
// package can evaluate it against identity.SourceRank.
func SourceRankSQL(col string) string { return sourceRankSQL(col) }
