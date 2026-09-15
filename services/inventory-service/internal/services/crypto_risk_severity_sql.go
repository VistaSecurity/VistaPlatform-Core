package services

import "strconv"

// One spelling of each crypto-risk severity predicate.
//
// These used to be written out inline in nine places across GetSummary and
// ListRisks, with a comment in two of them saying they "must stay IDENTICAL" —
// which is what you write when nothing can check it. Four of the copies had
// already drifted: the `COALESCE(col, '')` that B-39 added so a NULL column
// under a `NOT (…)` chain does not silently drop the row was present in some
// and missing from others, and the Critical chain spelled `%DES%` where the
// generated single-DES helper spells something narrower.
//
// The key-size and DES arms come from weak_crypto_detector.go's generated
// helpers, so the summary counters, the list filters and the Go classifier
// cannot disagree about what counts as weak.
//
// Every predicate here is NULL-safe: a comparison against a NULL column reads
// as FALSE rather than NULL, which matters because three of the call sites
// negate the whole chain. `NOT NULL` is NULL, and a row whose cipher_suite is
// NULL — every SSH configuration, by construction — then matches neither the
// chain nor its negation and vanishes from both buckets.

// cryptoCriticalSQL is the Critical severity band: SSL, TLS 1.0, RC4, single
// DES, NULL or EXPORT ciphers, MD4/MD5, and critically weak key sizes.
func cryptoCriticalSQL() string {
	return `(
		UPPER(COALESCE(ci.protocol_version, '')) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
		OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1.0%'
		OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1%0%'
		OR COALESCE(ci.protocol_version, '') = '1.0'
		OR COALESCE(ci.protocol_version, '') LIKE '1.0%'
		OR COALESCE(ci.protocol_version, '') LIKE '%1.0'
		OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%RC4%'
		OR ` + singleDESSQL("ci.cipher_suite") + `
		OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%NULL%'
		OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%EXPORT%'
		OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%MD5%'
		OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%MD4%'
		OR ` + criticallyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
	)`
}

// cryptoHighSQL is the High band: TLS 1.1, 3DES, SHA-1, and high-risk key
// sizes. It does NOT exclude Critical — the caller decides precedence, which is
// what makes a per-asset rollup possible without three nested NOTs.
func cryptoHighSQL() string {
	return `(
		UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1.1%'
		OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1%1%'
		OR COALESCE(ci.protocol_version, '') = '1.1'
		OR COALESCE(ci.protocol_version, '') LIKE '1.1%'
		OR COALESCE(ci.protocol_version, '') LIKE '%1.1'
		OR ` + tripleDESSQL("ci.cipher_suite") + `
		OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%SHA1%'
		OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%SHA-1%'
		OR ` + highRiskKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
	)`
}

// cryptoMediumSQL is the Medium band: a certificate expiring inside 30 days.
func cryptoMediumSQL() string {
	return certExpiringWithinSQL(30)
}

// certExpiringWithinSQL is an EXISTS over the configuration's certificates. The
// window is a Go int rather than a bind parameter because these fragments are
// spliced into queries whose parameter numbering the caller owns; it is never
// user input.
func certExpiringWithinSQL(days int) string {
	return `EXISTS (
		SELECT 1 FROM crypto_implementation_certificates cic
		JOIN certificates c ON cic.certificate_id = c.id
		WHERE cic.crypto_implementation_id = ci.id
		  AND c.not_after IS NOT NULL
		  AND c.not_after BETWEEN NOW() AND NOW() + (INTERVAL '1 day' * ` + strconv.Itoa(days) + `)
	)`
}

// cryptoInformationalSQL is the residue: scored above zero, and matching none of
// the three named bands. It is defined as the negation of the others so the four
// bands partition the scored configurations — a configuration cannot be both
// High and Informational, and none is left out.
func cryptoInformationalSQL() string {
	return `(
		ci.risk_score IS NOT NULL AND ci.risk_score > 0
		AND NOT (` + cryptoCriticalSQL() + ` OR ` + cryptoHighSQL() + ` OR ` + cryptoMediumSQL() + `)
	)`
}

// cryptoAnyRiskSQL is "matches any risk pattern at all" — the default ListRisks
// filter. The certificate window here is 90 days, not 30: the list surfaces a
// certificate worth looking at, while the Medium BAND is the narrower "expiring
// now" claim.
func cryptoAnyRiskSQL() string {
	return `(` + cryptoCriticalSQL() + `
		OR ` + cryptoHighSQL() + `
		OR ` + certExpiringWithinSQL(90) + `
		OR ` + anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
		OR (ci.risk_score IS NOT NULL AND ci.risk_score > 0)
	)`
}

// cryptoSeverityCaseSQL ranks a configuration 4..1 (critical..informational), 0
// for unscored. Ranking rather than four booleans is what lets a per-asset
// rollup be a plain MAX.
func cryptoSeverityCaseSQL() string {
	return `CASE
		WHEN ` + cryptoCriticalSQL() + ` THEN 4
		WHEN ` + cryptoHighSQL() + ` THEN 3
		WHEN ` + cryptoMediumSQL() + ` THEN 2
		WHEN ci.risk_score IS NOT NULL AND ci.risk_score > 0 THEN 1
		ELSE 0
	END`
}
