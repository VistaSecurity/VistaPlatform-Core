package entitlements

// ForgetLicenseTableForTest makes the next transaction-path licence read probe
// for platform_license again, as a freshly started process would. Test-only:
// the flag is process-global, and a test that drops the table must not inherit
// "seen" from another test in the same binary.
func ForgetLicenseTableForTest() { licenseTableSeen.Store(false) }
