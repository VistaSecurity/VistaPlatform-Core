package audit

// validEventCategories is the accepted set, for lookup. The constants and the
// reasoning are in types.go; the CHECK they mirror is in
// scripts/database/schema.sql, and TestEventCategories_MatchTheSchemaCheck
// compares the two.
var validEventCategories = map[string]bool{
	EventCategoryAsset:       true,
	EventCategoryDiscovery:   true,
	EventCategoryCompliance:  true,
	EventCategoryUser:        true,
	EventCategoryTenant:      true,
	EventCategorySystem:      true,
	EventCategoryReport:      true,
	EventCategoryCertificate: true,
	EventCategoryData:        true,
	EventCategoryConfig:      true,
	EventCategoryJob:         true,
	EventCategoryAuth:        true,
}

// ValidEventCategory reports whether audit.activity_logs will accept category.
//
// Use it in a test over a service's own audit call sites. Calling it at runtime
// to substitute a fallback would be the wrong fix: a miscategorised event is a
// programming error, and quietly relabelling it "system" would put the event
// somewhere nobody filtering the audit trail would look.
func ValidEventCategory(category string) bool { return validEventCategories[category] }

// EventCategories returns the accepted categories, sorted, for an error message
// that names them.
func EventCategories() []string {
	out := make([]string, 0, len(validEventCategories))
	for c := range validEventCategories {
		out = append(out, c)
	}
	sortStrings(out)
	return out
}

// sortStrings is sort.Strings without importing sort for one call in a package
// whose import list is otherwise all transport.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
