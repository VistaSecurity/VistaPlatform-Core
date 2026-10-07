package services

// Runs the external-connections search against a real Postgres, through the
// real List, so the claim is about the rows the ILIKE ... ESCAPE actually
// returns rather than the string the Go code builds. Skips without
// TEST_DATABASE_URL (`make test-integration-db`).
//
// Mutation check: put the old `"%"+f.Search+"%"` back in List (or drop the
// ESCAPE clause) and the `_` and `%` cases return extra rows.

import (
	"sort"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ExternalConnectionsSearch_WildcardsMatchLiterally(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	hosts := []string{
		"build_agent.example.com",
		"buildXagent.example.com",
		"100%-uptime.example.com",
		"1000-uptime.example.com",
		"plain.example.com",
	}
	for i, h := range hosts {
		if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
			SourceIP:     "192.0.2.10",
			DestIP:       "203.0.113." + string(rune('1'+i)),
			DestPort:     443,
			Protocol:     "TLS",
			DestHostname: strptr(h),
		}); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	search := func(term string) []string {
		rows, _, err := svc.List(tenant, models.ExternalConnectionFilters{Search: term, PageSize: 100})
		if err != nil {
			t.Fatalf("List(search=%q): %v", term, err)
		}
		var out []string
		for _, r := range rows {
			if r.DestHostname != nil {
				out = append(out, *r.DestHostname)
			}
		}
		sort.Strings(out)
		return out
	}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	for _, tc := range []struct {
		term string
		want []string
	}{
		{"_", []string{"build_agent.example.com"}},
		{"d_a", []string{"build_agent.example.com"}},
		{"%", []string{"100%-uptime.example.com"}},
		{"0%", []string{"100%-uptime.example.com"}},
		{"BUILD", []string{"buildXagent.example.com", "build_agent.example.com"}}, // still case-insensitive contains
		{"203.0.113.5", []string{"plain.example.com"}},                            // dest_ip match still works
	} {
		if got := search(tc.term); !eq(got, tc.want) {
			t.Errorf("search %q = %v, want %v", tc.term, got, tc.want)
		}
	}
}
