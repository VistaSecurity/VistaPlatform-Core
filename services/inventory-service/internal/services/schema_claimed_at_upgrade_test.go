package services

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSchemaClaimedAtAlterPrecedesSensorDiscoveriesView(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const alter = "ALTER TABLE IF EXISTS public.sensor_discoveries_partitioned\n    ADD COLUMN IF NOT EXISTS claimed_at timestamp with time zone;"
	const view = "CREATE OR REPLACE VIEW public.sensor_discoveries AS"

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			alterIdx := strings.Index(sql, alter)
			if alterIdx < 0 {
				t.Fatalf("missing upgrade-safe claimed_at ALTER in %s", rel)
			}
			viewIdx := strings.Index(sql, view)
			if viewIdx < 0 {
				t.Fatalf("missing sensor_discoveries view in %s", rel)
			}
			if alterIdx > viewIdx {
				t.Fatalf("claimed_at ALTER must run before the sensor_discoveries view is recreated in %s", rel)
			}
		})
	}
}

func TestSchemaRepairsInvalidNetworkAssetParentPrimaryKey(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const repairMarker = "ALTER INDEX public.network_assets_partitioned_pkey ATTACH PARTITION public.network_assets_part_%s_pkey"
	const compositeFK = "REFERENCES public.network_assets_partitioned(tenant_id, id)"

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			repairIdx := strings.Index(sql, repairMarker)
			if repairIdx < 0 {
				t.Fatalf("missing invalid network_assets_partitioned_pkey repair in %s", rel)
			}
			fkIdx := strings.Index(sql, compositeFK)
			if fkIdx < 0 {
				t.Fatalf("missing tenant-scoped network_assets_partitioned FK in %s", rel)
			}
			if repairIdx > fkIdx {
				t.Fatalf("invalid parent pkey repair must run before composite network_assets_partitioned FKs in %s", rel)
			}
		})
	}
}

func TestSchemaAddsServiceAccountTokenLookupBeforeIndex(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	const alter = "ALTER TABLE IF EXISTS public.service_accounts\n    ADD COLUMN IF NOT EXISTS token_lookup text;"
	const index = "CREATE INDEX IF NOT EXISTS idx_service_accounts_token_lookup"

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			alterIdx := strings.Index(sql, alter)
			if alterIdx < 0 {
				t.Fatalf("missing upgrade-safe service_accounts.token_lookup ALTER in %s", rel)
			}
			indexIdx := strings.Index(sql, index)
			if indexIdx < 0 {
				t.Fatalf("missing service_accounts.token_lookup index in %s", rel)
			}
			if alterIdx > indexIdx {
				t.Fatalf("service_accounts.token_lookup ALTER must run before its index in %s", rel)
			}
		})
	}
}

func TestSchemaKeepsLateUpgradeRepairsForLegacyResidue(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))

	required := []string{
		"DROP TABLE IF EXISTS public.crypto_configurations CASCADE;",
		"DROP FUNCTION IF EXISTS public.update_crypto_configurations_updated_at();",
		"ALTER TABLE IF EXISTS public.crypto_implementation_certificates\n  DROP CONSTRAINT IF EXISTS valid_certificate_role;",
		"CHECK (certificate_role IN ('leaf', 'primary', 'additional', 'intermediate', 'root'))",
	}

	for _, rel := range []string{
		"scripts/database/schema.sql",
		"charts/vistaplatform/files/schema/schema.sql",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			sql := string(body)
			for _, want := range required {
				if !strings.Contains(sql, want) {
					t.Fatalf("missing late upgrade repair %q in %s", want, rel)
				}
			}
		})
	}
}
