package services

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	invmodels "github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

var pptpSeedRowRe = regexp.MustCompile(`(?s)\('PPTP'\s*,\s*'([^']+)'\s*,\s*'[^']*'\s*,\s*'[^']*'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*(\d+)`)

// TestSeededPPTPProtocolVersionRowStaysLoadBearing is the cheap guard for the
// catalogue half of PPTP risk scoring. The DB integration test proves the full
// ingest path, but skips without TEST_DATABASE_URL; this fails on a plain
// package test if the seed row that path depends on is removed or weakened.
func TestSeededPPTPProtocolVersionRowStaysLoadBearing(t *testing.T) {
	seedPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql")
	body, err := os.ReadFile(seedPath) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read seed.sql: %v", err)
	}
	seed := string(body)

	if n := strings.Count(seed, "('PPTP'"); n != 1 {
		t.Fatalf("seed.sql has %d PPTP algorithm row(s), want exactly 1", n)
	}

	m := pptpSeedRowRe.FindStringSubmatch(seed)
	if m == nil {
		t.Fatalf("seed.sql no longer seeds the PPTP algorithm row in the expected algorithms tuple shape")
	}

	category, strength, deprecation := m[1], m[2], m[3]
	score, err := strconv.Atoi(m[4])
	if err != nil {
		t.Fatalf("parse PPTP risk score %q: %v", m[4], err)
	}

	if category != "protocol_version" {
		t.Fatalf("PPTP category = %q, want protocol_version - classifyAndLinkAlgorithms links "+
			"PPTP through ProtocolVersion, so moving this row makes enabled PPTP score 0", category)
	}
	if strength != "weak" || deprecation != "obsolete" {
		t.Errorf("PPTP assessment = strength %q, deprecation %q; want weak/obsolete", strength, deprecation)
	}
	if band := invmodels.GetRiskLevel(score); band != "Critical" {
		t.Fatalf("PPTP risk score = %d (%s), want Critical - enabled PPTP must stay near the "+
			"top of the risk list, not become an informational row", score, band)
	}
}
