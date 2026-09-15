package services

// The lifecycle vocabulary is spelled in three places — the Go constants the
// producer writes, the schema's CHECK that accepts them, and the SQL this
// package builds to read them — and a word present in one and absent from
// another fails silently: the producer writes it, the database accepts it,
// and the column falls through to `not_assessed` for an answer that was
// recorded. These are unit tests (schema.sql is in the repository), so they
// run on every `go test ./...` rather than only when a Postgres is up.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

var lifecycleCheckPattern = regexp.MustCompile(
	`software_install_lifecycle_assessment_check CHECK \(assessment = ANY \(ARRAY\[([^\]]+)\]\)\)`)

func TestSchemaLifecycleCheckMatchesTheGoVocabulary(t *testing.T) {
	body := schemaSQL(t)
	m := lifecycleCheckPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("schema.sql has no software_install_lifecycle_assessment_check in the expected shape")
	}
	var got []string
	for _, part := range strings.Split(m[1], ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimSuffix(part, "::text")
		got = append(got, strings.Trim(part, "'"))
	}
	want := software.LifecycleAssessments
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("schema CHECK accepts %v; the Go vocabulary is %v — a word in one and not the other is written and never read, or refused inside the producer's transaction",
			got, want)
	}
}

// Every recorded word except `end_of_life` is read as a state of its own;
// `end_of_life` is deliberately NOT — the open finding carries that state, and
// a record saying end_of_life beside a closed finding must fall through (see
// the file comment on software_findings_rollup.go). Deleting a WHEN branch
// from either builder fails this.
func TestEOLStateSQL_ReadsEveryRecordedWordExceptEndOfLife(t *testing.T) {
	perInstall := eolStateSQL("f", "lc")
	for _, w := range software.LifecycleAssessments {
		has := strings.Contains(perInstall, "lc.assessment = '"+w+"'")
		if w == software.LifecycleEndOfLife {
			if has {
				t.Errorf("the per-install state reads the recorded %q directly; the open finding is the only source of that state", w)
			}
			continue
		}
		if !has {
			t.Errorf("the producer records %q and the per-install state never reads it", w)
		}
	}

	product := eolProductStateSQL("c")
	aggregates := eolLifecycleAggregatesSQL("lc")
	for _, w := range []struct{ word, count string }{
		{software.LifecycleSupported, "supported_install_count"},
		{software.LifecycleNoDate, "no_date_install_count"},
		{software.LifecycleNotInCatalogue, "uncatalogued_install_count"},
	} {
		if !strings.Contains(aggregates, "lc.assessment = '"+w.word+"'") {
			t.Errorf("the catalogue aggregate never counts %q installs", w.word)
		}
		if !strings.Contains(product, "c."+w.count) {
			t.Errorf("the catalogue state never reads %s", w.count)
		}
	}
	if strings.Contains(aggregates, "'"+software.LifecycleEndOfLife+"'") {
		t.Error("the catalogue aggregate counts recorded end_of_life rows; eol_install_count comes from OPEN findings, not the record")
	}

	// And every state the read side can emit is one the API contract names.
	for _, state := range []string{SoftwareEOLEndOfLife, SoftwareEOLSupported, SoftwareEOLNoDate, SoftwareEOLNotInCatalogue, SoftwareEOLNotAssessed} {
		if !strings.Contains(perInstall, "'"+state+"'") || !strings.Contains(product, "'"+state+"'") {
			t.Errorf("state %q is not emitted by both the per-install and the catalogue ladders", state)
		}
	}
}
