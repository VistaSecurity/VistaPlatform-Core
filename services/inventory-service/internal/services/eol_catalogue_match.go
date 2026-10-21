package services

// Automatic end-of-life catalogue matching (DCIM gap 4 follow-up).
//
// device_types.eol_catalogue_id and platforms.eol_catalogue_id are set by hand
// in the catalogue forms; the fallback to a catalogue entry only works when a
// person linked one. This file links the unambiguous ones for them:
//
//   - a device type matches a `hardware` entry whose vendor is the
//     manufacturer's name and whose product is the model or the part number
//     (equal after trimming, collapsing whitespace and lower-casing), or, when
//     none is equal, whose product is a whole-token prefix of the model;
//   - a platform matches an `os` entry whose product is the platform's name
//     (or whose "product cycle" reads as the name), and, when both the
//     platform's manufacturer and the entry's vendor are recorded, the two
//     agree.
//
// Exactly one matching entry sets the link; two or more is no guess (the
// catalogue holds one row per release cycle, so a bare product name usually
// names several). A link is only ever written to a NULL column, so a person's
// link is never replaced, and a row a person once unlinked is left alone. The
// change is recorded with source `intake:eol-match`, which is how the
// catalogue forms tell a link made here from one made by a person.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// EOLMatchSource is the change source of an automatic link.
const EOLMatchSource = "eol-match"

// eolEntry is the part of an eol_catalogue row the matcher reads, already
// normalised.
type eolEntry struct {
	ID      uuid.UUID
	Vendor  string
	Product string
	Cycle   string
}

// normaliseEOLText trims, collapses runs of whitespace to one space and
// lower-cases: the only normalisation the match applies.
func normaliseEOLText(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// eolMatchResult is the outcome for one row.
type eolMatchResult int

const (
	eolNoMatch eolMatchResult = iota
	eolMatched
	eolAmbiguous
)

// matchEOLHardware finds the single hardware entry for a device type.
// entries must already be limited to hardware ones.
func matchEOLHardware(manufacturer, model, partNumber string, entries []eolEntry) (uuid.UUID, eolMatchResult) {
	vendor := normaliseEOLText(manufacturer)
	m, p := normaliseEOLText(model), normaliseEOLText(partNumber)
	if vendor == "" || (m == "" && p == "") {
		return uuid.Nil, eolNoMatch
	}
	var exact, prefix []uuid.UUID
	for _, e := range entries {
		if e.Vendor != vendor || e.Product == "" {
			continue
		}
		switch {
		case e.Product == m || (p != "" && e.Product == p):
			exact = append(exact, e.ID)
		case m != "" && hasTokenPrefix(m, e.Product):
			prefix = append(prefix, e.ID)
		}
	}
	if len(exact) > 0 {
		return single(exact)
	}
	return single(prefix)
}

// matchEOLPlatform finds the single os entry for a platform.
func matchEOLPlatform(name, manufacturer string, entries []eolEntry) (uuid.UUID, eolMatchResult) {
	n, vendor := normaliseEOLText(name), normaliseEOLText(manufacturer)
	if n == "" {
		return uuid.Nil, eolNoMatch
	}
	var hit []uuid.UUID
	for _, e := range entries {
		if e.Product == "" {
			continue
		}
		if e.Product != n && e.Product+" "+e.Cycle != n {
			continue
		}
		if vendor != "" && e.Vendor != "" && e.Vendor != vendor {
			continue
		}
		hit = append(hit, e.ID)
	}
	return single(hit)
}

func single(ids []uuid.UUID) (uuid.UUID, eolMatchResult) {
	switch len(ids) {
	case 0:
		return uuid.Nil, eolNoMatch
	case 1:
		return ids[0], eolMatched
	default:
		return uuid.Nil, eolAmbiguous
	}
}

// hasTokenPrefix reports whether s starts with prefix and the prefix ends at a
// token boundary, so "c9300" prefixes "c9300-48p" but "catalyst 9" does not
// prefix "catalyst 9300".
func hasTokenPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := s[len(prefix):]
	if rest == "" {
		return true
	}
	pr := []rune(prefix)
	return !isEOLWordRune([]rune(rest)[0]) || !isEOLWordRune(pr[len(pr)-1])
}

func isEOLWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// loadEOLEntries reads the catalogue entries of one kind (all of them when
// vendor is nil, else only that normalised vendor's).
func loadEOLEntries(ctx context.Context, tx *sql.Tx, kind string, vendor *string) ([]eolEntry, error) {
	q := `SELECT id, COALESCE(vendor, ''), product, cycle FROM public.eol_catalogue WHERE product_kind = $1`
	args := []any{kind}
	if vendor != nil {
		q += ` AND lower(regexp_replace(btrim(COALESCE(vendor, '')), '\s+', ' ', 'g')) = $2`
		args = append(args, *vendor)
	}
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []eolEntry
	for rows.Next() {
		var e eolEntry
		var vend, prod, cyc string
		if err := rows.Scan(&e.ID, &vend, &prod, &cyc); err != nil {
			return nil, err
		}
		e.Vendor, e.Product, e.Cycle = normaliseEOLText(vend), normaliseEOLText(prod), normaliseEOLText(cyc)
		out = append(out, e)
	}
	return out, rows.Err()
}

// eolLinkTarget describes the two tables the matcher links.
type eolLinkTarget struct {
	kind  dcim.ObjectKind
	table string
}

var (
	eolDeviceTypes = eolLinkTarget{dcim.ObjectKindDeviceType, "device_types"}
	eolPlatforms   = eolLinkTarget{dcim.ObjectKindPlatform, "platforms"}
)

// linkEOLEntry writes entry onto a row whose link is still NULL and records the
// change. It returns false when the row was linked (or removed) meanwhile.
func linkEOLEntry(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, target eolLinkTarget, id, entry uuid.UUID) (bool, error) {
	var pre []byte
	err := tx.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT to_jsonb(t) FROM public.%s t WHERE t.id = $1 AND t.tenant_id = $2 AND t.eol_catalogue_id IS NULL FOR UPDATE`, target.table),
		id, tenant).Scan(&pre)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var post []byte
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(
		`UPDATE public.%s AS t SET eol_catalogue_id = $3, updated_at = now() WHERE t.id = $1 AND t.tenant_id = $2 RETURNING to_jsonb(t)`, target.table),
		id, tenant, entry).Scan(&post); err != nil {
		return false, err
	}
	err = changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: target.kind, ID: id, Action: changes.ActionUpdate,
		Pre: json.RawMessage(pre), Post: json.RawMessage(post), Source: changes.IntakeSource(EOLMatchSource),
	})
	return err == nil, err
}

// eolRow is one unlinked device type or platform.
type eolRow struct {
	id           uuid.UUID
	manufacturer string
	name         string // the model for a device type, the name for a platform
	partNumber   string
}

// eolUnlinkedSQL lists the tenant's unlinked rows, minus those a person has
// unlinked (a ui/api change that took a non-NULL link back to NULL).
func eolUnlinkedSQL(target eolLinkTarget) string {
	nameCol, partCol := "t.name", "''"
	if target.table == "device_types" {
		nameCol, partCol = "t.model", "COALESCE(t.part_number, '')"
	}
	return fmt.Sprintf(`
		SELECT t.id, COALESCE(m.name, ''), %s, %s
		FROM public.%s t
		LEFT JOIN public.manufacturers m ON m.id = t.manufacturer_id
		WHERE t.tenant_id = $1 AND t.eol_catalogue_id IS NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM public.object_changes c
		      WHERE c.tenant_id = t.tenant_id AND c.object_kind = '%s' AND c.object_id = t.id
		        AND c.source IN ('ui', 'api')
		        AND 'eol_catalogue_id' = ANY (c.changed_fields)
		        AND c.prechange_data ->> 'eol_catalogue_id' IS NOT NULL
		        AND c.postchange_data ->> 'eol_catalogue_id' IS NULL)
		ORDER BY t.id`, nameCol, partCol, target.table, target.kind)
}

// EOLMatchCounts is what one pass did.
type EOLMatchCounts struct {
	Linked    int
	Ambiguous int
}

// MatchEOLCatalogue links every unlinked device type and platform of the tenant
// that has exactly one matching catalogue entry.
func (s *CatalogueService) MatchEOLCatalogue(ctx context.Context, tenant uuid.UUID) (EOLMatchCounts, error) {
	var out EOLMatchCounts
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		hw, err := loadEOLEntries(ctx, tx, "hardware", nil)
		if err != nil {
			return err
		}
		osEntries, err := loadEOLEntries(ctx, tx, "os", nil)
		if err != nil {
			return err
		}
		for _, target := range []eolLinkTarget{eolDeviceTypes, eolPlatforms} {
			rows, err := tx.QueryContext(ctx, eolUnlinkedSQL(target), tenant)
			if err != nil {
				return err
			}
			var todo []eolRow
			for rows.Next() {
				var r eolRow
				if err := rows.Scan(&r.id, &r.manufacturer, &r.name, &r.partNumber); err != nil {
					_ = rows.Close()
					return err
				}
				todo = append(todo, r)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range todo {
				var entry uuid.UUID
				var res eolMatchResult
				if target == eolDeviceTypes {
					entry, res = matchEOLHardware(r.manufacturer, r.name, r.partNumber, hw)
				} else {
					entry, res = matchEOLPlatform(r.name, r.manufacturer, osEntries)
				}
				switch res {
				case eolAmbiguous:
					out.Ambiguous++
					slog.Info("eol catalogue match: more than one entry fits; not guessing",
						"tenant", tenant, "kind", target.kind, "id", r.id)
				case eolMatched:
					ok, err := linkEOLEntry(ctx, tx, tenant, target, r.id, entry)
					if err != nil {
						return fmt.Errorf("%s %s: %w", target.kind, r.id, err)
					}
					if ok {
						out.Linked++
					}
				}
			}
		}
		return nil
	})
	return out, err
}

// matchEOLAfterWrite is the device type and platform specs' AfterWrite: on a
// create, or when the fields the match reads changed, try the one row. It
// runs in the writing transaction, so the link and its change record commit
// with the row.
func matchEOLAfterWrite(target eolLinkTarget) func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	return func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
		if post == nil || post["eol_catalogue_id"] != nil {
			return nil
		}
		if pre != nil {
			same := true
			for _, k := range []string{"manufacturer_id", "model", "part_number", "name"} {
				if fmt.Sprint(pre[k]) != fmt.Sprint(post[k]) {
					same = false
				}
			}
			if same {
				return nil
			}
		}
		id, err := uuid.Parse(fmt.Sprint(post["id"]))
		if err != nil {
			return nil
		}
		var mfr string
		if m := fmt.Sprint(post["manufacturer_id"]); post["manufacturer_id"] != nil {
			if err := tx.QueryRowContext(ctx, `SELECT name FROM public.manufacturers WHERE id = $1::uuid`, m).Scan(&mfr); err != nil && err != sql.ErrNoRows {
				return err
			}
		}
		var entry uuid.UUID
		var res eolMatchResult
		if target == eolDeviceTypes {
			vendor := normaliseEOLText(mfr)
			entries, err := loadEOLEntries(ctx, tx, "hardware", &vendor)
			if err != nil {
				return err
			}
			entry, res = matchEOLHardware(mfr, strVal(post["model"]), strVal(post["part_number"]), entries)
		} else {
			entries, err := loadEOLEntries(ctx, tx, "os", nil)
			if err != nil {
				return err
			}
			entry, res = matchEOLPlatform(strVal(post["name"]), mfr, entries)
		}
		if res != eolMatched {
			return nil
		}
		_, err = linkEOLEntry(ctx, tx, tenant, target, id, entry)
		return err
	}
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// EOLMatchTenants lists the live tenants (BYPASS connection, like the other
// workers' enumerations).
func EOLMatchTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	return ClassFloorSweepTenants(ctx, bypass)
}

// eolLinkSourceSQL is the list projection's `eol_link_source`: how the row's
// current end-of-life catalogue link came about. NULL when there is no link,
// `automatic` when the latest change that set it came from the matcher, else
// `manual` (a person, an import, or a link older than the change record). A
// platform-scoped row (no tenant) reads `manual`: it was seeded, not matched.
func eolLinkSourceSQL(kind string) string {
	return `(CASE WHEN t.eol_catalogue_id IS NULL THEN NULL ELSE COALESCE((
		SELECT CASE WHEN c.source = 'intake:` + EOLMatchSource + `' THEN 'automatic' ELSE 'manual' END
		FROM public.object_changes c
		WHERE c.tenant_id = t.tenant_id AND c.object_kind = '` + kind + `' AND c.object_id = t.id
		  AND 'eol_catalogue_id' = ANY (c.changed_fields)
		  AND c.postchange_data ->> 'eol_catalogue_id' IS NOT NULL
		ORDER BY c.created_at DESC LIMIT 1), 'manual') END)`
}
