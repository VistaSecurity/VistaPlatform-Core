package api

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Tests for data subject export and erasure.
//
// The two that matter are the redaction test and the secret-column test. Both
// guard the same failure: handing over, or leaving behind, material that must
// never be in either place.

// secretColumns are the columns on `users` that hold credential material. Any
// one of them surviving an erasure, or appearing in an export, is a defect.
var secretColumns = []string{
	"password_hash",
	"password_history",
	"password_reset_token",
	"password_reset_expires",
	"email_verification_token",
	"email_verification_expires",
}

// TestEraseUser_ClearsEverySecretColumn is cited by name in
// scripts/audit-credential-encryption.mjs, which exempts this file from the
// encrypt-your-credentials rule on the grounds that erasure only ever CLEARS
// these columns. That exemption is only honest while this test passes.
func TestEraseUser_ClearsEverySecretColumn(t *testing.T) {
	for _, col := range secretColumns {
		t.Run(col, func(t *testing.T) {
			if !strings.Contains(erasureProfileUpdate, col) {
				t.Fatalf("erasure does not touch users.%s — a secret column would survive "+
					"an erasure the operator has told a data subject was completed", col)
			}
			// Each must be assigned a cleared value, not merely mentioned.
			pattern := regexp.MustCompile(col + `\s*=\s*(NULL|'\[\]'::jsonb|'\{\}'::jsonb)`)
			if !pattern.MatchString(erasureProfileUpdate) {
				t.Fatalf("users.%s appears in the erasure statement but is not cleared to "+
					"NULL or an empty literal:\n%s", col, erasureProfileUpdate)
			}
		})
	}
}

// TestEraseUser_ClearsIdentifyingProfileFields covers the non-secret half: the
// name and avatar are what actually identify the person.
func TestEraseUser_ClearsIdentifyingProfileFields(t *testing.T) {
	for _, col := range []string{"first_name", "last_name", "avatar_url"} {
		if !regexp.MustCompile(col + `\s*=\s*NULL`).MatchString(erasureProfileUpdate) {
			t.Errorf("users.%s is not cleared by the erasure statement", col)
		}
	}
	if !strings.Contains(erasureProfileUpdate, "email = $3") {
		t.Error("the email is not replaced by the tombstone — the person stays identifiable")
	}
}

// TestExportProfileColumns_ExcludeEverySecret pins the export's allowlist. The
// column list is a constant precisely so this test can read it: a `SELECT *`
// would start exporting the password hash the day somebody adds a column.
func TestExportProfileColumns_ExcludeEverySecret(t *testing.T) {
	if strings.Contains(profileExportColumns, "*") {
		t.Fatal("the export selects * — it must name its columns, or a future column ships to the subject")
	}
	for _, col := range secretColumns {
		if strings.Contains(profileExportColumns, col) {
			t.Errorf("export selects users.%s — secret material must never leave in an export", col)
		}
	}
}

// TestExportPayload_SerializesNoSecretFields fills every field of the payload
// and inspects the JSON. It is deliberately structural rather than a spot
// check: if someone adds a field carrying a token, this notices.
func TestExportPayload_SerializesNoSecretFields(t *testing.T) {
	now := time.Now().UTC()
	s := "value"
	payload := dataExport{
		Subject:       exportSubject{UserID: uuid.New(), TenantID: uuid.New()},
		GeneratedAt:   now,
		Profile:       &exportProfile{Email: "person@example.com", FirstName: &s, LastName: &s, Timezone: &s, AvatarURL: &s, LastLoginAt: &now},
		LegalAccepted: []exportLegalAccepted{{DocType: "terms_of_service", Version: 1, ContentHash: "abc", AcceptedAt: now, AcceptedIP: &s, UserAgent: &s}},
		Invitations:   []exportInvitation{{Email: "person@example.com", Role: "viewer", Status: "accepted", CreatedAt: &now}},
		APITokens:     []exportAPIToken{{Name: "ci", Prefix: "vp_abc", CreatedAt: now, LastUsedAt: &now}},
		AuditEvents:   []exportAuditEvent{{OccurredAt: now, EventType: "auth.login", Action: "login", Success: true, IPAddress: &s}},
		AuditWindow:   exportWindow{From: now.AddDate(0, 0, -365), To: now},
		NotIncluded:   notIncludedNotice(),
		SchemaVersion: 1,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	forbidden := []string{
		"password", "password_hash", "token_hash", "secret",
		"mfa", "totp", "session", "private_key",
	}
	walk(t, generic, "", func(t *testing.T, path string) {
		lower := strings.ToLower(path)
		for _, f := range forbidden {
			// token_prefix and api_tokens are metadata and legitimate; the value
			// never is.
			if strings.Contains(lower, f) && !strings.Contains(lower, "token_prefix") && !strings.Contains(lower, "api_tokens") {
				t.Errorf("export payload exposes a field matching %q at %s", f, path)
			}
		}
	})
}

// TestExportPayload_StatesWhatItOmits — an export answers a request by what it
// hands over AND by being straight about what it does not.
func TestExportPayload_StatesWhatItOmits(t *testing.T) {
	notices := strings.ToLower(strings.Join(notIncludedNotice(), " "))
	for _, want := range []string{"discovery", "secret material", "tickets"} {
		if !strings.Contains(notices, want) {
			t.Errorf("the export does not tell the subject that %q is excluded", want)
		}
	}
}

// TestErasureRetention_IsStatedWithReasons — keeping data after an erasure
// request is defensible only if the reason travels with it.
func TestErasureRetention_IsStatedWithReasons(t *testing.T) {
	retained := strings.ToLower(strings.Join(retainedCategories(), " "))
	for _, want := range []string{"legal acceptance", "audit trail", "tickets"} {
		if !strings.Contains(retained, want) {
			t.Errorf("erasure result does not declare that %q is retained", want)
		}
	}
	// A bare list of what we kept, with no reasons, is worse than useless.
	for _, want := range []string{"evidence", "complete", "operational record"} {
		if !strings.Contains(retained, want) {
			t.Errorf("retention list does not explain itself (missing %q)", want)
		}
	}
}

// TestErasureLimitations_AreStated — an operator who believes erasure was total
// when it was not will tell a data subject something untrue.
func TestErasureLimitations_AreStated(t *testing.T) {
	limits := strings.ToLower(strings.Join(erasureLimitations(), " "))
	for _, want := range []string{"payload", "discovery", "backup"} {
		if !strings.Contains(limits, want) {
			t.Errorf("erasure result does not disclose the %q limitation", want)
		}
	}
}

// TestErasureVerify_CoversEveryAnonymizedTable — the post-erasure check is what
// turns "we ran some UPDATEs" into "we confirmed nothing identifying survived".
// If a table is anonymized but not verified, a silent failure ships as success.
func TestErasureVerify_CoversEveryAnonymizedTable(t *testing.T) {
	for _, table := range []string{"users", "api_tokens", "refresh_tokens", "invitations", "audit.activity_logs"} {
		if !strings.Contains(erasureVerify, table) {
			t.Errorf("the erasure verification query does not re-check %s", table)
		}
	}
}

func TestEraseUser_DeletesInvitationsByUserIDOrOriginalEmail(t *testing.T) {
	for _, want := range []string{"accepted_user_id = $2", "lower(email) = lower($3)"} {
		if !strings.Contains(erasureInvitationDelete, want) {
			t.Errorf("invitation erasure does not match %q:\n%s", want, erasureInvitationDelete)
		}
	}
}

func TestTombstoneEmail_IsStableAndUnroutable(t *testing.T) {
	id := uuid.New()
	first, second := tombstoneEmail(id), tombstoneEmail(id)
	if first != second {
		t.Fatal("tombstone is not deterministic — re-running an erasure would create a second identity")
	}
	if !strings.HasSuffix(tombstoneEmail(id), "@erased.invalid") {
		t.Fatalf("tombstone %q is not in the RFC 2606 .invalid space and could be routed or registered", tombstoneEmail(id))
	}
	if tombstoneEmail(id) == tombstoneEmail(uuid.New()) {
		t.Fatal("two different users share a tombstone — the email column is UNIQUE")
	}
}

// walk visits every leaf path in a decoded JSON document.
func walk(t *testing.T, v any, path string, visit func(*testing.T, string)) {
	t.Helper()
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			p := k
			if path != "" {
				p = path + "." + k
			}
			visit(t, p)
			walk(t, child, p, visit)
		}
	case []any:
		for i, child := range node {
			_ = i
			walk(t, child, path+"[]", visit)
		}
	}
}
