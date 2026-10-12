package handlers

// PUT /admin/settings: one transaction, and a value can be cleared.
//
// The save used to upsert key by key with no transaction (a failure part-way
// left a half-applied policy) and skipped empty strings, so platform_name,
// platform_domain, admin_ui_base_url and support_email could never be cleared.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func putSettings(store *stubPlatformSettingsStore, body string) (int, string) {
	w := doRequest(newSettingsEngine(store, true), http.MethodPut, apiBase+"/admin/settings", strings.NewReader(body))
	return w.Code, w.Body.String()
}

func upsertedValue(s *stubPlatformSettingsStore, key string) (string, bool) {
	for _, kv := range s.upsertedValues {
		if kv.Key == key {
			return string(kv.Value), true
		}
	}
	return "", false
}

func TestUpdatePlatformSettings_EmptyStringClearsAndAbsentKeeps(t *testing.T) {
	store := &stubPlatformSettingsStore{securityManage: true}
	code, body := putSettings(store, `{"support_email":"","platform_name":"Acme","platform_domain":null}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if v, ok := upsertedValue(store, "support_email"); !ok || v != `""` {
		t.Fatalf("support_email was not cleared: written=%v value=%q", ok, v)
	}
	if v, ok := upsertedValue(store, "platform_name"); !ok || v != `"Acme"` {
		t.Fatalf("platform_name = %q (written=%v)", v, ok)
	}
	for _, kept := range []string{"platform_domain", "admin_ui_base_url"} {
		if _, ok := upsertedValue(store, kept); ok {
			t.Errorf("%s was written although the request left it out (or sent null)", kept)
		}
	}
}

// Clearing the staff reset-link host is a write of a security-gated key: it
// must need platform.security.manage exactly as setting it does.
func TestUpdatePlatformSettings_ClearingAGatedKeyNeedsTheGatePermission(t *testing.T) {
	store := &stubPlatformSettingsStore{securityManage: false}
	code, body := putSettings(store, `{"admin_ui_base_url":""}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", code, body)
	}
	if len(store.upserted) != 0 {
		t.Fatalf("a refused save wrote %v", store.upserted)
	}
	store = &stubPlatformSettingsStore{securityManage: true}
	if code, body = putSettings(store, `{"admin_ui_base_url":""}`); code != http.StatusOK {
		t.Fatalf("with the permission: %d %s", code, body)
	}
	if v, ok := upsertedValue(store, "admin_ui_base_url"); !ok || v != `""` {
		t.Fatalf("admin_ui_base_url not cleared: %v %q", ok, v)
	}
}

func TestUpdatePlatformSettings_FailedSaveIsAnErrorAndWritesNothing(t *testing.T) {
	store := &stubPlatformSettingsStore{securityManage: true, upsertErr: errors.New("db down")}
	code, _ := putSettings(store, `{"platform_name":"A","password_min_length":14,"max_login_attempts":5}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", code)
	}
	if len(store.upserted) != 0 {
		t.Fatalf("a failed save left %v behind", store.upserted)
	}
}

// The repository half of atomicity: UpsertSettings against a real Postgres
// rolls the whole batch back when one row fails.
func TestIntegration_PlatformSettingsRepository_UpsertSettingsRollsBack(t *testing.T) {
	db := testdb.Connect(t)
	store := newPlatformSettingsStore(db)
	user := itPlatformUser(t, db)
	good := "it_atomic_good_" + uuid.NewString()[:8]
	bad := "it_atomic_bad_" + uuid.NewString()[:8]
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_settings WHERE setting_key IN ($1, $2)`, good, bad) })

	err := store.UpsertSettings(context.Background(), []platformSettingKV{
		{Key: good, Value: []byte(`"ok"`)},
		{Key: bad, Value: []byte(`{not json`)}, // jsonb refuses it
	}, user)
	if err == nil {
		t.Fatal("a batch containing an invalid row succeeded")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_settings WHERE setting_key = $1`, good).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("the valid row of a failed batch was committed: the save is not atomic")
	}

	if err := store.UpsertSettings(context.Background(), []platformSettingKV{{Key: good, Value: []byte(`"ok"`)}}, user); err != nil {
		t.Fatalf("clean batch: %v", err)
	}
	var v string
	if err := db.QueryRow(`SELECT setting_value::text FROM platform_settings WHERE setting_key = $1`, good).Scan(&v); err != nil || v != `"ok"` {
		t.Fatalf("clean batch not stored: %q %v", v, err)
	}
}
