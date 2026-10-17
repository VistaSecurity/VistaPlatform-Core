package main

// Custom fields through the REAL routes over a real Postgres (DCIM row 5.1):
// definitions created through mountCustomFieldRoutes, then a prefix written
// through mountIPAMRoutes — the object engine's path, so this is the engine's
// validation hook under test, not the validator in isolation.
//
// Mutation: delete the applyEngineCustomFields call in ipam_engine.go's
// createTx → "required field blocks the create" and "choice outside the set"
// go red (the prefix is created); delete it from updateTx → "clearing a
// required field is refused" goes red.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CustomFieldRoutes_EngineValidatesEveryWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	user := uuid.New()
	if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, "cf-"+user.String()[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := raw.QueryRow(`INSERT INTO tenant_roles (tenant_id, name, display_name) VALUES ($1, $2, 'CF test') RETURNING id`, tenant, "cf_"+user.String()[:8]).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"dcim.read", "custom_fields.manage", "ipam.read", "ipam.manage"} {
		res, err := raw.Exec(`INSERT INTO tenant_role_permissions (role_id, permission_id) SELECT $1, id FROM tenant_permissions WHERE name = $2`, role, p)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("permission %s is not in the seeded catalogue", p)
		}
	}
	if _, err := raw.Exec(`INSERT INTO user_tenant_roles (user_id, tenant_id, role_id, is_active) VALUES ($1, $2, $3, true)`, user, tenant, role); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Recovery(), func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Set("userID", user)
		c.Set("email", "cf@example.com")
		c.Next()
	})
	v2 := r.Group("")
	mountCustomFieldRoutes(v2, raw, handlers.NewCustomFieldHandler(services.NewCustomFieldService(raw)))
	mountIPAMRoutes(v2, raw, handlers.NewIPAMHandler(services.NewIPAMService(raw)))

	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if d, ok := out["data"].(map[string]any); ok {
			return w.Code, d
		}
		return w.Code, out
	}
	const dcim = "/inventory-service/dcim"
	const prefixes = "/inventory-service/ipam/prefixes"

	code, set := call(http.MethodPost, dcim+"/custom-field-choice-sets", `{"name":"Tiers","choices":[["gold","Gold"],["silver","Silver"]]}`)
	if code != http.StatusCreated {
		t.Fatalf("create choice set: %d %v", code, set)
	}
	code, out := call(http.MethodPost, dcim+"/custom-fields", `{"name":"owner_team","label":"Owner team","type":"text","object_kinds":["prefix","asset"],"required":true}`)
	if code != http.StatusCreated {
		t.Fatalf("create required field: %d %v", code, out)
	}
	code, out = call(http.MethodPost, dcim+"/custom-fields", `{"name":"tier","type":"select","object_kinds":["prefix"],"choice_set_id":"`+set["id"].(string)+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("create select field: %d %v", code, out)
	}

	t.Run("a definition is checked: a default outside the choices is refused", func(t *testing.T) {
		code, out := call(http.MethodPost, dcim+"/custom-fields", `{"name":"tier2","type":"select","object_kinds":["prefix"],"choice_set_id":"`+set["id"].(string)+`","default":"bronze"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("got %d %v, want 400", code, out)
		}
	})

	t.Run("required field blocks the create", func(t *testing.T) {
		code, out := call(http.MethodPost, prefixes, `{"prefix":"10.91.0.0/24"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("prefix without owner_team: %d %v, want 400", code, out)
		}
	})
	t.Run("choice outside the set", func(t *testing.T) {
		code, out := call(http.MethodPost, prefixes, `{"prefix":"10.91.0.0/24","custom_fields":{"owner_team":"net","tier":"bronze"}}`)
		if code != http.StatusBadRequest {
			t.Fatalf("tier bronze: %d %v, want 400", code, out)
		}
	})
	t.Run("an undefined field is refused", func(t *testing.T) {
		code, out := call(http.MethodPost, prefixes, `{"prefix":"10.91.0.0/24","custom_fields":{"owner_team":"net","nope":"x"}}`)
		if code != http.StatusBadRequest {
			t.Fatalf("unknown field: %d %v, want 400", code, out)
		}
	})

	code, pfx := call(http.MethodPost, prefixes, `{"prefix":"10.91.0.0/24","custom_fields":{"owner_team":"net","tier":"gold"}}`)
	if code != http.StatusCreated {
		t.Fatalf("valid prefix: %d %v", code, pfx)
	}
	cf, _ := pfx["custom_fields"].(map[string]any)
	if cf["owner_team"] != "net" || cf["tier"] != "gold" {
		t.Fatalf("stored custom_fields %v", pfx["custom_fields"])
	}
	id := pfx["id"].(string)

	t.Run("an update names only the fields it changes", func(t *testing.T) {
		code, out := call(http.MethodPatch, prefixes+"/"+id, `{"custom_fields":{"tier":"silver"}}`)
		cf, _ := out["custom_fields"].(map[string]any)
		if code != http.StatusOK || cf["owner_team"] != "net" || cf["tier"] != "silver" {
			t.Fatalf("patch tier: %d %v", code, out)
		}
	})
	t.Run("clearing a required field is refused", func(t *testing.T) {
		code, out := call(http.MethodPatch, prefixes+"/"+id, `{"custom_fields":{"owner_team":null}}`)
		if code != http.StatusBadRequest {
			t.Fatalf("clear owner_team: %d %v, want 400", code, out)
		}
	})
	t.Run("a choice set in use cannot be deleted", func(t *testing.T) {
		code, out := call(http.MethodDelete, dcim+"/custom-field-choice-sets/"+set["id"].(string), "")
		if code != http.StatusConflict {
			t.Fatalf("delete choice set in use: %d %v, want 409", code, out)
		}
	})
	t.Run("defining a field is recorded in the change log", func(t *testing.T) {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'custom_field' AND action = 'create'`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("custom_field create changes: %d, want 2", n)
		}
	})
	t.Run("the list filters by object kind", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, dcim+"/custom-fields?object_kind=asset", nil))
		var list struct {
			Data []map[string]any `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		if w.Code != http.StatusOK || len(list.Data) != 1 || list.Data[0]["name"] != "owner_team" {
			t.Fatalf("object_kind=asset: %d %s", w.Code, w.Body.String())
		}
	})
}
