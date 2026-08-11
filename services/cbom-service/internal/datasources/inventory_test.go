package datasources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestInventoryDataSourceQueryAssetsAggregatesPaginatedResults(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/inventory-service/assets" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization header = %q, want Bearer test-token", got)
		}
		// X-Tenant-ID must be set on every internal call so inventory's HMAC verifier
		// can route to the tenant-scoped path (regression guard for the Phase 0 fix).
		if got := r.Header.Get("X-Tenant-ID"); got != "00000000-0000-0000-0000-000000000001" {
			t.Fatalf("X-Tenant-ID header = %q, want 00000000-0000-0000-0000-000000000001", got)
		}
		if got := r.URL.Query().Get("page_size"); got != "1000" {
			t.Fatalf("page_size = %q, want 1000", got)
		}

		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"assets": []map[string]interface{}{
					{"id": "asset-1", "name": "gateway"},
				},
				"pagination": map[string]interface{}{"has_next": true},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"assets": []map[string]interface{}{
					{"id": "asset-2", "name": "worker"},
				},
				"pagination": map[string]interface{}{"has_next": false},
			})
		default:
			t.Fatalf("unexpected page: %s", page)
		}
	}))
	defer server.Close()

	dataSource, err := NewInventoryDataSource(server.URL)
	if err != nil {
		t.Fatalf("NewInventoryDataSource returned error: %v", err)
	}

	items, err := dataSource.QueryAssets(context.Background(), "test-token", "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("QueryAssets returned error: %v", err)
	}

	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0]["id"] != "asset-1" || items[1]["id"] != "asset-2" {
		t.Fatalf("unexpected item ids: %+v", items)
	}
}

func TestInventoryDataSourceQueryAllListEndpointFailsClosedWithoutPagination(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/inventory-service/crypto-implementations" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		items := make([]map[string]interface{}, 1000)
		for index := range items {
			items[index] = map[string]interface{}{
				"id":   "impl-" + strconv.Itoa(index),
				"name": "implementation-" + strconv.Itoa(index),
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"crypto_implementations": items,
		})
	}))
	defer server.Close()

	dataSource, err := NewInventoryDataSource(server.URL)
	if err != nil {
		t.Fatalf("NewInventoryDataSource returned error: %v", err)
	}

	_, err = dataSource.QueryCryptoImplementations(context.Background(), "", "")
	if err == nil {
		t.Fatal("expected fail-closed pagination error, got nil")
	}
	if !strings.Contains(err.Error(), "full page without pagination metadata") {
		t.Fatalf("unexpected error: %v", err)
	}
}
