package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnauthorized maps any credential rejection (PAT or downstream JWT) to a
// single sentinel so callers emit one consistent message.
var ErrUnauthorized = errors.New("invalid or expired API token")

// apiError is a non-2xx platform response surfaced as a tool error. The
// upstream body's "error" field is included verbatim when present — those
// messages are already tenant-facing.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("platform API error (HTTP %d): %s", e.Status, e.Message)
	}
	return fmt.Sprintf("platform API error (HTTP %d)", e.Status)
}

// Client calls platform service read APIs as the grant's user (JWT bearer).
type Client struct {
	httpc *http.Client

	InventoryURL  string
	ComplianceURL string
	CBOMURL       string
}

func NewClient(httpc *http.Client, inventoryURL, complianceURL, cbomURL string) *Client {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		httpc:         httpc,
		InventoryURL:  inventoryURL,
		ComplianceURL: complianceURL,
		CBOMURL:       cbomURL,
	}
}

// Get performs an authenticated GET against base+path with query params and
// decodes the JSON response into a generic value.
func (c *Client) Get(ctx context.Context, base, path string, q url.Values) (any, error) {
	g, ok := GrantFromContext(ctx)
	if !ok {
		return nil, ErrUnauthorized
	}

	u := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("platform service unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read platform response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := ""
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil {
			msg = e.Error
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg}
	}

	var v any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, fmt.Errorf("platform response was not JSON: %w", err)
		}
	}
	return v, nil
}

// Prune removes named keys anywhere in a decoded JSON tree. Used to strip
// token-hungry payload fields (PEM bodies, raw discovery blobs) that no
// conversational consumer needs; the full data remains available in the UI.
func Prune(v any, keys ...string) any {
	drop := map[string]bool{}
	for _, k := range keys {
		drop[k] = true
	}
	var walk func(any) any
	walk = func(n any) any {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if drop[k] {
					delete(t, k)
					continue
				}
				t[k] = walk(val)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		default:
			return n
		}
	}
	return walk(v)
}
