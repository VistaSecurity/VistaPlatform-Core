package platform

import (
	"bytes"
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
// upstream body's "error" and "message" fields are included verbatim when
// present — those messages are already tenant-facing.
type apiError struct {
	Status  int
	Message string

	// Reason is the platform's machine-readable `reason` key, when the body
	// carried one. It exists because several unrelated refusals share a status
	// — four different things answer 403 on the ask route — and a tool that
	// told them apart by looking for a word in Message got it wrong the first
	// time a sentence was reworded. Empty is the normal case and means "this
	// response did not classify itself", which a caller must treat as "I do not
	// know", never as a default classification.
	Reason string
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("platform API error (HTTP %d): %s", e.Status, e.Message)
	}
	return fmt.Sprintf("platform API error (HTTP %d)", e.Status)
}

// QueryDiagnostic is one entry of the query language's structured error list
// (QUERY_LANGUAGE.md §10), decoded from the platform's 400 body.
type QueryDiagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Span    struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"span"`
	Suggestion string `json:"suggestion,omitempty"`
}

// QueryError is a query the platform refused, carried up with its diagnostics
// intact rather than flattened into "platform API error (HTTP 400)".
//
// The whole point of the structured list is that the caller can fix the query
// and try again, and on this surface the caller is an agent. Collapsing the
// list would leave it with nothing to act on but the word "invalid" — which is
// exactly the failure the language's §10 error shape exists to prevent for a
// human with a caret in a text box.
type QueryError struct {
	Status int
	// Query is the text the spans index into, echoed by the platform.
	Query string
	// Errors is every diagnostic, one per problem.
	Errors []QueryDiagnostic
}

// Error renders the diagnostics as prose plus the verbatim JSON list, so a
// model can read either and a client can parse the second.
func (e *QueryError) Error() string {
	b, err := json.Marshal(e.Errors)
	if err != nil {
		b = []byte("[]")
	}
	return fmt.Sprintf(
		"the platform refused this query, so NO rows were returned — correct the query and call the tool again. "+
			"query: %s\ndiagnostics (one per problem; span is a byte range into the query): %s",
		e.Query, string(b))
}

// HTTPStatus reports the platform status behind err, and the message the
// platform sent with it.
//
// It exists because SOME non-2xx answers are not failures to report as errors:
// a 402 from `/ask` means "your edition does not include this", and a tool that
// surfaced that as a tool error would invite a retry of something that can
// never succeed. A tool that wants to answer such a status with a structured
// "not available" result needs to be able to tell it apart from a 500, and the
// error types carrying it are deliberately unexported so nothing outside this
// package constructs one.
//
// ok is false for a transport failure or a credential rejection, which have no
// platform status at all — and "no status" must not read as status 0.
func HTTPStatus(err error) (status int, message string, ok bool) {
	var api *apiError
	if errors.As(err, &api) {
		return api.Status, api.Message, true
	}
	var qe *QueryError
	if errors.As(err, &qe) {
		return qe.Status, qe.Error(), true
	}
	return 0, "", false
}

// Reason reports the platform's machine-readable `reason` key behind err, or ""
// when the response did not carry one.
//
// It is how a caller identifies ONE particular refusal POSITIVELY, instead of
// identifying every other refusal negatively and defaulting to it. The
// difference matters because the default is what a status nobody anticipated
// lands in: four different things answer 403 on the ask route, and only one of
// them means "this capability is switched off". Empty means "unclassified", and
// unclassified must fall through to a real error rather than to a guess.
func Reason(err error) string {
	var api *apiError
	if errors.As(err, &api) {
		return api.Reason
	}
	return ""
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
	return c.do(ctx, http.MethodGet, base, path, q, nil)
}

// Post performs an authenticated POST with a JSON body.
//
// The read-only rule this surface is built on is about what the PLATFORM does,
// not about which verb carries the request: every tool wraps a read, and the
// one POST here — `/ask` — reads inventory and writes nothing. It is a POST
// because its input is a question, and a question does not belong in a URL
// where proxies and access logs keep it.
func (c *Client) Post(ctx context.Context, base, path string, body any) (any, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}
	return c.do(ctx, http.MethodPost, base, path, nil, encoded)
}

func (c *Client) do(ctx context.Context, method, base, path string, q url.Values, body []byte) (any, error) {
	g, ok := GrantFromContext(ctx)
	if !ok {
		return nil, ErrUnauthorized
	}

	u := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("platform service unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read platform response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
			// Message is the platform's second, longer field on several error
			// shapes (the facets endpoint puts the valid level list behind it).
			// Dropping it turned "level must be one of …" into "Failed to get
			// facets", which tells a caller nothing it can act on.
			Message string `json:"message"`
			// Reason is the platform's own classification of a refusal that
			// shares a status with other refusals. Only surfaces that set it
			// deliberately have one.
			Reason string            `json:"reason"`
			Query  string            `json:"query"`
			Errors []QueryDiagnostic `json:"errors"`
		}
		_ = json.Unmarshal(respBody, &e)
		// A query the caller got wrong is reported as the diagnostics, not as a
		// generic HTTP failure: it is the one error on this surface the caller
		// can fix by itself.
		if len(e.Errors) > 0 {
			return nil, &QueryError{Status: resp.StatusCode, Query: e.Query, Errors: e.Errors}
		}
		msg := e.Error
		if e.Message != "" && e.Message != msg {
			if msg == "" {
				msg = e.Message
			} else {
				msg += ": " + e.Message
			}
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg, Reason: e.Reason}
	}

	var v any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &v); err != nil {
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
