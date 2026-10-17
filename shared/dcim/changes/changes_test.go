package changes

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// A field named like a secret is listed as changed but its value reaches
// neither image. Mutation: drop the redact.Map calls in Diff → the PSK appears
// in both images and this fails.
func TestChanges_Diff_RedactsSecrets(t *testing.T) {
	pre := map[string]any{"name": "tunnel-a", "psk": "hunter2-old", "nested": map[string]any{"api_token": "t0k"}}
	post := map[string]any{"name": "tunnel-a", "psk": "hunter2-new", "nested": map[string]any{"api_token": "t0k"}}

	changed, preJSON, postJSON, err := Diff(pre, post)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(changed, []string{"psk"}) {
		t.Errorf("changed = %v, want [psk] — a rotated secret is still a change", changed)
	}
	for name, img := range map[string]string{"pre": string(preJSON), "post": string(postJSON)} {
		for _, secret := range []string{"hunter2-old", "hunter2-new", "t0k"} {
			if strings.Contains(img, secret) {
				t.Errorf("%s-image carries the secret %q: %s", name, secret, img)
			}
		}
		if !strings.Contains(img, `"psk":"[redacted]"`) {
			t.Errorf("%s-image does not show the redaction marker: %s", name, img)
		}
		if !strings.Contains(img, `"name":"tunnel-a"`) {
			t.Errorf("%s-image lost a non-secret field: %s", name, img)
		}
	}
}

// The other polarity: posture fields that merely contain "key" survive.
func TestChanges_Diff_KeepsPostureFields(t *testing.T) {
	_, _, post, err := Diff(nil, map[string]any{"key_size": 2048, "public_key": "MIIB..."})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(post), `"key_size":2048`) || !strings.Contains(string(post), `"public_key":"MIIB..."`) {
		t.Errorf("posture fields were redacted: %s", post)
	}
}

func TestChanges_Diff_StructAndMapCompareEqual(t *testing.T) {
	type obj struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	changed, _, _, err := Diff(obj{"a", 1}, map[string]any{"name": "a", "n": 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("changed = %v, want none", changed)
	}
	changed, _, _, _ = Diff(map[string]any{"a": 1, "updated_at": "x"}, map[string]any{"a": 1, "updated_at": "y", "b": 2})
	if !reflect.DeepEqual(changed, []string{"b"}) {
		t.Errorf("changed = %v, want [b] (updated_at alone is not a change)", changed)
	}
	if _, _, _, err := Diff([]int{1}, nil); err == nil {
		t.Error("a non-object image was accepted")
	}
}

func baseChange() Change {
	return Change{
		TenantID: uuid.New(), Kind: dcim.ObjectKindAsset, ID: uuid.New(), Action: ActionUpdate,
		Pre: map[string]any{"name": "a"}, Post: map[string]any{"name": "b"},
	}
}

// A ui/api change with nobody behind it is refused; the non-person sources are
// allowed only when the caller SAYS so. Mutation: drop the RequiresActor check
// in Prepare → the first case records an anonymous ui change and this fails.
func TestChanges_Record_RequiresActorInContext(t *testing.T) {
	actor := WithActor(context.Background(), Actor{UserID: uuid.New(), UserName: "a@example.com"})
	cases := []struct {
		name    string
		ctx     context.Context
		source  Source
		wantErr error
	}{
		{"ui source, no actor", WithSource(context.Background(), SourceUI), "", ErrNoActor},
		{"api source on the change, no actor", context.Background(), SourceAPI, ErrNoActor},
		{"no source at all, no actor", context.Background(), "", ErrNoActor},
		{"no source at all, actor", actor, "", ErrNoActor},
		{"system set explicitly", System(context.Background()), "", nil},
		{"intake source on the change", context.Background(), IntakeSource("lldp"), nil},
		{"sync source on the change", context.Background(), SyncSource("netbox"), nil},
		{"ui with actor", WithSource(actor, SourceUI), "", nil},
		{"invalid source", context.Background(), Source("cron"), ErrInvalidSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseChange()
			c.Source = tc.source
			row, _, err := Prepare(tc.ctx, c)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if row.Source.RequiresActor() && row.UserID == nil {
					t.Fatal("a ui/api row without a user id")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestChanges_Prepare_Rules(t *testing.T) {
	ctx := WithRequestID(System(context.Background()), uuid.New())

	c := baseChange()
	c.Kind = "rack_thing"
	if _, _, err := Prepare(ctx, c); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: err = %v", err)
	}
	c = baseChange()
	c.Action = "upsert"
	if _, _, err := Prepare(ctx, c); !errors.Is(err, ErrInvalidAction) {
		t.Errorf("bad action: err = %v", err)
	}
	c = baseChange()
	c.Action = ActionCreate
	if _, _, err := Prepare(ctx, c); !errors.Is(err, ErrImages) {
		t.Errorf("create with a pre-image: err = %v", err)
	}
	c = baseChange()
	c.TenantID = uuid.Nil
	if _, _, err := Prepare(ctx, c); !errors.Is(err, ErrNoTenant) {
		t.Errorf("no tenant: err = %v", err)
	}

	c = baseChange()
	c.Post = c.Pre
	if _, skip, err := Prepare(ctx, c); err != nil || !skip {
		t.Errorf("no-op update: skip=%v err=%v, want skip", skip, err)
	}

	c = baseChange()
	row, _, err := Prepare(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if row.RequestID == nil {
		t.Error("request id from the context was not carried")
	}
	if !reflect.DeepEqual(row.ChangedFields, []string{"name"}) {
		t.Errorf("changed = %v", row.ChangedFields)
	}
}

// The middleware is what puts the actor on the context; a handler that skips it
// records nothing (ErrNoActor), which is the point.
func TestChanges_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	uid := uuid.New()
	rid := uuid.New()
	var got struct {
		actor  Actor
		ok     bool
		source Source
		rid    uuid.UUID
	}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", uid); c.Set("email", "op@example.com") })
	r.Use(Middleware())
	r.GET("/", func(c *gin.Context) {
		got.actor, got.ok = ActorFrom(c.Request.Context())
		got.source, _ = SourceFrom(c.Request.Context())
		got.rid, _ = RequestIDFrom(c.Request.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, rid.String())
	r.ServeHTTP(httptest.NewRecorder(), req)
	if !got.ok || got.actor.UserID != uid || got.actor.UserName != "op@example.com" {
		t.Errorf("actor = %+v ok=%v", got.actor, got.ok)
	}
	if got.source != SourceUI || got.rid != rid {
		t.Errorf("source=%q rid=%v", got.source, got.rid)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set(RequestIDHeader, "not-a-uuid")
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got.source != SourceAPI || got.rid == uuid.Nil || got.rid == rid {
		t.Errorf("bearer call: source=%q rid=%v (want api and a minted id)", got.source, got.rid)
	}
}

// InTx takes a transaction, not a pool: a recorder over *sql.DB would write
// the change on its own connection and keep it when the caller's write rolled
// back. Mutation: widen InTx's parameter back to DBTX → *sql.DB satisfies it
// and this fails.
func TestChanges_InTx_RefusesAPool(t *testing.T) {
	txType := reflect.TypeOf((*Tx)(nil)).Elem()
	if reflect.TypeOf((*sql.DB)(nil)).Implements(txType) {
		t.Fatal("*sql.DB satisfies changes.Tx: InTx would accept a pool")
	}
	if !reflect.TypeOf((*sql.Tx)(nil)).Implements(txType) {
		t.Fatal("*sql.Tx does not satisfy changes.Tx")
	}
	if in := reflect.TypeOf(InTx).In(0); in != txType {
		t.Fatalf("InTx takes %v, want changes.Tx", in)
	}
}
