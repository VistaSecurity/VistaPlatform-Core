package apitokens

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestGenerateToken(t *testing.T) {
	tok1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(tok1, TokenPrefix) {
		t.Fatalf("token %q missing prefix %q", tok1, TokenPrefix)
	}
	// 32 bytes base64url unpadded = 43 chars
	if got := len(tok1) - len(TokenPrefix); got != 43 {
		t.Fatalf("token body length = %d, want 43", got)
	}
	tok2, _ := GenerateToken()
	if tok1 == tok2 {
		t.Fatal("two generated tokens are identical")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	h1 := HashToken("qvpat_example")
	h2 := HashToken("qvpat_example")
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if len(h1) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(h1))
	}
	if h1 == HashToken("qvpat_other") {
		t.Fatal("distinct tokens hash equal")
	}
}

func TestValidatePermissions(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{name: "empty gets defaults", in: nil, want: DefaultPermissions},
		{name: "valid subset", in: []string{"assets.read"}, want: []string{"assets.read"}},
		{name: "dedup", in: []string{"assets.read", "assets.read"}, want: []string{"assets.read"}},
		{name: "write permission rejected", in: []string{"assets.manage"}, wantErr: true},
		{name: "unknown rejected", in: []string{"nonsense.read"}, wantErr: true},
		{name: "whitespace-only falls back to defaults", in: []string{"  "}, want: DefaultPermissions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidatePermissions(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	svc := NewService(nil, nil) // must not reach the DB for malformed input
	for _, tok := range []string{"", "bearer", "qvpat_short", "sk_live_abcdef"} {
		if _, err := svc.Validate(tok); err == nil {
			t.Fatalf("Validate(%q) succeeded, want error", tok)
		}
	}
}

func newMock(t *testing.T) (*Service, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	return NewService(db, db), mock, func() { _ = db.Close() }
}

var tokenCols = []string{"id", "tenant_id", "user_id", "name", "token_prefix", "permissions",
	"expires_at", "last_used_at", "revoked_at", "created_at"}

func TestCreateInsertsHashedToken(t *testing.T) {
	svc, mock, done := newMock(t)
	defer done()

	tenantID, userID := uuid.New(), uuid.New()
	// RLS Phase 3: Create runs the active-count read and the INSERT each inside
	// its own WithTenantTx, so each is wrapped in Begin → set_tenant_context →
	// op → Commit.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM api_tokens")).
		WithArgs(userID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO api_tokens")).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	tok, plaintext, err := svc.Create(tenantID, userID, "ci token", nil, 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(plaintext, TokenPrefix) {
		t.Fatalf("plaintext %q missing prefix", plaintext)
	}
	if !strings.HasPrefix(plaintext, tok.TokenPrefix) {
		t.Fatalf("display prefix %q is not a prefix of the token", tok.TokenPrefix)
	}
	if tok.ExpiresAt == nil {
		t.Fatal("default expiry not applied")
	}
	wantExp := time.Now().UTC().Add(DefaultExpiryDays * 24 * time.Hour)
	if d := tok.ExpiresAt.Sub(wantExp); d > time.Minute || d < -time.Minute {
		t.Fatalf("default expiry %v not ~%d days out", tok.ExpiresAt, DefaultExpiryDays)
	}
	if len(tok.Permissions) != len(DefaultPermissions) {
		t.Fatalf("permissions %v, want defaults %v", tok.Permissions, DefaultPermissions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateEnforcesActiveCap(t *testing.T) {
	svc, mock, done := newMock(t)
	defer done()

	tenantID, userID := uuid.New(), uuid.New()
	// RLS Phase 3: the active-count read runs inside WithTenantTx.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM api_tokens")).
		WithArgs(userID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(MaxActiveTokensPerUser))
	mock.ExpectCommit()

	if _, _, err := svc.Create(tenantID, userID, "one too many", nil, 0); err != ErrTooManyTokens {
		t.Fatalf("err = %v, want ErrTooManyTokens", err)
	}
}

func TestCreateRejectsBadExpiry(t *testing.T) {
	svc, _, done := newMock(t)
	defer done()
	if _, _, err := svc.Create(uuid.New(), uuid.New(), "t", nil, MaxExpiryDays+1); err != ErrInvalidExpiry {
		t.Fatalf("err = %v, want ErrInvalidExpiry", err)
	}
	if _, _, err := svc.Create(uuid.New(), uuid.New(), "t", nil, -1); err != ErrInvalidExpiry {
		t.Fatalf("err = %v, want ErrInvalidExpiry", err)
	}
}

func TestValidateLifecycle(t *testing.T) {
	plaintext, _ := GenerateToken()
	hash := HashToken(plaintext)
	id, tenantID, userID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	selectRe := regexp.QuoteMeta("FROM api_tokens")
	mkRow := func(expires, revoked *time.Time) *sqlmock.Rows {
		return sqlmock.NewRows(append(append([]string{}, tokenCols...), "token_hash")).
			AddRow(id, tenantID, userID, "t", plaintext[:10], []byte(`["assets.read"]`),
				expires, nil, revoked, now, hash)
	}

	t.Run("active token validates", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectQuery(selectRe).WithArgs(hash).WillReturnRows(mkRow(&future, nil))
		tok, err := svc.Validate(plaintext)
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if tok.UserID != userID || tok.TenantID != tenantID {
			t.Fatal("wrong identity resolved")
		}
		if len(tok.Permissions) != 1 || tok.Permissions[0] != "assets.read" {
			t.Fatalf("permissions = %v", tok.Permissions)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectQuery(selectRe).WithArgs(hash).WillReturnRows(mkRow(&past, nil))
		if _, err := svc.Validate(plaintext); err != ErrTokenExpired {
			t.Fatalf("err = %v, want ErrTokenExpired", err)
		}
	})

	t.Run("revoked token rejected", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectQuery(selectRe).WithArgs(hash).WillReturnRows(mkRow(&future, &now))
		if _, err := svc.Validate(plaintext); err != ErrTokenRevoked {
			t.Fatalf("err = %v, want ErrTokenRevoked", err)
		}
	})

	t.Run("unknown token rejected", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectQuery(selectRe).WithArgs(hash).
			WillReturnRows(sqlmock.NewRows(append(append([]string{}, tokenCols...), "token_hash")))
		if _, err := svc.Validate(plaintext); err != ErrTokenNotFound {
			t.Fatalf("err = %v, want ErrTokenNotFound", err)
		}
	})
}

func TestRevokeDistinguishesMissingFromRevoked(t *testing.T) {
	tenantID, userID, tokenID := uuid.New(), uuid.New(), uuid.New()

	// RLS Phase 3: Revoke runs inside WithTenantTx (Begin → set_tenant_context →
	// UPDATE [→ EXISTS] → Commit). When the closure returns a sentinel error
	// (ErrTokenRevoked/ErrTokenNotFound) WithTenantTx returns before Commit, so
	// the deferred Rollback fires instead.
	t.Run("revokes active", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta("UPDATE api_tokens SET revoked_at")).
			WithArgs(tokenID, tenantID, userID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if err := svc.Revoke(tenantID, userID, tokenID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta("UPDATE api_tokens SET revoked_at")).
			WithArgs(tokenID, tenantID, userID).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS")).
			WithArgs(tokenID, tenantID, userID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectRollback()
		if err := svc.Revoke(tenantID, userID, tokenID); err != ErrTokenRevoked {
			t.Fatalf("err = %v, want ErrTokenRevoked", err)
		}
	})

	t.Run("not owner or missing", func(t *testing.T) {
		svc, mock, done := newMock(t)
		defer done()
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta("UPDATE api_tokens SET revoked_at")).
			WithArgs(tokenID, tenantID, userID).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS")).
			WithArgs(tokenID, tenantID, userID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectRollback()
		if err := svc.Revoke(tenantID, userID, tokenID); err != ErrTokenNotFound {
			t.Fatalf("err = %v, want ErrTokenNotFound", err)
		}
	})
}
