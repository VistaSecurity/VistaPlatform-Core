package gcp

import (
	"encoding/json"
	"testing"
)

func TestServiceAccountKeyParsing(t *testing.T) {
	validKey := `{
		"type": "service_account",
		"project_id": "my-project",
		"private_key_id": "key123",
		"private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
		"client_email": "test@my-project.iam.gserviceaccount.com",
		"client_id": "123456789",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`

	var key ServiceAccountKey
	err := json.Unmarshal([]byte(validKey), &key)
	if err != nil {
		t.Fatalf("Failed to parse valid service account key: %v", err)
	}

	if key.Type != "service_account" {
		t.Errorf("Type = %q, want %q", key.Type, "service_account")
	}
	if key.ProjectID != "my-project" {
		t.Errorf("ProjectID = %q, want %q", key.ProjectID, "my-project")
	}
	if key.ClientEmail != "test@my-project.iam.gserviceaccount.com" {
		t.Errorf("ClientEmail = %q, want %q", key.ClientEmail, "test@my-project.iam.gserviceaccount.com")
	}
	if key.TokenURI != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenURI = %q, want %q", key.TokenURI, "https://oauth2.googleapis.com/token")
	}
}

func TestServiceAccountKeyValidation(t *testing.T) {
	tests := []struct {
		name      string
		jsonStr   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid key",
			jsonStr: `{"type":"service_account","project_id":"p","private_key_id":"k","private_key":"pk","client_email":"e@e.com"}`,
			wantErr: false,
		},
		{
			name:      "wrong type",
			jsonStr:   `{"type":"authorized_user","project_id":"p","private_key":"pk","client_email":"e@e.com"}`,
			wantErr:   true,
			errSubstr: "service_account",
		},
		{
			name:    "invalid json",
			jsonStr: `{invalid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key ServiceAccountKey
			err := json.Unmarshal([]byte(tt.jsonStr), &key)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("Unexpected parse error: %v", err)
				}
				return
			}

			// Validate type
			if key.Type != "service_account" {
				if !tt.wantErr {
					t.Errorf("Expected valid service_account type")
				}
			} else if tt.wantErr && tt.errSubstr == "service_account" {
				t.Errorf("Expected wrong type error but got valid type")
			}
		})
	}
}

func TestTruncateBody(t *testing.T) {
	short := "short message"
	if got := truncateBody([]byte(short)); got != short {
		t.Errorf("truncateBody(%q) = %q, want %q", short, got, short)
	}

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	result := truncateBody(long)
	if len(result) != 503 { // 500 + "..."
		t.Errorf("truncateBody(600 bytes) length = %d, want 503", len(result))
	}
}
