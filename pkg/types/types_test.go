package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPasskeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		passkey *Passkey
		wantErr bool
	}{
		{
			name: "valid passkey",
			passkey: &Passkey{
				IdField:        "test-id",
				CredentialID:   []byte("cred-id"),
				UserHandle:     []byte("user-handle"),
				PrivateKey:     []byte("private-key"),
				RelyingPartyID: "example.com",
				CreatedDate:    time.Now(),
			},
			wantErr: false,
		},
		{
			name: "missing credentialId",
			passkey: &Passkey{
				IdField:        "test-id",
				RelyingPartyID: "example.com",
			},
			wantErr: true,
		},
		{
			name: "missing relyingPartyId",
			passkey: &Passkey{
				IdField:      "test-id",
				CredentialID: []byte("cred-id"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.passkey.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Passkey.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasskeyJSONMarshaling(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	passkey := &Passkey{
		IdField:        "test-id",
		CredentialID:   []byte("credential-id"),
		UserHandle:     []byte("user-handle"),
		PrivateKey:     []byte("private-key"),
		RelyingPartyID: "example.com",
		UserName:       "testuser",
		CreatedDate:    now,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(passkey)
	if err != nil {
		t.Fatalf("Failed to marshal passkey: %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify key fields exist
	if result["id"] != "test-id" {
		t.Errorf("Expected id=test-id, got %v", result["id"])
	}
	if result["type"] != "passkey" {
		t.Errorf("Expected type=passkey, got %v", result["type"])
	}
	if result["relyingPartyId"] != "example.com" {
		t.Errorf("Expected relyingPartyId=example.com, got %v", result["relyingPartyId"])
	}
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name     string
		password *Password
		wantErr  bool
	}{
		{
			name: "valid password",
			password: &Password{
				IdField:  "test-id",
				Username: "user@example.com",
				Password: "secret123",
				URL:      "https://example.com",
				Created:  time.Now(),
			},
			wantErr: false,
		},
		{
			name: "missing username",
			password: &Password{
				IdField:  "test-id",
				Password: "secret123",
				URL:      "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			password: &Password{
				IdField:  "test-id",
				Username: "user@example.com",
				URL:      "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "missing url",
			password: &Password{
				IdField:  "test-id",
				Username: "user@example.com",
				Password: "secret123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.password.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Password.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordJSONMarshaling(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	password := &Password{
		IdField:  "test-id",
		Username: "user@example.com",
		Password: "secret123",
		URL:      "https://example.com",
		Name:     "Example Account",
		Created:  now,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(password)
	if err != nil {
		t.Fatalf("Failed to marshal password: %v", err)
	}

	// Unmarshal back
	var result Password
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal password: %v", err)
	}

	// Verify fields match
	if result.IdField != password.IdField {
		t.Errorf("Expected id=%s, got %s", password.IdField, result.IdField)
	}
	if result.Username != password.Username {
		t.Errorf("Expected username=%s, got %s", password.Username, result.Username)
	}
	if result.URL != password.URL {
		t.Errorf("Expected url=%s, got %s", password.URL, result.URL)
	}
}

func TestCredentialInterface(t *testing.T) {
	// Verify Passkey implements Credential
	var _ Credential = (*Passkey)(nil)

	// Verify Password implements Credential
	var _ Credential = (*Password)(nil)

	// Test Type() and ID() methods
	passkey := &Passkey{
		IdField:        "passkey-id",
		CredentialID:   []byte("cred"),
		RelyingPartyID: "example.com",
	}
	if passkey.Type() != "passkey" {
		t.Errorf("Expected type=passkey, got %s", passkey.Type())
	}
	if passkey.ID() != "passkey-id" {
		t.Errorf("Expected id=passkey-id, got %s", passkey.ID())
	}

	password := &Password{
		IdField:  "password-id",
		Username: "user",
		Password: "pass",
		URL:      "https://example.com",
	}
	if password.Type() != "password" {
		t.Errorf("Expected type=password, got %s", password.Type())
	}
	if password.ID() != "password-id" {
		t.Errorf("Expected id=password-id, got %s", password.ID())
	}
}
