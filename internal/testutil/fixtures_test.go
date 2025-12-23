package testutil

import (
	"testing"
)

func TestGenerateTestPasskey(t *testing.T) {
	passkey := GenerateTestPasskey()

	// Verify passkey is valid
	if err := passkey.Validate(); err != nil {
		t.Errorf("Generated passkey is invalid: %v", err)
	}

	// Verify fields are populated
	if passkey.ID() == "" {
		t.Error("Passkey ID is empty")
	}
	if len(passkey.CredentialID) != 32 {
		t.Errorf("Expected CredentialID length 32, got %d", len(passkey.CredentialID))
	}
	if len(passkey.UserHandle) != 32 {
		t.Errorf("Expected UserHandle length 32, got %d", len(passkey.UserHandle))
	}
	if len(passkey.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}

	// Generate multiple times and verify randomness
	passkey2 := GenerateTestPasskey()
	if passkey.ID() == passkey2.ID() {
		t.Error("Generated passkeys have same ID")
	}
}

func TestGenerateTestPassword(t *testing.T) {
	password := GenerateTestPassword()

	// Verify password is valid
	if err := password.Validate(); err != nil {
		t.Errorf("Generated password is invalid: %v", err)
	}

	// Verify fields are populated
	if password.ID() == "" {
		t.Error("Password ID is empty")
	}
	if password.Username == "" {
		t.Error("Username is empty")
	}
	if password.Password == "" {
		t.Error("Password is empty")
	}
	if password.URL == "" {
		t.Error("URL is empty")
	}

	// Generate multiple times and verify randomness
	password2 := GenerateTestPassword()
	if password.ID() == password2.ID() {
		t.Error("Generated passwords have same ID")
	}
	if password.Password == password2.Password {
		t.Error("Generated passwords have same password value")
	}
}

func TestGenerateRandomID(t *testing.T) {
	id1 := GenerateRandomID()
	id2 := GenerateRandomID()

	// Verify IDs are not empty
	if id1 == "" || id2 == "" {
		t.Error("Generated ID is empty")
	}

	// Verify IDs are different
	if id1 == id2 {
		t.Error("Generated IDs are identical")
	}

	// Verify ID is hex string (32 hex chars = 16 bytes)
	if len(id1) != 32 {
		t.Errorf("Expected ID length 32, got %d", len(id1))
	}
}
