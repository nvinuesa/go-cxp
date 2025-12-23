// Package testutil provides test fixture generators for testing.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/nvinuesa/go-credential-exchange/pkg/types"
)

// GenerateTestPasskey creates a valid passkey with random but realistic values.
func GenerateTestPasskey() *types.Passkey {
	// Generate random CredentialID (32 bytes)
	credentialID := make([]byte, 32)
	rand.Read(credentialID)

	// Generate random UserHandle (32 bytes)
	userHandle := make([]byte, 32)
	rand.Read(userHandle)

	// Generate P-256 ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encode private key as PKCS#8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	return &types.Passkey{
		IdField:         GenerateRandomID(),
		CredentialID:    credentialID,
		UserHandle:      userHandle,
		PrivateKey:      privateKeyBytes,
		RelyingPartyID:  "example.com",
		UserName:        "testuser",
		UserDisplayName: "Test User",
		CreatedDate:     time.Now(),
	}
}

// GenerateTestPassword creates a valid password with realistic values.
func GenerateTestPassword() *types.Password {
	// Generate random 16-char password
	passwordBytes := make([]byte, 16)
	rand.Read(passwordBytes)
	password := hex.EncodeToString(passwordBytes)

	return &types.Password{
		IdField:  GenerateRandomID(),
		Username: "user@example.com",
		Password: password,
		URL:      "https://example.com",
		Name:     "Example Account",
		Created:  time.Now(),
	}
}

// GenerateRandomID generates a UUID-like random ID as a hex string.
func GenerateRandomID() string {
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	return hex.EncodeToString(idBytes)
}
