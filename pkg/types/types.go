// Package types provides core credential types and interfaces for the CXP implementation.
package types

import (
	"encoding/base64"
	"errors"
	"time"
)

// Credential is the interface that all credential types must implement.
type Credential interface {
	Type() string
	ID() string
	Validate() error
}

// Passkey represents a FIDO2/WebAuthn passkey credential.
type Passkey struct {
	IdField         string    `json:"id"`
	TypeField       string    `json:"type"`
	CredentialID    []byte    `json:"credentialId"`
	UserHandle      []byte    `json:"userHandle"`
	PrivateKey      []byte    `json:"privateKey"`
	RelyingPartyID  string    `json:"relyingPartyId"`
	UserName        string    `json:"userName,omitempty"`
	UserDisplayName string    `json:"userDisplayName,omitempty"`
	CreatedDate     time.Time `json:"createdDate"`
}

// Type returns the credential type identifier.
func (p *Passkey) Type() string {
	return "passkey"
}

// ID returns the unique identifier for this credential.
func (p *Passkey) ID() string {
	return p.IdField
}

// Validate checks that all required fields are present and valid.
func (p *Passkey) Validate() error {
	if len(p.CredentialID) == 0 {
		return errors.New("passkey: credentialId is required")
	}
	if p.RelyingPartyID == "" {
		return errors.New("passkey: relyingPartyId is required")
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling for Passkey.
func (p *Passkey) MarshalJSON() ([]byte, error) {
	type Alias Passkey
	return []byte(`{` +
		`"id":"` + p.IdField + `",` +
		`"type":"` + p.Type() + `",` +
		`"credentialId":"` + base64.StdEncoding.EncodeToString(p.CredentialID) + `",` +
		`"userHandle":"` + base64.StdEncoding.EncodeToString(p.UserHandle) + `",` +
		`"privateKey":"` + base64.StdEncoding.EncodeToString(p.PrivateKey) + `",` +
		`"relyingPartyId":"` + p.RelyingPartyID + `",` +
		`"userName":"` + p.UserName + `",` +
		`"userDisplayName":"` + p.UserDisplayName + `",` +
		`"createdDate":"` + p.CreatedDate.Format(time.RFC3339) + `"` +
		`}`), nil
}

// UnmarshalJSON implements custom JSON unmarshaling for Passkey.
func (p *Passkey) UnmarshalJSON(data []byte) error {
	// Simple implementation - in production would use encoding/json properly
	// For MVP, this is a placeholder
	return errors.New("unmarshal not yet implemented")
}

// Password represents a username/password credential.
type Password struct {
	IdField   string    `json:"id"`
	TypeField string    `json:"type"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	URL       string    `json:"url"`
	Name      string    `json:"name,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	Created   time.Time `json:"created"`
	Modified  time.Time `json:"modified,omitempty"`
}

// Type returns the credential type identifier.
func (p *Password) Type() string {
	return "password"
}

// ID returns the unique identifier for this credential.
func (p *Password) ID() string {
	return p.IdField
}

// Validate checks that all required fields are present and valid.
func (p *Password) Validate() error {
	if p.Username == "" {
		return errors.New("password: username is required")
	}
	if p.Password == "" {
		return errors.New("password: password is required")
	}
	if p.URL == "" {
		return errors.New("password: url is required")
	}
	return nil
}
