// Package cxp provides Go types for the FIDO Alliance Credential Exchange Protocol (CXP) v1.0.
//
// This package implements the protocol message types for secure credential exchange between
// providers. It is designed to be used alongside github.com/nvinuesa/go-cxf for the
// Credential Exchange Format types.
//
// See: https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html
package cxp

import (
	"encoding/json"
	"fmt"
)

// ExportRequest is sent by the importing provider to request credentials from an exporting provider.
type ExportRequest struct {
	Version         Version            `json:"version"`
	Hpke            []HpkeParameters   `json:"hpke"`
	Importer        string             `json:"importer"`
	Archive         []ArchiveAlgorithm `json:"archive,omitempty"`
	CredentialTypes []CredentialType   `json:"credentialTypes,omitempty"`
	KnownExtensions []KnownExtension   `json:"knownExtensions,omitempty"`
}

// ExportResponse is sent by the exporting provider containing encrypted credentials.
type ExportResponse struct {
	Version  Version          `json:"version"`
	Hpke     HpkeParameters   `json:"hpke"`
	Exporter string           `json:"exporter"`
	Archive  ArchiveAlgorithm `json:"archive,omitempty"`
	Payload  string           `json:"payload"` // base64url encoded
}

// ErrorResponse is sent by the exporting provider when an error occurs.
type ErrorResponse struct {
	Version Version   `json:"version"`
	Error   ErrorCode `json:"error"`
}

// Version represents the protocol version.
type Version uint8

const (
	// VersionV0 is the current protocol version.
	VersionV0 Version = 0
)

// MarshalJSON implements json.Marshaler for Version.
func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint8(v))
}

// UnmarshalJSON implements json.Unmarshaler for Version.
func (v *Version) UnmarshalJSON(data []byte) error {
	var val uint8
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}
	*v = Version(val)
	return nil
}

// ErrorCode represents an error that occurred during credential exchange.
type ErrorCode string

const (
	// ErrorUserCanceled indicates that a user confirmation action was refused.
	ErrorUserCanceled ErrorCode = "user-canceled"
	// ErrorIncompatibleHpkeParameters indicates the exporter doesn't support any requested HPKE parameters.
	ErrorIncompatibleHpkeParameters ErrorCode = "incompatible-hpke-parameters"
	// ErrorMissingImporterKey indicates the importer didn't provide a required key.
	ErrorMissingImporterKey ErrorCode = "missing-importer-key"
	// ErrorIncorrectImporterKeyEncoding indicates the importer provided an invalid key.
	ErrorIncorrectImporterKeyEncoding ErrorCode = "incorrect-importer-key-encoding"
	// ErrorUnsupportedVersion indicates the exporter doesn't support the requested protocol version.
	ErrorUnsupportedVersion ErrorCode = "unsupported-version"
	// ErrorInvalidJson indicates an error occurred while parsing the JSON request.
	ErrorInvalidJson ErrorCode = "invalid-json"
	// ErrorForbiddenAction indicates the exporter refused the export due to policy.
	ErrorForbiddenAction ErrorCode = "forbidden-action"
)

// CredentialType represents a type of credential that can be exchanged.
type CredentialType string

const (
	CredentialTypeBasicAuth        CredentialType = "basic-auth"
	CredentialTypePasskey          CredentialType = "passkey"
	CredentialTypeTotp             CredentialType = "totp"
	CredentialTypeNote             CredentialType = "note"
	CredentialTypeFile             CredentialType = "file"
	CredentialTypeAddress          CredentialType = "address"
	CredentialTypeCreditCard       CredentialType = "credit-card"
	CredentialTypeDriverLicense    CredentialType = "driver-license"
	CredentialTypeItemReference    CredentialType = "item-reference"
	CredentialTypeIdentityDocument CredentialType = "identity-document"
	CredentialTypePassport         CredentialType = "passport"
	CredentialTypePersonName       CredentialType = "person-name"
	CredentialTypeSshKey           CredentialType = "ssh-key"
	CredentialTypeApiKey           CredentialType = "api-key"
)

// KnownExtension represents a known protocol extension.
type KnownExtension string

const (
	// KnownExtensionShared represents the shared credentials extension.
	KnownExtensionShared KnownExtension = "shared"
)

// ArchiveAlgorithm represents an archiving algorithm for compressing credentials.
// See: https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20240522.html#dom-archivealgorithm-deflate
type ArchiveAlgorithm string

const (
	// ArchiveAlgorithmDeflate uses the DEFLATE algorithm defined in RFC1951.
	ArchiveAlgorithmDeflate ArchiveAlgorithm = "deflate"
)

// HpkeParameters defines the HPKE configuration for encryption.
type HpkeParameters struct {
	Mode HpkeMode        `json:"mode"`
	Kem  HpkeKem         `json:"kem"`
	Kdf  HpkeKdf         `json:"kdf"`
	Aead HpkeAead        `json:"aead"`
	Key  json.RawMessage `json:"key,omitempty"` // JWK
}

// Equal compares two HpkeParameters, ignoring the Key field (which is ephemeral).
func (h HpkeParameters) Equal(other HpkeParameters) bool {
	return h.Mode == other.Mode &&
		h.Kem == other.Kem &&
		h.Kdf == other.Kdf &&
		h.Aead == other.Aead
}

// HpkeMode represents the HPKE operating mode.
type HpkeMode string

const (
	HpkeModeBase    HpkeMode = "base"
	HpkeModePsk     HpkeMode = "psk"
	HpkeModeAuth    HpkeMode = "auth"
	HpkeModeAuthPsk HpkeMode = "auth-psk"
)

// HpkeKem represents the HPKE Key Encapsulation Mechanism.
type HpkeKem uint16

const (
	HpkeKemReserved              HpkeKem = 0x0000
	HpkeKemDhP256                HpkeKem = 0x0010
	HpkeKemDhP384                HpkeKem = 0x0011
	HpkeKemDhP521                HpkeKem = 0x0012
	HpkeKemDhCP256               HpkeKem = 0x0013
	HpkeKemDhCP384               HpkeKem = 0x0014
	HpkeKemDhCP521               HpkeKem = 0x0015
	HpkeKemDhSecP256K1           HpkeKem = 0x0016
	HpkeKemDhX25519              HpkeKem = 0x0020
	HpkeKemDhX448                HpkeKem = 0x0021
	HpkeKemX25519Kyber768Draft00 HpkeKem = 0x0030
)

// MarshalJSON implements json.Marshaler for HpkeKem.
func (k HpkeKem) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint16(k))
}

// UnmarshalJSON implements json.Unmarshaler for HpkeKem.
func (k *HpkeKem) UnmarshalJSON(data []byte) error {
	var val uint16
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}
	*k = HpkeKem(val)
	return nil
}

// String returns the string representation of the KEM.
func (k HpkeKem) String() string {
	switch k {
	case HpkeKemReserved:
		return "Reserved"
	case HpkeKemDhP256:
		return "DHKEM(P-256, HKDF-SHA256)"
	case HpkeKemDhP384:
		return "DHKEM(P-384, HKDF-SHA384)"
	case HpkeKemDhP521:
		return "DHKEM(P-521, HKDF-SHA512)"
	case HpkeKemDhX25519:
		return "DHKEM(X25519, HKDF-SHA256)"
	case HpkeKemDhX448:
		return "DHKEM(X448, HKDF-SHA512)"
	case HpkeKemX25519Kyber768Draft00:
		return "X25519Kyber768Draft00"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(k))
	}
}

// HpkeKdf represents the HPKE Key Derivation Function.
type HpkeKdf uint16

const (
	HpkeKdfReserved   HpkeKdf = 0x0000
	HpkeKdfHkdfSha256 HpkeKdf = 0x0001
	HpkeKdfHkdfSha384 HpkeKdf = 0x0002
	HpkeKdfHkdfSha512 HpkeKdf = 0x0003
)

// MarshalJSON implements json.Marshaler for HpkeKdf.
func (k HpkeKdf) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint16(k))
}

// UnmarshalJSON implements json.Unmarshaler for HpkeKdf.
func (k *HpkeKdf) UnmarshalJSON(data []byte) error {
	var val uint16
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}
	*k = HpkeKdf(val)
	return nil
}

// String returns the string representation of the KDF.
func (k HpkeKdf) String() string {
	switch k {
	case HpkeKdfReserved:
		return "Reserved"
	case HpkeKdfHkdfSha256:
		return "HKDF-SHA256"
	case HpkeKdfHkdfSha384:
		return "HKDF-SHA384"
	case HpkeKdfHkdfSha512:
		return "HKDF-SHA512"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(k))
	}
}

// HpkeAead represents the HPKE AEAD cipher.
type HpkeAead uint16

const (
	HpkeAeadReserved         HpkeAead = 0x0000
	HpkeAeadAes128Gcm        HpkeAead = 0x0001
	HpkeAeadAes256Gcm        HpkeAead = 0x0002
	HpkeAeadChaCha20Poly1305 HpkeAead = 0x0003
	HpkeAeadExportOnly       HpkeAead = 0xFFFF
)

// MarshalJSON implements json.Marshaler for HpkeAead.
func (a HpkeAead) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint16(a))
}

// UnmarshalJSON implements json.Unmarshaler for HpkeAead.
func (a *HpkeAead) UnmarshalJSON(data []byte) error {
	var val uint16
	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}
	*a = HpkeAead(val)
	return nil
}

// String returns the string representation of the AEAD.
func (a HpkeAead) String() string {
	switch a {
	case HpkeAeadReserved:
		return "Reserved"
	case HpkeAeadAes128Gcm:
		return "AES-128-GCM"
	case HpkeAeadAes256Gcm:
		return "AES-256-GCM"
	case HpkeAeadChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case HpkeAeadExportOnly:
		return "Export-Only"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(a))
	}
}
