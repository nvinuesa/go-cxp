package cxp

import (
	"encoding/json"
	"testing"
)

func TestVersionSerialization(t *testing.T) {
	tests := []struct {
		name    string
		version Version
		want    string
	}{
		{"V0", VersionV0, "0"},
		{"Unknown version 5", Version(5), "5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.version)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("got %s, want %s", string(data), tt.want)
			}

			var got Version
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if got != tt.version {
				t.Errorf("roundtrip: got %v, want %v", got, tt.version)
			}
		})
	}
}

func TestHpkeKemSerialization(t *testing.T) {
	tests := []struct {
		name string
		kem  HpkeKem
		want string
	}{
		{"Reserved", HpkeKemReserved, "0"},
		{"P-256", HpkeKemDhP256, "16"},
		{"X25519", HpkeKemDhX25519, "32"},
		{"X25519Kyber768Draft00", HpkeKemX25519Kyber768Draft00, "48"},
		{"Unknown", HpkeKem(0x1234), "4660"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.kem)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("got %s, want %s", string(data), tt.want)
			}

			var got HpkeKem
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if got != tt.kem {
				t.Errorf("roundtrip: got %v, want %v", got, tt.kem)
			}
		})
	}
}

func TestHpkeKdfSerialization(t *testing.T) {
	tests := []struct {
		name string
		kdf  HpkeKdf
		want string
	}{
		{"Reserved", HpkeKdfReserved, "0"},
		{"HKDF-SHA256", HpkeKdfHkdfSha256, "1"},
		{"HKDF-SHA384", HpkeKdfHkdfSha384, "2"},
		{"HKDF-SHA512", HpkeKdfHkdfSha512, "3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.kdf)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("got %s, want %s", string(data), tt.want)
			}

			var got HpkeKdf
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if got != tt.kdf {
				t.Errorf("roundtrip: got %v, want %v", got, tt.kdf)
			}
		})
	}
}

func TestHpkeAeadSerialization(t *testing.T) {
	tests := []struct {
		name string
		aead HpkeAead
		want string
	}{
		{"Reserved", HpkeAeadReserved, "0"},
		{"AES-128-GCM", HpkeAeadAes128Gcm, "1"},
		{"AES-256-GCM", HpkeAeadAes256Gcm, "2"},
		{"ChaCha20-Poly1305", HpkeAeadChaCha20Poly1305, "3"},
		{"Export-Only", HpkeAeadExportOnly, "65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.aead)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("got %s, want %s", string(data), tt.want)
			}

			var got HpkeAead
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if got != tt.aead {
				t.Errorf("roundtrip: got %v, want %v", got, tt.aead)
			}
		})
	}
}

func TestHpkeParametersSerialization(t *testing.T) {
	params := HpkeParameters{
		Mode: HpkeModeBase,
		Kem:  HpkeKemDhX25519,
		Kdf:  HpkeKdfHkdfSha256,
		Aead: HpkeAeadAes256Gcm,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var got HpkeParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !got.Equal(params) {
		t.Errorf("roundtrip failed: got %+v, want %+v", got, params)
	}
}

func TestHpkeParametersEqual(t *testing.T) {
	p1 := HpkeParameters{
		Mode: HpkeModeBase,
		Kem:  HpkeKemDhX25519,
		Kdf:  HpkeKdfHkdfSha256,
		Aead: HpkeAeadAes256Gcm,
		Key:  json.RawMessage(`{"kty":"OKP","crv":"X25519"}`),
	}
	p2 := HpkeParameters{
		Mode: HpkeModeBase,
		Kem:  HpkeKemDhX25519,
		Kdf:  HpkeKdfHkdfSha256,
		Aead: HpkeAeadAes256Gcm,
		Key:  nil, // Different key, should still be equal
	}

	if !p1.Equal(p2) {
		t.Error("Equal should ignore Key field")
	}

	p3 := HpkeParameters{
		Mode: HpkeModeAuth, // Different mode
		Kem:  HpkeKemDhX25519,
		Kdf:  HpkeKdfHkdfSha256,
		Aead: HpkeAeadAes256Gcm,
	}
	if p1.Equal(p3) {
		t.Error("Equal should detect different modes")
	}
}

func TestExportRequestSerialization(t *testing.T) {
	req := ExportRequest{
		Version:  VersionV0,
		Importer: "example.com",
		Hpke: []HpkeParameters{
			{
				Mode: HpkeModeBase,
				Kem:  HpkeKemDhX25519,
				Kdf:  HpkeKdfHkdfSha256,
				Aead: HpkeAeadAes256Gcm,
			},
		},
		Archive: []ArchiveAlgorithm{
			ArchiveAlgorithmDeflate,
		},
		CredentialTypes: []CredentialType{
			CredentialTypePasskey,
			CredentialTypeBasicAuth,
		},
		KnownExtensions: []KnownExtension{
			KnownExtensionShared,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Check that JSON uses camelCase
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	if _, ok := m["archive"]; !ok {
		t.Error("expected 'archive' in JSON")
	}
	if _, ok := m["credentialTypes"]; !ok {
		t.Error("expected camelCase 'credentialTypes' in JSON")
	}
	if _, ok := m["knownExtensions"]; !ok {
		t.Error("expected camelCase 'knownExtensions' in JSON")
	}

	var got ExportRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got.Version != req.Version {
		t.Errorf("Version: got %v, want %v", got.Version, req.Version)
	}
	if got.Importer != req.Importer {
		t.Errorf("Importer: got %v, want %v", got.Importer, req.Importer)
	}
	if len(got.Archive) != 1 || got.Archive[0] != ArchiveAlgorithmDeflate {
		t.Errorf("Archive: got %v, want [deflate]", got.Archive)
	}
	if len(got.CredentialTypes) != 2 {
		t.Errorf("CredentialTypes: got %d items, want 2", len(got.CredentialTypes))
	}
}

func TestExportRequestOmitsEmptyOptionalFields(t *testing.T) {
	req := ExportRequest{
		Version:  VersionV0,
		Importer: "example.com",
		Hpke: []HpkeParameters{
			{
				Mode: HpkeModeBase,
				Kem:  HpkeKemDhX25519,
				Kdf:  HpkeKdfHkdfSha256,
				Aead: HpkeAeadAes256Gcm,
			},
		},
		// No Archive, CredentialTypes or KnownExtensions
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	if _, ok := m["archive"]; ok {
		t.Error("expected 'archive' to be omitted when empty")
	}
	if _, ok := m["credentialTypes"]; ok {
		t.Error("expected 'credentialTypes' to be omitted when empty")
	}
	if _, ok := m["knownExtensions"]; ok {
		t.Error("expected 'knownExtensions' to be omitted when empty")
	}
}

func TestExportResponseSerialization(t *testing.T) {
	resp := ExportResponse{
		Version:  VersionV0,
		Exporter: "exporter.example.com",
		Hpke: HpkeParameters{
			Mode: HpkeModeBase,
			Kem:  HpkeKemDhX25519,
			Kdf:  HpkeKdfHkdfSha256,
			Aead: HpkeAeadAes256Gcm,
		},
		Archive: ArchiveAlgorithmDeflate,
		Payload: "SGVsbG8gV29ybGQ", // base64url encoded
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Check that JSON contains archive
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if _, ok := m["archive"]; !ok {
		t.Error("expected 'archive' in JSON")
	}

	var got ExportResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got.Version != resp.Version {
		t.Errorf("Version: got %v, want %v", got.Version, resp.Version)
	}
	if got.Exporter != resp.Exporter {
		t.Errorf("Exporter: got %v, want %v", got.Exporter, resp.Exporter)
	}
	if got.Archive != ArchiveAlgorithmDeflate {
		t.Errorf("Archive: got %v, want %v", got.Archive, ArchiveAlgorithmDeflate)
	}
	if got.Payload != resp.Payload {
		t.Errorf("Payload: got %v, want %v", got.Payload, resp.Payload)
	}
}

func TestExportResponseOmitsEmptyArchive(t *testing.T) {
	resp := ExportResponse{
		Version:  VersionV0,
		Exporter: "exporter.example.com",
		Hpke: HpkeParameters{
			Mode: HpkeModeBase,
			Kem:  HpkeKemDhX25519,
			Kdf:  HpkeKdfHkdfSha256,
			Aead: HpkeAeadAes256Gcm,
		},
		Payload: "SGVsbG8gV29ybGQ",
		// No Archive
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	if _, ok := m["archive"]; ok {
		t.Error("expected 'archive' to be omitted when empty")
	}
}

func TestErrorResponseSerialization(t *testing.T) {
	resp := ErrorResponse{
		Version: VersionV0,
		Error:   ErrorUserCanceled,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var got ErrorResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if got.Error != ErrorUserCanceled {
		t.Errorf("Error: got %v, want %v", got.Error, ErrorUserCanceled)
	}
}

func TestCredentialTypeConstants(t *testing.T) {
	tests := []struct {
		ct   CredentialType
		want string
	}{
		{CredentialTypeBasicAuth, "basic-auth"},
		{CredentialTypePasskey, "passkey"},
		{CredentialTypeTotp, "totp"},
		{CredentialTypeNote, "note"},
		{CredentialTypeFile, "file"},
		{CredentialTypeAddress, "address"},
		{CredentialTypeCreditCard, "credit-card"},
		{CredentialTypeDriverLicense, "driver-license"},
		{CredentialTypeItemReference, "item-reference"},
		{CredentialTypeIdentityDocument, "identity-document"},
		{CredentialTypePassport, "passport"},
		{CredentialTypePersonName, "person-name"},
		{CredentialTypeSshKey, "ssh-key"},
		{CredentialTypeApiKey, "api-key"},
	}

	for _, tt := range tests {
		if string(tt.ct) != tt.want {
			t.Errorf("CredentialType: got %s, want %s", tt.ct, tt.want)
		}
	}
}

func TestErrorCodeConstants(t *testing.T) {
	tests := []struct {
		ec   ErrorCode
		want string
	}{
		{ErrorUserCanceled, "user-canceled"},
		{ErrorIncompatibleHpkeParameters, "incompatible-hpke-parameters"},
		{ErrorMissingImporterKey, "missing-importer-key"},
		{ErrorIncorrectImporterKeyEncoding, "incorrect-importer-key-encoding"},
		{ErrorUnsupportedVersion, "unsupported-version"},
		{ErrorInvalidJson, "invalid-json"},
		{ErrorForbiddenAction, "forbidden-action"},
	}

	for _, tt := range tests {
		if string(tt.ec) != tt.want {
			t.Errorf("ErrorCode: got %s, want %s", tt.ec, tt.want)
		}
	}
}

func TestHpkeModeConstants(t *testing.T) {
	tests := []struct {
		mode HpkeMode
		want string
	}{
		{HpkeModeBase, "base"},
		{HpkeModePsk, "psk"},
		{HpkeModeAuth, "auth"},
		{HpkeModeAuthPsk, "auth-psk"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("HpkeMode: got %s, want %s", tt.mode, tt.want)
		}
	}
}

func TestArchiveAlgorithmConstants(t *testing.T) {
	tests := []struct {
		alg  ArchiveAlgorithm
		want string
	}{
		{ArchiveAlgorithmDeflate, "deflate"},
	}

	for _, tt := range tests {
		if string(tt.alg) != tt.want {
			t.Errorf("ArchiveAlgorithm: got %s, want %s", tt.alg, tt.want)
		}
	}
}

func TestHpkeKemString(t *testing.T) {
	tests := []struct {
		kem  HpkeKem
		want string
	}{
		{HpkeKemReserved, "Reserved"},
		{HpkeKemDhP256, "DHKEM(P-256, HKDF-SHA256)"},
		{HpkeKemDhX25519, "DHKEM(X25519, HKDF-SHA256)"},
		{HpkeKem(0x9999), "Unknown(0x9999)"},
	}

	for _, tt := range tests {
		if got := tt.kem.String(); got != tt.want {
			t.Errorf("HpkeKem.String(): got %s, want %s", got, tt.want)
		}
	}
}

func TestHpkeKdfString(t *testing.T) {
	tests := []struct {
		kdf  HpkeKdf
		want string
	}{
		{HpkeKdfReserved, "Reserved"},
		{HpkeKdfHkdfSha256, "HKDF-SHA256"},
		{HpkeKdfHkdfSha512, "HKDF-SHA512"},
		{HpkeKdf(0x9999), "Unknown(0x9999)"},
	}

	for _, tt := range tests {
		if got := tt.kdf.String(); got != tt.want {
			t.Errorf("HpkeKdf.String(): got %s, want %s", got, tt.want)
		}
	}
}

func TestHpkeAeadString(t *testing.T) {
	tests := []struct {
		aead HpkeAead
		want string
	}{
		{HpkeAeadReserved, "Reserved"},
		{HpkeAeadAes256Gcm, "AES-256-GCM"},
		{HpkeAeadChaCha20Poly1305, "ChaCha20-Poly1305"},
		{HpkeAeadExportOnly, "Export-Only"},
		{HpkeAead(0x9999), "Unknown(0x9999)"},
	}

	for _, tt := range tests {
		if got := tt.aead.String(); got != tt.want {
			t.Errorf("HpkeAead.String(): got %s, want %s", got, tt.want)
		}
	}
}
