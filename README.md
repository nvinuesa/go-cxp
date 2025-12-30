# go-cxp

Go implementation of the FIDO Alliance Credential Exchange Protocol (CXP) v1.0.

## Overview

This package provides Go type definitions for the CXP protocol messages used for secure credential exchange between providers. It implements the types defined in the [CXP specification](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html).

For the Credential Exchange Format (CXF) types, see [github.com/nvinuesa/go-cxf](https://github.com/nvinuesa/go-cxf).

## Installation

```bash
go get github.com/nvinuesa/go-cxp
```

## Usage

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/nvinuesa/go-cxp"
)

func main() {
    // Create an export request
    req := cxp.ExportRequest{
        Version:  cxp.VersionV0,
        Importer: "importer.example.com",
        Hpke: []cxp.HpkeParameters{
            {
                Mode: cxp.HpkeModeBase,
                Kem:  cxp.HpkeKemDhX25519,
                Kdf:  cxp.HpkeKdfHkdfSha256,
                Aead: cxp.HpkeAeadAes256Gcm,
            },
        },
        CredentialTypes: []cxp.CredentialType{
            cxp.CredentialTypePasskey,
            cxp.CredentialTypeBasicAuth,
        },
    }

    // Serialize to JSON
    data, _ := json.MarshalIndent(req, "", "  ")
    fmt.Println(string(data))
}
```

## Types

### Protocol Messages

- `ExportRequest` - Request sent by the importing provider
- `ExportResponse` - Response containing encrypted credentials
- `ErrorResponse` - Error response with error code

### HPKE Configuration

- `HpkeParameters` - HPKE encryption parameters
- `HpkeMode` - HPKE operating mode (base, psk, auth, auth-psk)
- `HpkeKem` - Key Encapsulation Mechanism identifiers
- `HpkeKdf` - Key Derivation Function identifiers
- `HpkeAead` - AEAD cipher identifiers

### Enums

- `Version` - Protocol version (currently V0)
- `CredentialType` - Types of credentials (passkey, basic-auth, totp, etc.)
- `KnownExtension` - Protocol extensions (shared)
- `ErrorCode` - Error codes for failed exchanges

## License

AGPLv3
