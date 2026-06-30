# OpenAPI Model Generation for NextGCore SBI

This directory contains tools and configuration for generating Rust data models
from 3GPP OpenAPI specifications.

## Overview

3GPP defines Service-Based Interface (SBI) APIs using OpenAPI 3.0 specifications.
These APIs are used between 5G Core Network Functions:

| Interface | NFs | Specification |
|-----------|-----|---------------|
| Namf | AMF | 3GPP TS 29.518 |
| Nsmf | SMF | 3GPP TS 29.502 |
| Nnrf | NRF | 3GPP TS 29.510 |
| Nausf | AUSF | 3GPP TS 29.509 |
| Nudm | UDM | 3GPP TS 29.503 |
| Nudr | UDR | 3GPP TS 29.504 |
| Npcf | PCF | 3GPP TS 29.507/512 |
| Nnssf | NSSF | 3GPP TS 29.531 |
| Nbsf | BSF | 3GPP TS 29.521 |

## Generating Models

### Prerequisites

1. Install OpenAPI Generator:
```bash
npm install @openapitools/openapi-generator-cli -g
# or
brew install openapi-generator
```

2. Download 3GPP OpenAPI specs from:
   - https://www.3gpp.org/ftp/Specs/archive/OpenAPI/
   - Or use: https://github.com/jdegre/5GC_APIs

### Generate Rust Models

```bash
./generate_models.sh
```

Or manually:

```bash
openapi-generator generate \
  -i specs/TS29510_Nnrf_NFManagement.yaml \
  -g rust \
  -o generated/nnrf \
  --additional-properties=packageName=ogs-sbi-nnrf,library=reqwest
```

### Configuration

The `openapi-generator-config.yaml` contains generator settings:

```yaml
generatorName: rust
additionalProperties:
  packageName: ogs-sbi-models
  library: reqwest
  supportAsync: true
  preferUnsignedInt: true
  dateLibrary: chrono
```

## Model Structure

Generated models follow this pattern:

```rust
// ogs-sbi/src/models/nf_profile.rs

use serde::{Deserialize, Serialize};

/// NF Profile as defined in 3GPP TS 29.510
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NfProfile {
    /// NF Instance ID
    #[serde(rename = "nfInstanceId")]
    pub nf_instance_id: String,

    /// NF Type
    #[serde(rename = "nfType")]
    pub nf_type: NfType,

    /// NF Status
    #[serde(rename = "nfStatus")]
    pub nf_status: NfStatus,

    // ... more fields
}
```

## Manual Models

Some models are hand-crafted for better Rust ergonomics. These are in
`src/models/` and take precedence over generated ones.

## 3GPP Release Versions

Models should target 3GPP Release 17 (frozen) or Release 18 (latest).

Check spec versions at:
- https://www.3gpp.org/specifications/specification-numbering

## Common Type Mappings

| OpenAPI Type | Rust Type |
|-------------|-----------|
| string | String |
| string (format: uri) | url::Url |
| string (format: date-time) | chrono::DateTime<Utc> |
| string (format: uuid) | uuid::Uuid |
| integer (format: int32) | i32 |
| integer (format: int64) | i64 |
| number | f64 |
| boolean | bool |
| object | serde_json::Value |
| array | Vec<T> |
| oneOf | enum |
| allOf | struct with flattened fields |

## Validation

Generated models include serde attributes for JSON serialization.
Additional validation can be added using the `validator` crate.
