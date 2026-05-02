# Cargo Taxonomy — Normative Specification

**Patent reference:** USPTO Provisional 64/055,601, claim C17
**Status:** Layer C reference. Wire format normative; production-grade hardening is Layer B.
**Author:** Stephen A. Rotzin, pro se
**Date:** 2026-05-02

---

## 1. Purpose

Agentic pipelines transport heterogeneous data: user PII, model outputs,
financial records, internal configuration, and publicly accessible content.
Without a shared vocabulary for data types and a machine-checkable sensitivity
classification, gate policies cannot enforce which agents may handle which data.

The Cargo Taxonomy primitive (hereafter "Taxonomy") solves two related problems:

1. **Type registration:** Any team in a multi-agent system can register a named
   cargo type with a version, a sensitivity level, and a JSON Schema that defines
   the shape of conforming payloads.

2. **Payload validation:** Before an agent declares cargo in a Pre-Action
   Attestation Manifest (claim C15), it can validate its payload against the
   registered schema. Gate enforcers (claim C19) use the registered sensitivity
   level to apply appropriate cargo policies.

The Taxonomy is the shared dictionary that makes cargo declarations in Manifests
meaningful and enforceable.

---

## 2. Conformance Terms

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

- An **issuer** is the HiveAttest service that stores cargo type registrations
  and signs receipts.
- A **cargo type** is identified by a `{id, version}` pair. The same `id` with
  a new `version` is a distinct cargo type; the `supersedes` field provides
  lineage.
- A **relying party** is any system (gate enforcer, auditor, agent) that queries
  registered types or validates payloads.
- The five sensitivity levels form a totally ordered scale:
  `public < internal < confidential < restricted < critical`.

---

## 3. Wire Format

### 3.1 Registration Request

`POST /v1/attest/cargo/register`

```json
{
  "id":          "<string, required>",
  "name":        "<string, required>",
  "version":     "<string, required>",
  "sensitivity": "<\"public\"|\"internal\"|\"confidential\"|\"restricted\"|\"critical\", required>",
  "schema":      "<JSON Schema object, required>",
  "supersedes":  {
    "id":      "<string>",
    "version": "<string>"
  }
}
```

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `id` | string | REQUIRED | Stable, human-readable identifier for the cargo type, e.g. `"user.pii.email"`. Reverse-DNS style RECOMMENDED. |
| `name` | string | REQUIRED | Human-readable display name. |
| `version` | string | REQUIRED | Semantic version string, e.g. `"1.0.0"`. |
| `sensitivity` | enum | REQUIRED | One of the five levels. Determines which gate policies apply. |
| `schema` | JSON Schema object | REQUIRED | JSON Schema (draft-07 or later) describing conforming payloads. The issuer stores this verbatim and uses it for validation requests. |
| `supersedes` | object | OPTIONAL | If provided, declares that this registration supersedes a prior `{id, version}`. The superseded version is not removed; lineage is advisory. |

### 3.2 Registration Response

```json
{
  "cargo_type": {
    "cargo_type_id":      "<uuid-v4>",
    "id":                 "<echoed>",
    "name":               "<echoed>",
    "version":            "<echoed>",
    "sensitivity":        "<echoed>",
    "schema_hash":        "<hex SHA-256 of JCS(schema)>",
    "registered_at":      "<ISO-8601 UTC>",
    "supersedes":         { "id": "<string>", "version": "<string>" },
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "<base64url SHA-256 of issuer public key>",
      "signature": "<base64url Ed25519 signature over JCS of signed body>"
    }
  },
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-cargo-taxonomy/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C17"
  }
}
```

| Field | Type | Semantics |
|-------|------|-----------|
| `cargo_type.cargo_type_id` | string (UUID v4) | Issuer-assigned globally unique identifier for this specific registration. |
| `cargo_type.schema_hash` | string | Lowercase hex SHA-256 of the RFC 8785 JCS-canonical encoding of the submitted `schema` object. Allows downstream parties to verify schema integrity without storing the full schema. |
| `cargo_type.supersedes` | object or null | Echoed from request; `null` if not provided. |

### 3.3 Validation Request

`POST /v1/attest/cargo/validate`

```json
{
  "cargo_type_id": "<string, required — the `id` field, not the UUID>",
  "version":       "<string, required>",
  "payload":       "<any JSON value, required>"
}
```

Response:

```json
{
  "valid":  true,
  "errors": [],
  "_meta":  { "layer": "C", "production_grade": false, "spec_url": "...", "patent": "USPTO 64/055,601", "claim": "C17" }
}
```

On validation failure, `valid` is `false` and `errors` is a non-empty array of
JSON Schema validation error objects.

### 3.4 Snapshot Request

`POST /v1/attest/cargo/snapshot`

Returns a signed snapshot of all currently registered cargo types, suitable for
offline auditing. Response schema is implementation-defined at Layer C; it MUST
include `_meta` with the standard Layer C fields.

---

## 4. Cryptography

### 4.1 Algorithms

| Primitive | Algorithm | Reference |
|-----------|-----------|-----------|
| Signing | Ed25519 (EdDSA) | RFC 8032 |
| Canonicalization | JSON Canonicalization Scheme (JCS) | RFC 8785 |
| Hashing | SHA-256 | FIPS 180-4 |
| Key identifier | base64url-no-pad SHA-256 of public key bytes | — |

### 4.2 Schema Hash

```
schema_hash = lowercase_hex( SHA-256( UTF-8( JCS( schema ) ) ) )
```

### 4.3 Signed Body Construction

The issuer signs the following object, JCS-canonicalized:

```json
{
  "cargo_type_id": "<uuid-v4>",
  "id":            "<string>",
  "name":          "<string>",
  "registered_at": "<ISO-8601 UTC>",
  "schema_hash":   "<hex>",
  "sensitivity":   "<enum>",
  "supersedes":    { "id": "<string>", "version": "<string>" },
  "version":       "<string>"
}
```

If `supersedes` was not provided in the request, it MUST be omitted from the
signed body (do not include a null-valued field).

```
signature = Ed25519Sign( privKey, UTF-8( JCS( signedBody ) ) )
```

### 4.4 Verification Recipe

Given the response object and the issuer's 32-byte Ed25519 public key:

1. Reconstruct `signedBody` from `cargo_type` fields (exclude `cargo_type.signing`).
2. Compute `bodyBytes = UTF-8( JCS( signedBody ) )`.
3. Decode `sigBytes = base64url_no_pad_decode( cargo_type.signing.signature )`.
4. Assert `Ed25519Verify( issuerPublicKey, bodyBytes, sigBytes ) == true`.
5. Assert `cargo_type.signing.key_id == base64url_no_pad( SHA-256( issuerPublicKey ) )`.

---

## 5. Endpoints (HTTP)

Base URL: `https://hivemorph.onrender.com`

### 5.1 Register a Cargo Type

```
POST /v1/attest/cargo/register
Content-Type: application/json
```

**Example request:**

```json
{
  "id":          "io.hiveattest.examples.user-email",
  "name":        "User Email Address",
  "version":     "1.0.0",
  "sensitivity": "confidential",
  "schema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["email"],
    "properties": {
      "email": {
        "type": "string",
        "format": "email"
      }
    },
    "additionalProperties": false
  }
}
```

**Example response (HTTP 200):**

```json
{
  "cargo_type": {
    "cargo_type_id":  "7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
    "id":             "io.hiveattest.examples.user-email",
    "name":           "User Email Address",
    "version":        "1.0.0",
    "sensitivity":    "confidential",
    "schema_hash":    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "registered_at":  "2026-05-02T14:00:00.000Z",
    "supersedes":     null,
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz01"
    }
  },
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-cargo-taxonomy/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C17"
  }
}
```

### 5.2 Validate a Payload

```
POST /v1/attest/cargo/validate
Content-Type: application/json
```

**Example request:**

```json
{
  "cargo_type_id": "io.hiveattest.examples.user-email",
  "version":       "1.0.0",
  "payload":       { "email": "user@example.com" }
}
```

**Example response (HTTP 200, valid):**

```json
{
  "valid":  true,
  "errors": [],
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-cargo-taxonomy/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C17"
  }
}
```

**Example response (HTTP 200, invalid):**

```json
{
  "valid":  false,
  "errors": [
    { "instancePath": "/email", "message": "must match format \"email\"" }
  ],
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-cargo-taxonomy/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C17"
  }
}
```

**Error responses:**

| HTTP Status | Condition |
|-------------|-----------|
| 400 | Missing required field or unknown `cargo_type_id`/`version` pair |
| 422 | Invalid JSON Schema in registration request |
| 409 | Duplicate `{id, version}` registration |

---

## 6. Layer C Honesty Contract

Every response from this endpoint MUST carry:

- **HTTP header:** `X-Hive-Layer: C-Reference`
- **Body field `_meta.layer`:** `"C"`
- **Body field `_meta.production_grade`:** `false`
- **Body field `_meta.spec_url`:** `"https://raw.githubusercontent.com/srotzin/hive-cargo-taxonomy/main/SPEC.md"`
- **Body field `_meta.patent`:** `"USPTO 64/055,601"`
- **Body field `_meta.claim`:** `"C17"`

---

## 7. Receipts and Verifiability

Given only the registration response and the issuer's 32-byte Ed25519 public key,
a third party MUST be able to:

1. **Verify the registration signature** per Section 4.4.
2. **Verify schema integrity** by re-computing `JCS + SHA-256` over the original
   schema object and comparing to `cargo_type.schema_hash`.
3. **Identify the key** via `cargo_type.signing.key_id` without needing the
   issuer's certificate chain.

A gate enforcer receiving a Manifest that declares cargo type
`"io.hiveattest.examples.user-email@1.0.0"` can:
- Look up the registered sensitivity level (`confidential`) and enforce the
  applicable gate policy.
- Re-validate the payload against the stored schema.
- Verify the registration receipt to confirm the schema has not been altered
  since registration.

---

## 8. Security Considerations

1. **In-process key storage.** The Ed25519 private key is held in process memory
   with no HSM backing. A process compromise allows forged registration receipts.

2. **No key rotation.** The same key signs all registrations. If the key is
   compromised, all historical receipts are suspect.

3. **Schema stored server-side only.** At Layer C, registered schemas are stored
   in the issuer's process memory or local store. If the server is restarted
   without persistence, registrations are lost. A Layer B implementation MUST
   use durable storage with cryptographic audit trails.

4. **No version immutability enforcement.** At Layer C, re-registering the same
   `{id, version}` with a different schema is rejected with HTTP 409, but this
   is enforced only in-memory. A server restart allows silent re-registration.
   A Layer B implementation MUST use an append-only log.

5. **No transparency log.** Registrations are not published to an external
   auditable log. The issuer can silently suppress or alter registrations.

6. **Sensitivity is advisory.** The sensitivity level is stored and returned but
   not enforced by this primitive itself. Enforcement is the responsibility of
   gate enforcers (claim C19) that consume taxonomy records.

7. **JSON Schema version.** The server validates payloads against the stored
   schema using a specific JSON Schema implementation. Version drift between
   the registrar's and the validator's JSON Schema engine may produce
   inconsistent results for edge cases. Draft-07 is used at Layer C.

---

## 9. References

- USPTO Provisional Application No. 64/055,601 — HiveAttest patent family
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- FIPS 180-4 — Secure Hash Standard (SHA-256)
- IETF JSON Schema draft-07 — https://json-schema.org/specification-links.html

---

## Appendix A. Test Vectors

**Vector 1: Register a minimal cargo type**

```
POST https://hivemorph.onrender.com/v1/attest/cargo/register
Content-Type: application/json

{
  "id":          "io.hiveattest.test.ping",
  "name":        "Test Ping Payload",
  "version":     "0.0.1",
  "sensitivity": "public",
  "schema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["ping"],
    "properties": {
      "ping": { "type": "boolean" }
    }
  }
}
```

Expected: HTTP 200, `cargo_type.sensitivity == "public"`,
`cargo_type.schema_hash` is deterministic for the above schema object.

**Vector 2: Validate a conforming payload**

```
POST https://hivemorph.onrender.com/v1/attest/cargo/validate
Content-Type: application/json

{
  "cargo_type_id": "io.hiveattest.test.ping",
  "version":       "0.0.1",
  "payload":       { "ping": true }
}
```

Expected: HTTP 200, `{ "valid": true, "errors": [] }`.

**Vector 3: Validate a non-conforming payload**

```json
{
  "cargo_type_id": "io.hiveattest.test.ping",
  "version":       "0.0.1",
  "payload":       { "ping": "not-a-boolean" }
}
```

Expected: HTTP 200, `{ "valid": false, "errors": [{ "instancePath": "/ping", ... }] }`.

**Supersession lineage:**

```json
{
  "id":          "io.hiveattest.test.ping",
  "version":     "0.0.2",
  "sensitivity": "public",
  "schema":      { ... },
  "supersedes":  { "id": "io.hiveattest.test.ping", "version": "0.0.1" }
}
```

Expected: HTTP 200. The v0.0.1 registration is NOT removed; both coexist.
