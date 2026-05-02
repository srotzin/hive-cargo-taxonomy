# @hivecivilization/hive-cargo-taxonomy

<div align="center">
<img src="https://img.shields.io/badge/license-Apache%202.0-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/patent%20pending-USPTO%2064%2F055%2C601-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/tests-45%20passing-FFB800?style=flat-square" />
</div>

**Versioned Cargo Taxonomy registry for autonomous agent payload classification.**

A machine-readable registry of cargo types (data classes: PII, PHI, CSAM-indicator, CBRN-uplift, etc.) with semver versioning, JSON Schema typed payload validation, sensitivity tiers, and Merkle-root cryptographic pinning so any manifest can commit to an exact taxonomy version.

---

## Claim Reference

**USPTO 64/055,601 — HiveAttest Claim C17**

> *A versioned cargo taxonomy registry for autonomous agent systems: defines typed cargo classes with semantic version identifiers, JSON Schema payload validation, and declared sensitivity tiers; enforces migration-path compatibility such that cargo may only flow to higher or equal semver-compatible versions; provides Merkle-root cryptographic pinning of each registry snapshot so Attestation Manifests can commit to an exact taxonomy version.*

---

## Quick Start

```typescript
import { CargoRegistry } from "@hivecivilization/hive-cargo-taxonomy";

const registry = new CargoRegistry();

// Register a cargo type
registry.register({
  id: "pii",
  name: "Personally Identifiable Information",
  version: "1.0.0",
  sensitivity: "confidential",
  schema: {
    type: "object",
    properties: {
      subject_id: { type: "string" },
      email: { type: "string" },
    },
    required: ["subject_id"],
    additionalProperties: false,
  },
  registered_at: new Date().toISOString(),
});

// Validate a payload
const result = registry.validate("pii", "1.0.0", { subject_id: "user-42", email: "x@x.com" });
console.log(result.valid); // true

// Check migration compatibility
const migration = registry.checkMigration("pii", "1.0.0", "pii", "1.1.0");
console.log(migration.compatible); // true (minor upgrade, same major)

// Get a Merkle-pinned registry snapshot
const snap = registry.snapshot();
console.log(snap.merkleRoot); // SHA-256 hex over all definition hashes
```

---

## NOTICE

Reference implementation — USPTO 64/055,601, HiveAttest Claim C17.  
Inventor: Stephen A. Rotzin. Apache License 2.0.
