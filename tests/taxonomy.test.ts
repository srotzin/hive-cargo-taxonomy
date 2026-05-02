/**
 * Tests for hive-cargo-taxonomy — Versioned Cargo Taxonomy (Claim C17).
 *
 * ≥30 tests covering: register, version-compat, schema-validation, migration-path,
 * sensitivity tiers, merkle root, snapshot.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { describe, it, expect } from "vitest";
import {
  CargoRegistry,
  validateAgainstSchema,
  parseSemVer,
  isVersionCompatible,
  computeRegistryMerkleRoot,
  sensitivityOrdinal,
  isSensitivityCompatible,
} from "../src/taxonomy.js";
import type { CargoSchema, CargoType } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helper fixtures
// ---------------------------------------------------------------------------

const PII_SCHEMA: CargoSchema = {
  type: "object",
  properties: {
    subject_id: { type: "string" },
    email: { type: "string" },
    age: { type: "number" },
  },
  required: ["subject_id"],
  additionalProperties: false,
};

const CSAM_SCHEMA: CargoSchema = {
  type: "object",
  properties: { present: { type: "boolean" } },
  required: ["present"],
};

function makePii(version = "1.0.0"): Omit<CargoType, "definition_hash"> {
  return {
    id: "pii",
    name: "PII",
    version,
    sensitivity: "confidential",
    schema: PII_SCHEMA,
    registered_at: "2026-05-02T00:00:00Z",
  };
}

// ---------------------------------------------------------------------------
// Semver parsing
// ---------------------------------------------------------------------------

describe("parseSemVer", () => {
  it("parses 1.0.0", () => {
    expect(parseSemVer("1.0.0")).toEqual({ major: 1, minor: 0, patch: 0 });
  });
  it("parses 2.3.11", () => {
    expect(parseSemVer("2.3.11")).toEqual({ major: 2, minor: 3, patch: 11 });
  });
  it("throws on non-semver string", () => {
    expect(() => parseSemVer("1.0")).toThrow();
  });
  it("throws on empty string", () => {
    expect(() => parseSemVer("")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Version compatibility
// ---------------------------------------------------------------------------

describe("isVersionCompatible", () => {
  it("same version is compatible", () => expect(isVersionCompatible("1.0.0", "1.0.0")).toBe(true));
  it("minor upgrade is compatible", () => expect(isVersionCompatible("1.0.0", "1.1.0")).toBe(true));
  it("patch upgrade is compatible", () => expect(isVersionCompatible("1.0.0", "1.0.1")).toBe(true));
  it("minor downgrade is not compatible", () => expect(isVersionCompatible("1.1.0", "1.0.0")).toBe(false));
  it("major version change is not compatible", () => expect(isVersionCompatible("1.0.0", "2.0.0")).toBe(false));
  it("lower major is not compatible", () => expect(isVersionCompatible("2.0.0", "1.9.9")).toBe(false));
});

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

describe("validateAgainstSchema", () => {
  it("valid payload passes", () => {
    const r = validateAgainstSchema({ subject_id: "user-1", email: "x@x.com" }, PII_SCHEMA);
    expect(r.valid).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it("missing required field fails", () => {
    const r = validateAgainstSchema({ email: "x@x.com" }, PII_SCHEMA);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("subject_id"))).toBe(true);
  });

  it("wrong type fails", () => {
    const r = validateAgainstSchema({ subject_id: "u", age: "not-a-number" }, PII_SCHEMA);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("age"))).toBe(true);
  });

  it("additional property rejected when additionalProperties=false", () => {
    const r = validateAgainstSchema({ subject_id: "u", unknown_field: "x" }, PII_SCHEMA);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("unknown_field"))).toBe(true);
  });

  it("non-object payload fails", () => {
    const r = validateAgainstSchema("not an object", PII_SCHEMA);
    expect(r.valid).toBe(false);
  });

  it("array payload fails", () => {
    const r = validateAgainstSchema([], PII_SCHEMA);
    expect(r.valid).toBe(false);
  });

  it("null payload fails", () => {
    const r = validateAgainstSchema(null, PII_SCHEMA);
    expect(r.valid).toBe(false);
  });

  it("schema without additionalProperties allows extra fields", () => {
    const schema: CargoSchema = {
      type: "object",
      properties: { name: { type: "string" } },
    };
    const r = validateAgainstSchema({ name: "Alice", extra: 123 }, schema);
    expect(r.valid).toBe(true);
  });

  it("multiple type union — accepts both types", () => {
    const schema: CargoSchema = {
      type: "object",
      properties: { val: { type: ["string", "number"] } },
    };
    expect(validateAgainstSchema({ val: "hello" }, schema).valid).toBe(true);
    expect(validateAgainstSchema({ val: 42 }, schema).valid).toBe(true);
    expect(validateAgainstSchema({ val: true }, schema).valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CargoRegistry — register
// ---------------------------------------------------------------------------

describe("CargoRegistry — register", () => {
  it("registers and retrieves a cargo type", () => {
    const reg = new CargoRegistry();
    const ct = reg.register(makePii());
    expect(reg.get("pii", "1.0.0")).toStrictEqual(ct);
  });

  it("definition_hash is a 64-char hex", () => {
    const reg = new CargoRegistry();
    const ct = reg.register(makePii());
    expect(ct.definition_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("same definition produces same hash", () => {
    const reg1 = new CargoRegistry();
    const reg2 = new CargoRegistry();
    expect(reg1.register(makePii()).definition_hash).toBe(reg2.register(makePii()).definition_hash);
  });

  it("different versions produce different hashes", () => {
    const reg = new CargoRegistry();
    const h1 = reg.register(makePii("1.0.0")).definition_hash;
    const h2 = reg.register(makePii("1.1.0")).definition_hash;
    expect(h1).not.toBe(h2);
  });

  it("throws on duplicate registration", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    expect(() => reg.register(makePii())).toThrow();
  });

  it("throws on invalid semver", () => {
    const reg = new CargoRegistry();
    expect(() => reg.register({ ...makePii(), version: "bad" })).toThrow();
  });

  it("list returns sorted entries", () => {
    const reg = new CargoRegistry();
    reg.register(makePii("2.0.0"));
    reg.register(makePii("1.0.0"));
    const ids = reg.list().map((e) => `${e.id}@${e.version}`);
    expect(ids).toEqual(["pii@1.0.0", "pii@2.0.0"]);
  });

  it("get returns undefined for unknown id", () => {
    expect(new CargoRegistry().get("unknown", "1.0.0")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// CargoRegistry — validate
// ---------------------------------------------------------------------------

describe("CargoRegistry — validate", () => {
  it("validates valid payload successfully", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    const r = reg.validate("pii", "1.0.0", { subject_id: "u1" });
    expect(r.valid).toBe(true);
  });

  it("returns error for unregistered type", () => {
    const reg = new CargoRegistry();
    const r = reg.validate("nonexistent", "1.0.0", {});
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toContain("not registered");
  });

  it("returns errors for invalid payload", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    const r = reg.validate("pii", "1.0.0", {});
    expect(r.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Migration path
// ---------------------------------------------------------------------------

describe("CargoRegistry — migration path", () => {
  it("same id, minor upgrade → compatible", () => {
    const reg = new CargoRegistry();
    reg.register(makePii("1.0.0"));
    reg.register(makePii("1.1.0"));
    expect(reg.checkMigration("pii", "1.0.0", "pii", "1.1.0").compatible).toBe(true);
  });

  it("same id, downgrade → not compatible", () => {
    const reg = new CargoRegistry();
    reg.register(makePii("1.0.0"));
    reg.register(makePii("1.1.0"));
    expect(reg.checkMigration("pii", "1.1.0", "pii", "1.0.0").compatible).toBe(false);
  });

  it("different id without supersedes → not compatible", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    reg.register({ id: "phi", name: "PHI", version: "1.0.0", sensitivity: "critical",
      schema: PII_SCHEMA, registered_at: "2026-05-02T00:00:00Z" });
    expect(reg.checkMigration("pii", "1.0.0", "phi", "1.0.0").compatible).toBe(false);
  });

  it("different id with supersedes link → compatible", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    reg.register({ id: "phi", name: "PHI", version: "1.0.0", sensitivity: "critical",
      schema: PII_SCHEMA, registered_at: "2026-05-02T00:00:00Z",
      supersedes: { id: "pii", version: "1.0.0" } });
    expect(reg.checkMigration("pii", "1.0.0", "phi", "1.0.0").compatible).toBe(true);
  });

  it("missing from entry → not compatible", () => {
    const reg = new CargoRegistry();
    reg.register(makePii("1.1.0"));
    expect(reg.checkMigration("pii", "1.0.0", "pii", "1.1.0").compatible).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Sensitivity
// ---------------------------------------------------------------------------

describe("sensitivity", () => {
  it("ordinal order is correct", () => {
    expect(sensitivityOrdinal("public")).toBeLessThan(sensitivityOrdinal("critical"));
  });
  it("isSensitivityCompatible: same tier", () => {
    expect(isSensitivityCompatible("confidential", "confidential")).toBe(true);
  });
  it("isSensitivityCompatible: higher tier OK", () => {
    expect(isSensitivityCompatible("internal", "critical")).toBe(true);
  });
  it("isSensitivityCompatible: lower tier not OK", () => {
    expect(isSensitivityCompatible("critical", "public")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Merkle root & snapshot
// ---------------------------------------------------------------------------

describe("computeRegistryMerkleRoot", () => {
  it("empty registry has non-empty root", () => {
    expect(computeRegistryMerkleRoot([])).toMatch(/^[0-9a-f]{64}$/);
  });
  it("single entry root is deterministic", () => {
    const h = "a".repeat(64);
    expect(computeRegistryMerkleRoot([h])).toBe(computeRegistryMerkleRoot([h]));
  });
  it("different entries produce different roots", () => {
    expect(computeRegistryMerkleRoot(["a".repeat(64)])).not.toBe(
      computeRegistryMerkleRoot(["b".repeat(64)])
    );
  });
});

describe("CargoRegistry — snapshot", () => {
  it("snapshot has merkleRoot and count", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    const snap = reg.snapshot();
    expect(snap.count).toBe(1);
    expect(snap.merkleRoot).toMatch(/^[0-9a-f]{64}$/);
  });

  it("empty registry snapshot has count 0", () => {
    expect(new CargoRegistry().snapshot().count).toBe(0);
  });

  it("snapshot is deterministic with same nowMs", () => {
    const reg = new CargoRegistry();
    reg.register(makePii());
    const s1 = reg.snapshot(1000);
    const s2 = reg.snapshot(1000);
    expect(s1.merkleRoot).toBe(s2.merkleRoot);
  });
});
