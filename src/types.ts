/**
 * Types for hive-cargo-taxonomy — Versioned Cargo Taxonomy (HiveAttest C17).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

/** Sensitivity tier for a cargo type. */
export type SensitivityTier =
  | "public"
  | "internal"
  | "confidential"
  | "restricted"
  | "critical";

/** A JSON Schema sub-type (minimal subset sufficient for cargo validation). */
export type JsonSchemaType = "string" | "number" | "boolean" | "object" | "array" | "null";

/** Minimal JSON Schema descriptor for cargo type properties. */
export interface CargoSchemaProperty {
  type: JsonSchemaType | JsonSchemaType[];
  description?: string;
  required?: boolean;
}

/** JSON Schema for a cargo type's payload shape. */
export interface CargoSchema {
  type: "object";
  properties: Record<string, CargoSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

/** A registered cargo type. */
export interface CargoType {
  /** Unique identifier, e.g. "pii", "csam-indicator", "cbrn-uplift". */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Semver version string, e.g. "1.0.0". */
  version: string;
  /** Sensitivity tier. */
  sensitivity: SensitivityTier;
  /** JSON Schema defining the payload shape. */
  schema: CargoSchema;
  /** ISO-8601 date of registration. */
  registered_at: string;
  /** SHA-256 hex of the canonical cargo type definition. */
  definition_hash: string;
  /** Optional predecessor id+version (migration path). */
  supersedes?: { id: string; version: string };
}

/** Describes a migration path between two cargo versions. */
export interface MigrationPath {
  fromId: string;
  fromVersion: string;
  toId: string;
  toVersion: string;
  compatible: boolean;
}

/** Result of schema validation. */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/** Registry snapshot with Merkle root for version pinning. */
export interface RegistrySnapshot {
  /** ISO-8601 timestamp. */
  snapshotAt: string;
  /** Number of registered cargo types. */
  count: number;
  /** SHA-256 Merkle root over all definition_hash values (sorted by id+version). */
  merkleRoot: string;
}
