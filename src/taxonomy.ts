/**
 * hive-cargo-taxonomy — Versioned Cargo Taxonomy registry (HiveAttest Claim C17).
 *
 * A versioned registry of cargo types (data classes) with:
 *   - Semver versioning and compatibility checks
 *   - JSON Schema validation of payloads
 *   - Sensitivity tier enforcement
 *   - Merkle-root pinning for cryptographic version anchoring
 *   - Migration path enforcement (cargo may only flow to compatible versions)
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { sha256 } from "@noble/hashes/sha256";
import type {
  CargoSchema,
  CargoType,
  MigrationPath,
  RegistrySnapshot,
  SensitivityTier,
  ValidationResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function sha256Hex(s: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(s)));
}

/** RFC 8785 JCS (minimal, no deps). */
function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v)!;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new TypeError(`canonicalize: ${typeof v}`);
}

// ---------------------------------------------------------------------------
// Semver parsing
// ---------------------------------------------------------------------------

interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

export function parseSemVer(v: string): SemVer {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) throw new Error(`Invalid semver: "${v}"`);
  return { major: parseInt(m[1], 10), minor: parseInt(m[2], 10), patch: parseInt(m[3], 10) };
}

/**
 * Two versions are compatible (same-major, to >= from) or equal.
 * "cargo can only flow upward in compatible-version DAG"
 */
export function isVersionCompatible(from: string, to: string): boolean {
  const f = parseSemVer(from);
  const t = parseSemVer(to);
  if (f.major !== t.major) return false;
  if (t.minor > f.minor) return true;
  if (t.minor === f.minor && t.patch >= f.patch) return true;
  return false;
}

// ---------------------------------------------------------------------------
// JSON Schema validation (structural, no remote refs)
// ---------------------------------------------------------------------------

export function validateAgainstSchema(
  payload: unknown,
  schema: CargoSchema
): ValidationResult {
  const errors: string[] = [];

  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { valid: false, errors: ["payload must be a plain object"] };
  }

  const obj = payload as Record<string, unknown>;

  // Required fields
  for (const req of schema.required ?? []) {
    if (!(req in obj)) errors.push(`Missing required field: "${req}"`);
  }

  // Property type checks
  for (const [propName, propDef] of Object.entries(schema.properties)) {
    if (!(propName in obj)) continue; // not present — checked above if required
    const val = obj[propName];
    const types = Array.isArray(propDef.type) ? propDef.type : [propDef.type];
    const jsType = val === null ? "null" : Array.isArray(val) ? "array" : typeof val;
    if (!types.includes(jsType as typeof types[number])) {
      errors.push(`Field "${propName}" expected type ${types.join("|")} but got ${jsType}`);
    }
  }

  // Additional properties
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(obj)) {
      if (!(key in schema.properties)) {
        errors.push(`Additional property not allowed: "${key}"`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Merkle root over sorted hashes
// ---------------------------------------------------------------------------

function merkleParent(l: string, r: string): string {
  return sha256Hex(l + r);
}

export function computeRegistryMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return sha256Hex("empty-registry");
  let layer = hashes.slice();
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(merkleParent(layer[i], i + 1 < layer.length ? layer[i + 1] : layer[i]));
    }
    layer = next;
  }
  return layer[0];
}

// ---------------------------------------------------------------------------
// CargoRegistry
// ---------------------------------------------------------------------------

export class CargoRegistry {
  private readonly entries = new Map<string, CargoType>();

  private static key(id: string, version: string): string {
    return `${id}@${version}`;
  }

  /** Register a new cargo type. Computes and embeds definition_hash. */
  register(opts: Omit<CargoType, "definition_hash">): CargoType {
    // Validate semver
    parseSemVer(opts.version); // throws if invalid

    const key = CargoRegistry.key(opts.id, opts.version);
    if (this.entries.has(key)) {
      throw new Error(`Cargo type ${key} already registered`);
    }

    const definitionHash = sha256Hex(canonicalize({
      id: opts.id,
      version: opts.version,
      sensitivity: opts.sensitivity,
      schema: opts.schema,
    }));

    const entry: CargoType = { ...opts, definition_hash: definitionHash };
    this.entries.set(key, entry);
    return entry;
  }

  /** List all registered cargo types, sorted by id+version. */
  list(): CargoType[] {
    return Array.from(this.entries.values()).sort((a, b) => {
      const ka = CargoRegistry.key(a.id, a.version);
      const kb = CargoRegistry.key(b.id, b.version);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
  }

  /** Look up a specific version. Returns undefined if not found. */
  get(id: string, version: string): CargoType | undefined {
    return this.entries.get(CargoRegistry.key(id, version));
  }

  /** Validate a payload against the schema of a registered cargo type. */
  validate(id: string, version: string, payload: unknown): ValidationResult {
    const entry = this.get(id, version);
    if (!entry) {
      return { valid: false, errors: [`Cargo type ${id}@${version} not registered`] };
    }
    return validateAgainstSchema(payload, entry.schema);
  }

  /**
   * Check whether migration from one cargo type/version to another is compatible.
   * Rules:
   *   - Same id, semver-compatible (same major, to >= from) → compatible
   *   - Different id only if `supersedes` link exists from `to` pointing at `from`
   */
  checkMigration(
    fromId: string, fromVersion: string,
    toId: string, toVersion: string,
  ): MigrationPath {
    const fromEntry = this.get(fromId, fromVersion);
    const toEntry = this.get(toId, toVersion);

    if (!fromEntry || !toEntry) {
      return { fromId, fromVersion, toId, toVersion, compatible: false };
    }

    // Same type ID — semver compatibility
    if (fromId === toId) {
      return {
        fromId, fromVersion, toId, toVersion,
        compatible: isVersionCompatible(fromVersion, toVersion),
      };
    }

    // Different type ID — requires explicit supersedes link
    const compatible =
      toEntry.supersedes?.id === fromId && toEntry.supersedes.version === fromVersion;
    return { fromId, fromVersion, toId, toVersion, compatible };
  }

  /** Produce a registry snapshot with Merkle root over all definition hashes. */
  snapshot(nowMs?: number): RegistrySnapshot {
    const sorted = this.list();
    const hashes = sorted.map((e) => e.definition_hash);
    return {
      snapshotAt: new Date(nowMs ?? Date.now()).toISOString(),
      count: sorted.length,
      merkleRoot: computeRegistryMerkleRoot(hashes),
    };
  }
}

// ---------------------------------------------------------------------------
// Built-in seed types (v0 taxonomy)
// ---------------------------------------------------------------------------

export const SENSITIVITY_ORDER: SensitivityTier[] = [
  "public",
  "internal",
  "confidential",
  "restricted",
  "critical",
];

export function sensitivityOrdinal(tier: SensitivityTier): number {
  return SENSITIVITY_ORDER.indexOf(tier);
}

/** Returns true if `to` is at least as sensitive as `from`. */
export function isSensitivityCompatible(from: SensitivityTier, to: SensitivityTier): boolean {
  return sensitivityOrdinal(to) >= sensitivityOrdinal(from);
}
