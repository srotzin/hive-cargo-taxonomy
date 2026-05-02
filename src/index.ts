/**
 * @hivecivilization/hive-cargo-taxonomy
 *
 * Versioned Cargo Taxonomy registry — HiveAttest Claim C17, USPTO 64/055,601.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

export {
  CargoRegistry,
  validateAgainstSchema,
  parseSemVer,
  isVersionCompatible,
  computeRegistryMerkleRoot,
  sensitivityOrdinal,
  isSensitivityCompatible,
  SENSITIVITY_ORDER,
} from "./taxonomy.js";

export type {
  CargoType,
  CargoSchema,
  CargoSchemaProperty,
  SensitivityTier,
  JsonSchemaType,
  MigrationPath,
  ValidationResult,
  RegistrySnapshot,
} from "./types.js";
