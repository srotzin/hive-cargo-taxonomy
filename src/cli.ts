#!/usr/bin/env node
/**
 * hive-cargo CLI — register/list/validate cargo types.
 *
 * Usage:
 *   hive-cargo list               List all registered cargo types
 *   hive-cargo snapshot           Print registry Merkle root
 *   hive-cargo validate <id> <v>  Validate stdin payload against cargo type
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { CargoRegistry } from "./taxonomy.js";

const registry = new CargoRegistry();

// Seed a minimal built-in taxonomy
registry.register({
  id: "pii",
  name: "Personally Identifiable Information",
  version: "1.0.0",
  sensitivity: "confidential",
  registered_at: "2026-05-02T00:00:00Z",
  schema: {
    type: "object",
    properties: {
      subject_id: { type: "string" },
      pii_classes: { type: "array" },
    },
    required: ["subject_id"],
  },
});

registry.register({
  id: "csam-indicator",
  name: "CSAM Indicator",
  version: "1.0.0",
  sensitivity: "critical",
  registered_at: "2026-05-02T00:00:00Z",
  schema: {
    type: "object",
    properties: {
      present: { type: "boolean" },
    },
    required: ["present"],
  },
});

const [, , cmd, ...args] = process.argv;

if (cmd === "list") {
  for (const t of registry.list()) {
    console.log(`${t.id}@${t.version}  [${t.sensitivity}]  ${t.name}`);
  }
} else if (cmd === "snapshot") {
  const snap = registry.snapshot();
  console.log(JSON.stringify(snap, null, 2));
} else if (cmd === "validate") {
  const [id, version] = args;
  if (!id || !version) {
    console.error("Usage: hive-cargo validate <id> <version>");
    process.exit(1);
  }
  let data = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => (data += chunk));
  process.stdin.on("end", () => {
    let payload: unknown;
    try {
      payload = JSON.parse(data);
    } catch {
      console.error("Invalid JSON on stdin");
      process.exit(1);
    }
    const result = registry.validate(id, version, payload);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  });
} else {
  console.log("Commands: list | snapshot | validate <id> <version>");
  process.exit(1);
}
