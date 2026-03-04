/**
 * RFC 6902 JSON Patch Application
 *
 * Pure implementation of JSON Patch (add, remove, replace) with
 * RFC 6901 JSON Pointer path resolution.
 *
 * - applyPatch throws on malformed operations or unresolvable paths
 *   (programming errors are loud)
 * - Input is deep-cloned; the original document is never mutated
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

import type { JsonPatchOperation } from "./types.js";

/**
 * Apply a sequence of JSON Patch operations to a document.
 *
 * Deep-clones the input via structuredClone (immutability guarantee).
 * Supports: add, remove, replace.
 * Throws on invalid paths or malformed operations.
 *
 * @param document - The JSON document to patch
 * @param operations - Array of RFC 6902 patch operations
 * @returns A new document with all operations applied
 */
export function applyPatch(
  document: unknown,
  operations: JsonPatchOperation[],
): unknown {
  let doc = structuredClone(document);

  for (const op of operations) {
    switch (op.op) {
      case "add":
        doc = applyAdd(doc, op.path, op.value);
        break;
      case "remove":
        doc = applyRemove(doc, op.path);
        break;
      case "replace":
        doc = applyReplace(doc, op.path, op.value);
        break;
      default:
        throw new Error(`Unsupported JSON Patch operation: ${(op as { op: string }).op}`);
    }
  }

  return doc;
}

/**
 * Parse a JSON Pointer (RFC 6901) into path segments.
 *
 * Handles escape sequences:
 * - ~1 → /
 * - ~0 → ~
 *
 * @param pointer - A JSON Pointer string (e.g., "/schema:address/schema:addressLocality")
 * @returns Array of unescaped path segments
 */
function parsePointer(pointer: string): string[] {
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) {
    throw new Error(`Invalid JSON Pointer: must start with "/", got: "${pointer}"`);
  }

  return pointer
    .substring(1)
    .split("/")
    .map((segment) => segment.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * Resolve a JSON Pointer to the parent object and final key.
 *
 * Navigates to the parent of the target location.
 * Throws if any intermediate path segment doesn't exist.
 */
function resolvePath(
  root: unknown,
  pointer: string,
): { parent: Record<string, unknown>; key: string } {
  const segments = parsePointer(pointer);
  if (segments.length === 0) {
    throw new Error("Cannot resolve empty pointer to parent/key");
  }

  let current: unknown = root;
  for (let i = 0; i < segments.length - 1; i++) {
    if (current === null || typeof current !== "object") {
      throw new Error(
        `Cannot navigate path segment "${segments[i]}": parent is ${typeof current}`,
      );
    }
    const obj = current as Record<string, unknown>;
    if (!(segments[i] in obj)) {
      throw new Error(
        `Path segment "${segments[i]}" not found at depth ${i}`,
      );
    }
    current = obj[segments[i]];
  }

  if (current === null || typeof current !== "object") {
    throw new Error(
      `Cannot resolve final segment "${segments[segments.length - 1]}": parent is ${typeof current}`,
    );
  }

  return {
    parent: current as Record<string, unknown>,
    key: segments[segments.length - 1],
  };
}

function applyAdd(doc: unknown, path: string, value: unknown): unknown {
  if (path === "") {
    // Replace the entire document
    return structuredClone(value);
  }

  const { parent, key } = resolvePath(doc, path);
  parent[key] = structuredClone(value);
  return doc;
}

function applyRemove(doc: unknown, path: string): unknown {
  if (path === "") {
    throw new Error("Cannot remove root document");
  }

  const { parent, key } = resolvePath(doc, path);
  if (!(key in parent)) {
    throw new Error(`Cannot remove: key "${key}" does not exist`);
  }
  delete parent[key];
  return doc;
}

function applyReplace(doc: unknown, path: string, value: unknown): unknown {
  if (path === "") {
    // Replace entire document
    return structuredClone(value);
  }

  const { parent, key } = resolvePath(doc, path);
  if (!(key in parent)) {
    throw new Error(`Cannot replace: key "${key}" does not exist`);
  }
  parent[key] = structuredClone(value);
  return doc;
}
