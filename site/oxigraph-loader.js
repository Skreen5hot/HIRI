/**
 * Oxigraph Browser Loader
 *
 * This module acts as a shim so that `import oxigraph from "oxigraph"`
 * in the bundled demo code resolves to the browser WASM build.
 *
 * The HTML import map points "oxigraph" → this file.
 * This file re-exports the web.js classes and provides init().
 */

// Import the web build's init function and all named exports
import init, * as oxigraphWeb from "./oxigraph-web.js";

let initialized = false;

/**
 * Must be called once before any oxigraph classes are used.
 * Loads the WASM binary.
 */
export async function initOxigraph() {
  if (!initialized) {
    // Pass explicit WASM URL relative to this script's location.
    // oxigraph-web.js default init() uses `new URL('web_bg.wasm', import.meta.url)`
    // which resolves correctly since we copy web_bg.wasm alongside this file.
    await init();
    initialized = true;
  }
}

// Re-export all named exports (Store, Quad, NamedNode, etc.)
export * from "./oxigraph-web.js";

// Default export: namespace object matching what the adapter expects
// (adapter does `import oxigraph from "oxigraph"` then `new oxigraph.Store()`)
export default oxigraphWeb;
