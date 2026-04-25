/**
 * Tab B: Verifiable Knowledge Builder
 *
 * Create signed JSON-LD content, build version chains with tamper-evident deltas.
 * Users fill a structured form, see real-time JSON-LD preview, then sign and chain.
 *
 * Kernel functions used:
 *   prepareContent, stableStringify, buildUnsignedManifest, signManifest,
 *   hashManifest, validateGenesis, validateChainLink, buildDelta, verifyDelta,
 *   applyPatch, verifyManifest, verifyChain
 */

import { buildUnsignedManifest, prepareContent } from "../kernel/manifest.js";
import { signManifest, verifyManifest } from "../kernel/signing.js";
import { hashManifest, validateChainLink, verifyChain, verifyChainWithKeyLifecycle } from "../kernel/chain.js";
import { validateGenesis } from "../kernel/genesis.js";
import { buildDelta, verifyDelta } from "../kernel/delta.js";
import { applyPatch } from "../kernel/json-patch.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { defaultCryptoProvider } from "../adapters/crypto/provider.js";
import { InMemoryStorageAdapter } from "../adapters/persistence/storage.js";
import { demoState } from "./state.js";
import type {
  ResolutionManifest,
  ManifestParams,
  ManifestChain,
  JsonPatchOperation,
} from "../kernel/types.js";

const crypto = defaultCryptoProvider;

let container: HTMLElement;

type InputMode = "form" | "upload" | "paste";
let inputMode: InputMode = "form";

interface UploadedContent {
  bytes: Uint8Array;
  format: string;
  filename: string;
  canonicalizable: boolean; // true for JSON/JSON-LD, false for markdown/plain
}
let uploadedContent: UploadedContent | null = null;

// Track form/content data for delta computation
let v1FormData: Record<string, string> | null = null;
let v1ContentStr: string | null = null;
let v1ContentHash: string | null = null;
// When non-null, V2 can compute a JSON Patch delta. When null, V2 is opaque.
let v1JsonForDelta: object | null = null;
// The URI path segment used for the previous version (so V2 keeps the same @id).
let v1PathSegment: string = "data/person";

export function initBuildTab(el: HTMLElement): void {
  container = el;
  render();
}

function render(): void {
  container.innerHTML = `
    <div id="build-gate"></div>
    <div class="split" id="build-split" style="display:none">
      <div>
        <div class="panel">
          <div class="panel-header">Content</div>
          <div class="panel-body">
            <div style="display:flex;gap:0.25rem;margin-bottom:0.75rem;border:1px solid var(--border);border-radius:var(--radius);padding:0.15rem;background:var(--bg)">
              <button class="btn btn-mode" data-mode="form" style="flex:1;font-size:0.75rem;padding:0.3rem 0.5rem">Form</button>
              <button class="btn btn-mode" data-mode="upload" style="flex:1;font-size:0.75rem;padding:0.3rem 0.5rem">Upload</button>
              <button class="btn btn-mode" data-mode="paste" style="flex:1;font-size:0.75rem;padding:0.3rem 0.5rem">Paste</button>
            </div>

            <div id="mode-form" class="mode-panel">
              <div class="form-group">
                <label>Name</label>
                <input class="form-input" id="field-name" value="Dana Reeves" placeholder="Full name">
              </div>
              <div class="form-group">
                <label>Job Title</label>
                <input class="form-input" id="field-job" value="Protocol Architect" placeholder="Job title">
              </div>
              <div class="form-group">
                <label>City</label>
                <input class="form-input" id="field-city" value="Portland" placeholder="City">
              </div>
              <div class="form-group">
                <label>Region</label>
                <input class="form-input" id="field-region" value="Oregon" placeholder="Region">
              </div>
            </div>

            <div id="mode-upload" class="mode-panel" style="display:none">
              <div class="form-group">
                <label>Upload File</label>
                <input class="form-input" id="upload-file" type="file" accept=".md,.markdown,.txt,.json,.jsonld,.json-ld">
                <p style="color:var(--text-muted);font-size:0.7rem;margin-top:0.25rem">Accepted: .md, .markdown, .txt, .json, .jsonld</p>
              </div>
              <div id="upload-info" style="font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem"></div>
            </div>

            <div id="mode-paste" class="mode-panel" style="display:none">
              <div class="form-group">
                <label>Content Type</label>
                <select class="form-input" id="paste-type" style="width:auto">
                  <option value="markdown">Markdown (text/markdown)</option>
                  <option value="plain">Plain Text (text/plain)</option>
                  <option value="json">JSON (application/json)</option>
                  <option value="json-ld">JSON-LD (application/ld+json)</option>
                </select>
              </div>
              <div class="form-group">
                <label>Pasted Content</label>
                <textarea class="form-input" id="paste-content" rows="8" placeholder="Paste content here..." style="font-family:var(--font-mono,monospace);font-size:0.8rem"></textarea>
              </div>
            </div>

            <div class="form-group" id="uri-path-group" style="display:none;margin-top:0.5rem">
              <label>URI Path Segment</label>
              <div style="display:flex;align-items:center;gap:0.25rem">
                <span style="color:var(--text-muted);font-size:0.75rem">hiri://&lt;authority&gt;/</span>
                <input class="form-input" id="uri-path" value="doc/upload" placeholder="doc/upload" style="flex:1">
              </div>
            </div>
          </div>
        </div>
        <div class="action-bar">
          <button class="btn btn-primary" id="btn-sign">Draft & Sign (V1)</button>
          <button class="btn" id="btn-update" disabled>Update & Chain (V2)</button>
          <button class="btn" id="btn-verify-chain" disabled>Verify Chain</button>
          <button class="btn" id="btn-export" disabled>Export Package</button>
        </div>
      </div>
      <div>
        <div class="panel">
          <div class="panel-header"><span id="preview-header">JSON-LD Preview</span> <span style="font-size:0.7rem;font-weight:400;color:var(--yellow);margin-left:0.5rem;padding:0.1rem 0.4rem;border:1px solid rgba(210,153,34,0.3);border-radius:3px">Draft (unsigned)</span></div>
          <div class="panel-body">
            <pre id="jsonld-preview"></pre>
          </div>
        </div>
        <div id="manifest-panel"></div>
        <div id="chain-panel"></div>
      </div>
    </div>
    <div class="transparency">
      <button class="transparency-toggle" id="hood-toggle-build">Under the Hood</button>
      <div class="transparency-content" id="hood-content-build"></div>
    </div>
  `;

  container.querySelector("#hood-toggle-build")!.addEventListener("click", () => {
    document.getElementById("hood-content-build")!.classList.toggle("open");
  });

  checkGate();
}

function checkGate(): void {
  const gate = document.getElementById("build-gate")!;
  if (!demoState.initialized || !demoState.activeKeypair) {
    gate.innerHTML = `<div class="info-box info">Generate a key in Tab A first, then create and sign content here.</div>`;
    return;
  }

  gate.innerHTML = "";
  document.getElementById("build-split")!.style.display = "grid";

  // Form-mode field listeners
  const fields = ["field-name", "field-job", "field-city", "field-region"];
  fields.forEach(id => {
    document.getElementById(id)!.addEventListener("input", updatePreview);
  });

  // Mode-toggle buttons
  container.querySelectorAll(".btn-mode").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const mode = (e.currentTarget as HTMLElement).getAttribute("data-mode") as InputMode;
      setInputMode(mode);
    });
  });

  // Upload file input
  document.getElementById("upload-file")!.addEventListener("change", handleFileUpload);

  // Paste mode listeners
  document.getElementById("paste-content")!.addEventListener("input", updatePreview);
  document.getElementById("paste-type")!.addEventListener("change", updatePreview);

  // URI path input
  document.getElementById("uri-path")!.addEventListener("input", updatePreview);

  document.getElementById("btn-sign")!.addEventListener("click", handleSign);
  document.getElementById("btn-update")!.addEventListener("click", handleUpdate);
  document.getElementById("btn-verify-chain")!.addEventListener("click", handleVerifyChain);
  document.getElementById("btn-export")!.addEventListener("click", handleExport);

  setInputMode(inputMode);

  // Restore UI state if manifests already exist (prevents duplicate V1 on tab switch)
  if (demoState.manifests.length > 0) {
    const btnSign = document.getElementById("btn-sign") as HTMLButtonElement;
    btnSign.disabled = true;
    btnSign.textContent = "V1 Signed";

    (document.getElementById("btn-update") as HTMLButtonElement).disabled = false;

    (document.getElementById("btn-export") as HTMLButtonElement).disabled = false;

    if (demoState.manifests.length >= 2) {
      (document.getElementById("btn-verify-chain") as HTMLButtonElement).disabled = false;
    }

    // Restore form fields to latest content
    if (v1FormData) {
      (document.getElementById("field-name") as HTMLInputElement).value = v1FormData.name;
      (document.getElementById("field-job") as HTMLInputElement).value = v1FormData.jobTitle;
      (document.getElementById("field-city") as HTMLInputElement).value = v1FormData.city;
      (document.getElementById("field-region") as HTMLInputElement).value = v1FormData.region;
    }
    // Restore URI path segment for non-form modes
    if (inputMode !== "form" && v1PathSegment) {
      const pathInput = document.getElementById("uri-path") as HTMLInputElement;
      if (pathInput) pathInput.value = v1PathSegment;
    }

    // Re-render manifest and chain panels
    const latest = demoState.manifests[demoState.manifests.length - 1];
    renderManifest(latest.manifest, latest.manifestHash);
    if (demoState.manifests.length >= 2) {
      renderChainVisualization();
    }
  }

  updatePreview();
}

function getFormData(): Record<string, string> {
  return {
    name: (document.getElementById("field-name") as HTMLInputElement).value,
    jobTitle: (document.getElementById("field-job") as HTMLInputElement).value,
    city: (document.getElementById("field-city") as HTMLInputElement).value,
    region: (document.getElementById("field-region") as HTMLInputElement).value,
  };
}

function buildJsonLd(data: Record<string, string>): object {
  return {
    "@context": {
      "schema": "http://schema.org/",
    },
    "@id": demoState.authority ? `hiri://${demoState.authority}/data/person` : "hiri://AUTHORITY/data/person",
    "@type": "schema:Person",
    "schema:name": data.name,
    "schema:jobTitle": data.jobTitle,
    "schema:address": {
      "@type": "schema:PostalAddress",
      "schema:addressLocality": data.city,
      "schema:addressRegion": data.region,
    },
  };
}

function setInputMode(mode: InputMode): void {
  inputMode = mode;
  // Toggle visual selection on mode buttons
  container.querySelectorAll(".btn-mode").forEach(btn => {
    const btnMode = btn.getAttribute("data-mode");
    if (btnMode === mode) {
      btn.classList.add("btn-primary");
    } else {
      btn.classList.remove("btn-primary");
    }
  });
  // Show only the active panel
  document.getElementById("mode-form")!.style.display = mode === "form" ? "" : "none";
  document.getElementById("mode-upload")!.style.display = mode === "upload" ? "" : "none";
  document.getElementById("mode-paste")!.style.display = mode === "paste" ? "" : "none";
  // URI path input shows only for upload/paste
  document.getElementById("uri-path-group")!.style.display = mode === "form" ? "none" : "";
  updatePreview();
}

interface FormatInfo {
  mime: string;
  canonicalizable: boolean; // true → JCS, false → "none"
}

function detectFormatFromExtension(filename: string): FormatInfo | null {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".md") || lower.endsWith(".markdown")) {
    return { mime: "text/markdown", canonicalizable: false };
  }
  if (lower.endsWith(".txt")) {
    return { mime: "text/plain", canonicalizable: false };
  }
  if (lower.endsWith(".jsonld") || lower.endsWith(".json-ld")) {
    return { mime: "application/ld+json", canonicalizable: true };
  }
  if (lower.endsWith(".json")) {
    return { mime: "application/json", canonicalizable: true };
  }
  return null;
}

function detectFormatFromSelect(value: string): FormatInfo {
  switch (value) {
    case "markdown": return { mime: "text/markdown", canonicalizable: false };
    case "plain": return { mime: "text/plain", canonicalizable: false };
    case "json": return { mime: "application/json", canonicalizable: true };
    case "json-ld": return { mime: "application/ld+json", canonicalizable: true };
    default: return { mime: "text/plain", canonicalizable: false };
  }
}

/** Sanitize a URI path segment: strip leading slashes, lowercase, replace illegal chars. */
function sanitizePathSegment(raw: string): string {
  const trimmed = raw.trim().replace(/^\/+/, "").replace(/\/+$/, "");
  if (!trimmed) return "doc/upload";
  return trimmed
    .toLowerCase()
    .replace(/[^a-z0-9/_-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/\/{2,}/g, "/");
}

function getCurrentPathSegment(): string {
  if (inputMode === "form") return "data/person";
  const raw = (document.getElementById("uri-path") as HTMLInputElement).value;
  return sanitizePathSegment(raw);
}

async function handleFileUpload(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  const info = document.getElementById("upload-info")!;
  if (!file) {
    uploadedContent = null;
    info.textContent = "";
    updatePreview();
    return;
  }

  const fmt = detectFormatFromExtension(file.name);
  if (!fmt) {
    uploadedContent = null;
    info.innerHTML = `<span style="color:var(--red)">Unsupported file type. Use .md, .markdown, .txt, .json, or .jsonld</span>`;
    updatePreview();
    return;
  }

  try {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    uploadedContent = {
      bytes,
      format: fmt.mime,
      filename: file.name,
      canonicalizable: fmt.canonicalizable,
    };
    const sizeKb = (bytes.length / 1024).toFixed(2);
    info.innerHTML = `<strong>${escapeHtml(file.name)}</strong> — ${fmt.mime}, ${sizeKb} KB`;

    // Auto-fill URI path from filename stem
    const stem = file.name.replace(/\.[^.]+$/, "");
    const pathInput = document.getElementById("uri-path") as HTMLInputElement;
    if (!pathInput.value || pathInput.value === "doc/upload") {
      pathInput.value = `doc/${stem}`;
    }

    updatePreview();
  } catch (err) {
    info.innerHTML = `<span style="color:var(--red)">Read failed: ${escapeHtml((err as Error).message)}</span>`;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]!));
}

interface ContentForSigning {
  contentBytes: Uint8Array;
  contentFormat: string;
  canonicalization: "JCS" | "none";
  uri: string;
  jsonForDelta: object | null;
  pathSegment: string;
}

function getContentForSigning(): ContentForSigning {
  const authority = demoState.authority || "AUTHORITY";

  if (inputMode === "form") {
    const data = getFormData();
    const jsonLd = buildJsonLd(data);
    const canonical = stableStringify(jsonLd);
    return {
      contentBytes: new TextEncoder().encode(canonical),
      contentFormat: "application/ld+json",
      canonicalization: "JCS",
      uri: `hiri://${authority}/data/person`,
      jsonForDelta: jsonLd,
      pathSegment: "data/person",
    };
  }

  if (inputMode === "upload") {
    if (!uploadedContent) {
      throw new Error("No file uploaded. Choose a file first.");
    }
    const pathSegment = getCurrentPathSegment();
    const uri = `hiri://${authority}/${pathSegment}`;

    if (uploadedContent.canonicalizable) {
      // JSON / JSON-LD: parse + JCS-canonicalize
      const text = new TextDecoder().decode(uploadedContent.bytes);
      const parsed = JSON.parse(text);
      const canonical = stableStringify(parsed);
      return {
        contentBytes: new TextEncoder().encode(canonical),
        contentFormat: uploadedContent.format,
        canonicalization: "JCS",
        uri,
        jsonForDelta: parsed,
        pathSegment,
      };
    }

    // Markdown / plaintext: opaque bytes, no canonicalization
    return {
      contentBytes: uploadedContent.bytes,
      contentFormat: uploadedContent.format,
      canonicalization: "none",
      uri,
      jsonForDelta: null,
      pathSegment,
    };
  }

  // paste mode
  const text = (document.getElementById("paste-content") as HTMLTextAreaElement).value;
  const typeValue = (document.getElementById("paste-type") as HTMLSelectElement).value;
  const fmt = detectFormatFromSelect(typeValue);
  const pathSegment = getCurrentPathSegment();
  const uri = `hiri://${authority}/${pathSegment}`;

  if (fmt.canonicalizable) {
    const parsed = JSON.parse(text);
    const canonical = stableStringify(parsed);
    return {
      contentBytes: new TextEncoder().encode(canonical),
      contentFormat: fmt.mime,
      canonicalization: "JCS",
      uri,
      jsonForDelta: parsed,
      pathSegment,
    };
  }

  return {
    contentBytes: new TextEncoder().encode(text),
    contentFormat: fmt.mime,
    canonicalization: "none",
    uri,
    jsonForDelta: null,
    pathSegment,
  };
}

function updatePreview(): void {
  const headerEl = document.getElementById("preview-header");
  const previewEl = document.getElementById("jsonld-preview");
  if (!headerEl || !previewEl) return;

  try {
    if (inputMode === "form") {
      const data = getFormData();
      const jsonLd = buildJsonLd(data);
      headerEl.textContent = "JSON-LD Preview";
      previewEl.textContent = stableStringify(jsonLd, true);
      return;
    }

    if (inputMode === "upload") {
      if (!uploadedContent) {
        headerEl.textContent = "Content Preview";
        previewEl.textContent = "(no file selected)";
        return;
      }
      if (uploadedContent.canonicalizable) {
        const text = new TextDecoder().decode(uploadedContent.bytes);
        const parsed = JSON.parse(text);
        headerEl.textContent = uploadedContent.format === "application/ld+json"
          ? "JSON-LD Preview"
          : "JSON Preview";
        previewEl.textContent = stableStringify(parsed, true);
        return;
      }
      // Opaque
      const text = new TextDecoder().decode(uploadedContent.bytes);
      const head = text.length > 500 ? text.slice(0, 500) + "\n\n... (truncated)" : text;
      headerEl.textContent = "Content Preview";
      previewEl.textContent =
        `[${uploadedContent.format}] ${uploadedContent.filename}\n` +
        `${uploadedContent.bytes.length} bytes\n` +
        `\n` +
        head;
      return;
    }

    // Paste mode
    const text = (document.getElementById("paste-content") as HTMLTextAreaElement).value;
    const typeValue = (document.getElementById("paste-type") as HTMLSelectElement).value;
    const fmt = detectFormatFromSelect(typeValue);

    if (fmt.canonicalizable) {
      headerEl.textContent = fmt.mime === "application/ld+json" ? "JSON-LD Preview" : "JSON Preview";
      if (!text.trim()) {
        previewEl.textContent = "(paste JSON content)";
        return;
      }
      try {
        const parsed = JSON.parse(text);
        previewEl.textContent = stableStringify(parsed, true);
      } catch (e) {
        previewEl.textContent = `// Invalid JSON: ${(e as Error).message}\n\n${text}`;
      }
      return;
    }

    // Opaque paste
    headerEl.textContent = "Content Preview";
    if (!text) {
      previewEl.textContent = "(paste content)";
      return;
    }
    const head = text.length > 500 ? text.slice(0, 500) + "\n\n... (truncated)" : text;
    previewEl.textContent = `[${fmt.mime}] ${text.length} bytes\n\n${head}`;
  } catch (e) {
    previewEl.textContent = `// Preview error: ${(e as Error).message}`;
  }
}

async function handleSign(): Promise<void> {
  if (!demoState.activeKeypair) return;
  const btn = document.getElementById("btn-sign") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Signing...";

  const steps: string[] = [];

  try {
    const keypair = demoState.activeKeypair;

    // Step 1: Resolve content for signing
    const c = getContentForSigning();
    const canonLabel = c.canonicalization === "none" ? "opaque (no canonicalization)" : "JCS";
    steps.push(`1. Content (${canonLabel}, ${c.contentFormat}): ${c.contentBytes.length} bytes`);

    // Step 2: Hash content
    const contentHash = await crypto.hash(c.contentBytes);
    steps.push(`2. Hash (SHA-256): ${contentHash}`);

    // Step 3: Build unsigned manifest
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const manifestParams: ManifestParams = {
      id: c.uri,
      version: "1",
      branch: "main",
      created: timestamp,
      contentHash,
      contentFormat: c.contentFormat,
      contentSize: c.contentBytes.length,
      addressing: "raw-sha256",
      canonicalization: c.canonicalization,
    };
    const unsigned = buildUnsignedManifest(manifestParams);
    steps.push(`3. Build unsigned manifest: version=${unsigned["hiri:version"]}, id=${c.uri}`);

    // Step 4: Sign manifest (always JCS for the manifest itself)
    const signed = await signManifest(unsigned, keypair, timestamp, "JCS", crypto);
    steps.push(`4. Sign manifest: proofValue=${signed["hiri:signature"].proofValue.substring(0, 20)}...`);

    // Step 5: Hash the signed manifest
    const manifestHash = await hashManifest(signed, crypto);
    steps.push(`5. Manifest hash: ${manifestHash}`);

    // Step 6: Validate genesis
    const genesisResult = validateGenesis(signed);
    steps.push(`6. Validate genesis: ${genesisResult.valid ? "VALID" : "INVALID: " + genesisResult.reason}`);

    // Store delta-tracking state
    if (inputMode === "form") {
      v1FormData = { ...getFormData() };
    } else {
      v1FormData = null;
    }
    // Track canonicalized JSON string only when JSON path was used (for V2 delta)
    v1ContentStr = c.canonicalization === "JCS" ? new TextDecoder().decode(c.contentBytes) : null;
    v1ContentHash = contentHash;
    v1JsonForDelta = c.jsonForDelta;
    v1PathSegment = c.pathSegment;

    demoState.manifests.push({
      manifest: signed,
      manifestHash,
      contentBytes: c.contentBytes,
      contentHash,
      version: "1",
    });

    // Store in storage adapter for resolution
    await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
    await demoState.storage.put(contentHash, c.contentBytes);

    // Render manifest
    renderManifest(signed, manifestHash);

    btn.textContent = "V1 Signed";
    (document.getElementById("btn-update") as HTMLButtonElement).disabled = false;
    (document.getElementById("btn-export") as HTMLButtonElement).disabled = false;

    // Update transparency
    document.getElementById("hood-content-build")!.innerHTML =
      `<pre>${steps.join("\n")}</pre>`;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Draft & Sign (V1)";
    document.getElementById("hood-content-build")!.innerHTML =
      `<div class="info-box error">Sign failed: ${escapeHtml((e as Error).message)}</div>`;
    document.getElementById("hood-content-build")!.classList.add("open");
    console.error("Sign failed:", e);
  }
}

async function handleUpdate(): Promise<void> {
  if (!demoState.activeKeypair || demoState.manifests.length === 0) return;

  const btn = document.getElementById("btn-update") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Chaining...";

  const steps: string[] = [];

  try {
    const keypair = demoState.activeKeypair;

    // Resolve current content for V2
    const c = getContentForSigning();
    const v2ContentHash = await crypto.hash(c.contentBytes);
    const canonLabel = c.canonicalization === "none" ? "opaque (no canonicalization)" : "JCS";
    steps.push(`1. V2 content (${canonLabel}, ${c.contentFormat}): ${c.contentBytes.length} bytes`);

    // Previous manifest
    const prevEntry = demoState.manifests[demoState.manifests.length - 1];
    const prevManifestHash = prevEntry.manifestHash;
    const genesisHash = demoState.manifests[0].manifestHash;
    const depth = demoState.manifests.length + 1;

    // Decide whether we can compute a JSON Patch delta:
    //  - previous version must have a tracked JSON object (v1JsonForDelta)
    //  - current content must also be canonicalized as JSON (jsonForDelta)
    const canDelta = v1JsonForDelta !== null && c.jsonForDelta !== null && c.canonicalization === "JCS";

    let deltaForManifest: { hash: string; format: string; appliesTo: string; operations: number } | undefined;
    let deltaBytesForStorage: Uint8Array | null = null;
    let deltaHashForStorage: string | null = null;

    if (canDelta) {
      const operations = computePatch(
        v1JsonForDelta as Record<string, unknown>,
        c.jsonForDelta as Record<string, unknown>,
      );
      const deltaCanonical = stableStringify(operations);
      const deltaBytes = new TextEncoder().encode(deltaCanonical);
      const deltaHash = await crypto.hash(deltaBytes);
      steps.push(`2. Computed ${operations.length} JSON Patch operations`);
      steps.push(`3. Delta hash: ${deltaHash}`);

      // Verify delta applies correctly
      const applied = applyPatch(v1JsonForDelta as Record<string, unknown>, operations);
      const appliedCanonical = stableStringify(applied);
      const appliedBytes = new TextEncoder().encode(appliedCanonical);
      const appliedHash = await crypto.hash(appliedBytes);
      const deltaValid = appliedHash === v2ContentHash;
      steps.push(`4. Delta verification: ${deltaValid ? "PASS" : "FAIL"} (applied hash matches content hash)`);

      deltaForManifest = {
        hash: deltaHash,
        format: "application/json-patch+json",
        appliesTo: prevEntry.contentHash,
        operations: operations.length,
      };
      deltaBytesForStorage = deltaBytes;
      deltaHashForStorage = deltaHash;
    } else {
      steps.push(`2. Opaque content — JSON Patch delta omitted (chain still records previous + genesis + depth)`);
    }

    // Build chain metadata
    const chain: ManifestChain = {
      previous: prevManifestHash,
      previousBranch: "main",
      genesisHash,
      depth,
    };
    steps.push(`${canDelta ? "5" : "3"}. Chain: depth=${depth}, previous=${prevManifestHash.substring(0, 24)}...`);

    // Build manifest
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const unsigned = buildUnsignedManifest({
      id: c.uri,
      version: String(demoState.manifests.length + 1),
      branch: "main",
      created: timestamp,
      contentHash: v2ContentHash,
      contentFormat: c.contentFormat,
      contentSize: c.contentBytes.length,
      addressing: "raw-sha256",
      canonicalization: c.canonicalization,
      chain,
      ...(deltaForManifest ? { delta: deltaForManifest } : {}),
    });

    const signed = await signManifest(unsigned, keypair, timestamp, "JCS", crypto);
    const manifestHash = await hashManifest(signed, crypto);
    steps.push(`${canDelta ? "6" : "4"}. Signed V${unsigned["hiri:version"]}: ${manifestHash.substring(0, 24)}...`);

    // Validate chain link
    const linkResult = await validateChainLink(signed, prevEntry.manifest, crypto);
    steps.push(`${canDelta ? "7" : "5"}. Chain link validation: ${linkResult.valid ? "VALID" : "INVALID: " + linkResult.reason}`);

    // Store
    demoState.manifests.push({
      manifest: signed,
      manifestHash,
      contentBytes: c.contentBytes,
      contentHash: v2ContentHash,
      version: unsigned["hiri:version"],
    });

    await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
    await demoState.storage.put(v2ContentHash, c.contentBytes);
    if (deltaBytesForStorage && deltaHashForStorage) {
      await demoState.storage.put(deltaHashForStorage, deltaBytesForStorage);
    }

    // Update for next chain iteration
    v1FormData = inputMode === "form" ? { ...getFormData() } : null;
    v1ContentStr = c.canonicalization === "JCS" ? new TextDecoder().decode(c.contentBytes) : null;
    v1ContentHash = v2ContentHash;
    v1JsonForDelta = c.jsonForDelta;
    v1PathSegment = c.pathSegment;

    // Render
    renderManifest(signed, manifestHash);
    renderChainVisualization();

    btn.disabled = false;
    btn.textContent = "Update & Chain (next)";
    (document.getElementById("btn-verify-chain") as HTMLButtonElement).disabled = false;

    document.getElementById("hood-content-build")!.innerHTML =
      `<pre>${steps.join("\n")}</pre>`;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Update & Chain";
    document.getElementById("hood-content-build")!.innerHTML =
      `<div class="info-box error">Chain failed: ${escapeHtml((e as Error).message)}</div>`;
    document.getElementById("hood-content-build")!.classList.add("open");
    console.error("Chain failed:", e);
  }
}

async function handleVerifyChain(): Promise<void> {
  if (demoState.manifests.length < 2) return;

  const btn = document.getElementById("btn-verify-chain") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Verifying...";

  try {
    const head = demoState.manifests[demoState.manifests.length - 1];
    const manifestMap = new Map<string, ResolutionManifest>();
    for (const entry of demoState.manifests) {
      manifestMap.set(entry.manifestHash, entry.manifest);
    }

    const fetchManifest = async (hash: string) => manifestMap.get(hash) ?? null;
    const fetchContent = async () => null;

    let result;
    if (demoState.keyDocument) {
      // Use key-lifecycle-aware verification when Key Document exists
      const verificationTime = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
      result = await verifyChainWithKeyLifecycle(
        head.manifest,
        demoState.keyDocument,
        verificationTime,
        fetchManifest,
        fetchContent,
        crypto,
      );
    } else {
      // Use active keypair (the key that signed the manifests)
      const keypair = demoState.activeKeypair!;
      result = await verifyChain(
        head.manifest,
        keypair.publicKey,
        fetchManifest,
        fetchContent,
        crypto,
      );
    }

    const chainPanel = document.getElementById("chain-panel")!;
    chainPanel.innerHTML += `
      <div class="info-box ${result.valid ? "success" : "error"}" style="margin-top:0.5rem">
        Chain Verification: <strong>${result.valid ? "VALID" : "INVALID"}</strong>
        — depth: ${result.depth}
        ${result.warnings.length > 0 ? `<br>Warnings: ${result.warnings.join(", ")}` : ""}
        ${result.reason ? `<br>Reason: ${result.reason}` : ""}
      </div>
    `;

    btn.textContent = result.valid ? "Chain Valid" : "Chain Invalid";
    btn.disabled = false;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Verify Chain";
    console.error("Chain verification failed:", e);
  }
}

function renderManifest(manifest: ResolutionManifest, hash: string): void {
  const panel = document.getElementById("manifest-panel")!;
  panel.innerHTML = `
    <div class="panel" style="margin-top:1rem">
      <div class="panel-header">Signed Manifest (V${manifest["hiri:version"]}) <span style="font-size:0.7rem;font-weight:400;color:var(--green);margin-left:0.5rem;padding:0.1rem 0.4rem;border:1px solid rgba(63,185,80,0.3);border-radius:3px">Committed</span></div>
      <div class="panel-body">
        <div style="margin-bottom:0.5rem">
          <span style="color:var(--text-muted);font-size:0.75rem">Manifest Hash:</span>
          <code style="font-size:0.75rem">${hash}</code>
        </div>
        <pre>${stableStringify(manifest, true)}</pre>
      </div>
    </div>
  `;
}

function renderChainVisualization(): void {
  const panel = document.getElementById("chain-panel")!;
  const entries = demoState.manifests;

  const chainHtml = entries.map((entry, i) => {
    const isHead = i === entries.length - 1;
    return `
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
        <span style="color:${isHead ? "var(--accent)" : "var(--text-muted)"};font-size:0.8rem;font-weight:${isHead ? 600 : 400}">
          V${entry.version}
        </span>
        <code style="font-size:0.7rem;color:var(--text-muted)">${entry.manifestHash.substring(0, 20)}...</code>
        ${i < entries.length - 1 ? '<span style="color:var(--border)">←</span>' : ""}
      </div>
    `;
  }).reverse().join("");

  panel.innerHTML = `
    <div class="panel" style="margin-top:1rem">
      <div class="panel-header">Chain (${entries.length} manifests)</div>
      <div class="panel-body">${chainHtml}</div>
    </div>
  `;
}

/** Encode bytes as base64url without padding (RFC 4648 §5). */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface HiriExportPackage {
  version: 1;
  authority: string;
  uri: string;
  publicKey: string;
  entries: Array<{ hash: string; data: string }>;
  privacyMode?: string;
  keyDocumentHash?: string;
}

async function exportPackage(): Promise<string> {
  const entries: Array<{ hash: string; data: string }> = [];

  for (const manifestEntry of demoState.manifests) {
    // Add manifest bytes
    const manifestBytes = new TextEncoder().encode(
      stableStringify(manifestEntry.manifest)
    );
    entries.push({
      hash: manifestEntry.manifestHash,
      data: base64urlEncode(manifestBytes),
    });

    // Add content bytes
    entries.push({
      hash: manifestEntry.contentHash,
      data: base64urlEncode(manifestEntry.contentBytes),
    });
  }

  // Include delta blobs from storage (they may exist for chained manifests)
  for (const manifestEntry of demoState.manifests) {
    const delta = (manifestEntry.manifest as Record<string, unknown>)["hiri:delta"] as
      { hash?: string } | undefined;
    if (delta?.hash) {
      const deltaBytes = await demoState.storage.get(delta.hash);
      if (deltaBytes && deltaBytes.length > 0) {
        entries.push({
          hash: delta.hash,
          data: base64urlEncode(deltaBytes),
        });
      }
    }
  }

  const latestManifest = demoState.latestManifest!;
  const pkg: HiriExportPackage = {
    version: 1,
    authority: demoState.authority,
    uri: latestManifest.manifest["@id"],
    publicKey: base64urlEncode(demoState.primaryKeypair!.publicKey),
    entries,
  };

  // Detect privacy mode if present
  const privacy = (latestManifest.manifest as Record<string, unknown>)["hiri:privacy"];
  if (privacy && typeof privacy === "object" && "mode" in (privacy as Record<string, unknown>)) {
    pkg.privacyMode = (privacy as Record<string, unknown>).mode as string;
  }

  // Include Key Document if present (key rotation scenario)
  if (demoState.keyDocument) {
    const kdBytes = new TextEncoder().encode(stableStringify(demoState.keyDocument));
    const kdHash = await crypto.hash(kdBytes);
    entries.push({ hash: kdHash, data: base64urlEncode(kdBytes) });
    pkg.keyDocumentHash = kdHash;
  }

  return JSON.stringify(pkg);
}

async function handleExport(): Promise<void> {
  if (demoState.manifests.length === 0) return;

  const btn = document.getElementById("btn-export") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Exporting...";

  try {
    const json = await exportPackage();
    const manifestCount = demoState.manifests.length;
    const sizeKb = (json.length / 1024).toFixed(1);

    try {
      await navigator.clipboard.writeText(json);
      document.getElementById("hood-content-build")!.innerHTML =
        `<div class="info-box success">Package copied to clipboard (${sizeKb} KB, ${manifestCount} manifest${manifestCount > 1 ? "s" : ""})</div>`;
    } catch {
      // Fallback: show JSON in a textarea for manual copy
      document.getElementById("hood-content-build")!.innerHTML = `
        <div class="info-box warning" style="margin-bottom:0.5rem">Clipboard not available. Copy the package below manually.</div>
        <textarea class="form-input" rows="6" readonly style="font-size:0.7rem;font-family:var(--font-mono)">${json}</textarea>
      `;
      document.getElementById("hood-content-build")!.classList.add("open");
    }

    btn.textContent = "Exported";
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = "Export Package";
    }, 2000);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Export Package";
    document.getElementById("hood-content-build")!.innerHTML =
      `<div class="info-box error">Export failed: ${(e as Error).message}</div>`;
    document.getElementById("hood-content-build")!.classList.add("open");
  }
}

/**
 * Compute a simple JSON Patch (RFC 6902) between two objects.
 * Only handles flat and shallow nested differences — sufficient for the demo.
 */
function computePatch(a: Record<string, unknown>, b: Record<string, unknown>, prefix = ""): JsonPatchOperation[] {
  const ops: JsonPatchOperation[] = [];

  for (const key of Object.keys(b)) {
    const path = `${prefix}/${key}`;
    if (!(key in a)) {
      ops.push({ op: "add", path, value: b[key] });
    } else if (typeof a[key] === "object" && typeof b[key] === "object" &&
               a[key] !== null && b[key] !== null &&
               !Array.isArray(a[key]) && !Array.isArray(b[key])) {
      ops.push(...computePatch(
        a[key] as Record<string, unknown>,
        b[key] as Record<string, unknown>,
        path,
      ));
    } else if (stableStringify(a[key]) !== stableStringify(b[key])) {
      ops.push({ op: "replace", path, value: b[key] });
    }
  }

  for (const key of Object.keys(a)) {
    if (!(key in b)) {
      ops.push({ op: "remove", path: `${prefix}/${key}` });
    }
  }

  return ops;
}
