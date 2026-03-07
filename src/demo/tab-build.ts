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

// Track form data for delta computation
let v1FormData: Record<string, string> | null = null;
let v1ContentStr: string | null = null;
let v1ContentHash: string | null = null;

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
          <div class="panel-header">Content Form</div>
          <div class="panel-body">
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
        </div>
        <div class="action-bar">
          <button class="btn btn-primary" id="btn-sign">Draft & Sign (V1)</button>
          <button class="btn" id="btn-update" disabled>Update & Chain (V2)</button>
          <button class="btn" id="btn-verify-chain" disabled>Verify Chain</button>
        </div>
      </div>
      <div>
        <div class="panel">
          <div class="panel-header">JSON-LD Preview <span style="font-size:0.7rem;font-weight:400;color:var(--yellow);margin-left:0.5rem;padding:0.1rem 0.4rem;border:1px solid rgba(210,153,34,0.3);border-radius:3px">Draft (unsigned)</span></div>
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

  // Wire up events
  const fields = ["field-name", "field-job", "field-city", "field-region"];
  fields.forEach(id => {
    document.getElementById(id)!.addEventListener("input", updatePreview);
  });

  document.getElementById("btn-sign")!.addEventListener("click", handleSign);
  document.getElementById("btn-update")!.addEventListener("click", handleUpdate);
  document.getElementById("btn-verify-chain")!.addEventListener("click", handleVerifyChain);

  // Restore UI state if manifests already exist (prevents duplicate V1 on tab switch)
  if (demoState.manifests.length > 0) {
    const btnSign = document.getElementById("btn-sign") as HTMLButtonElement;
    btnSign.disabled = true;
    btnSign.textContent = "V1 Signed";

    (document.getElementById("btn-update") as HTMLButtonElement).disabled = false;

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

function updatePreview(): void {
  const data = getFormData();
  const jsonLd = buildJsonLd(data);
  document.getElementById("jsonld-preview")!.textContent = stableStringify(jsonLd, true);
}

async function handleSign(): Promise<void> {
  if (!demoState.activeKeypair) return;
  const btn = document.getElementById("btn-sign") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Signing...";

  const steps: string[] = [];

  try {
    const keypair = demoState.activeKeypair;
    const data = getFormData();
    const jsonLd = buildJsonLd(data);

    // Step 1: Canonicalize
    const canonical = stableStringify(jsonLd);
    steps.push(`1. Canonicalize (JCS): ${canonical.length} bytes`);

    // Step 2: Encode to bytes and hash
    const contentBytes = new TextEncoder().encode(canonical);
    const contentHash = await crypto.hash(contentBytes);
    steps.push(`2. Hash (SHA-256): ${contentHash}`);

    // Step 3: Build unsigned manifest
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const manifestParams: ManifestParams = {
      id: `hiri://${demoState.authority}/data/person`,
      version: "1",
      branch: "main",
      created: timestamp,
      contentHash,
      contentFormat: "application/ld+json",
      contentSize: contentBytes.length,
      addressing: "raw-sha256",
      canonicalization: "JCS",
    };
    const unsigned = buildUnsignedManifest(manifestParams);
    steps.push(`3. Build unsigned manifest: version=${unsigned["hiri:version"]}`);

    // Step 4: Sign manifest
    const signed = await signManifest(unsigned, keypair, timestamp, "JCS", crypto);
    steps.push(`4. Sign manifest: proofValue=${signed["hiri:signature"].proofValue.substring(0, 20)}...`);

    // Step 5: Hash the signed manifest
    const manifestHash = await hashManifest(signed, crypto);
    steps.push(`5. Manifest hash: ${manifestHash}`);

    // Step 6: Validate genesis
    const genesisResult = validateGenesis(signed);
    steps.push(`6. Validate genesis: ${genesisResult.valid ? "VALID" : "INVALID: " + genesisResult.reason}`);

    // Store
    v1FormData = { ...data };
    v1ContentStr = canonical;
    v1ContentHash = contentHash;

    demoState.manifests.push({
      manifest: signed,
      manifestHash,
      contentBytes,
      contentHash,
      version: "1",
    });

    // Store in storage adapter for resolution
    await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
    await demoState.storage.put(contentHash, contentBytes);

    // Render manifest
    renderManifest(signed, manifestHash);

    btn.textContent = "V1 Signed";
    (document.getElementById("btn-update") as HTMLButtonElement).disabled = false;

    // Update transparency
    document.getElementById("hood-content-build")!.innerHTML =
      `<pre>${steps.join("\n")}</pre>`;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Draft & Sign (V1)";
    console.error("Sign failed:", e);
  }
}

async function handleUpdate(): Promise<void> {
  if (!demoState.activeKeypair || !v1ContentStr || !v1ContentHash) return;

  const btn = document.getElementById("btn-update") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Chaining...";

  const steps: string[] = [];

  try {
    const keypair = demoState.activeKeypair;
    const data = getFormData();
    const jsonLd = buildJsonLd(data);

    // Current content
    const v2Canonical = stableStringify(jsonLd);
    const v2ContentBytes = new TextEncoder().encode(v2Canonical);
    const v2ContentHash = await crypto.hash(v2ContentBytes);

    // Compute JSON Patch delta (v1ContentStr tracks the PREVIOUS version's content)
    const prevObj = JSON.parse(v1ContentStr!);
    const v2Obj = JSON.parse(v2Canonical);
    const operations = computePatch(prevObj, v2Obj);
    steps.push(`1. Computed ${operations.length} delta operations`);

    // Build delta metadata
    const deltaCanonical = stableStringify(operations);
    const deltaBytes = new TextEncoder().encode(deltaCanonical);
    const deltaHash = await crypto.hash(deltaBytes);
    steps.push(`2. Delta hash: ${deltaHash}`);

    // Verify delta applies correctly
    const applied = applyPatch(prevObj, operations);
    const appliedCanonical = stableStringify(applied);
    const appliedBytes = new TextEncoder().encode(appliedCanonical);
    const appliedHash = await crypto.hash(appliedBytes);
    const deltaValid = appliedHash === v2ContentHash;
    steps.push(`3. Delta verification: ${deltaValid ? "PASS" : "FAIL"} (applied hash matches content hash)`);

    // Previous manifest
    const prevEntry = demoState.manifests[demoState.manifests.length - 1];
    const prevManifestHash = prevEntry.manifestHash;
    const genesisHash = demoState.manifests[0].manifestHash;
    const depth = demoState.manifests.length + 1;

    // Build chain metadata
    const chain: ManifestChain = {
      previous: prevManifestHash,
      previousBranch: "main",
      genesisHash,
      depth,
    };
    steps.push(`4. Chain: depth=${depth}, previous=${prevManifestHash.substring(0, 24)}...`);

    // Build manifest
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const unsigned = buildUnsignedManifest({
      id: `hiri://${demoState.authority}/data/person`,
      version: String(demoState.manifests.length + 1),
      branch: "main",
      created: timestamp,
      contentHash: v2ContentHash,
      contentFormat: "application/ld+json",
      contentSize: v2ContentBytes.length,
      addressing: "raw-sha256",
      canonicalization: "JCS",
      chain,
      delta: {
        hash: deltaHash,
        format: "application/json-patch+json",
        appliesTo: prevEntry.contentHash,
        operations: operations.length,
      },
    });

    const signed = await signManifest(unsigned, keypair, timestamp, "JCS", crypto);
    const manifestHash = await hashManifest(signed, crypto);
    steps.push(`5. Signed V${unsigned["hiri:version"]}: ${manifestHash.substring(0, 24)}...`);

    // Validate chain link
    const linkResult = await validateChainLink(signed, prevEntry.manifest, crypto);
    steps.push(`6. Chain link validation: ${linkResult.valid ? "VALID" : "INVALID: " + linkResult.reason}`);

    // Store
    demoState.manifests.push({
      manifest: signed,
      manifestHash,
      contentBytes: v2ContentBytes,
      contentHash: v2ContentHash,
      version: unsigned["hiri:version"],
    });

    await demoState.storage.put(manifestHash, new TextEncoder().encode(stableStringify(signed)));
    await demoState.storage.put(v2ContentHash, v2ContentBytes);
    await demoState.storage.put(deltaHash, deltaBytes);

    // Update for next chain
    v1FormData = { ...data };
    v1ContentStr = v2Canonical;
    v1ContentHash = v2ContentHash;

    // Render
    renderManifest(signed, manifestHash);
    renderChainVisualization();

    btn.textContent = `V${unsigned["hiri:version"]} Chained`;
    btn.disabled = false;
    btn.textContent = "Update & Chain (next)";
    (document.getElementById("btn-verify-chain") as HTMLButtonElement).disabled = false;

    document.getElementById("hood-content-build")!.innerHTML =
      `<pre>${steps.join("\n")}</pre>`;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Update & Chain";
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
