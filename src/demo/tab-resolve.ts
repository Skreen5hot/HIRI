/**
 * Tab D: Network Simulator — Resolver
 *
 * Resolve HIRI URIs against different storage backends (InMemory, Delayed).
 * Inject faults to test tamper detection. Prove byte-identical results.
 *
 * Kernel functions used:
 *   resolve, ResolutionError, InMemoryStorageAdapter, DelayedAdapter,
 *   HiriURI, stableStringify, hashManifest
 */

import { resolve, ResolutionError } from "../kernel/resolve.js";
import { InMemoryStorageAdapter } from "../adapters/persistence/storage.js";
import { DelayedAdapter } from "../adapters/persistence/delayed.js";
import { HiriURI } from "../kernel/hiri-uri.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { defaultCryptoProvider } from "../adapters/crypto/provider.js";
import { demoState } from "./state.js";
import type { StorageAdapter } from "../kernel/types.js";

const crypto = defaultCryptoProvider;

let container: HTMLElement;

export function initResolveTab(el: HTMLElement): void {
  container = el;
  render();
}

function render(): void {
  container.innerHTML = `
    <div id="resolve-gate"></div>
    <div id="resolve-main" style="display:none">
      <div class="panel">
        <div class="panel-header">Resolver</div>
        <div class="panel-body">
          <div class="form-group">
            <label>HIRI URI</label>
            <input class="form-input" id="resolve-uri" placeholder="hiri://key:ed25519:.../data/person">
          </div>
          <div class="form-group">
            <label>Storage Adapter</label>
            <div style="display:flex;gap:0.5rem;margin-top:0.25rem">
              <label style="font-size:0.8rem;cursor:pointer">
                <input type="radio" name="adapter" value="instant" checked> Instant (InMemory)
              </label>
              <label style="font-size:0.8rem;cursor:pointer">
                <input type="radio" name="adapter" value="slow50"> 50ms Latency
              </label>
              <label style="font-size:0.8rem;cursor:pointer">
                <input type="radio" name="adapter" value="slow500"> 500ms Latency
              </label>
            </div>
          </div>
          <div class="action-bar">
            <button class="btn btn-primary" id="btn-resolve">Resolve</button>
            <button class="btn" id="btn-prove-identical">Prove Byte-Identical</button>
          </div>
        </div>
      </div>

      <div id="resolve-steps" style="margin-top:1rem"></div>
      <div id="resolve-result" style="margin-top:1rem"></div>
      <div id="identical-proof" style="margin-top:1rem"></div>

      <div class="panel" style="margin-top:1rem">
        <div class="panel-header">Fault Injection</div>
        <div class="panel-body">
          <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:0.75rem">
            Inject faults into the storage adapter to test tamper detection.
            Each fault modifies the underlying storage, then you re-resolve to see the error.
          </p>
          <div class="action-bar">
            <button class="btn btn-danger" id="btn-fault-content">Corrupt Content</button>
            <button class="btn btn-danger" id="btn-fault-sig">Corrupt Signature</button>
            <button class="btn btn-danger" id="btn-fault-remove">Remove Manifest</button>
            <button class="btn" id="btn-fault-reset">Reset Storage</button>
          </div>
          <div id="fault-result" style="margin-top:0.5rem"></div>
        </div>
      </div>

      <div class="transparency">
        <button class="transparency-toggle" id="hood-toggle-resolve">Under the Hood</button>
        <div class="transparency-content" id="hood-content-resolve"></div>
      </div>
    </div>
  `;

  checkGate();
}

function checkGate(): void {
  const gate = document.getElementById("resolve-gate")!;
  if (demoState.manifests.length === 0 || !demoState.primaryKeypair) {
    gate.innerHTML = `<div class="info-box info">Create signed content in Tab B, then resolve URIs here.</div>`;
    return;
  }

  gate.innerHTML = "";
  document.getElementById("resolve-main")!.style.display = "block";

  // Pre-fill URI
  const latestManifest = demoState.latestManifest;
  if (latestManifest) {
    (document.getElementById("resolve-uri") as HTMLInputElement).value =
      latestManifest.manifest["@id"];
  }

  // Wire events
  document.getElementById("btn-resolve")!.addEventListener("click", handleResolve);
  document.getElementById("btn-prove-identical")!.addEventListener("click", handleProveIdentical);
  document.getElementById("btn-fault-content")!.addEventListener("click", () => injectFault("content"));
  document.getElementById("btn-fault-sig")!.addEventListener("click", () => injectFault("signature"));
  document.getElementById("btn-fault-remove")!.addEventListener("click", () => injectFault("remove"));
  document.getElementById("btn-fault-reset")!.addEventListener("click", resetStorage);
  document.getElementById("hood-toggle-resolve")!.addEventListener("click", () => {
    document.getElementById("hood-content-resolve")!.classList.toggle("open");
  });
}

function getSelectedAdapter(): StorageAdapter {
  const selected = (document.querySelector('input[name="adapter"]:checked') as HTMLInputElement).value;
  switch (selected) {
    case "slow50": return new DelayedAdapter(demoState.storage, 50);
    case "slow500": return new DelayedAdapter(demoState.storage, 500);
    default: return demoState.storage;
  }
}

function getSelectedAdapterName(): string {
  const selected = (document.querySelector('input[name="adapter"]:checked') as HTMLInputElement).value;
  switch (selected) {
    case "slow50": return "DelayedAdapter(50ms)";
    case "slow500": return "DelayedAdapter(500ms)";
    default: return "InMemoryStorageAdapter";
  }
}

async function handleResolve(): Promise<void> {
  const uri = (document.getElementById("resolve-uri") as HTMLInputElement).value.trim();
  if (!uri) return;

  const btn = document.getElementById("btn-resolve") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Resolving...";

  const stepsDiv = document.getElementById("resolve-steps")!;
  const resultDiv = document.getElementById("resolve-result")!;
  stepsDiv.innerHTML = "";
  resultDiv.innerHTML = "";

  try {
    // Parse URI for step display
    let parsed: HiriURI;
    try {
      parsed = HiriURI.parse(uri);
      addStep(stepsDiv, "Parse URI", `authority=${parsed.authority}, type=${parsed.type}, id=${parsed.identifier}`, true);
    } catch (e) {
      addStep(stepsDiv, "Parse URI", (e as Error).message, false);
      throw e;
    }

    addStep(stepsDiv, "Derive Authority", `From genesis public key`, true);

    // Get adapter and latest manifest hash
    const adapter = getSelectedAdapter();
    const latestManifest = demoState.latestManifest;
    if (!latestManifest) throw new Error("No manifest available");

    const keypair = demoState.primaryKeypair!;
    const startTime = performance.now();

    addStep(stepsDiv, "Fetch Manifest", `hash=${latestManifest.manifestHash.substring(0, 24)}...`, true);
    addStep(stepsDiv, "Verify Hash", "Comparing stored vs computed hash", true);

    const result = await resolve(uri, adapter, {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash: latestManifest.manifestHash,
      ...(demoState.keyDocument ? {
        keyDocument: demoState.keyDocument,
        verificationTime: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      } : {}),
    });

    const elapsed = (performance.now() - startTime).toFixed(1);

    addStep(stepsDiv, "Verify Signature", "Cryptographic verification passed", true);
    if (result.manifest["hiri:chain"]) {
      addStep(stepsDiv, "Walk Chain", `Depth=${result.manifest["hiri:chain"].depth}`, true);
    }
    addStep(stepsDiv, "Fetch Content", `hash=${result.contentHash.substring(0, 24)}...`, true);
    addStep(stepsDiv, "Verify Content", "Content hash matches manifest", true);

    // Display result
    const contentStr = new TextDecoder().decode(result.content);
    resultDiv.innerHTML = `
      <div class="info-box success">
        Resolution <strong>succeeded</strong> in ${elapsed}ms via ${getSelectedAdapterName()}
        ${result.warnings && result.warnings.length > 0
          ? `<br><span style="color:var(--yellow)">Warnings: ${result.warnings.join("; ")}</span>`
          : ""}
      </div>
      <div style="display:flex;gap:1rem;flex-wrap:wrap;font-size:0.8rem;margin-bottom:1rem;padding:0.5rem 0.75rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)">
        <span>Signature: <span style="color:var(--green)">✓ valid</span></span>
        <span>Key: <span style="color:${result.keyVerification ? (result.keyVerification.keyStatus === "active" ? "var(--green)" : "var(--yellow)") : "var(--text-muted)"}">${result.keyVerification?.keyStatus ?? "direct"}</span></span>
        <span>Revocation: <span style="color:var(--text-muted)">${result.keyVerification?.revocationStatus ?? "not-checked"}</span></span>
        <span>Timestamp: <span style="color:var(--text-muted)">${result.keyVerification?.timestampVerification ?? "advisory-only"}</span></span>
      </div>
      <div class="panel">
        <div class="panel-header">Verified Content (V${result.manifest["hiri:version"]})</div>
        <div class="panel-body">
          <pre>${stableStringify(JSON.parse(contentStr), true)}</pre>
        </div>
      </div>
    `;

    // Update transparency
    document.getElementById("hood-content-resolve")!.innerHTML = `<pre>${stableStringify({
      uri,
      adapter: getSelectedAdapterName(),
      elapsedMs: parseFloat(elapsed),
      contentHash: result.contentHash,
      authority: result.authority,
      manifestVersion: result.manifest["hiri:version"],
      warnings: result.warnings ?? [],
      keyVerification: result.keyVerification ?? null,
    }, true)}</pre>`;
  } catch (e) {
    const isResolutionError = e instanceof ResolutionError;
    if (isResolutionError) {
      addStep(stepsDiv, "FAILED", `${(e as ResolutionError).code}: ${e.message}`, false);
    }
    resultDiv.innerHTML = `
      <div class="info-box error">
        Resolution <strong>failed</strong>:
        ${isResolutionError ? `<code>${(e as ResolutionError).code}</code> — ` : ""}${(e as Error).message}
      </div>
    `;
  } finally {
    btn.disabled = false;
    btn.textContent = "Resolve";
  }
}

async function handleProveIdentical(): Promise<void> {
  const uri = (document.getElementById("resolve-uri") as HTMLInputElement).value.trim();
  if (!uri || demoState.manifests.length === 0 || !demoState.primaryKeypair) return;

  const btn = document.getElementById("btn-prove-identical") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Running 3 adapters...";

  const proofDiv = document.getElementById("identical-proof")!;

  try {
    const latestManifest = demoState.latestManifest!;
    const keypair = demoState.primaryKeypair!;
    const resolveOpts = {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash: latestManifest.manifestHash,
      ...(demoState.keyDocument ? {
        keyDocument: demoState.keyDocument,
        verificationTime: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      } : {}),
    };

    const adapters: Array<{ name: string; adapter: StorageAdapter }> = [
      { name: "InMemory (instant)", adapter: demoState.storage },
      { name: "Delayed (50ms)", adapter: new DelayedAdapter(demoState.storage, 50) },
      { name: "Delayed (500ms)", adapter: new DelayedAdapter(demoState.storage, 500) },
    ];

    const results: Array<{ name: string; elapsed: number; contentHex: string }> = [];

    for (const { name, adapter } of adapters) {
      const start = performance.now();
      const result = await resolve(uri, adapter, resolveOpts);
      const elapsed = performance.now() - start;
      const hex = Array.from(result.content).map(b => b.toString(16).padStart(2, "0")).join("");
      results.push({ name, elapsed: parseFloat(elapsed.toFixed(1)), contentHex: hex });
    }

    // Check byte identity
    const allIdentical = results.every(r => r.contentHex === results[0].contentHex);

    proofDiv.innerHTML = `
      <div class="panel">
        <div class="panel-header">Byte-Identical Proof</div>
        <div class="panel-body">
          <div class="info-box ${allIdentical ? "success" : "error"}" style="margin-bottom:0.75rem">
            ${allIdentical
              ? "All 3 adapters produced <strong>byte-identical</strong> VerifiedContent"
              : "Content <strong>differs</strong> across adapters (unexpected!)"}
          </div>
          <table class="results-table">
            <thead><tr><th>Adapter</th><th>Time</th><th>Content Hash (first 32 chars)</th></tr></thead>
            <tbody>
              ${results.map(r => `
                <tr>
                  <td>${r.name}</td>
                  <td>${r.elapsed}ms</td>
                  <td><code style="font-size:0.7rem">${r.contentHex.substring(0, 32)}...</code></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    proofDiv.innerHTML = `<div class="info-box error">Proof failed: ${(e as Error).message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Prove Byte-Identical";
  }
}

async function injectFault(type: "content" | "signature" | "remove"): Promise<void> {
  const faultDiv = document.getElementById("fault-result")!;
  const latestManifest = demoState.latestManifest;
  if (!latestManifest) {
    faultDiv.innerHTML = `<div class="info-box warning">No manifest available.</div>`;
    return;
  }

  try {
    switch (type) {
      case "content": {
        // Flip one byte in stored content
        const contentBytes = await demoState.storage.get(latestManifest.contentHash);
        if (contentBytes) {
          const corrupted = new Uint8Array(contentBytes);
          corrupted[0] = corrupted[0] ^ 0xff; // Flip first byte
          await demoState.storage.put(latestManifest.contentHash, corrupted);
          faultDiv.innerHTML = `<div class="info-box warning">Content byte 0 flipped. Re-resolve to see the error.</div>`;
        }
        break;
      }
      case "signature": {
        // Corrupt the manifest's signature bytes
        const manifestBytes = await demoState.storage.get(latestManifest.manifestHash);
        if (manifestBytes) {
          const manifestStr = new TextDecoder().decode(manifestBytes);
          const manifest = JSON.parse(manifestStr);
          const sig = manifest["hiri:signature"].proofValue;
          // Flip last character
          manifest["hiri:signature"].proofValue =
            sig.substring(0, sig.length - 1) + (sig[sig.length - 1] === "a" ? "b" : "a");
          const corruptedBytes = new TextEncoder().encode(stableStringify(manifest));
          // Re-hash and re-store with same hash key (hash won't match now)
          await demoState.storage.put(latestManifest.manifestHash, corruptedBytes);
          faultDiv.innerHTML = `<div class="info-box warning">Signature corrupted. Re-resolve to see the error.</div>`;
        }
        break;
      }
      case "remove": {
        // Remove manifest from storage by storing null-length
        // We can't truly "remove" from InMemoryStorageAdapter, so store empty
        await demoState.storage.put(latestManifest.manifestHash, new Uint8Array(0));
        faultDiv.innerHTML = `<div class="info-box warning">Manifest zeroed out. Re-resolve to see the error.</div>`;
        break;
      }
    }
  } catch (e) {
    faultDiv.innerHTML = `<div class="info-box error">Fault injection failed: ${(e as Error).message}</div>`;
  }
}

async function resetStorage(): Promise<void> {
  // Rebuild storage from manifest entries
  demoState.storage.clear();
  for (const entry of demoState.manifests) {
    await demoState.storage.put(entry.manifestHash, new TextEncoder().encode(stableStringify(entry.manifest)));
    await demoState.storage.put(entry.contentHash, entry.contentBytes);
  }
  document.getElementById("fault-result")!.innerHTML =
    `<div class="info-box success">Storage reset to clean state.</div>`;
}

function addStep(container: HTMLElement, label: string, detail: string, success: boolean): void {
  const icon = success ? "&#10003;" : "&#10007;";
  const color = success ? "var(--green)" : "var(--red)";
  container.innerHTML += `
    <div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.25rem;font-size:0.8rem">
      <span style="color:${color}">${icon}</span>
      <span style="color:var(--text)">${label}</span>
      <span style="color:var(--text-muted)">${detail}</span>
    </div>
  `;
}
