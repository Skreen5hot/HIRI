/**
 * Tab A: Identity & Authority Sandbox
 *
 * Generate Ed25519 identities, manage key lifecycle (rotation, revocation),
 * and observe temporal key status transitions via the Mock Clock slider.
 *
 * Kernel functions used:
 *   generateKeypair, deriveAuthority, buildKeyDocument, signKeyDocument,
 *   resolveSigningKey, verifyManifestWithKeyLifecycle, buildUnsignedManifest,
 *   signManifest, hashManifest, stableStringify, base58Encode, addDuration,
 *   compareTimestamps, verifyRotationProof
 */

import { generateKeypair } from "../adapters/crypto/ed25519.js";
import { deriveAuthority } from "../kernel/authority.js";
import { buildKeyDocument, buildUnsignedManifest } from "../kernel/manifest.js";
import { signKeyDocument, signManifest } from "../kernel/signing.js";
import { hashManifest } from "../kernel/chain.js";
import {
  resolveSigningKey,
  verifyManifestWithKeyLifecycle,
  verifyRotationProof,
} from "../kernel/key-lifecycle.js";
import { addDuration } from "../kernel/temporal.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { encode as base58Encode } from "../kernel/base58.js";
import { defaultCryptoProvider } from "../adapters/crypto/provider.js";
import { demoState } from "./state.js";
import type {
  SigningKey,
  KeyDocument,
  ResolutionManifest,
  VerificationKey,
  RotatedKey,
  RevokedKey,
  KeyVerificationResult,
  RotationClaim,
} from "../kernel/types.js";

// ── Constants ──────────────────────────────────────────────────────────

const crypto = defaultCryptoProvider;

const T_KEY1_CREATED = "2025-01-01T00:00:00Z";
const T_ROTATION = "2025-07-01T00:00:00Z";
const T_REVOCATION = "2025-09-01T00:00:00Z";
const T_MANIFEST_INVALID_AFTER = "2025-06-01T00:00:00Z";
const GRACE_DURATION = "P180D";
const TIMELINE_END = "2026-06-01T00:00:00Z";

// ── Module State ───────────────────────────────────────────────────────

let container: HTMLElement;
let key1: SigningKey | null = null;
let key2: SigningKey | null = null;
let authority = "";
let keyDocUri = "";

let testManifestKey1: ResolutionManifest | null = null;
let testManifestKey2: ResolutionManifest | null = null;

type Phase = "initial" | "genesis" | "rotated" | "revoked";
let phase: Phase = "initial";

// ── Public Entry ───────────────────────────────────────────────────────

export function initKeysTab(el: HTMLElement): void {
  container = el;
  render();
}

// ── Rendering ──────────────────────────────────────────────────────────

function render(): void {
  container.innerHTML = `
    <div class="action-bar">
      <button class="btn btn-primary" id="btn-generate">Generate Genesis Identity</button>
      <button class="btn" id="btn-rotate" disabled>Rotate Key</button>
      <button class="btn btn-danger" id="btn-revoke" disabled>Revoke Key</button>
    </div>
    <div id="identity-panel"></div>
    <div id="keydoc-panel"></div>
    <div id="clock-section" style="display:none"></div>
    <div class="transparency" id="transparency-keys">
      <button class="transparency-toggle" id="hood-toggle-keys">Under the Hood</button>
      <div class="transparency-content" id="hood-content-keys"></div>
    </div>
  `;

  container.querySelector("#btn-generate")!.addEventListener("click", handleGenerate);
  container.querySelector("#btn-rotate")!.addEventListener("click", handleRotate);
  container.querySelector("#btn-revoke")!.addEventListener("click", handleRevoke);
  container.querySelector("#hood-toggle-keys")!.addEventListener("click", () => {
    document.getElementById("hood-content-keys")!.classList.toggle("open");
  });
}

function renderIdentityPanel(): void {
  const panel = document.getElementById("identity-panel")!;
  const keypairs = [key1, key2].filter(Boolean) as SigningKey[];

  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header">Identity</div>
      <div class="panel-body">
        <div style="margin-bottom:0.5rem">
          <span style="color:var(--text-muted);font-size:0.8rem">Authority URI</span><br>
          <code style="color:var(--accent);font-size:0.85rem">hiri://${authority}</code>
        </div>
        ${keypairs.map((k, i) => `
          <div style="margin-bottom:0.5rem;padding:0.5rem;border:1px solid var(--border);border-radius:var(--radius)">
            <span style="color:var(--text-muted);font-size:0.75rem">Key ${i + 1} (${k.keyId})</span>
            <span class="badge ${i === keypairs.length - 1 && phase !== "revoked" ? "badge-active" : (phase === "revoked" && i === 0 ? "badge-revoked" : "badge-grace")}"
                  style="margin-left:0.5rem">
              ${i === keypairs.length - 1 && phase !== "revoked" ? "active" : (phase === "revoked" && i === 0 ? "revoked" : "rotated")}
            </span><br>
            <span style="color:var(--text-muted);font-size:0.7rem">Public Key: ${bytesToHex(k.publicKey).substring(0, 32)}...</span>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function renderKeyDocPanel(): void {
  const panel = document.getElementById("keydoc-panel")!;
  if (!demoState.keyDocument) return;

  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header">Key Document (v${demoState.keyDocument["hiri:version"]})</div>
      <div class="panel-body">
        <pre>${stableStringify(demoState.keyDocument, true)}</pre>
      </div>
    </div>
  `;
}

function renderClock(): void {
  const section = document.getElementById("clock-section")!;
  section.style.display = "block";

  const graceEnd = phase === "rotated" || phase === "revoked"
    ? addDuration(T_ROTATION, GRACE_DURATION)
    : null;

  // Build timeline markers
  const markers: Array<{ time: string; label: string }> = [
    { time: T_KEY1_CREATED, label: "Key 1 Created" },
  ];
  if (phase === "rotated" || phase === "revoked") {
    markers.push({ time: T_ROTATION, label: "Rotated" });
    markers.push({ time: graceEnd!, label: "Grace Ends" });
  }
  if (phase === "revoked") {
    markers.push({ time: T_REVOCATION, label: "Revoked" });
    markers.push({ time: T_MANIFEST_INVALID_AFTER, label: "Invalid After" });
  }

  section.innerHTML = `
    <div class="panel">
      <div class="panel-header">Mock Clock — Temporal Key Status</div>
      <div class="panel-body">
        <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:0.75rem">
          Drag the slider to change the <strong>verification time</strong>.
          The key status is re-evaluated at each position.
        </p>
        <div style="display:flex;justify-content:space-between;font-size:0.7rem;color:var(--accent);margin-bottom:0.25rem">
          ${markers.map(m => `<span><code>${m.time.replace("T00:00:00Z", "")}</code></span>`).join("")}
        </div>
        <div class="slider-container">
          <input type="range" id="clock-slider" min="0" max="1000" value="0" style="width:100%">
          <div class="slider-labels">
            ${markers.map(m => `<span>${m.label}</span>`).join("")}
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:1rem;margin-top:0.75rem">
          <span style="color:var(--text-muted);font-size:0.8rem">Verification Time:</span>
          <code id="clock-time" style="color:var(--accent);font-size:0.85rem">${T_KEY1_CREATED}</code>
        </div>
        <div id="clock-results" style="margin-top:1rem"></div>
      </div>
    </div>
  `;

  const slider = document.getElementById("clock-slider") as HTMLInputElement;
  slider.addEventListener("input", () => updateClock(parseInt(slider.value)));
  updateClock(0);
}

function updateClock(position: number): void {
  const startMs = Date.parse(T_KEY1_CREATED);
  const endMs = Date.parse(TIMELINE_END);
  const currentMs = startMs + (position / 1000) * (endMs - startMs);
  const verificationTime = new Date(currentMs).toISOString().replace(/\.\d{3}Z$/, "Z");

  document.getElementById("clock-time")!.textContent = verificationTime;

  const results: string[] = [];

  if (testManifestKey1 && demoState.keyDocument) {
    const r1 = resolveSigningKey(testManifestKey1, demoState.keyDocument, verificationTime);
    results.push(renderKeyResult("Test Manifest (Key 1)", r1));
  }

  if (testManifestKey2 && demoState.keyDocument) {
    const r2 = resolveSigningKey(testManifestKey2, demoState.keyDocument, verificationTime);
    results.push(renderKeyResult("Test Manifest (Key 2)", r2));
  }

  document.getElementById("clock-results")!.innerHTML = results.join("");

  // Update transparency panel
  updateTransparency(verificationTime);
}

function renderKeyResult(label: string, result: KeyVerificationResult): string {
  const badgeClass = statusBadgeClass(result.keyStatus);
  return `
    <div style="padding:0.5rem;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:0.5rem">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <span style="font-size:0.85rem">${label}</span>
        <div>
          <span class="badge ${badgeClass}">${result.keyStatus}</span>
          <span class="badge ${result.valid ? "badge-active" : "badge-expired"}" style="margin-left:0.25rem">
            ${result.valid ? "VALID" : "REJECTED"}
          </span>
        </div>
      </div>
      ${result.warning ? `<div style="color:var(--yellow);font-size:0.75rem;margin-top:0.25rem">${result.warning}</div>` : ""}
    </div>
  `;
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case "active": return "badge-active";
    case "rotated-grace": return "badge-grace";
    case "rotated-expired": return "badge-expired";
    case "revoked": return "badge-revoked";
    default: return "badge-unknown";
  }
}

function updateTransparency(verificationTime: string): void {
  const panel = document.getElementById("hood-content-keys")!;
  if (!testManifestKey1 || !demoState.keyDocument) {
    panel.innerHTML = "<pre>No data yet</pre>";
    return;
  }

  const r1 = resolveSigningKey(testManifestKey1, demoState.keyDocument, verificationTime);
  const r2 = testManifestKey2
    ? resolveSigningKey(testManifestKey2, demoState.keyDocument, verificationTime)
    : null;

  panel.innerHTML = `
    <pre>${stableStringify({
      function: "resolveSigningKey()",
      verificationTime,
      results: [
        { manifest: "Test Manifest (Key 1)", ...r1 },
        ...(r2 ? [{ manifest: "Test Manifest (Key 2)", ...r2 }] : []),
      ],
      keyDocument: {
        version: demoState.keyDocument["hiri:version"],
        activeKeys: demoState.keyDocument["hiri:activeKeys"].map((k: VerificationKey) => k["@id"]),
        rotatedKeys: demoState.keyDocument["hiri:rotatedKeys"].map((k: RotatedKey) => k["@id"]),
        revokedKeys: demoState.keyDocument["hiri:revokedKeys"].map((k: RevokedKey) => k["@id"]),
        gracePeriod: demoState.keyDocument["hiri:policies"].gracePeriodAfterRotation,
      },
    }, true)}</pre>
  `;
}

// ── Event Handlers ─────────────────────────────────────────────────────

async function handleGenerate(): Promise<void> {
  const btn = document.getElementById("btn-generate") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Generating...";

  try {
    // Generate keypair
    key1 = await generateKeypair("key-1");
    authority = deriveAuthority(key1.publicKey, key1.algorithm);
    keyDocUri = `hiri://${authority}/key/main`;

    // Store in DemoState
    demoState.keypairs.push({ keypair: key1, keyId: key1.keyId, authority });
    demoState.authority = authority;

    // Build Key Document (v1)
    const verificationKey: VerificationKey = {
      "@id": `${keyDocUri}#key-1`,
      "@type": "Ed25519VerificationKey2020",
      controller: keyDocUri,
      publicKeyMultibase: "z" + base58Encode(key1.publicKey),
      purposes: ["assertionMethod"],
      validFrom: T_KEY1_CREATED,
    };

    const unsigned = buildKeyDocument({
      authority,
      authorityType: "key",
      version: "1",
      activeKeys: [verificationKey],
      policies: {
        gracePeriodAfterRotation: GRACE_DURATION,
        minimumKeyValidity: "P365D",
      },
    });

    demoState.keyDocument = await signKeyDocument(unsigned, key1, T_KEY1_CREATED, "JCS", crypto);

    // Create test manifest signed by key-1
    const content = stableStringify({ "@id": `hiri://${authority}/data/test`, name: "Test Subject" });
    const contentBytes = new TextEncoder().encode(content);
    const contentHash = await crypto.hash(contentBytes);

    const unsignedManifest = buildUnsignedManifest({
      id: `hiri://${authority}/data/test`,
      version: "1",
      branch: "main",
      created: T_KEY1_CREATED,
      contentHash,
      contentFormat: "application/ld+json",
      contentSize: contentBytes.length,
      addressing: "raw-sha256",
      canonicalization: "JCS",
    });

    testManifestKey1 = await signManifest(unsignedManifest, key1, T_KEY1_CREATED, "JCS", crypto);

    // Test manifest is only used by the Mock Clock slider (stored in testManifestKey1).
    // It is NOT pushed to demoState.manifests, which is reserved for Tab B's person data.

    phase = "genesis";
    demoState.initialized = true;

    // Update UI
    renderIdentityPanel();
    renderKeyDocPanel();
    renderClock();

    btn.textContent = "Generated";
    (document.getElementById("btn-rotate") as HTMLButtonElement).disabled = false;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Generate Genesis Identity";
    console.error("Generate failed:", e);
    document.getElementById("identity-panel")!.innerHTML =
      `<div class="info-box error">Generation failed: ${(e as Error).message}</div>`;
  }
}

async function handleRotate(): Promise<void> {
  if (!key1 || !demoState.keyDocument) return;

  const btn = document.getElementById("btn-rotate") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Rotating...";

  try {
    // Generate key-2
    key2 = await generateKeypair("key-2");
    demoState.keypairs.push({ keypair: key2, keyId: key2.keyId });

    // Build rotation proof (dual signatures)
    const rotationClaim: RotationClaim = {
      oldKeyId: `${keyDocUri}#key-1`,
      newKeyId: `${keyDocUri}#key-2`,
      rotatedAt: T_ROTATION,
      reason: "scheduled-rotation",
    };
    const claimBytes = new TextEncoder().encode(stableStringify(rotationClaim));
    const oldKeySig = await crypto.sign(claimBytes, key1.privateKey);
    const newKeySig = await crypto.sign(claimBytes, key2.privateKey);

    // Build new Key Document (v2)
    const graceEnd = addDuration(T_ROTATION, GRACE_DURATION);

    const rotatedEntry: RotatedKey = {
      "@id": `${keyDocUri}#key-1`,
      rotatedAt: T_ROTATION,
      rotatedTo: `${keyDocUri}#key-2`,
      reason: "scheduled-rotation",
      verifyUntil: graceEnd,
      publicKeyMultibase: "z" + base58Encode(key1.publicKey),
      rotationProof: [
        {
          purpose: "old-key-authorizes-rotation",
          verificationMethod: `${keyDocUri}#key-1`,
          proofValue: "z" + base58Encode(oldKeySig),
        },
        {
          purpose: "new-key-confirms-rotation",
          verificationMethod: `${keyDocUri}#key-2`,
          proofValue: "z" + base58Encode(newKeySig),
        },
      ],
    };

    const newActiveKey: VerificationKey = {
      "@id": `${keyDocUri}#key-2`,
      "@type": "Ed25519VerificationKey2020",
      controller: keyDocUri,
      publicKeyMultibase: "z" + base58Encode(key2.publicKey),
      purposes: ["assertionMethod"],
      validFrom: T_ROTATION,
    };

    const unsigned = buildKeyDocument({
      authority,
      authorityType: "key",
      version: "2",
      activeKeys: [newActiveKey],
      rotatedKeys: [rotatedEntry],
      policies: {
        gracePeriodAfterRotation: GRACE_DURATION,
        minimumKeyValidity: "P365D",
      },
    });

    demoState.keyDocument = await signKeyDocument(unsigned, key2, T_ROTATION, "JCS", crypto);

    // Create test manifest signed by key-2
    const content = stableStringify({ "@id": `hiri://${authority}/data/test-v2`, name: "Test Subject V2" });
    const contentBytes = new TextEncoder().encode(content);
    const contentHash = await crypto.hash(contentBytes);

    const unsignedManifest = buildUnsignedManifest({
      id: `hiri://${authority}/data/test`,
      version: "2",
      branch: "main",
      created: T_ROTATION,
      contentHash,
      contentFormat: "application/ld+json",
      contentSize: contentBytes.length,
      addressing: "raw-sha256",
      canonicalization: "JCS",
    });

    testManifestKey2 = await signManifest(unsignedManifest, key2, T_ROTATION, "JCS", crypto);

    phase = "rotated";

    // Update UI
    renderIdentityPanel();
    renderKeyDocPanel();
    renderClock();

    btn.textContent = "Rotated";
    (document.getElementById("btn-revoke") as HTMLButtonElement).disabled = false;
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Rotate Key";
    console.error("Rotation failed:", e);
  }
}

async function handleRevoke(): Promise<void> {
  if (!key1 || !key2 || !demoState.keyDocument) return;

  const btn = document.getElementById("btn-revoke") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Revoking...";

  try {
    // Move key-1 from rotatedKeys to revokedKeys
    const revokedEntry: RevokedKey = {
      "@id": `${keyDocUri}#key-1`,
      revokedAt: T_REVOCATION,
      reason: "compromise-suspected",
      manifestsInvalidAfter: T_MANIFEST_INVALID_AFTER,
      publicKeyMultibase: "z" + base58Encode(key1.publicKey),
    };

    const activeKey: VerificationKey = {
      "@id": `${keyDocUri}#key-2`,
      "@type": "Ed25519VerificationKey2020",
      controller: keyDocUri,
      publicKeyMultibase: "z" + base58Encode(key2.publicKey),
      purposes: ["assertionMethod"],
      validFrom: T_ROTATION,
    };

    const unsigned = buildKeyDocument({
      authority,
      authorityType: "key",
      version: "3",
      activeKeys: [activeKey],
      revokedKeys: [revokedEntry],
      policies: {
        gracePeriodAfterRotation: GRACE_DURATION,
        minimumKeyValidity: "P365D",
      },
    });

    demoState.keyDocument = await signKeyDocument(unsigned, key2, T_REVOCATION, "JCS", crypto);

    phase = "revoked";

    // Update UI
    renderIdentityPanel();
    renderKeyDocPanel();
    renderClock();

    btn.textContent = "Revoked";

    // Show explanation about revocation
    const infoHtml = `
      <div class="info-box warning" style="margin-top:1rem">
        Key 1 revoked with <code>manifestsInvalidAfter: ${T_MANIFEST_INVALID_AFTER}</code>.<br>
        The test manifest was signed at <code>${T_KEY1_CREATED}</code> (before invalidation) —
        so it remains valid with a warning. Notice the slider does not change the revocation verdict;
        revocation depends on <strong>when the manifest was signed</strong>, not when you verify it.
      </div>
    `;
    document.getElementById("clock-section")!.insertAdjacentHTML("beforeend", infoHtml);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Revoke Key";
    console.error("Revocation failed:", e);
  }
}

// ── Utility ────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
