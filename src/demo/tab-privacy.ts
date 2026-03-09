/**
 * Tab E: Privacy Sandbox
 *
 * Five sub-panels (accordion) demonstrating HIRI privacy modes:
 *   E.1 Proof of Possession (§6)
 *   E.2 Encrypted Distribution (§7)
 *   E.3 Selective Disclosure (§8)
 *   E.4 Anonymous Publication (§9)
 *   E.5 Third-Party Attestation (§10)
 *
 * Privacy functions used:
 *   resolveWithPrivacy, encryptContent, decryptContent, buildEncryptedManifest,
 *   buildStatementIndex, generateHmacTags, encryptHmacKeyForRecipients,
 *   decryptHmacKey, verifyStatementInIndex, verifyIndexRoot, verifyHmacTag,
 *   generateEphemeralAuthority, buildAnonymousPrivacyBlock,
 *   buildAttestationManifest, verifyAttestation, validateAttestationManifest,
 *   isCustodyStale, getPrivacyMode
 */

import { generateKeypair } from "../adapters/crypto/ed25519.js";
import { deriveAuthority } from "../kernel/authority.js";
import { buildUnsignedManifest, prepareContent } from "../kernel/manifest.js";
import { signManifest, verifyManifest } from "../kernel/signing.js";
import { hashManifest } from "../kernel/chain.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { defaultCryptoProvider } from "../adapters/crypto/provider.js";
import { InMemoryStorageAdapter } from "../adapters/persistence/storage.js";
import { generateX25519Keypair } from "../adapters/crypto/x25519.js";
import { ed25519PublicToX25519 } from "../adapters/crypto/key-conversion.js";
import { demoState } from "./state.js";
import type { RecipientEntry } from "./state.js";
import type { SigningKey, ResolutionManifest } from "../kernel/types.js";

// Privacy imports
import { resolveWithPrivacy } from "../privacy/resolve.js";
import { isCustodyStale } from "../privacy/proof-of-possession.js";
import { encryptContent } from "../privacy/encryption.js";
import { decryptContent } from "../privacy/decryption.js";
import { buildEncryptedManifest } from "../privacy/encrypted-manifest.js";
import { buildSelectiveDisclosureManifest } from "../privacy/selective-manifest.js";
import { buildStatementIndex, verifyStatementInIndex, verifyIndexRoot } from "../privacy/statement-index.js";
import { generateHmacTags, verifyHmacTag, decryptHmacKey, encryptHmacKeyForRecipients } from "../privacy/hmac-disclosure.js";
import { generateEphemeralAuthority, buildAnonymousPrivacyBlock } from "../privacy/anonymous.js";
import { buildAttestationManifest, verifyAttestation, validateAttestationManifest } from "../privacy/attestation.js";
import type { SignedAttestationManifest } from "../privacy/attestation.js";
import type { EncryptedPrivacyParams, AnonymousParams, AttestationSubject, AttestationClaim, AttestationEvidence } from "../privacy/types.js";

const crypto = defaultCryptoProvider;

let container: HTMLElement;

// ── Public Entry ───────────────────────────────────────────────────────

export function initPrivacyTab(el: HTMLElement): void {
  container = el;
  render();
}

// ── Rendering ──────────────────────────────────────────────────────────

function render(): void {
  container.innerHTML = `
    <div id="privacy-gate"></div>
    <div id="privacy-main" style="display:none">
      <div class="privacy-accordion">
        ${renderAccordionHeader("pop", "E.1", "Proof of Possession", "§6", "badge-pop")}
        <div class="accordion-body" id="panel-pop" style="display:none">${renderPoPPanel()}</div>

        ${renderAccordionHeader("enc", "E.2", "Encrypted Distribution", "§7", "badge-enc")}
        <div class="accordion-body" id="panel-enc" style="display:none">${renderEncryptedPanel()}</div>

        ${renderAccordionHeader("sd", "E.3", "Selective Disclosure", "§8", "badge-sd")}
        <div class="accordion-body" id="panel-sd" style="display:none">${renderSDPanel()}</div>

        ${renderAccordionHeader("anon", "E.4", "Anonymous Publication", "§9", "badge-anon")}
        <div class="accordion-body" id="panel-anon" style="display:none">${renderAnonPanel()}</div>

        ${renderAccordionHeader("attest", "E.5", "Third-Party Attestation", "§10", "badge-attest")}
        <div class="accordion-body" id="panel-attest" style="display:none">${renderAttestPanel()}</div>
      </div>

      <div class="transparency" style="margin-top:1rem">
        <button class="transparency-toggle" id="hood-toggle-privacy">Under the Hood</button>
        <div class="transparency-content" id="hood-content-privacy"></div>
      </div>
    </div>
  `;

  checkGate();
}

function checkGate(): void {
  const gate = document.getElementById("privacy-gate")!;
  const main = document.getElementById("privacy-main")!;

  if (!demoState.initialized || !demoState.activeKeypair) {
    gate.innerHTML = `
      <div class="info-box">
        Generate an identity in <strong>Tab A</strong> first, or load a preset.
      </div>
    `;
    gate.style.display = "";
    main.style.display = "none";
    return;
  }

  gate.style.display = "none";
  main.style.display = "";

  // Ensure shared recipients exist
  ensureRecipients();
  wireAccordion();
  wirePoPPanel();
  wireEncryptedPanel();
  wireSDPanel();
  wireAnonPanel();
  wireAttestPanel();
  wireHoodToggle();
}

// ── Shared Recipients ──────────────────────────────────────────────────

function ensureRecipients(): void {
  if (demoState.privacyRecipients.length > 0) return;
  demoState.privacyRecipients = [
    { id: "alice", ...generateX25519Keypair() },
    { id: "bob", ...generateX25519Keypair() },
  ];
}

function recipientListHTML(includeRemove: boolean): string {
  return demoState.privacyRecipients.map((r, i) => `
    <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.8rem;margin-bottom:0.25rem">
      <span style="color:var(--text-muted)">☑</span>
      <strong>${r.id}</strong>
      <code style="font-size:0.7rem;color:var(--text-muted)">${bytesToHex(r.x25519Public).substring(0, 16)}...</code>
      ${includeRemove && i > 0 ? `<button class="btn btn-sm btn-remove-recipient" data-idx="${i}" style="font-size:0.65rem;padding:0.1rem 0.3rem">Remove</button>` : ""}
    </div>
  `).join("");
}

// ── Accordion Infrastructure ───────────────────────────────────────────

function renderAccordionHeader(id: string, label: string, title: string, spec: string, badgeClass: string): string {
  return `
    <div class="accordion-header" data-panel="${id}" style="cursor:pointer;padding:0.75rem;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:0.25rem;display:flex;align-items:center;gap:0.5rem">
      <span class="accordion-arrow" id="arrow-${id}" style="transition:transform 0.2s">▶</span>
      <span style="font-weight:600">${label}</span>
      <span class="${badgeClass}" style="padding:0.15rem 0.5rem;border-radius:0.25rem;font-size:0.75rem">${title}</span>
      <span style="color:var(--text-muted);font-size:0.7rem;margin-left:auto">${spec}</span>
    </div>
  `;
}

function wireAccordion(): void {
  container.querySelectorAll(".accordion-header").forEach(header => {
    header.addEventListener("click", () => {
      const panelId = (header as HTMLElement).dataset.panel!;
      const body = document.getElementById(`panel-${panelId}`)!;
      const arrow = document.getElementById(`arrow-${panelId}`)!;
      const isOpen = body.style.display !== "none";

      // Close all
      container.querySelectorAll(".accordion-body").forEach(b => (b as HTMLElement).style.display = "none");
      container.querySelectorAll(".accordion-arrow").forEach(a => (a as HTMLElement).style.transform = "");

      if (!isOpen) {
        body.style.display = "";
        arrow.style.transform = "rotate(90deg)";
      }
    });
  });
}

// ── E.1: Proof of Possession ───────────────────────────────────────────

function renderPoPPanel(): string {
  return `
    <div class="panel" style="margin:0.5rem 0">
      <div class="panel-body">
        <div class="form-group">
          <label>Content (never leaves this panel)</label>
          <textarea class="form-input" id="pop-content" rows="4" style="font-family:monospace;font-size:0.8rem">{ "@type": "Person",
  "name": "Dana Reeves",
  "clearance": "TS/SCI" }</textarea>
        </div>
        <div id="pop-hash" style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem"></div>
        <div class="form-group">
          <label>Refresh Policy</label>
          <select class="form-input" id="pop-refresh" style="width:auto">
            <option value="P7D">P7D (7 days)</option>
            <option value="P30D" selected>P30D (30 days)</option>
            <option value="P90D">P90D (90 days)</option>
            <option value="P365D">P365D (1 year)</option>
            <option value="">None</option>
          </select>
        </div>
        <div class="action-bar">
          <button class="btn btn-primary" id="btn-pop-sign">Sign Custody Assertion</button>
        </div>
        <div id="pop-result" style="margin-top:0.75rem"></div>

        <div style="margin-top:1rem;border-top:1px solid var(--border);padding-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Mock Clock — Staleness Check</label>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem">
            <span style="font-size:0.7rem;color:var(--text-muted)">Created</span>
            <input type="range" id="pop-clock" min="0" max="365" value="0" style="flex:1">
            <span style="font-size:0.7rem;color:var(--text-muted)">+1 year</span>
          </div>
          <div id="pop-clock-display" style="font-size:0.8rem;margin-top:0.25rem"></div>
          <div id="pop-staleness" style="font-size:0.8rem;margin-top:0.25rem"></div>
        </div>
      </div>
    </div>
  `;
}

let popManifest: ResolutionManifest | null = null;
let popManifestHash: string | null = null;
let popCreatedTime: string = "";

function wirePoPPanel(): void {
  const contentEl = document.getElementById("pop-content") as HTMLTextAreaElement;
  const hashEl = document.getElementById("pop-hash")!;

  // Live hash
  const updateHash = async () => {
    try {
      const bytes = new TextEncoder().encode(contentEl.value);
      const hash = await crypto.hash(bytes);
      hashEl.textContent = `Content Hash: ${hash.substring(0, 40)}...`;
    } catch { hashEl.textContent = ""; }
  };
  contentEl.addEventListener("input", updateHash);
  updateHash();

  // Sign button
  document.getElementById("btn-pop-sign")!.addEventListener("click", handlePoPSign);

  // Clock slider
  document.getElementById("pop-clock")!.addEventListener("input", handlePoPClock);
}

async function handlePoPSign(): Promise<void> {
  const resultDiv = document.getElementById("pop-result")!;
  const keypair = demoState.activeKeypair!;
  const contentStr = (document.getElementById("pop-content") as HTMLTextAreaElement).value;
  const refreshPolicy = (document.getElementById("pop-refresh") as HTMLSelectElement).value;

  try {
    const contentBytes = new TextEncoder().encode(contentStr);
    const contentHash = await crypto.hash(contentBytes);
    popCreatedTime = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    // Build manifest with PoP privacy block — content is NOT stored
    const unsigned = buildUnsignedManifest({
      authority: demoState.authority,
      contentHash,
      contentFormat: "application/json",
      contentSize: contentBytes.length,
      version: "1",
      addressing: "raw-sha256",
      created: popCreatedTime,
    });

    // Add privacy block
    (unsigned as Record<string, unknown>)["hiri:privacy"] = {
      mode: "proof-of-possession",
      parameters: {
        refreshPolicy: refreshPolicy || undefined,
      },
    };

    const signed = await signManifest(unsigned, keypair, popCreatedTime, "JCS", crypto);
    popManifest = signed;

    const manifestBytes = new TextEncoder().encode(stableStringify(signed));
    popManifestHash = await crypto.hash(manifestBytes);

    // Store ONLY the manifest — content is never stored (§6.4)
    await demoState.storage.put(popManifestHash, manifestBytes);

    resultDiv.innerHTML = `
      <div class="info-box success">
        <div>✓ Manifest signed (content <strong>NOT stored</strong>)</div>
        <div style="margin-top:0.25rem;font-size:0.8rem">
          <span class="badge-pop" style="padding:0.1rem 0.4rem;border-radius:0.2rem">contentStatus: private-custody-asserted</span>
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem;color:var(--text-muted)">
          Manifest hash: ${popManifestHash.substring(0, 32)}...
        </div>
      </div>
    `;

    // Reset clock
    (document.getElementById("pop-clock") as HTMLInputElement).value = "0";
    handlePoPClock();

    updateHood("pop-sign", {
      function: "buildUnsignedManifest + signManifest",
      mode: "proof-of-possession",
      contentStored: false,
      refreshPolicy: refreshPolicy || "none",
      manifestHash: popManifestHash,
    });
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

function handlePoPClock(): void {
  if (!popManifest || !popCreatedTime) return;
  const slider = document.getElementById("pop-clock") as HTMLInputElement;
  const days = parseInt(slider.value);
  const created = new Date(popCreatedTime);
  const checkDate = new Date(created.getTime() + days * 86400000);
  const checkTime = checkDate.toISOString().replace(/\.\d{3}Z$/, "Z");

  const refreshPolicy = (document.getElementById("pop-refresh") as HTMLSelectElement).value;
  const stale = isCustodyStale(popCreatedTime, refreshPolicy || undefined, checkTime);

  document.getElementById("pop-clock-display")!.textContent = `Verification time: ${checkTime.substring(0, 10)} (${days} days after creation)`;

  const stalenessEl = document.getElementById("pop-staleness")!;
  if (stale) {
    stalenessEl.innerHTML = `<span style="color:var(--yellow)">⚠ Custody assertion is <strong>stale</strong> (${days}d exceeds policy)</span>`;
  } else {
    stalenessEl.innerHTML = `<span style="color:var(--green)">✓ Custody assertion is <strong>current</strong> (${days}d within policy)</span>`;
  }
}

// ── E.2: Encrypted Distribution ────────────────────────────────────────

function renderEncryptedPanel(): string {
  return `
    <div class="panel" style="margin:0.5rem 0">
      <div class="panel-body">
        <div class="form-group">
          <label>Plaintext</label>
          <textarea class="form-input" id="enc-plaintext" rows="4" style="font-family:monospace;font-size:0.8rem">{ "name": "Dana Reeves",
  "clearance": "TS/SCI",
  "compartment": "GAMMA" }</textarea>
        </div>
        <div class="form-group">
          <label>Recipients</label>
          <div id="enc-recipients"></div>
          <button class="btn btn-sm" id="btn-enc-add-recipient" style="margin-top:0.25rem;font-size:0.7rem">+ Add Recipient</button>
        </div>
        <div class="action-bar">
          <button class="btn btn-primary" id="btn-enc-encrypt">Encrypt & Sign</button>
        </div>
        <div id="enc-hashes" style="margin-top:0.75rem"></div>
        <div id="enc-resolve-section" style="margin-top:0.75rem;display:none">
          <label style="font-size:0.8rem;font-weight:600">Resolve As...</label>
          <div style="display:flex;flex-direction:column;gap:0.25rem;margin-top:0.25rem" id="enc-perspectives"></div>
          <div id="enc-resolve-result" style="margin-top:0.5rem"></div>
        </div>
      </div>
    </div>
  `;
}

let encManifest: ResolutionManifest | null = null;
let encManifestHash: string | null = null;
let encStorage: InMemoryStorageAdapter | null = null;

function wireEncryptedPanel(): void {
  document.getElementById("enc-recipients")!.innerHTML = recipientListHTML(true);
  document.getElementById("btn-enc-encrypt")!.addEventListener("click", handleEncrypt);
  document.getElementById("btn-enc-add-recipient")!.addEventListener("click", () => {
    const name = `recipient-${demoState.privacyRecipients.length + 1}`;
    demoState.privacyRecipients.push({ id: name, ...generateX25519Keypair() });
    document.getElementById("enc-recipients")!.innerHTML = recipientListHTML(true);
  });
}

async function handleEncrypt(): Promise<void> {
  const hashesDiv = document.getElementById("enc-hashes")!;
  const keypair = demoState.activeKeypair!;
  const plaintext = (document.getElementById("enc-plaintext") as HTMLTextAreaElement).value;
  const plaintextBytes = new TextEncoder().encode(plaintext);

  try {
    // Compute plaintext hash
    const plaintextHash = await crypto.hash(plaintextBytes);

    // Build recipient list for encryption
    const recipients = demoState.privacyRecipients.map(r => ({
      id: r.id,
      x25519PublicKey: r.x25519Public,
    }));

    // Get publisher's X25519 public key
    const publisherX25519 = ed25519PublicToX25519(keypair.publicKey);

    // Encrypt
    const encResult = await encryptContent(plaintextBytes, recipients, publisherX25519);

    // Build encrypted manifest
    const created = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const encManifestParams = buildEncryptedManifest({
      authority: demoState.authority,
      ciphertext: encResult.ciphertext,
      plaintextHash,
      plaintextFormat: "application/json",
      plaintextSize: plaintextBytes.length,
      iv: encResult.iv,
      ephemeralPublicKey: encResult.ephemeralPublicKey,
      recipients: encResult.recipientKeys,
      version: "1",
      created,
    });

    const signed = await signManifest(encManifestParams, keypair, created, "JCS", crypto);
    encManifest = signed;

    const manifestBytes = new TextEncoder().encode(stableStringify(signed));
    encManifestHash = await crypto.hash(manifestBytes);

    // Store in isolated storage
    encStorage = new InMemoryStorageAdapter();
    await encStorage.put(encManifestHash, manifestBytes);

    // Store ciphertext at its hash
    const ciphertextHash = signed["hiri:content"].hash;
    await encStorage.put(ciphertextHash, encResult.ciphertext);

    hashesDiv.innerHTML = `
      <div style="padding:0.75rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)">
        <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.5rem">Dual Hashes</div>
        <div style="font-size:0.75rem;display:flex;flex-direction:column;gap:0.25rem">
          <div>Plaintext hash: <code>${plaintextHash.substring(0, 32)}...</code></div>
          <div>Ciphertext hash: <code>${ciphertextHash.substring(0, 32)}...</code></div>
          <div style="color:var(--text-muted);font-size:0.7rem">(manifest stores ciphertext hash; privacy block stores plaintext hash)</div>
        </div>
      </div>
    `;

    // Show resolve perspectives
    const section = document.getElementById("enc-resolve-section")!;
    section.style.display = "";
    const perspDiv = document.getElementById("enc-perspectives")!;
    perspDiv.innerHTML = `
      <label style="font-size:0.8rem;cursor:pointer">
        <input type="radio" name="enc-perspective" value="none" checked> Unauthorized (no key) → ciphertext-verified
      </label>
      ${demoState.privacyRecipients.map(r => `
        <label style="font-size:0.8rem;cursor:pointer">
          <input type="radio" name="enc-perspective" value="${r.id}"> ${r.id} (has key) → decrypted-verified
        </label>
      `).join("")}
      <label style="font-size:0.8rem;cursor:pointer">
        <input type="radio" name="enc-perspective" value="eve"> Eve (wrong key) → decryption-failed
      </label>
    `;

    // Wire perspective radio buttons
    perspDiv.querySelectorAll("input[type=radio]").forEach(radio => {
      radio.addEventListener("change", () => handleEncResolve((radio as HTMLInputElement).value));
    });

    // Auto-resolve as unauthorized
    handleEncResolve("none");

    updateHood("enc-encrypt", {
      function: "encryptContent + buildEncryptedManifest + signManifest",
      mode: "encrypted",
      recipientCount: recipients.length,
      plaintextHash,
      ciphertextHash,
      manifestHash: encManifestHash,
    });
  } catch (e) {
    hashesDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

async function handleEncResolve(perspective: string): Promise<void> {
  if (!encManifest || !encManifestHash || !encStorage) return;
  const resultDiv = document.getElementById("enc-resolve-result")!;
  const keypair = demoState.activeKeypair!;

  try {
    // Build resolve options based on perspective
    const opts: Record<string, unknown> = {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash: encManifestHash,
    };

    if (perspective !== "none") {
      if (perspective === "eve") {
        // Wrong key — generate random X25519 keypair
        const eveKeys = generateX25519Keypair();
        opts.decryptionKey = eveKeys.privateKey;
        opts.recipientId = "eve";
      } else {
        // Valid recipient
        const recipient = demoState.privacyRecipients.find(r => r.id === perspective)!;
        opts.decryptionKey = recipient.x25519Private;
        opts.recipientId = recipient.id;
      }
    }

    const uri = `hiri://${demoState.authority}/data/encrypted-demo`;
    const result = await resolveWithPrivacy(uri, encStorage, opts as Parameters<typeof resolveWithPrivacy>[2]);

    const statusColor = result.contentStatus === "decrypted-verified" ? "var(--green)"
      : result.contentStatus === "ciphertext-verified" ? "var(--accent)"
      : "var(--yellow)";

    resultDiv.innerHTML = `
      <div class="info-box ${result.verified ? "success" : "error"}">
        <div>verified: ${result.verified ? "✓ true" : "✗ false"}</div>
        <div style="margin-top:0.25rem">
          <span class="badge-enc" style="padding:0.1rem 0.4rem;border-radius:0.2rem">privacyMode: encrypted</span>
          <span style="padding:0.1rem 0.4rem;border-radius:0.2rem;background:rgba(88,166,255,0.1);color:${statusColor}">${result.contentStatus}</span>
        </div>
        ${result.decryptedContent ? `
          <div style="margin-top:0.5rem">
            <div style="font-size:0.75rem;font-weight:600">Decrypted content:</div>
            <pre style="font-size:0.75rem;margin-top:0.25rem">${new TextDecoder().decode(result.decryptedContent)}</pre>
          </div>
        ` : ""}
        ${result.warnings.length > 0 ? `
          <div style="margin-top:0.25rem;font-size:0.75rem;color:var(--yellow)">
            ${result.warnings.map(w => `⚠ ${w}`).join("<br>")}
          </div>
        ` : ""}
      </div>
    `;

    updateHood("enc-resolve", {
      function: "resolveWithPrivacy",
      perspective,
      verified: result.verified,
      contentStatus: result.contentStatus,
      privacyMode: result.privacyMode,
      hasDecryptedContent: !!result.decryptedContent,
      warnings: result.warnings,
    });
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

// ── E.3: Selective Disclosure ──────────────────────────────────────────

function renderSDPanel(): string {
  return `
    <div class="panel" style="margin:0.5rem 0">
      <div class="panel-body">
        <div class="form-group">
          <label>Source Document (N-Quads)</label>
          <textarea class="form-input" id="sd-source" rows="6" style="font-family:monospace;font-size:0.75rem"><https://example.org/person/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<https://example.org/person/1> <http://schema.org/name> "Dana Reeves" .
<https://example.org/person/1> <http://schema.org/jobTitle> "Protocol Architect" .
<https://example.org/person/1> <http://schema.org/email> "dana@example.org" .
<https://example.org/person/1> <http://schema.org/birthDate> "1990-05-15" .</textarea>
        </div>

        <div id="sd-statements" style="margin-top:0.5rem"></div>

        <div class="form-group" style="margin-top:0.5rem">
          <label style="font-size:0.8rem">Mandatory Statements (always visible)</label>
          <div id="sd-mandatory-list"></div>
        </div>

        <div class="form-group">
          <label>Recipients</label>
          <div id="sd-recipients" style="font-size:0.8rem"></div>
        </div>

        <div class="action-bar">
          <button class="btn" id="btn-sd-parse">Parse Statements</button>
          <button class="btn btn-primary" id="btn-sd-build" disabled>Build Index & Sign</button>
        </div>

        <div id="sd-index-result" style="margin-top:0.75rem"></div>

        <div id="sd-verify-section" style="margin-top:0.75rem;display:none">
          <label style="font-size:0.8rem;font-weight:600">Verifier Perspectives</label>
          <div style="display:flex;gap:0.5rem;margin-top:0.25rem">
            <button class="btn btn-sm" id="btn-sd-verify-unauth">Unauthorized</button>
            <button class="btn btn-sm" id="btn-sd-verify-alice">Alice</button>
            <button class="btn btn-sm" id="btn-sd-verify-bob">Bob</button>
          </div>
          <div id="sd-verify-result" style="margin-top:0.5rem"></div>
        </div>

        <div id="sd-attack-section" style="margin-top:0.75rem;display:none;border-top:1px solid var(--border);padding-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Dictionary Attack Defense (§B.9)</label>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">
            Attacker knows the predicate (schema:birthDate) and tries all dates.
          </div>
          <div id="sd-attack-result" style="margin-top:0.5rem"></div>
        </div>
      </div>
    </div>
  `;
}

let sdStatements: string[] = [];
let sdMandatoryIndices: number[] = [0, 1];
let sdManifest: ResolutionManifest | null = null;
let sdManifestHash: string | null = null;
let sdStorage: InMemoryStorageAdapter | null = null;
let sdSalt: Uint8Array | null = null;
let sdHmacTags: Uint8Array[] = [];
let sdStatementHashes: Uint8Array[] = [];

function wireSDPanel(): void {
  document.getElementById("btn-sd-parse")!.addEventListener("click", handleSDParse);
  document.getElementById("btn-sd-build")!.addEventListener("click", handleSDBuild);
  document.getElementById("sd-recipients")!.innerHTML = `
    <div style="font-size:0.75rem;margin-bottom:0.25rem">Alice: mandatory + statements 2,3 (name, job, email)</div>
    <div style="font-size:0.75rem">Bob: mandatory only (name only)</div>
  `;
}

function handleSDParse(): void {
  const source = (document.getElementById("sd-source") as HTMLTextAreaElement).value.trim();
  sdStatements = source.split("\n").filter(s => s.trim().length > 0);

  const listEl = document.getElementById("sd-mandatory-list")!;
  listEl.innerHTML = sdStatements.map((stmt, i) => {
    const checked = sdMandatoryIndices.includes(i) ? "checked" : "";
    const label = stmt.length > 70 ? stmt.substring(0, 67) + "..." : stmt;
    return `
      <label style="display:flex;align-items:flex-start;gap:0.25rem;font-size:0.75rem;margin-bottom:0.15rem;cursor:pointer">
        <input type="checkbox" class="sd-mandatory-cb" data-idx="${i}" ${checked} style="margin-top:0.15rem">
        <code>[${i}]</code> <span style="color:var(--text-muted)">${escapeHTML(label)}</span>
      </label>
    `;
  }).join("");

  // Wire checkboxes
  listEl.querySelectorAll(".sd-mandatory-cb").forEach(cb => {
    cb.addEventListener("change", () => {
      sdMandatoryIndices = [];
      listEl.querySelectorAll(".sd-mandatory-cb:checked").forEach(checked => {
        sdMandatoryIndices.push(parseInt((checked as HTMLInputElement).dataset.idx!));
      });
    });
  });

  document.getElementById("sd-statements")!.innerHTML = `
    <div style="font-size:0.8rem;color:var(--green)">✓ ${sdStatements.length} statements parsed</div>
  `;
  (document.getElementById("btn-sd-build") as HTMLButtonElement).disabled = false;
}

async function handleSDBuild(): Promise<void> {
  const resultDiv = document.getElementById("sd-index-result")!;
  const keypair = demoState.activeKeypair!;

  try {
    // Build statement index
    const indexResult = await buildStatementIndex(sdStatements);
    sdSalt = indexResult.salt;
    sdStatementHashes = indexResult.statementHashes;

    // Generate HMAC tags
    const hmacKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
    sdHmacTags = generateHmacTags(sdStatements, hmacKey, sdSalt);

    // Encrypt HMAC key for recipients
    // Alice gets statements 0,1,2,3; Bob gets "all" (but effectively only sees mandatory)
    const aliceRecipient = demoState.privacyRecipients.find(r => r.id === "alice");
    const bobRecipient = demoState.privacyRecipients.find(r => r.id === "bob");

    const disclosureMap = new Map<string, number[] | "all">();
    if (aliceRecipient) disclosureMap.set("alice", [0, 1, 2, 3]);
    if (bobRecipient) disclosureMap.set("bob", sdMandatoryIndices);

    const recipientKeys = new Map<string, Uint8Array>();
    if (aliceRecipient) recipientKeys.set("alice", aliceRecipient.x25519Public);
    if (bobRecipient) recipientKeys.set("bob", bobRecipient.x25519Public);

    const publisherX25519 = ed25519PublicToX25519(keypair.publicKey);
    const hmacDistribution = await encryptHmacKeyForRecipients(
      hmacKey,
      recipientKeys,
      disclosureMap,
      publisherX25519,
    );

    // Build the SD content blob
    const mandatoryNQuads = sdMandatoryIndices.map(i => sdStatements[i]);
    const sdContentBlob = stableStringify({
      mandatoryNQuads,
      statementIndex: sdStatementHashes.map(h => bytesToHex(h)),
      hmacTags: sdHmacTags.map(t => bytesToHex(t)),
    });
    const sdContentBytes = new TextEncoder().encode(sdContentBlob);
    const sdContentHash = await crypto.hash(sdContentBytes);

    // Build manifest with SD privacy block
    const created = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const unsigned = buildUnsignedManifest({
      authority: demoState.authority,
      contentHash: sdContentHash,
      contentFormat: "application/json",
      contentSize: sdContentBytes.length,
      version: "1",
      addressing: "raw-sha256",
      created,
    });

    // Index root
    const indexRootBytes = new Uint8Array(await globalThis.crypto.subtle.digest(
      "SHA-256",
      new Uint8Array(sdStatementHashes.reduce((acc, h) => {
        const merged = new Uint8Array(acc.length + h.length);
        merged.set(acc); merged.set(h, acc.length);
        return merged;
      }, new Uint8Array(0))),
    ));
    const indexRoot = "sha256:" + bytesToHex(indexRootBytes);

    (unsigned as Record<string, unknown>)["hiri:privacy"] = {
      mode: "selective-disclosure",
      parameters: {
        disclosureProofSuite: "hiri-hmac-sd-2026",
        statementCount: sdStatements.length,
        indexSalt: bytesToBase64url(sdSalt),
        indexRoot,
        mandatoryStatements: sdMandatoryIndices,
        hmacKeyRecipients: hmacDistribution,
      },
    };

    const signed = await signManifest(unsigned, keypair, created, "JCS", crypto);
    sdManifest = signed;

    const manifestBytes = new TextEncoder().encode(stableStringify(signed));
    sdManifestHash = await crypto.hash(manifestBytes);

    sdStorage = new InMemoryStorageAdapter();
    await sdStorage.put(sdManifestHash, manifestBytes);
    await sdStorage.put(sdContentHash, sdContentBytes);

    resultDiv.innerHTML = `
      <div style="padding:0.75rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface)">
        <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.5rem">Statement Index Built</div>
        <div style="font-size:0.75rem;display:flex;flex-direction:column;gap:0.15rem">
          <div>Salt: <code>${bytesToBase64url(sdSalt).substring(0, 20)}...</code></div>
          <div>Index root: <code>${indexRoot.substring(0, 32)}...</code></div>
          <div>Statements: ${sdStatements.length} total, ${sdMandatoryIndices.length} mandatory</div>
          <div>HMAC tags: ${sdHmacTags.length} tags generated</div>
          <div>Recipients: ${disclosureMap.size} (Alice: [0,1,2,3], Bob: mandatory only)</div>
        </div>
      </div>
    `;

    // Show verify section
    document.getElementById("sd-verify-section")!.style.display = "";
    document.getElementById("sd-attack-section")!.style.display = "";

    document.getElementById("btn-sd-verify-unauth")!.addEventListener("click", () => handleSDVerify("unauth"));
    document.getElementById("btn-sd-verify-alice")!.addEventListener("click", () => handleSDVerify("alice"));
    document.getElementById("btn-sd-verify-bob")!.addEventListener("click", () => handleSDVerify("bob"));

    // Static dictionary attack result
    document.getElementById("sd-attack-result")!.innerHTML = `
      <div style="font-size:0.75rem;padding:0.5rem;border:1px solid var(--border);border-radius:var(--radius)">
        <div>Withheld statement [4] is birthDate.</div>
        <div>Attacker tries date combinations against salted hash...</div>
        <div style="margin-top:0.25rem;color:var(--yellow)">⚠ Salted hash match <em>could</em> be found by enumeration</div>
        <div style="color:var(--green)">✓ But HMAC tag <strong>cannot be forged</strong> without the key</div>
        <div style="color:var(--text-muted);margin-top:0.25rem;font-size:0.7rem">Defense-in-depth: salt defeats rainbow tables, HMAC key defeats per-manifest enumeration (§B.9)</div>
      </div>
    `;

    // Clear hmac key
    hmacKey.fill(0);

    updateHood("sd-build", {
      function: "buildStatementIndex + generateHmacTags + encryptHmacKeyForRecipients",
      mode: "selective-disclosure",
      statementCount: sdStatements.length,
      mandatoryIndices: sdMandatoryIndices,
      indexRoot,
      recipientCount: disclosureMap.size,
    });
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

async function handleSDVerify(perspective: string): Promise<void> {
  if (!sdManifest || !sdManifestHash || !sdStorage) return;
  const resultDiv = document.getElementById("sd-verify-result")!;
  const keypair = demoState.activeKeypair!;

  try {
    const opts: Record<string, unknown> = {
      crypto,
      publicKey: keypair.publicKey,
      manifestHash: sdManifestHash,
    };

    if (perspective !== "unauth") {
      const recipient = demoState.privacyRecipients.find(r => r.id === perspective)!;
      opts.decryptionKey = recipient.x25519Private;
      opts.recipientId = recipient.id;
    }

    const uri = `hiri://${demoState.authority}/data/sd-demo`;
    const result = await resolveWithPrivacy(uri, sdStorage, opts as Parameters<typeof resolveWithPrivacy>[2]);

    const canVerify = perspective !== "unauth";
    resultDiv.innerHTML = `
      <div class="info-box ${result.verified ? "success" : "error"}">
        <div style="font-size:0.8rem;font-weight:600">${perspective === "unauth" ? "Unauthorized" : perspective.charAt(0).toUpperCase() + perspective.slice(1)}</div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          <span class="badge-sd" style="padding:0.1rem 0.4rem;border-radius:0.2rem">contentStatus: ${result.contentStatus}</span>
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          ${sdMandatoryIndices.length > 0 ? `✓ Can verify ${sdMandatoryIndices.length} mandatory statement(s) via index` : ""}
        </div>
        <div style="font-size:0.75rem">
          ${canVerify ? "✓ Can decrypt HMAC key and verify tags" : "✗ Cannot verify withheld statements"}
        </div>
        ${result.warnings.length > 0 ? `
          <div style="margin-top:0.25rem;font-size:0.7rem;color:var(--yellow)">
            ${result.warnings.map(w => `⚠ ${w}`).join("<br>")}
          </div>
        ` : ""}
      </div>
    `;
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

// ── E.4: Anonymous Publication ─────────────────────────────────────────

function renderAnonPanel(): string {
  return `
    <div class="panel" style="margin:0.5rem 0">
      <div class="panel-body">
        <div class="form-group">
          <label>Authority Type</label>
          <div style="display:flex;gap:1rem;margin-top:0.25rem">
            <label style="font-size:0.8rem;cursor:pointer">
              <input type="radio" name="anon-type" value="ephemeral" checked> Ephemeral
            </label>
            <label style="font-size:0.8rem;cursor:pointer">
              <input type="radio" name="anon-type" value="pseudonymous"> Pseudonymous
            </label>
          </div>
        </div>
        <div class="form-group">
          <label>Content Visibility</label>
          <select class="form-input" id="anon-visibility" style="width:auto">
            <option value="public" selected>Public</option>
            <option value="encrypted">Encrypted</option>
            <option value="private">Private (PoP)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Content</label>
          <textarea class="form-input" id="anon-content" rows="3" style="font-family:monospace;font-size:0.8rem">{ "whistleblower_report": true,
  "finding": "Unauthorized data sharing" }</textarea>
        </div>
        <div class="action-bar">
          <button class="btn btn-primary" id="btn-anon-sign">Generate Identity & Sign</button>
        </div>
        <div id="anon-result" style="margin-top:0.75rem"></div>

        <div style="margin-top:1rem;border-top:1px solid var(--border);padding-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Unlinkability Proof</label>
          <button class="btn btn-sm" id="btn-anon-unlink" style="margin-left:0.5rem;font-size:0.7rem">Generate Two Ephemeral Identities</button>
          <div id="anon-unlink-result" style="margin-top:0.5rem"></div>
        </div>

        <div style="margin-top:0.75rem;border-top:1px solid var(--border);padding-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Pseudonymous Comparison</label>
          <button class="btn btn-sm" id="btn-anon-pseudo" style="margin-left:0.5rem;font-size:0.7rem">Sign Two with Same Pseudonym</button>
          <div id="anon-pseudo-result" style="margin-top:0.5rem"></div>
        </div>
      </div>
    </div>
  `;
}

function wireAnonPanel(): void {
  document.getElementById("btn-anon-sign")!.addEventListener("click", handleAnonSign);
  document.getElementById("btn-anon-unlink")!.addEventListener("click", handleAnonUnlink);
  document.getElementById("btn-anon-pseudo")!.addEventListener("click", handleAnonPseudo);
}

async function handleAnonSign(): Promise<void> {
  const resultDiv = document.getElementById("anon-result")!;
  const authorityType = (document.querySelector("input[name=anon-type]:checked") as HTMLInputElement).value as "ephemeral" | "pseudonymous";
  const contentVisibility = (document.getElementById("anon-visibility") as HTMLSelectElement).value;
  const contentStr = (document.getElementById("anon-content") as HTMLTextAreaElement).value;

  try {
    // Generate ephemeral or pseudonymous identity
    let keypair: SigningKey;
    let authority: string;

    if (authorityType === "ephemeral") {
      const ephemeral = await generateEphemeralAuthority(crypto);
      keypair = { publicKey: ephemeral.publicKey, privateKey: ephemeral.privateKey };
      authority = ephemeral.authority;
      // Store for reference
      demoState.ephemeralKeypairs.push({
        publicKey: ephemeral.publicKey,
        privateKey: ephemeral.privateKey,
        authority,
      });
    } else {
      // Pseudonymous — generate once, reuse
      if (demoState.ephemeralKeypairs.length === 0 || !demoState.ephemeralKeypairs[0]) {
        const pseudo = await generateEphemeralAuthority(crypto);
        demoState.ephemeralKeypairs = [{
          publicKey: pseudo.publicKey,
          privateKey: pseudo.privateKey,
          authority: pseudo.authority,
        }];
      }
      const stored = demoState.ephemeralKeypairs[0];
      keypair = { publicKey: stored.publicKey, privateKey: stored.privateKey };
      authority = stored.authority;
    }

    const contentBytes = new TextEncoder().encode(contentStr);
    const contentHash = await crypto.hash(contentBytes);
    const created = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    const unsigned = buildUnsignedManifest({
      authority,
      contentHash,
      contentFormat: "application/json",
      contentSize: contentBytes.length,
      version: "1",
      addressing: "raw-sha256",
      created,
    });

    // Add anonymous privacy block
    const anonBlock = buildAnonymousPrivacyBlock(authorityType, contentVisibility as AnonymousParams["contentVisibility"]);
    (unsigned as Record<string, unknown>)["hiri:privacy"] = anonBlock;

    const signed = await signManifest(unsigned, keypair, created, "JCS", crypto);

    // Destroy private key for ephemeral
    if (authorityType === "ephemeral") {
      keypair.privateKey.fill(0);
    }

    resultDiv.innerHTML = `
      <div class="info-box success">
        <div>✓ Manifest signed anonymously</div>
        <div style="margin-top:0.25rem">
          <span class="badge-anon" style="padding:0.1rem 0.4rem;border-radius:0.2rem">identityType: ${authorityType === "ephemeral" ? "anonymous-ephemeral" : "pseudonymous"}</span>
          <span class="badge-anon" style="padding:0.1rem 0.4rem;border-radius:0.2rem;margin-left:0.25rem">contentVisibility: ${contentVisibility}</span>
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          Authority: <code>${authority.substring(0, 40)}...</code>
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem;color:var(--text-muted)">
          ${authorityType === "ephemeral" ? "Private key: destroyed after signing ✓" : "Private key: retained for linkability"}
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem;color:var(--text-muted)">
          KeyDocument: ${authorityType === "ephemeral" ? "NONE (§9.5)" : "optional (pseudonymous)"}
        </div>
      </div>
    `;

    updateHood("anon-sign", {
      function: "generateEphemeralAuthority + signManifest",
      mode: "anonymous",
      authorityType,
      contentVisibility,
      authority,
      privateKeyDestroyed: authorityType === "ephemeral",
      keyDocumentExpected: false,
    });
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

async function handleAnonUnlink(): Promise<void> {
  const resultDiv = document.getElementById("anon-unlink-result")!;
  try {
    const eph1 = await generateEphemeralAuthority(crypto);
    const eph2 = await generateEphemeralAuthority(crypto);

    const keysDiffer = bytesToHex(eph1.publicKey) !== bytesToHex(eph2.publicKey);

    resultDiv.innerHTML = `
      <div style="font-size:0.75rem;padding:0.5rem;border:1px solid var(--border);border-radius:var(--radius)">
        <div>Authority 1: <code>${eph1.authority.substring(0, 40)}...</code></div>
        <div>Authority 2: <code>${eph2.authority.substring(0, 40)}...</code></div>
        <div style="margin-top:0.25rem">
          Keys differ: ${keysDiffer ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">✗</span>'}
          &nbsp; Authorities differ: ${keysDiffer ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">✗</span>'}
        </div>
        <div style="color:var(--green);margin-top:0.25rem">→ Computationally unlinkable</div>
      </div>
    `;

    eph1.privateKey.fill(0);
    eph2.privateKey.fill(0);
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

async function handleAnonPseudo(): Promise<void> {
  const resultDiv = document.getElementById("anon-pseudo-result")!;
  try {
    // Generate one pseudonymous key, sign two manifests
    const pseudo = await generateEphemeralAuthority(crypto);
    const authority = pseudo.authority;

    resultDiv.innerHTML = `
      <div style="font-size:0.75rem;padding:0.5rem;border:1px solid var(--border);border-radius:var(--radius)">
        <div>Manifest 1 authority: <code>${authority.substring(0, 40)}...</code> ← same</div>
        <div>Manifest 2 authority: <code>${authority.substring(0, 40)}...</code> ← same</div>
        <div style="margin-top:0.25rem;color:var(--yellow)">→ Linkable (same persistent identity)</div>
        <div style="color:var(--text-muted);margin-top:0.25rem;font-size:0.7rem">Pseudonymous mode reuses the same keypair intentionally</div>
      </div>
    `;

    pseudo.privateKey.fill(0);
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

// ── E.5: Third-Party Attestation ───────────────────────────────────────

function renderAttestPanel(): string {
  return `
    <div class="panel" style="margin:0.5rem 0">
      <div class="panel-body">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
          <div>
            <label style="font-size:0.8rem;font-weight:600">Subject (data owner)</label>
            <div id="attest-subject" style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">
              Auto-generated on attestation sign
            </div>
          </div>
          <div>
            <label style="font-size:0.8rem;font-weight:600">Attestor (examiner)</label>
            <div id="attest-attestor" style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">
              Uses Tab A active key
            </div>
          </div>
        </div>

        <div style="margin-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Claim</label>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-top:0.25rem">
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Property</label>
              <input class="form-input" id="attest-property" value="security-clearance-valid" style="font-size:0.8rem">
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Value</label>
              <input class="form-input" id="attest-value" value="true" style="font-size:0.8rem">
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Scope</label>
              <input class="form-input" id="attest-scope" value="TS/SCI" style="font-size:0.8rem">
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Valid Until</label>
              <input class="form-input" id="attest-valid-until" value="2027-03-07T00:00:00Z" style="font-size:0.8rem">
            </div>
          </div>
        </div>

        <div style="margin-top:0.5rem">
          <label style="font-size:0.8rem;font-weight:600">Evidence</label>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-top:0.25rem">
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Method</label>
              <input class="form-input" id="attest-method" value="direct-examination" style="font-size:0.8rem">
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label style="font-size:0.7rem">Description</label>
              <input class="form-input" id="attest-description" value="Examined personnel security record" style="font-size:0.8rem">
            </div>
          </div>
        </div>

        <div class="action-bar" style="margin-top:0.75rem">
          <button class="btn btn-primary" id="btn-attest-sign">Sign Attestation</button>
        </div>
        <div id="attest-result" style="margin-top:0.75rem"></div>

        <div id="attest-verify-section" style="margin-top:0.75rem;display:none">
          <label style="font-size:0.8rem;font-weight:600">Verification</label>
          <div style="display:flex;gap:0.5rem;margin-top:0.25rem;flex-wrap:wrap">
            <button class="btn btn-sm" id="btn-attest-verify-full">Both Available</button>
            <button class="btn btn-sm" id="btn-attest-verify-partial">Subject Unavailable</button>
            <button class="btn btn-sm btn-danger" id="btn-attest-verify-revoked" style="font-size:0.7rem">Attestor Revoked</button>
          </div>
          <div id="attest-verify-result" style="margin-top:0.5rem"></div>
        </div>

        <div id="attest-staleness-section" style="margin-top:0.75rem;display:none;border-top:1px solid var(--border);padding-top:0.75rem">
          <label style="font-size:0.8rem;font-weight:600">Staleness Check</label>
          <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem">
            <span style="font-size:0.7rem;color:var(--text-muted)">Attested</span>
            <input type="range" id="attest-clock" min="0" max="730" value="0" style="flex:1">
            <span style="font-size:0.7rem;color:var(--text-muted)">+2 years</span>
          </div>
          <div id="attest-staleness-display" style="font-size:0.8rem;margin-top:0.25rem"></div>
        </div>
      </div>
    </div>
  `;
}

let attestManifest: SignedAttestationManifest | null = null;
let attestSubjectKeypair: SigningKey | null = null;
let attestSubjectManifest: ResolutionManifest | null = null;
let attestSubjectManifestHash: string | null = null;
let attestStorage: InMemoryStorageAdapter | null = null;
let attestCreatedTime: string = "";
let attestValidUntil: string = "";

function wireAttestPanel(): void {
  document.getElementById("btn-attest-sign")!.addEventListener("click", handleAttestSign);
}

async function handleAttestSign(): Promise<void> {
  const resultDiv = document.getElementById("attest-result")!;
  const attestorKeypair = demoState.activeKeypair!;

  try {
    // Generate subject identity
    attestSubjectKeypair = await generateKeypair(crypto);
    const subjectAuthority = deriveAuthority(attestSubjectKeypair.publicKey, "ed25519");

    // Build a simple subject manifest
    const subjectContent = new TextEncoder().encode('{"name":"Dana Reeves","clearance":"TS/SCI"}');
    const subjectContentHash = await crypto.hash(subjectContent);
    attestCreatedTime = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    const subjectUnsigned = buildUnsignedManifest({
      authority: subjectAuthority,
      contentHash: subjectContentHash,
      contentFormat: "application/json",
      contentSize: subjectContent.length,
      version: "1",
      addressing: "raw-sha256",
      created: attestCreatedTime,
    });
    attestSubjectManifest = await signManifest(subjectUnsigned, attestSubjectKeypair, attestCreatedTime, "JCS", crypto);

    const subjectManifestBytes = new TextEncoder().encode(stableStringify(attestSubjectManifest));
    attestSubjectManifestHash = await crypto.hash(subjectManifestBytes);

    // Build attestation
    const property = (document.getElementById("attest-property") as HTMLInputElement).value;
    const value = (document.getElementById("attest-value") as HTMLInputElement).value;
    const scope = (document.getElementById("attest-scope") as HTMLInputElement).value;
    attestValidUntil = (document.getElementById("attest-valid-until") as HTMLInputElement).value;
    const method = (document.getElementById("attest-method") as HTMLInputElement).value;
    const description = (document.getElementById("attest-description") as HTMLInputElement).value;

    const attestorAuthority = demoState.authority;

    const attestationUnsigned = buildAttestationManifest({
      attestorAuthority,
      subject: {
        authority: subjectAuthority,
        manifestHash: attestSubjectManifestHash,
        contentHash: subjectContentHash,
        manifestVersion: "1",
      },
      claim: {
        "@type": "hiri:PropertyAttestation" as const,
        property,
        value: value === "true" ? true : value === "false" ? false : value,
        scope: scope || undefined,
        attestedAt: attestCreatedTime,
        validUntil: attestValidUntil || undefined,
      },
      evidence: { method, description },
      version: "1",
      created: attestCreatedTime,
    });

    const signed = await signManifest(attestationUnsigned as unknown as Parameters<typeof signManifest>[0], attestorKeypair, attestCreatedTime, "JCS", crypto);
    attestManifest = signed as unknown as SignedAttestationManifest;

    // Store
    attestStorage = new InMemoryStorageAdapter();
    const attestManifestBytes = new TextEncoder().encode(stableStringify(signed));
    const attestManifestHash = await crypto.hash(attestManifestBytes);
    await attestStorage.put(attestManifestHash, attestManifestBytes);
    await attestStorage.put(attestSubjectManifestHash, subjectManifestBytes);
    await attestStorage.put(subjectContentHash, subjectContent);

    // Display subject info
    document.getElementById("attest-subject")!.innerHTML = `
      <div>Authority: <code>${subjectAuthority.substring(0, 32)}...</code></div>
      <div>Manifest: <code>${attestSubjectManifestHash.substring(0, 24)}...</code></div>
    `;
    document.getElementById("attest-attestor")!.innerHTML = `
      <div>Authority: <code>${attestorAuthority.substring(0, 32)}...</code></div>
    `;

    resultDiv.innerHTML = `
      <div class="info-box success">
        <div>✓ Attestation manifest signed</div>
        <div style="margin-top:0.25rem">
          <span class="badge-attest" style="padding:0.1rem 0.4rem;border-radius:0.2rem">@type: hiri:AttestationManifest</span>
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem;color:var(--text-muted)">
          hiri:content: ABSENT (§10.4)
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          Claim: <strong>${property}</strong> = ${value} (scope: ${scope || "none"})
        </div>
      </div>
    `;

    // Show verify section
    const verifySection = document.getElementById("attest-verify-section")!;
    verifySection.style.display = "";
    document.getElementById("btn-attest-verify-full")!.addEventListener("click", () => handleAttestVerify("full"));
    document.getElementById("btn-attest-verify-partial")!.addEventListener("click", () => handleAttestVerify("partial"));
    document.getElementById("btn-attest-verify-revoked")!.addEventListener("click", () => handleAttestVerify("revoked"));

    // Show staleness
    const stalenessSection = document.getElementById("attest-staleness-section")!;
    stalenessSection.style.display = "";
    document.getElementById("attest-clock")!.addEventListener("input", handleAttestClock);
    handleAttestClock();

    updateHood("attest-sign", {
      function: "buildAttestationManifest + signManifest",
      mode: "attestation",
      dualSignature: true,
      subjectAuthority,
      attestorAuthority,
      claim: { property, value, scope },
      "§10.4": "no hiri:content block",
    });
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

async function handleAttestVerify(scenario: "full" | "partial" | "revoked"): Promise<void> {
  if (!attestManifest || !attestSubjectKeypair) return;
  const resultDiv = document.getElementById("attest-verify-result")!;
  const attestorKeypair = demoState.activeKeypair!;

  try {
    const subjectManifest = scenario === "full" ? attestSubjectManifest : null;
    const subjectPublicKey = scenario === "full" ? attestSubjectKeypair.publicKey : null;
    const attestorKeyStatus = scenario === "revoked" ? "revoked" : "active";

    const result = await verifyAttestation(
      attestManifest,
      attestorKeypair.publicKey,
      subjectManifest,
      subjectPublicKey,
      crypto,
      attestorKeyStatus,
    );

    const trustColor = result.trustLevel === "full" ? "var(--green)"
      : result.trustLevel === "partial" ? "var(--yellow)"
      : "var(--red)";

    const trustBar = result.trustLevel === "full" ? "████████████"
      : result.trustLevel === "partial" ? "████████░░░░"
      : "░░░░░░░░░░░░";

    resultDiv.innerHTML = `
      <div class="info-box ${result.attestationVerified ? "success" : "error"}">
        <div style="font-size:0.8rem;font-weight:600">${scenario === "full" ? "Both Available" : scenario === "partial" ? "Subject Unavailable" : "Attestor Key Revoked"}</div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          Attestor signature: ${result.attestationVerified ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">✗</span>'}
        </div>
        <div style="font-size:0.75rem">
          Subject manifest: ${result.subjectManifestVerified ? '<span style="color:var(--green)">✓ verified</span>' : '<span style="color:var(--text-muted)">unavailable</span>'}
        </div>
        <div style="margin-top:0.25rem;font-size:0.75rem">
          Trust level: <span style="color:${trustColor};font-weight:600">${result.trustLevel.toUpperCase()}</span>
          <span style="font-family:monospace;letter-spacing:-1px;color:${trustColor}"> ${trustBar}</span>
        </div>
        ${result.stale ? '<div style="font-size:0.75rem;color:var(--yellow)">⚠ Attestation is stale</div>' : ""}
        ${result.warnings.length > 0 ? `
          <div style="margin-top:0.25rem;font-size:0.7rem;color:var(--yellow)">
            ${result.warnings.map(w => `⚠ ${w}`).join("<br>")}
          </div>
        ` : ""}
      </div>
    `;
  } catch (e) {
    resultDiv.innerHTML = `<div class="info-box error">${(e as Error).message}</div>`;
  }
}

function handleAttestClock(): void {
  if (!attestCreatedTime || !attestValidUntil) return;
  const slider = document.getElementById("attest-clock") as HTMLInputElement;
  const days = parseInt(slider.value);
  const created = new Date(attestCreatedTime);
  const checkDate = new Date(created.getTime() + days * 86400000);
  const validUntil = new Date(attestValidUntil);
  const stale = checkDate > validUntil;

  const displayEl = document.getElementById("attest-staleness-display")!;
  const checkStr = checkDate.toISOString().substring(0, 10);
  if (stale) {
    displayEl.innerHTML = `<span style="color:var(--yellow)">⚠ ${checkStr} — stale (past validUntil: ${attestValidUntil.substring(0, 10)})</span>`;
  } else {
    displayEl.innerHTML = `<span style="color:var(--green)">✓ ${checkStr} — valid (before ${attestValidUntil.substring(0, 10)})</span>`;
  }
}

// ── Shared Utilities ───────────────────────────────────────────────────

function updateHood(operation: string, data: Record<string, unknown>): void {
  const el = document.getElementById("hood-content-privacy");
  if (el) {
    el.innerHTML = `<pre>${stableStringify({ operation, ...data }, true)}</pre>`;
  }
}

function wireHoodToggle(): void {
  const toggle = document.getElementById("hood-toggle-privacy");
  const content = document.getElementById("hood-content-privacy");
  if (toggle && content) {
    toggle.addEventListener("click", () => {
      content.style.display = content.style.display === "none" ? "" : "none";
    });
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escapeHTML(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
