# M18: Export/Import Package — Cross-Session Transfer

## Objective

Enable genuine cross-session data transfer for the demo. A presenter signs content in one browser session, exports a self-contained verification package, and imports it in a separate browser session (incognito or different machine) for resolution. No shared state, no presets, no shortcuts.

This is the missing piece in the demo script: Acts 1–2 claim "transport doesn't matter" but currently rely on presets that generate independent data in each session.

## The User Flow

```
Main Browser (Tab B)              Incognito Browser (Tab D)
─────────────────────             ─────────────────────────
1. Generate identity (Tab A)
2. Sign content (Tab B)
3. Click "Export Package"
   → JSON blob on clipboard
                                  4. Click "Import Package"
                                     → Paste from clipboard
                                  5. URI and key auto-populated
                                  6. Click "Resolve"
                                     → Green checkmarks
                                     → "Zero Network" stays green
```

## Files Touched (3)

| File | Action | What |
|------|--------|------|
| `src/demo/tab-build.ts` | MODIFY | Add "Export Package" button after sign, generate export blob |
| `src/demo/tab-resolve.ts` | MODIFY | Add "Import Package" section above resolver, parse blob, populate storage + UI |
| `site/index.html` | MODIFY | Add import section HTML to Tab D |

Architectural review: 3 files, all Layer 2 demo. Zero kernel changes. Zero privacy layer changes.

## Package Format

A single JSON object containing everything needed to verify a manifest independently:

```typescript
interface HiriExportPackage {
  /** Format version for forward compatibility */
  version: 1;

  /** The authority string (e.g., "key:ed25519:z6Mk...") */
  authority: string;

  /** The HIRI URI to resolve */
  uri: string;

  /** Ed25519 public key, base64url encoded (no padding) */
  publicKey: string;

  /** Array of storage entries — manifest(s) + content + deltas */
  entries: Array<{
    /** Content-addressed hash (e.g., "sha256:abc123...") */
    hash: string;
    /** Raw bytes, base64url encoded (no padding) */
    data: string;
  }>;

  /** Optional: privacy mode hint for Tab D badge display */
  privacyMode?: string;

  /** Optional: Key Document hash for key rotation scenarios */
  keyDocumentHash?: string;
}
```

### Design Decisions

**Why base64url, not hex?** The package needs to survive clipboard copy/paste. Base64url is ~33% smaller than hex for the same bytes. A typical package (1 manifest + 1 content blob) is ~2–4KB as base64url JSON.

**Why an entries array, not separate fields?** Version chains have multiple manifests plus content plus delta blobs. A flat array of hash→data pairs is the simplest structure that handles chains of any depth. The import side just does `for (const entry of entries) storage.put(entry.hash, decode(entry.data))`.

**Why include the URI?** So the import side can auto-populate the URI field in Tab D. The user doesn't need to copy the URI separately.

**Why include the authority?** For display purposes in the import confirmation. Not used for verification — the public key is what matters.

**Why no private key?** The export package is designed to be shared on untrusted channels. It contains only public verification material. The importer can verify but not sign.

## Task 1: Export (tab-build.ts)

### UI

Add an "Export Package" button to the action bar in Tab B. The button appears after the first successful sign (disabled before that).

```
[Draft & Sign (V1)]  [Update & Chain (V2)]  [Verify Chain]  [Export Package]
```

### Behavior

On click:

1. Collect all manifest entries from `demoState.manifests` (handles chains of any depth)
2. For each manifest entry: include the manifest bytes (serialized signed manifest) and the content bytes
3. If deltas exist in the chain, include delta blobs
4. Include the public key from `demoState.primaryKeypair` (the genesis key)
5. Include the URI from the latest manifest's `@id` field
6. Include the latest manifest hash (the entry point for resolution)
7. Serialize as JSON, copy to clipboard via `navigator.clipboard.writeText()`
8. Show confirmation: "Package copied to clipboard (X.X KB, Y manifests, Z content blobs)"

### Export Function

```typescript
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

  // If deltas are stored separately, include them too
  // (deltaHash → deltaBytes from demoState if tracked)

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
  if (privacy && typeof privacy === "object" && "mode" in privacy) {
    pkg.privacyMode = (privacy as Record<string, unknown>).mode as string;
  }

  return JSON.stringify(pkg);
}
```

### Clipboard Handling

```typescript
try {
  await navigator.clipboard.writeText(json);
  showConfirmation(`Package copied to clipboard (${(json.length / 1024).toFixed(1)} KB)`);
} catch {
  // Fallback: show the JSON in a textarea for manual copy
  showCopyFallback(json);
}
```

The clipboard API may fail in non-HTTPS contexts or if the page doesn't have focus. The fallback shows a read-only textarea with the JSON pre-selected and a "Copy" button that uses `document.execCommand('copy')`.

## Task 2: Import (tab-resolve.ts)

### UI

Add an "Import Package" section at the top of Tab D's resolver panel, above the existing URI input:

```
┌─ Import Package ─────────────────────────────────────────┐
│                                                          │
│ [Paste a HIRI export package to verify independently]    │
│                                                          │
│ ┌──────────────────────────────────────────────────────┐ │
│ │                                                      │ │
│ │  (paste area — textarea, 3 rows)                     │ │
│ │                                                      │ │
│ └──────────────────────────────────────────────────────┘ │
│                                                          │
│ [Import & Load]                                          │
│                                                          │
│ (after import:)                                          │
│ ✓ Imported: 2 manifests, 2 content blobs (3.2 KB)       │
│   Authority: key:ed25519:z6Mk...                        │
│   URI auto-populated. Click Resolve.                     │
└──────────────────────────────────────────────────────────┘
```

### Behavior

On "Import & Load" click:

1. Parse the textarea content as JSON
2. Validate the package structure (version, required fields, entries array)
3. Decode the public key from base64url
4. For each entry in `entries`: decode data from base64url, call `storage.put(hash, bytes)`
5. Verify that each stored entry's hash matches (compute `crypto.hash(bytes)`, compare to declared hash — reject if mismatch, this catches clipboard corruption)
6. Set `demoState.primaryKeypair` to a verification-only keypair (public key only, no private key)
7. Set `demoState.latestManifestHash` to the last manifest hash in the entries array
8. Auto-populate the URI input field
9. Auto-populate the public key for resolution
10. Show confirmation with entry count and size
11. Enable the Resolve button

### Import Function

```typescript
async function importPackage(json: string): Promise<ImportResult> {
  const pkg = JSON.parse(json) as HiriExportPackage;

  // Validate structure
  if (pkg.version !== 1) throw new Error(`Unsupported package version: ${pkg.version}`);
  if (!pkg.authority || !pkg.uri || !pkg.publicKey || !Array.isArray(pkg.entries)) {
    throw new Error("Invalid package structure");
  }
  if (pkg.entries.length === 0) throw new Error("Package contains no entries");

  // Decode public key
  const publicKey = base64urlDecode(pkg.publicKey);
  if (publicKey.length !== 32) throw new Error(`Invalid public key length: ${publicKey.length}`);

  // Store entries with integrity check
  let manifestCount = 0;
  let contentCount = 0;
  let totalBytes = 0;

  for (const entry of pkg.entries) {
    const bytes = base64urlDecode(entry.data);
    // INVARIANT: crypto.hash() returns "sha256:<hex>" format, matching the
    // declared hash in pkg.entries[].hash. If the demo adopts CIDv1 addressing,
    // this comparison must be updated.
    const computedHash = await crypto.hash(bytes);

    if (computedHash !== entry.hash) {
      throw new Error(
        `Integrity check failed for ${entry.hash.substring(0, 24)}... ` +
        `(computed ${computedHash.substring(0, 24)}...)`
      );
    }

    await demoState.storage.put(entry.hash, bytes);
    totalBytes += bytes.length;

    // Heuristic: manifests are JSON with "@type", content is anything else
    try {
      const parsed = JSON.parse(new TextDecoder().decode(bytes));
      if (parsed["@type"] || parsed["hiri:signature"]) {
        manifestCount++;
      } else {
        contentCount++;
      }
    } catch {
      contentCount++; // Binary content (e.g., ciphertext)
    }
  }

  // Determine the manifest hash (last manifest entry, or the one whose
  // URI matches pkg.uri)
  const lastManifestHash = findManifestHash(pkg.entries);

  // Restore Key Document if present (key rotation scenario)
  if (pkg.keyDocumentHash) {
    const kdBytes = await demoState.storage.get(pkg.keyDocumentHash);
    if (kdBytes) {
      const keyDocument = JSON.parse(new TextDecoder().decode(kdBytes));
      demoState.keyDocument = keyDocument;
    }
  }

  return {
    authority: pkg.authority,
    uri: pkg.uri,
    publicKey,
    manifestHash: lastManifestHash,
    privacyMode: pkg.privacyMode,
    manifestCount,
    contentCount,
    totalBytes,
  };
}
```

### Finding the Head Manifest Hash

The entries array contains both manifests and content blobs. The head manifest (the one to resolve) is identified by:

1. Parse each entry as JSON
2. If it has `"hiri:version"` and `"hiri:signature"`, it's a manifest
3. The manifest with the highest `"hiri:version"` value is the head
4. Its hash in the entries array is the `manifestHash` for resolution

```typescript
function findManifestHash(entries: Array<{ hash: string; data: string }>): string {
  let headHash = entries[0].hash;
  let headVersion = "0";

  for (const entry of entries) {
    try {
      const parsed = JSON.parse(
        new TextDecoder().decode(base64urlDecode(entry.data))
      );
      if (parsed["hiri:signature"] && parsed["hiri:version"]) {
        if (Number(parsed["hiri:version"]) > Number(headVersion)) {
          headVersion = parsed["hiri:version"];
          headHash = entry.hash;
        }
      }
    } catch {
      // Not JSON — skip (binary content)
    }
  }

  return headHash;
}
```

### Post-Import State

After a successful import, the resolver should behave exactly as if the data had been created locally:

- The URI field is populated with `pkg.uri`
- The public key is set for verification
- The Resolve button works normally
- The Fault Injection panel works normally (corrupt, tamper, reset)
- The "Prove Byte-Identical" button works (same data in all three adapter latencies)
- Privacy mode badges appear if the manifest has a `hiri:privacy` block
- If a Key Document was imported, the resolver receives it for key lifecycle verification:

```typescript
// In the post-import state setup:
if (demoState.keyDocument) {
  resolveOptions.keyDocument = demoState.keyDocument;
  resolveOptions.verificationTime = new Date().toISOString();
}
```

The only difference from locally-created data: there is no private key. The import is verification-only. Tab B remains empty (no manifests in `demoState.manifests`). Only Tab D is populated.

## Task 3: HTML Changes (index.html)

Add the import section to Tab D's resolve-main div, above the existing Resolver panel:

```html
<div id="import-section" class="panel" style="margin-bottom:1rem">
  <div class="panel-header">Import Package</div>
  <div class="panel-body">
    <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:0.5rem">
      Paste a HIRI export package from another session to verify independently.
    </p>
    <textarea class="form-input" id="import-input" rows="3"
      placeholder="Paste export package JSON here..."></textarea>
    <div class="action-bar" style="margin-top:0.5rem">
      <button class="btn btn-primary" id="btn-import">Import & Load</button>
    </div>
    <div id="import-result" style="margin-top:0.5rem"></div>
  </div>
</div>
```

## Edge Cases

### Clipboard paste includes surrounding whitespace or quotes
Trim the input. If it starts with `"` and ends with `"`, strip the outer quotes (some systems wrap clipboard text in quotes).

### Package is too large for clipboard (~1MB+ chains)
For chains with many versions, the JSON blob could exceed practical clipboard limits. Show a warning if the export exceeds 500KB. For very large chains, offer a download-as-file alternative (`.hiri` extension, `application/json` content type).

### Import into a session that already has data
The import adds to the existing storage — it doesn't clear it. This means you can import multiple packages into the same session. If there's a hash collision (same hash, different bytes), the integrity check will catch it. If the same hash exists with the same bytes, it's a no-op (idempotent).

### Privacy manifests (encrypted, SD, attestation)
The export includes the signed manifest and the stored content (which may be ciphertext for Mode 2 or an SD content blob for Mode 3). The import side resolves via `resolveWithPrivacy()` which handles all modes. For encrypted content, the importer sees `ciphertext-verified` (no decryption key). For attestation manifests, the importer sees `attestation-verified`. This is correct: the export is verification-only, not access-granting.

### Key Document inclusion
If `demoState.keyDocument` exists (key rotation scenario), include it as an additional entry in the package. The resolver needs it for key lifecycle verification. Add a `keyDocumentHash` field to the package if present.

```typescript
// In exportPackage():
if (demoState.keyDocument) {
  const kdBytes = new TextEncoder().encode(stableStringify(demoState.keyDocument));
  const kdHash = await crypto.hash(kdBytes);
  entries.push({ hash: kdHash, data: base64urlEncode(kdBytes) });
  pkg.keyDocumentHash = kdHash;
}
```

## Demo Script Integration

The demo script (Act 2) changes from:

> "Load the 'Chain with Delta' preset in both sessions"

To:

> "In the main browser, Tab B, click 'Export Package'. The entire signed data package is now on my clipboard — manifest, content, signature, public key. Everything needed to verify."
>
> *Switch to incognito.*
>
> "In Tab D, I paste it into the Import box. Click 'Import & Load'."
>
> *Click Import. Point to the confirmation: "Imported: 1 manifest, 1 content blob, 2.4 KB"*
>
> "The data arrived. Let's verify it."
>
> *Click Resolve.*

This is a genuine transfer. The audience watches bytes move from one session to another via the clipboard — the most untrusted channel possible.

## Verification Checklist

- [ ] Export button appears after first sign in Tab B
- [ ] Export copies valid JSON to clipboard
- [ ] Export confirmation shows size and entry count
- [ ] Clipboard fallback textarea appears when clipboard API fails
- [ ] Import parses JSON and populates storage
- [ ] Import integrity check catches corrupted entries (flip one base64 character, expect error)
- [ ] Import auto-populates URI field in Tab D
- [ ] Resolve works after import with zero additional setup
- [ ] Network indicator stays green throughout export and import
- [ ] Chain exports include all manifests + content + deltas
- [ ] Privacy manifests export and import correctly (encrypted → ciphertext-verified on import)
- [ ] Key rotation exports include Key Document
- [ ] Import into a session with existing data doesn't corrupt existing entries
- [ ] Export of 10+ version chain stays under 500KB
- [ ] Fault injection works on imported data (corrupt, tamper, reset)
