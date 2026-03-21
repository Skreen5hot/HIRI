# M19: Privacy Panel Export Buttons

## Summary

Add "Export Package" buttons to E.2 (Encrypted), E.3 (Selective Disclosure), and E.5 (Attestation). Same format as Tab B's M18 export. Same import flow in Tab D — no import changes needed.

## Files Touched (2)

| File | Action |
|------|--------|
| `src/demo/tab-privacy.ts` | Add export button + handler to 3 panels |
| `site/index.html` | Add button elements to E.2, E.3, E.5 action bars |

Zero kernel, zero privacy layer, zero adapter changes.

## Button Placement

```
E.2: [Encrypt & Sign]  [Export Package]    ← disabled until encrypt succeeds
E.3: [Build Index & Sign]  [Export Package] ← disabled until build succeeds
E.5: [Sign Attestation]  [Export Package]   ← disabled until sign succeeds
```

Same styling as Tab B's export button. Same clipboard + fallback behavior.

## What Each Export Contains

### E.2 — Encrypted Distribution

| Entry | Include | Exclude |
|-------|---------|---------|
| Signed encrypted manifest | ✓ | |
| Ciphertext blob | ✓ | |
| Plaintext | | ✗ Never |
| Recipient private keys | | ✗ Never |
| Key Document (if rotated) | ✓ if exists | |

Import-side result: `ciphertext-verified` (unauthorized), `decrypted-verified` (if recipient key is available in importing session — it won't be).

### E.3 — Selective Disclosure

| Entry | Include | Exclude |
|-------|---------|---------|
| Signed SD manifest | ✓ | |
| SD content blob (mandatoryNQuads, statementIndex, hmacTags) | ✓ | |
| HMAC key | | ✗ Never |
| Withheld statement text | | ✗ Never (not in blob by design) |
| Key Document (if rotated) | ✓ if exists | |

Import-side result: mandatory statements visible, withheld statements absent.

### E.5 — Attestation

| Entry | Include | Exclude |
|-------|---------|---------|
| Signed attestation manifest | ✓ | |
| Subject signed manifest | ✓ if available | |
| Subject content blob | ✓ if available | |
| Key Document (if rotated) | ✓ if exists | |

Import-side result: `trustLevel: full` if subject included, `trustLevel: partial` if not.

## Implementation

Each panel stores its result in panel-local state after the sign/encrypt/build action. Add a `getExportableEntries()` call per panel that returns the M18 package format:

```typescript
interface HiriExportPackage {
  version: 1;
  authority: string;
  uri: string;
  publicKey: string;         // base64url
  entries: Array<{
    hash: string;            // "sha256:..."
    data: string;            // base64url
  }>;
  privacyMode?: string;
  keyDocumentHash?: string;  // if Key Document included
}
```

The export handler is identical across all three panels:

```typescript
async function handleExport(getEntries: () => Promise<HiriExportPackage>) {
  const pkg = await getEntries();
  const json = JSON.stringify(pkg);
  try {
    await navigator.clipboard.writeText(json);
    showConfirmation(`Package copied (${(json.length / 1024).toFixed(1)} KB)`);
  } catch {
    showCopyFallback(json);
  }
}
```

The per-panel `getEntries` functions differ only in which blobs they collect. Reuse the `base64urlEncode` and hash format from M18.

## CRITICAL: What Must NOT Be Exported

- E.2: No plaintext bytes. No recipient X25519 private keys. No CEK.
- E.3: No HMAC key. No recipient X25519 private keys. (Withheld statement text is already absent from the SD blob by design — just don't add it.)
- E.5: No attestor private key.

The export is verification-only material. The import side can prove authenticity but cannot access protected content. This is the demo point.

## Verification Checklist

- [ ] E.2 export button appears after successful encrypt
- [ ] E.2 export contains manifest + ciphertext only (no plaintext)
- [ ] E.3 export button appears after successful build
- [ ] E.3 export contains manifest + SD blob only (no HMAC key)
- [ ] E.5 export button appears after successful sign
- [ ] E.5 export contains attestation manifest (no private keys)
- [ ] All three imports resolve correctly in Tab D
- [ ] Network indicator stays green throughout
- [ ] `privacyMode` field is set correctly in each package
- [ ] Clipboard fallback works when clipboard API is unavailable
