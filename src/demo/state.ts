/**
 * Demo State
 *
 * Single mutable state object shared across all workspaces.
 * Holds keypairs, manifests, storage adapters, and Key Documents.
 */

import type {
  SigningKey,
  ResolutionManifest,
  KeyDocument,
  StorageAdapter,
} from "../kernel/types.js";
import { InMemoryStorageAdapter } from "../adapters/persistence/storage.js";

export interface ManifestEntry {
  manifest: ResolutionManifest;
  manifestHash: string;
  contentBytes: Uint8Array;
  contentHash: string;
  version: number;
}

export interface KeypairEntry {
  keypair: SigningKey;
  keyId: string;
  authority?: string;
}

export class DemoState {
  // Identity
  keypairs: KeypairEntry[] = [];
  authority: string = "";
  keyDocument: KeyDocument | null = null;

  // Content & Chain
  manifests: ManifestEntry[] = [];
  currentFormData: Record<string, string> = {};

  // Storage
  storage: InMemoryStorageAdapter = new InMemoryStorageAdapter();

  // UI state
  activeTab: string = "keys";
  initialized: boolean = false;

  /** Get the primary (genesis) keypair */
  get primaryKeypair(): SigningKey | null {
    return this.keypairs.length > 0 ? this.keypairs[0].keypair : null;
  }

  /** Get the currently active keypair (last one) */
  get activeKeypair(): SigningKey | null {
    return this.keypairs.length > 0
      ? this.keypairs[this.keypairs.length - 1].keypair
      : null;
  }

  /** Get the latest manifest */
  get latestManifest(): ManifestEntry | null {
    return this.manifests.length > 0
      ? this.manifests[this.manifests.length - 1]
      : null;
  }

  /** Get the latest manifest hash (for URI construction) */
  get latestManifestHash(): string | null {
    return this.latestManifest?.manifestHash ?? null;
  }

  /** Reset all state */
  clear(): void {
    this.keypairs = [];
    this.authority = "";
    this.keyDocument = null;
    this.manifests = [];
    this.currentFormData = {};
    this.storage = new InMemoryStorageAdapter();
    this.initialized = false;
  }
}

// Singleton
export const demoState = new DemoState();
