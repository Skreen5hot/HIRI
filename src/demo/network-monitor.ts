/**
 * Network Monitor
 *
 * Intercepts fetch, XMLHttpRequest, and navigator.sendBeacon
 * to prove zero network activity during protocol operations.
 */

export interface NetworkMonitor {
  /** Number of intercepted network calls since last reset */
  readonly callCount: number;
  /** Whether any network call has been made since last reset */
  readonly violated: boolean;
  /** Reset the counter */
  reset(): void;
  /** Get the log of intercepted calls */
  readonly log: string[];
}

let callCount = 0;
let log: string[] = [];
let installed = false;

const monitor: NetworkMonitor = {
  get callCount() {
    return callCount;
  },
  get violated() {
    return callCount > 0;
  },
  reset() {
    callCount = 0;
    log = [];
  },
  get log() {
    return [...log];
  },
};

export function installNetworkMonitor(): NetworkMonitor {
  if (installed) return monitor;
  installed = true;

  // Intercept fetch
  const originalFetch = globalThis.fetch;
  if (originalFetch) {
    globalThis.fetch = function (...args: Parameters<typeof fetch>) {
      callCount++;
      const url = typeof args[0] === "string" ? args[0] : args[0] instanceof URL ? args[0].href : "(Request)";
      log.push(`fetch: ${url}`);
      return originalFetch.apply(this, args);
    } as typeof fetch;
  }

  // Intercept XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  if (originalOpen) {
    XMLHttpRequest.prototype.open = function (method: string, url: string | URL, ...rest: unknown[]) {
      callCount++;
      log.push(`XHR: ${method} ${url}`);
      return (originalOpen as Function).call(this, method, url, ...rest);
    } as typeof XMLHttpRequest.prototype.open;
  }

  // Intercept sendBeacon
  if (navigator.sendBeacon) {
    const originalBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url: string | URL, data?: BodyInit | null) {
      callCount++;
      log.push(`sendBeacon: ${url}`);
      return originalBeacon(url, data);
    };
  }

  return monitor;
}

export function getNetworkMonitor(): NetworkMonitor {
  return monitor;
}
