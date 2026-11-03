export interface BrowserBeaconOptions {
  endpoint?: string;
  getRoute?: () => string;
  maxReports?: number;
  target?: unknown;
}
/** Registers window.onerror + unhandledrejection; returns an uninstall function. */
export function installBrowserBeacon(options?: BrowserBeaconOptions): () => void;
