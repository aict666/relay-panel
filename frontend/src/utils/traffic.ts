export const BYTES_PER_GB = 1024 * 1024 * 1024;

// Keep every byte count produced by the browser inside JavaScript's exact
// integer range. The backend accepts i64, but values above this boundary can
// be silently rounded before JSON serialization.
export const MAX_SAFE_TRAFFIC_GB = Math.floor(Number.MAX_SAFE_INTEGER / BYTES_PER_GB);

export function bytesToGb(bytes: number): number {
  return bytes > 0 ? Math.round((bytes / BYTES_PER_GB) * 100) / 100 : 0;
}

export function gbToBytes(gb: number): number {
  return Math.round((gb || 0) * BYTES_PER_GB);
}

/**
 * Forms display only two decimal places. Compare the submitted GB value with
 * that same display projection, not with the original byte count, so saving an
 * unrelated field does not rewrite an exact byte quota with a rounded value.
 */
export function trafficGbChanged(originalBytes: number, submittedGb: number): boolean {
  return submittedGb !== bytesToGb(originalBytes);
}
