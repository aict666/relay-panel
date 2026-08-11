// Transfer figures vary much more than status/resource values. Give those
// columns enough room to remain readable while preserving the fork's wider
// status column for control-channel warnings.
export const nodeDesktopColumnWidths = {
  status: 100,
  nodeVersion: 100,
  nodeUpgrade: 72,
  cpu: 84,
  mem: 100,
  disk: 100,
  rate: 192,
  traffic: 172,
} as const;
