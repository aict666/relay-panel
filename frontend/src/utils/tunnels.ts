import type { Tunnel } from '../api/types';

/**
 * An existing preset binding may be preserved even when the tunnel is no
 * longer present in the user's selectable catalog. Missing catalog data must
 * never authorize a new binding; the backend remains the final permission
 * check for resume/rebind operations.
 */
export function canUsePresetForRuleUpdate(
  requestedId: number | undefined,
  existingId: number | null | undefined,
  preset: Tunnel | undefined,
): boolean {
  if (!requestedId) return false;
  const keepingCurrent = requestedId === existingId;
  if (!preset) return keepingCurrent;
  return (preset.enabled || keepingCurrent) && preset.hops.length >= 2;
}

/** Snapshot the exact persisted route shown when an administrator opens the
 * edit form. Automatic ports must stay concrete here: the backend compares
 * this value transactionally to reject stale full-path replacements. */
export function tunnelPathSnapshot(tunnel: Pick<Tunnel, 'hops'>) {
  return tunnel.hops.map(hop => ({
    device_group_id: hop.device_group_id,
    listen_port: hop.listen_port ?? null,
  }));
}

/** Only send scalar fields the administrator actually changed after opening
 * the form. A path replacement carries an optimistic hop snapshot, but an
 * unchanged stale name/status/sharing value must not overwrite another
 * administrator's independent partial update. */
export function tunnelScalarChanges(
  tunnel: Pick<Tunnel, 'name' | 'enabled' | 'shared'>,
  next: Pick<Tunnel, 'name' | 'enabled' | 'shared'>,
) {
  const changes: Partial<Pick<Tunnel, 'name' | 'enabled' | 'shared'>> = {};
  if (next.name !== tunnel.name) changes.name = next.name;
  if (next.enabled !== tunnel.enabled) changes.enabled = next.enabled;
  if (next.shared !== tunnel.shared) changes.shared = next.shared;
  return changes;
}

export interface TunnelHopDraft {
  device_group_id?: number;
  port_mode?: 'auto' | 'fixed';
  listen_port?: number | null;
}

/** Whether a tunnel form changes the persisted topology. "Auto" is not a
 * stored mode: for an unchanged group it means preserve the concrete allocated
 * port, so scalar-only edits must not delete/recreate all hop rows. */
export function tunnelPathChanged(tunnel: Pick<Tunnel, 'hops'>, drafts: TunnelHopDraft[]) {
  if (drafts.length !== tunnel.hops.length) return true;
  return drafts.some((draft, index) => {
    const stored = tunnel.hops[index];
    if (draft.device_group_id !== stored.device_group_id) return true;
    return index > 0
      && draft.port_mode === 'fixed'
      && draft.listen_port !== stored.listen_port;
  });
}
