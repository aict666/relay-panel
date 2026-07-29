/**
 * v1.3.16: control-plane liveness, kept strictly separate from `online`.
 *
 * A node has TWO independent channels to the panel:
 *   - the HTTP status report (data plane heartbeat) → drives `online`
 *   - the WS control channel                        → drives this module
 *
 * They fail independently, and for a while the board only ever showed the
 * first. A node whose wss:// upgrade was blocked kept reporting status every
 * 30s and rendered as a healthy 在线 row, while "诊断" answered
 * "控制通道离线，无法下发" — two screens contradicting each other, with no way
 * to tell which was lying. Nothing was lying; they measure different things.
 *
 * Pure function so both the desktop table and the mobile list resolve the state
 * identically (same reason upgrade.ts exists).
 */
import type { NodeDisplayRow } from '../../api/types';

export type ControlChannelState =
  /** Nothing to say: the node is fully offline (the offline tag already covers
   *  it), or the panel/endpoint doesn't report control-plane state at all —
   *  an older panel, or the regular-user board. Render NOTHING. */
  | 'unknown'
  /** WS control channel is live — directed commands work. */
  | 'online'
  /** No live socket for this node's group at all: the node never completed a
   *  WS upgrade. Typically wss:// blocked on the path, or a reverse proxy that
   *  doesn't forward Upgrade. */
  | 'offline'
  /** This node is not addressable and its group also has one or more
   *  unidentified sockets. Because those sockets have no node_id, the panel
   *  cannot prove that any one of them belongs to this particular row. */
  | 'group-unidentified';

export type ControlChannelTipKey =
  | 'controlChannelOfflineTip'
  | 'controlChannelUnidentifiedTip';

/**
 * Resolve what (if anything) to warn about for one node row.
 *
 * A node that is wholly offline returns 'unknown', not 'offline': its status
 * tag already says 离线, and stacking a second warning on top adds noise
 * without adding information. The states that matter are the contradictory
 * ones — node reporting fine, control plane not.
 */
export function resolveControlChannel(row: NodeDisplayRow): ControlChannelState {
  // Older panel (field absent) or the user board (field never sent) — we know
  // nothing, so claim nothing.
  if (row.control_channel_online == null) return 'unknown';
  // The node isn't reporting at all; the offline tag is the whole story.
  if (!row.online) return 'unknown';
  if (row.control_channel_online) return 'online';
  return (row.ws_conn_unidentified ?? 0) > 0 ? 'group-unidentified' : 'offline';
}

/** i18n key for the tooltip explaining a non-online control-channel state. */
export function controlChannelTipKey(state: ControlChannelState): ControlChannelTipKey | null {
  switch (state) {
    case 'offline':
      return 'controlChannelOfflineTip';
    case 'group-unidentified':
      return 'controlChannelUnidentifiedTip';
    default:
      return null;
  }
}
