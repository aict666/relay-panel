import { describe, it, expect } from 'vitest';
import { resolveControlChannel, controlChannelTipKey } from './controlChannel';
import type { NodeDisplayRow } from '../../api/types';

const row = (over: Partial<NodeDisplayRow> = {}): NodeDisplayRow => ({
  group_id: 1,
  node_id: 'node-a',
  online: true,
  ...over,
});

describe('resolveControlChannel', () => {
  it('says nothing when the panel does not report control-plane state', () => {
    // Older panel, or the regular-user board (/nodes/shared never sends it).
    expect(resolveControlChannel(row({ control_channel_online: undefined }))).toBe('unknown');
    expect(resolveControlChannel(row({ control_channel_online: null }))).toBe('unknown');
  });

  it('says nothing for a fully offline node', () => {
    // The 离线 tag is already the whole story; a second warning is just noise.
    expect(resolveControlChannel(row({ online: false, control_channel_online: false }))).toBe('unknown');
  });

  it('reports a healthy control channel', () => {
    expect(resolveControlChannel(row({ control_channel_online: true }))).toBe('online');
  });

  it('reports offline when the group has no live socket at all', () => {
    expect(
      resolveControlChannel(row({ control_channel_online: false, ws_conn_total: 0, ws_conn_unidentified: 0 })),
    ).toBe('offline');
  });

  it('reports an unidentified socket as group-level evidence', () => {
    // The panel cannot know whether this unidentified socket belongs to this
    // row, because the missing node_id is exactly the information needed to
    // correlate them.
    expect(
      resolveControlChannel(row({ control_channel_online: false, ws_conn_total: 1, ws_conn_unidentified: 1 })),
    ).toBe('group-unidentified');
  });

  it('treats a group with only OTHER nodes connected as plain offline', () => {
    // Sockets exist and all of them are identified, so none of them is this
    // node's — nothing was stripped, this node simply never dialled in.
    expect(
      resolveControlChannel(row({ control_channel_online: false, ws_conn_total: 2, ws_conn_unidentified: 0 })),
    ).toBe('offline');
  });
});

describe('controlChannelTipKey', () => {
  it('only produces a tooltip for the states worth warning about', () => {
    expect(controlChannelTipKey('unknown')).toBeNull();
    expect(controlChannelTipKey('online')).toBeNull();
    expect(controlChannelTipKey('offline')).toBe('controlChannelOfflineTip');
    expect(controlChannelTipKey('group-unidentified')).toBe('controlChannelUnidentifiedTip');
  });
});
