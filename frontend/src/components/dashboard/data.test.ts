import { describe, expect, it } from 'vitest';
import type { DeviceGroup, ForwardRule } from '../../api/types';
import type { NodeGroupSummary } from '../nodes/aggregate';
import {
  buildGroupHealth,
  buildGroupRateRanking,
  buildRuleTrafficRanking,
  insertHistoryGaps,
} from './data';

const deviceGroup = (id: number): DeviceGroup => ({ id, name: `g${id}` } as DeviceGroup);
const nodeGroup = (
  group_id: number,
  status: NodeGroupSummary['status'],
  upload_bps = 0,
  download_bps = 0,
): NodeGroupSummary => ({
  group_id,
  group_name: `g${group_id}`,
  online_nodes: status === 'offline' ? 0 : 1,
  total_nodes: 1,
  connections: 0,
  upload_bps,
  download_bps,
  upload_bytes: 0,
  download_bytes: 0,
  status,
});

describe('dashboard chart data', () => {
  it('classifies configured groups with no node record as unreported', () => {
    expect(buildGroupHealth(
      [deviceGroup(1), deviceGroup(2), deviceGroup(3), deviceGroup(4)],
      [nodeGroup(1, 'online'), nodeGroup(2, 'partial'), nodeGroup(3, 'offline')],
    )).toEqual([
      { status: 'online', count: 1 },
      { status: 'partial', count: 1 },
      { status: 'offline', count: 1 },
      { status: 'unreported', count: 1 },
    ]);
  });

  it('ranks group rate safely and keeps only the top eight', () => {
    const groups = Array.from({ length: 10 }, (_, index) =>
      nodeGroup(index + 1, 'online', index === 0 ? Number.NaN : index, index),
    );
    const ranking = buildGroupRateRanking(groups);
    expect(ranking).toHaveLength(8);
    expect(ranking[0].groupId).toBe(10);
    expect(ranking.some((item) => item.groupId === 1)).toBe(false);
  });

  it('ranks positive cumulative rule traffic with a stable id tie-break', () => {
    const rules = [
      { id: 3, name: 'three', traffic_used: 100 },
      { id: 1, name: 'one', traffic_used: 100 },
      { id: 2, name: 'zero', traffic_used: 0 },
      { id: 4, name: 'four', traffic_used: 90 },
      { id: 5, name: 'five', traffic_used: 80 },
      { id: 6, name: 'six', traffic_used: 70 },
      { id: 7, name: 'seven', traffic_used: 60 },
      { id: 8, name: 'invalid', traffic_used: Number.POSITIVE_INFINITY },
    ] as ForwardRule[];
    expect(buildRuleTrafficRanking(rules).map((item) => item.ruleId)).toEqual([1, 3, 4, 5, 6]);
  });

  it('inserts a null point when a history bucket is missing', () => {
    const base = {
      upload_bps_avg: 1,
      download_bps_avg: 2,
      upload_bps_max: 1,
      download_bps_max: 2,
      upload_bps_max_at: '2026-07-19T12:00:00Z',
      download_bps_max_at: '2026-07-19T12:00:00Z',
      connections_max: 3,
      online_nodes_min: 1,
      recent_nodes_max: 1,
      sample_count: 1,
    };
    const points = insertHistoryGaps([
      { ...base, timestamp: '2026-07-19T12:00:00Z' },
      { ...base, timestamp: '2026-07-19T12:03:00Z' },
    ], 60);
    expect(points).toHaveLength(3);
    expect(points[1].timestamp).toBe('2026-07-19T12:01:00.000Z');
    expect(points[1].upload_bps_avg).toBeNull();
    expect(points[1].upload_bps_max).toBeNull();
    expect(points[1].connections_max).toBeNull();
  });

  it('keeps an empty history empty', () => {
    expect(insertHistoryGaps([], 300)).toEqual([]);
  });
});
