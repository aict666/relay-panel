import type { DashboardHistoryPoint, DeviceGroup, ForwardRule } from '../../api/types';
import type { NodeGroupSummary } from '../nodes/aggregate';
import { safeNumber } from '../nodes/aggregate';

export type GroupHealthKey = 'online' | 'partial' | 'offline' | 'unreported';

export interface GroupHealthDatum {
  status: GroupHealthKey;
  count: number;
}

export interface GroupRateRank {
  groupId: number;
  groupName: string;
  uploadBps: number;
  downloadBps: number;
  totalBps: number;
}

export interface RuleTrafficRank {
  ruleId: number;
  ruleName: string;
  trafficUsed: number;
}

export type ChartHistoryPoint = Omit<DashboardHistoryPoint,
  'upload_bps_avg' | 'download_bps_avg' | 'upload_bps_max' | 'download_bps_max' | 'connections_max'> & {
    upload_bps_avg: number | null;
    download_bps_avg: number | null;
    upload_bps_max: number | null;
    download_bps_max: number | null;
    connections_max: number | null;
  };

const HEALTH_ORDER: GroupHealthKey[] = ['online', 'partial', 'offline', 'unreported'];

/** Include configured groups with no status row instead of letting stale-row
 * cleanup make an absent line look healthy. */
export function buildGroupHealth(
  deviceGroups: DeviceGroup[],
  nodeGroups: NodeGroupSummary[],
): GroupHealthDatum[] {
  const byId = new Map(nodeGroups.map((group) => [group.group_id, group]));
  const counts: Record<GroupHealthKey, number> = {
    online: 0,
    partial: 0,
    offline: 0,
    unreported: 0,
  };
  for (const group of deviceGroups) {
    const status = byId.get(group.id)?.status ?? 'unreported';
    counts[status] += 1;
  }
  return HEALTH_ORDER.map((status) => ({ status, count: counts[status] }))
    .filter((item) => item.count > 0);
}

export function buildGroupRateRanking(nodeGroups: NodeGroupSummary[]): GroupRateRank[] {
  return nodeGroups
    .map((group) => {
      const uploadBps = safeNumber(group.upload_bps);
      const downloadBps = safeNumber(group.download_bps);
      return {
        groupId: group.group_id,
        groupName: group.group_name || `#${group.group_id}`,
        uploadBps,
        downloadBps,
        totalBps: uploadBps + downloadBps,
      };
    })
    .filter((group) => group.totalBps > 0)
    .sort((a, b) => b.totalBps - a.totalBps || a.groupId - b.groupId)
    .slice(0, 8);
}

export function buildRuleTrafficRanking(rules: ForwardRule[]): RuleTrafficRank[] {
  return rules
    .map((rule) => ({
      ruleId: rule.id,
      ruleName: rule.name || `#${rule.id}`,
      trafficUsed: safeNumber(rule.traffic_used),
    }))
    .filter((rule) => rule.trafficUsed > 0)
    .sort((a, b) => b.trafficUsed - a.trafficUsed || a.ruleId - b.ruleId)
    .slice(0, 5);
}

/** Insert a null-valued point after a missed bucket so G2 breaks the line
 * instead of drawing a misleading bridge across a panel outage. */
export function insertHistoryGaps(
  points: DashboardHistoryPoint[],
  bucketSeconds: number,
): ChartHistoryPoint[] {
  if (bucketSeconds <= 0) return points;
  const output: ChartHistoryPoint[] = [];
  let previousMs: number | null = null;
  for (const point of points) {
    const currentMs = Date.parse(point.timestamp);
    if (
      previousMs !== null
      && Number.isFinite(currentMs)
      && currentMs - previousMs > bucketSeconds * 1500
    ) {
      const gapTimestamp = new Date(previousMs + bucketSeconds * 1000).toISOString();
      output.push({
        ...point,
        timestamp: gapTimestamp,
        upload_bps_max_at: gapTimestamp,
        download_bps_max_at: gapTimestamp,
        upload_bps_avg: null,
        download_bps_avg: null,
        upload_bps_max: null,
        download_bps_max: null,
        connections_max: null,
        sample_count: 0,
      });
    }
    output.push(point);
    previousMs = Number.isFinite(currentMs) ? currentMs : previousMs;
  }
  return output;
}
