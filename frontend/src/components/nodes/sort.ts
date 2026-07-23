/**
 * v0.4.16 PR3: stable, order-independent node-row sorting for the node-status
 * board.
 *
 * Problem: the panel groups come from a KVS scan whose return order is not
 * guaranteed, and within a group multiple nodes can arrive in any order. The
 * old `groupByGroupId` preserved first-seen order, so the board could reorder
 * itself on every 5s refresh — visually flickering and making it hard to read.
 *
 * Fix: these pure functions impose a deterministic order that depends only on
 * the row DATA, never on arrival order. The same input set always yields the
 * same output. Kept in a logic-only module (no React) so it can be unit-tested
 * directly and imported by the page without tripping the
 * react-refresh/only-export-components rule.
 */
import type { NodeDisplayRow } from '../../api/types';

/**
 * Compare two node rows for STABLE within-group ordering. Sort keys (first
 * difference wins):
 *   1. report_ip (falling back to the legacy self-detected addresses)
 *   2. public_ipv4 (falling back to legacy public_ip)
 *   3. public_ipv6
 *   4. node_id
 * Missing/empty values sort LAST (so a node that hasn't reported its IP yet
 * doesn't jump around above named nodes). The comparison is a plain string
 * compare — it just needs to be deterministic, not human-meaningful.
 */
export function compareNodeRows<T extends NodeDisplayRow>(a: T, b: T): number {
  const ar = a.report_ip ?? '';
  const br = b.report_ip ?? '';
  if (ar !== br && (ar || br)) return blankLast(ar, br);
  const av4 = a.public_ipv4 ?? a.public_ip ?? '';
  const bv4 = b.public_ipv4 ?? b.public_ip ?? '';
  if (av4 !== bv4) return blankLast(av4, bv4);
  const av6 = a.public_ipv6 ?? '';
  const bv6 = b.public_ipv6 ?? '';
  if (av6 !== bv6) return blankLast(av6, bv6);
  const aid = a.node_id ?? '';
  const bid = b.node_id ?? '';
  return blankLast(aid, bid);
}

/** Empty string sorts after non-empty (blank-last). Otherwise lexical. */
function blankLast(a: string, b: string): number {
  if (!a && !b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Stable, order-independent view of the node rows. Returns groups sorted by
 * group_id ascending, each group's rows sorted by compareNodeRows. Does NOT
 * depend on the order the API/KVS returned rows in.
 */
export function stableGroupedRows<T extends NodeDisplayRow>(
  rows: T[],
): Array<[number, T[]]> {
  const m = new Map<number, T[]>();
  for (const r of rows) {
    const arr = m.get(r.group_id) ?? [];
    arr.push(r);
    m.set(r.group_id, arr);
  }
  // Sort each group's rows stably, then emit groups by ascending group_id.
  for (const arr of m.values()) arr.sort(compareNodeRows);
  return Array.from(m.entries()).sort((x, y) => x[0] - y[0]);
}
