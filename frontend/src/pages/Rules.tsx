import { Table, Button, Modal, Form, Input, InputNumber, Select, Space, message, Popconfirm, Tag, Alert, Typography, Dropdown, Switch, Tabs, Spin, Tooltip, Card, Checkbox, Grid, List } from 'antd';
import type { MenuProps } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, ApiOutlined, CopyOutlined, DownloadOutlined, UploadOutlined, PauseCircleOutlined, PlayCircleOutlined, DeleteOutlined, ArrowUpOutlined, ArrowDownOutlined, MedicineBoxOutlined, QuestionCircleOutlined, ThunderboltOutlined, MoreOutlined, SearchOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/client';
import { canUsePresetForRuleUpdate } from '../utils/tunnels';
import { ruleFormTabForErrors } from '../utils/ruleForm';
import type { ApiEnvelope, ForwardRule, DeviceGroup, User, UserSelf, RuleTargetInput, DiagnoseResponse, NodeDiagnoseStatus, DiagnoseTargetResult, SharedGroupSummary, RestartResponse, Tunnel, BlockedProtocol } from '../api/types';
import { MIN_AUTO_RESTART_MINUTES } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';
import { useAuth } from '../auth/useAuth';
import { mapWithConcurrency } from '../utils/async';
import { asValidatedEntry, buildExportJSON, parseDest, ruleTargets, validateImportEntry } from '../utils/rulesIO';

const { Text } = Typography;
const { TextArea } = Input;
const BATCH_REQUEST_CONCURRENCY = 6;

function targetSummary(rule: ForwardRule): string {
  const targets = ruleTargets(rule).filter(t => t.enabled);
  const first = targets[0] ?? ruleTargets(rule)[0];
  if (!first) return '-';
  const suffix = targets.length > 1 ? ` (+${targets.length - 1})` : '';
  return `${first.host}:${first.port}${suffix}`;
}

function formTargets(values: { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }): RuleTargetInput[] {
  const targets = values.targets ?? [];
  return targets.map(t => ({
    host: t.host?.trim() ?? '',
    port: Number(t.port),
    enabled: t.enabled !== false,
    weight: Math.max(1, Math.min(100, Number(t.weight ?? 1))),
  }));
}

function payloadWithTargets<T extends Record<string, unknown>>(values: T & { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }) {
  const targets = formTargets(values);
  if (targets.length < 1) {
    throw new Error('targets must have at least one entry');
  }
  const first = targets[0];
  return {
    ...values,
    target_addr: first.host,
    target_port: first.port,
    targets,
  };
}

/** Trigger a browser download of a text file. */
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Rules() {
  const { t } = useI18n();
  const { isAdmin, user } = useAuth();
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.md;
  const [searchParams] = useSearchParams();
  // v0.4.20: admin can manage another user's rules via /rules?owner_uid=X.
  const filterOwnerUid: number | null = isAdmin
    ? (parseInt(searchParams.get('owner_uid') || '') || null)
    : null;
  const [rules, setRules] = useState<ForwardRule[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  // v0.4.11 PR3: shared inbound groups (admin-owned) for regular users.
  const [sharedGroups, setSharedGroups] = useState<SharedGroupSummary[]>([]);
  // v0.4.12 PR1: true when /groups/shared failed to load (DB error). A regular
  // user then sees a load-failure notice and rule creation is blocked, instead
  // of a misleading empty inbound dropdown.
  const [sharedLoadFailed, setSharedLoadFailed] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  // v1.0.7: a regular user's own traffic quota (admins read each owner's quota
  // from `users` instead). Used to flag rules whose owner is out of traffic —
  // those rules stop forwarding even though their `paused` flag stays false.
  const [selfQuota, setSelfQuota] = useState<{ used: number; limit: number } | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importGroupId, setImportGroupId] = useState<number | undefined>(undefined);
  const [importResults, setImportResults] = useState<string[]>([]);
  const [editing, setEditing] = useState<ForwardRule | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [busyRuleId, setBusyRuleId] = useState<number | null>(null);
  const [batchAction, setBatchAction] = useState<'delete' | 'pause' | 'resume' | 'restart' | null>(null);
  const batchBusy = batchAction !== null;
  const [query, setQuery] = useState('');
  const [createTab, setCreateTab] = useState('basic');
  const [editTab, setEditTab] = useState('basic');
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  // v0.4.8: rule diagnosis modal state.
  const [diagnosing, setDiagnosing] = useState<ForwardRule | null>(null);
  const [diagnoseLoading, setDiagnoseLoading] = useState(false);
  const [diagnoseResult, setDiagnoseResult] = useState<DiagnoseResponse | null>(null);
  const diagnoseGenerationRef = useRef(0);
  // v0.4.9: group-name column + filter. selectedGroup === null means "all".
  // (Explicit null, not !selectedGroup, so a future id of 0 wouldn't be falsy.)
  const [selectedGroup, setSelectedGroup] = useState<number | null>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<number[]>([]);
  const userId = user?.id;
  const ownerUid = filterOwnerUid ?? (isAdmin ? (userId ?? null) : null);
  const loadScope = isAdmin
    ? `admin:${ownerUid ?? 'self'}`
    : `user:${userId ?? 'anonymous'}`;
  const loadGenerationRef = useRef(0);
  const loadScopeRef = useRef<string | null>(null);
  const desiredLoadScopeRef = useRef(loadScope);
  useLayoutEffect(() => {
    desiredLoadScopeRef.current = loadScope;
  }, [loadScope]);

  const load = useCallback(async () => {
    if (desiredLoadScopeRef.current !== loadScope) return false;
    const requestId = ++loadGenerationRef.current;
    if (loadScopeRef.current !== loadScope) {
      loadScopeRef.current = loadScope;
      Modal.destroyAll();
      setRules([]);
      setGroups([]);
      setTunnels([]);
      setSharedGroups([]);
      setSharedLoadFailed(false);
      setUsers([]);
      setSelfQuota(null);
      setSelectedRowKeys([]);
      setEditing(null);
      setCreateOpen(false);
      setEditOpen(false);
      setImportOpen(false);
      ++diagnoseGenerationRef.current;
      setDiagnosing(null);
      setDiagnoseLoading(false);
      setDiagnoseResult(null);
    }
    setLoading(true);
    setLoadFailed(false);
    try {
      // v0.4.10: /admin/users is admin-only and NOT in the main Promise.all —
      // a regular user would 403 and block the whole page load. The owner
      // column / selector are hidden for non-admins (they only ever own their
      // own rules), so the users list is fetched separately and only when
      // isAdmin. A failure here leaves users empty but rules/groups still load.
      // v0.4.20: admin can filter rules by owner_uid.
      // Admin on own page → filter to their own rules; admin viewing another
      // user → use filterOwnerUid; regular user → backend filters automatically.
      const rulesUrl = ownerUid ? `/rules?owner_uid=${ownerUid}` : '/rules';
      const [r, g, tr] = await Promise.all([
        api.get<unknown, ApiEnvelope<ForwardRule[]>>(rulesUrl),
        isAdmin
          ? api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups')
          : Promise.resolve({ code: 0, message: 'ok', data: [] as DeviceGroup[] }),
        api.get<unknown, ApiEnvelope<Tunnel[]>>('/tunnels'),
      ]);
      const nextRules = r.data || [];
      let nextUsers: User[] = [];
      let nextSelfQuota: { used: number; limit: number } | null = null;
      let nextSharedGroups: SharedGroupSummary[] = [];
      let nextSharedLoadFailed = false;
      if (isAdmin) {
        try {
          const u = await api.get<unknown, ApiEnvelope<User[]>>('/admin/users');
          nextUsers = u.data || [];
        } catch {
          // Non-fatal: owner column falls back to "#uid" labels.
          nextUsers = [];
        }
      } else {
        // v1.0.7: a regular user only ever sees their own rules, so one /user/me
        // read gives the quota needed to flag all of them. Non-fatal on failure.
        try {
          const me = await api.get<unknown, ApiEnvelope<UserSelf>>('/user/me');
          nextSelfQuota = me.data ? { used: me.data.traffic_used, limit: me.data.traffic_limit } : null;
        } catch {
          nextSelfQuota = null;
        }
      }
      // v0.4.12 PR1: shared inbound groups (admin-owned) for regular users.
      // The endpoint wraps the payload in ApiResponse — a non-zero code is a
      // load failure (NOT an empty "no lines" state), so we flag it and block
      // rule creation rather than show an empty inbound dropdown.
      // Admins get an empty list (they manage groups directly).
      if (!isAdmin) {
        try {
          const sg = await api.get<unknown, ApiEnvelope<SharedGroupSummary[]>>('/groups/shared');
          if (sg.code !== 0) {
            nextSharedLoadFailed = true;
          } else {
            nextSharedGroups = sg.data || [];
          }
        } catch {
          nextSharedLoadFailed = true;
        }
      }

      if (requestId !== loadGenerationRef.current || desiredLoadScopeRef.current !== loadScope) return false;
      setRules(nextRules);
      setSelectedRowKeys(current => current.filter(id => nextRules.some(rule => rule.id === id)));
      setGroups(g.data || []);
      setTunnels(tr.data || []);
      setUsers(nextUsers);
      setSelfQuota(nextSelfQuota);
      setSharedGroups(nextSharedGroups);
      setSharedLoadFailed(nextSharedLoadFailed);
      setLoadFailed(false);
      return true;
    } catch {
      if (requestId === loadGenerationRef.current && desiredLoadScopeRef.current === loadScope) {
        setLoadFailed(true);
        message.error(t('loadFailed'));
      }
      return false;
    } finally {
      if (requestId === loadGenerationRef.current && desiredLoadScopeRef.current === loadScope) setLoading(false);
    }
  }, [isAdmin, loadScope, ownerUid, t]);

  useEffect(() => { load(); }, [load]);

  const mutationsBlocked = loading || loadFailed || saving || batchBusy || busyRuleId !== null;

  // User lookup map for the "owner" column.
  const userMap = new Map(users.map(u => [u.id, u.username]));
  // v1.0.7: owner-quota lookup for the "traffic exhausted" status tag. Admins
  // resolve each rule's owner from `users`; a regular user uses their own quota
  // (their rules are all self-owned). traffic_limit === 0 means unlimited.
  const userById = useMemo(() => new Map(users.map(u => [u.id, u])), [users]);
  const ruleOverQuota = (r: ForwardRule): boolean => {
    if (isAdmin) {
      const u = userById.get(r.uid);
      return !!u && u.traffic_limit > 0 && u.traffic_used >= u.traffic_limit;
    }
    return !!selfQuota && selfQuota.limit > 0 && selfQuota.used >= selfQuota.limit;
  };
  // v0.4.9: group lookup map for the "group name" column + filter. Memoized so
  // the column render + filter options share one derivation.
  const tunnelMap = useMemo(() => new Map(tunnels.map(tunnel => [tunnel.id, tunnel])), [tunnels]);
  // v1.0.8: group-name + listen-IP lookup for the rule columns. A regular user
  // cannot read the administrator group inventory. Their AUTHORIZED
  // groups come from /groups/shared (SharedGroupSummary, which carries name +
  // connect_host) — merge both so name/IP resolve for admins and users alike.
  const groupInfo = useMemo(() => {
    const m = new Map<number, { name: string; connect_host: string; blocked_protocols?: BlockedProtocol[] }>();
    for (const g of groups) m.set(g.id, {
      name: g.name,
      connect_host: g.connect_host,
      blocked_protocols: g.blocked_protocols,
    });
    for (const g of sharedGroups) {
      if (!m.has(g.id)) m.set(g.id, {
        name: g.name,
        connect_host: g.connect_host,
        blocked_protocols: g.blocked_protocols,
      });
    }
    return m;
  }, [groups, sharedGroups]);
  // The rules actually shown: filtered by the selected inbound group, or all
  // when selectedGroup === null. Computed once so the table + count stay in sync.
  const visibleRules = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return rules.filter((r) => {
      if (selectedGroup !== null && r.device_group_in !== selectedGroup) return false;
      if (!needle) return true;
      const targets = ruleTargets(r).map(target => `${target.host}:${target.port}`).join(' ');
      const haystack = [
        r.name,
        String(r.id),
        String(r.listen_port),
        groupInfo.get(r.device_group_in)?.name ?? '',
        targets,
      ].join(' ').toLocaleLowerCase();
      return haystack.includes(needle);
    });
  }, [groupInfo, query, rules, selectedGroup]);
  const visibleRuleIds = useMemo(() => new Set(visibleRules.map(rule => rule.id)), [visibleRules]);

  // A selected rule must remain visible. Otherwise a rename/group change can
  // hide it behind the active filters while batch actions still target it.
  useEffect(() => {
    setSelectedRowKeys(current => current.filter(id => visibleRuleIds.has(id)));
  }, [visibleRuleIds]);

  const handleCreate = async (values: {
    name: string; listen_port: number | null; protocol: string;
    public_transport?: string;
    ws_path?: string;
    device_group_in: number; device_group_out: number | null;
    forward_mode: string;
    route_mode?: string;
    tunnel_id?: number | null;
    hops?: number[];
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    max_connections?: number;
    auto_restart_minutes?: number;
    tunnel_profile_id?: number | null;
    owner_uid?: number | null;
  }) => {
    if (loading || loadFailed || saving) return;
    // v0.4.20: WS/TLS tunnel hidden — always raw, no profile.
    // owner determined by entry point (filterOwnerUid from URL).
    const owner_uid = filterOwnerUid ?? undefined;
    if (formTargets(values).length < 1) {
      setCreateTab('forward');
      message.error(t('targetRequired'));
      return;
    }
    const isPresetTunnel = values.route_mode === 'tunnel';
    const isChain = values.route_mode === 'chain';
    const preset = isPresetTunnel && values.tunnel_id ? tunnelMap.get(values.tunnel_id) : undefined;
    if (isPresetTunnel && (!preset || !preset.enabled || preset.hops.length < 2)) {
      message.error(t('tunnelSelectHint'));
      return;
    }
    const hops = (values.hops ?? []).filter((id): id is number => typeof id === 'number' && id > 0);
    if (isChain && hops.length < 2) {
      message.error(t('chainHopsHint'));
      return;
    }
    const payload = payloadWithTargets({
      ...values,
      listen_port: values.listen_port || null,
      public_transport: 'raw',
      tunnel_profile_id: null,
      forward_mode: isChain || isPresetTunnel ? 'chain' : 'direct',
      route_mode: isChain || isPresetTunnel ? 'chain' : 'direct',
      tunnel_id: isPresetTunnel ? preset!.id : null,
      device_group_in: isPresetTunnel ? preset!.hops[0].device_group_id : isChain ? hops[0] : values.device_group_in,
      device_group_out: isPresetTunnel ? preset!.hops[preset!.hops.length - 1].device_group_id : isChain ? hops[hops.length - 1] : null,
      hops: isChain ? hops : undefined,
      owner_uid,
    });
    setSaving(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>('/rules', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      await load();
    } catch { message.error(t('failedCreateRule')); }
    finally { setSaving(false); }
  };

  const handleEdit = (r: ForwardRule) => {
    if (loading || loadFailed || saving || batchBusy || busyRuleId !== null) return;
    setEditing(r);
    setEditTab('basic');
    const isChain = r.route_mode === 'chain' || r.forward_mode === 'chain';
    const lineMode = r.tunnel_id ? 'tunnel' : isChain ? 'chain' : 'direct';
    editForm.setFieldsValue({
      name: r.name, listen_port: r.listen_port, protocol: r.protocol,
      device_group_in: r.device_group_in,
      route_mode: lineMode,
      forward_mode: isChain ? 'chain' : 'direct',
      tunnel_id: r.tunnel_id ?? undefined,
      hops: isChain && r.hops?.length
        ? r.hops.map(h => h.device_group_id)
        : isChain ? [r.device_group_in, r.device_group_out].filter((x): x is number => !!x) : [],
      target_addr: r.target_addr, target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      max_connections: r.max_connections ?? 0,
      auto_restart_minutes: r.auto_restart_minutes ?? 0,
    });
    setEditOpen(true);
  };

  /** Copy: open the create modal pre-filled with the rule's values, but with
   *  a "-copy" name suffix and no listen_port (auto-assign). */
  const handleCopy = (r: ForwardRule) => {
    if (loading || loadFailed || saving || batchBusy || busyRuleId !== null) return;
    setEditing(null);
    setCreateTab('basic');
    createForm.resetFields();
    createForm.setFieldsValue({
      name: `${r.name}-copy`,
      listen_port: null,
      protocol: r.protocol,
      device_group_in: r.device_group_in,
      route_mode: r.tunnel_id ? 'tunnel' : (r.route_mode === 'chain' || r.forward_mode === 'chain') ? 'chain' : 'direct',
      forward_mode: r.route_mode === 'chain' || r.forward_mode === 'chain' ? 'chain' : 'direct',
      tunnel_id: r.tunnel_id ?? undefined,
      hops: r.tunnel_id ? undefined : (r.hops ?? []).map(h => h.device_group_id),
      target_addr: r.target_addr,
      target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      max_connections: r.max_connections ?? 0,
      auto_restart_minutes: r.auto_restart_minutes ?? 0,
    });
    setCreateOpen(true);
  };

  /** Export all rules as JSON download. */
  const handleExportAll = () => {
    downloadText(`relaypanel-rules-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(rules));
    message.success(t('exported'));
  };

  /** Export only the currently-selected rules as JSON download. */
  const handleExportSelected = () => {
    const selected = rules.filter(r => selectedRowKeys.includes(r.id));
    if (selected.length === 0) return;
    downloadText(`relaypanel-rules-selected-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(selected));
    message.success(t('exported'));
  };

const IMPORT_DEFAULTS = {
  protocol: 'tcp_udp' as const,
  public_transport: 'raw' as const,
  forward_mode: 'direct' as const,
  route_mode: 'direct' as const,
  load_balance_strategy: 'first' as const,
  upload_limit_mbps: 0,
  download_limit_mbps: 0,
};
  const handleImport = async () => {
    if (loading || loadFailed || saving) return;
    if (!importGroupId) {
      message.error(t('selectInboundGroup'));
      return;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(importText); } catch {
      message.error(t('importInvalidJson')); return;
    }
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    if (entries.length === 0) {
      message.error(t('importInvalidFormat')); return;
    }
    setSaving(true);
    const results: string[] = [];
    try {
      for (const e of entries) {
        const label = (typeof e === 'object' && e !== null && !Array.isArray(e))
          ? String((e as { name?: unknown })['name'] ?? '?')
          : '?';
        const err = validateImportEntry(e);
        if (err) { results.push(`❌ ${label}: ${err}`); continue; }
        const entry = asValidatedEntry(e);
        const targets = entry.dest.map(d => {
          // validateImportEntry already rejected any unparseable dest above, so
          // parseDest is non-null here; fall back to a safe default defensively.
          const p = parseDest(d) ?? { host: '', port: 0 };
          return { host: p.host, port: p.port, enabled: true, weight: 1 };
        });
        const first = targets[0];
        try {
          const res = await api.post<unknown, ApiEnvelope<null>>('/rules', {
            name: entry.name,
            listen_port: entry.listen_port,
            ...IMPORT_DEFAULTS,
            device_group_in: importGroupId,
            target_addr: first.host,
            target_port: first.port,
            targets,
            // v1.0.6: attribute to the target user when an admin imports via the
            // user-management entry (/rules?owner_uid=X); else owner = caller.
            owner_uid: filterOwnerUid ?? undefined,
          });
          if (res.code === 0) results.push(`✅ ${entry.name}:${entry.listen_port}`);
          else results.push(`❌ ${entry.name}: ${res.message}`);
        } catch { results.push(`❌ ${entry.name}: network error`); }
      }
      if (results.length === 0) { message.error(t('importInvalidFormat')); return; }
      setImportResults(results);
      await load();
    } finally {
      setSaving(false);
    }
  };
  const handleUpdate = async (values: {
    name?: string; listen_port?: number; protocol?: string;
    device_group_in?: number;
    route_mode?: string;
    forward_mode?: string;
    tunnel_id?: number | null;
    hops?: number[];
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    max_connections?: number;
    auto_restart_minutes?: number;
  }) => {
    if (!editing) return;
    if (loading || loadFailed || saving) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.listen_port !== undefined && values.listen_port !== editing.listen_port) payload.listen_port = values.listen_port;
    if (values.protocol !== undefined && values.protocol !== editing.protocol) payload.protocol = values.protocol;
    const isPresetTunnel = values.route_mode === 'tunnel';
    const isChain = values.route_mode === 'chain';
    const wasChain = editing.route_mode === 'chain' || editing.forward_mode === 'chain';
    const wasPresetTunnel = !!editing.tunnel_id;
    const hops = (values.hops ?? []).filter((id): id is number => typeof id === 'number' && id > 0);
    if (isPresetTunnel) {
      const preset = values.tunnel_id ? tunnelMap.get(values.tunnel_id) : undefined;
      const keepingCurrentBinding = !!values.tunnel_id && values.tunnel_id === editing.tunnel_id;
      if (!canUsePresetForRuleUpdate(values.tunnel_id, editing.tunnel_id, preset)) {
        message.error(t('tunnelSelectHint'));
        return;
      }
      if (!keepingCurrentBinding) {
        payload.route_mode = 'chain';
        payload.forward_mode = 'chain';
        payload.tunnel_id = preset!.id;
        payload.device_group_in = preset!.hops[0].device_group_id;
        payload.device_group_out = preset!.hops[preset!.hops.length - 1].device_group_id;
      }
    } else if (isChain) {
      if (hops.length < 2) {
        message.error(t('chainHopsHint'));
        return;
      }
      const oldHops = (editing.hops ?? []).map(h => h.device_group_id);
      if (!wasChain || wasPresetTunnel || JSON.stringify(hops) !== JSON.stringify(oldHops)) {
        payload.route_mode = 'chain';
        payload.forward_mode = 'chain';
        payload.tunnel_id = null;
        payload.hops = hops;
        payload.device_group_in = hops[0];
        payload.device_group_out = hops[hops.length - 1];
      }
    } else if (wasChain) {
      payload.route_mode = 'direct';
      payload.forward_mode = 'direct';
      payload.tunnel_id = null;
      if (values.device_group_in !== undefined) payload.device_group_in = values.device_group_in;
      payload.device_group_out = null;
    } else if (values.device_group_in !== undefined && values.device_group_in !== editing.device_group_in) {
      payload.device_group_in = values.device_group_in;
    }
    const newTargets = formTargets(values);
    const oldTargets = ruleTargets(editing);
    if (JSON.stringify(newTargets) !== JSON.stringify(oldTargets)) {
      if (newTargets.length < 1) {
        setEditTab('forward');
        message.error(t('targetRequired'));
        return;
      }
      const first = newTargets[0];
      payload.target_addr = first.host;
      payload.target_port = first.port;
      payload.targets = newTargets;
    }
    if (values.load_balance_strategy !== undefined && values.load_balance_strategy !== (editing.load_balance_strategy ?? 'first')) {
      payload.load_balance_strategy = values.load_balance_strategy;
    }
    const newUp = values.upload_limit_mbps ?? 0;
    const newDown = values.download_limit_mbps ?? 0;
    if (newUp !== (editing.upload_limit_mbps ?? 0) || newDown !== (editing.download_limit_mbps ?? 0)) {
      payload.upload_limit_mbps = newUp;
      payload.download_limit_mbps = newDown;
    }
    // v1.2.0: send both together when either changed. The API defaults an
    // omitted one to the rule's current value, so sending a single field is
    // safe — but sending the pair keeps the request self-describing.
    const newMaxConn = values.max_connections ?? 0;
    const newAutoRestart = values.auto_restart_minutes ?? 0;
    if (newMaxConn !== (editing.max_connections ?? 0) || newAutoRestart !== (editing.auto_restart_minutes ?? 0)) {
      payload.max_connections = newMaxConn;
      payload.auto_restart_minutes = newAutoRestart;
    }
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleUpdated'));
      setEditOpen(false);
      await load();
    } catch { message.error(t('failedUpdateRule')); }
    finally { setSaving(false); }
  };

  const handleDelete = async (id: number) => {
    if (loading || loadFailed || busyRuleId !== null || batchBusy) return;
    setBusyRuleId(id);
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/rules/${id}`);
      if (res.code !== 0) {
        message.error(res.message || t('deleteFailed'));
        return;
      }
      message.success(t('ruleDeleted'));
      await load();
    } catch {
      message.error(t('deleteFailed'));
    } finally {
      setBusyRuleId(null);
    }
  };

  const handleBatchDelete = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0 || loading || loadFailed || batchBusy || busyRuleId !== null) return;
    setBatchAction('delete');
    // Tally per-rule success/failure and keep request fan-out bounded. A large
    // selection must not open one browser/server connection per rule at once.
    try {
      const results = await mapWithConcurrency(ids, BATCH_REQUEST_CONCURRENCY, async id => {
        try {
          const res = await api.delete<unknown, ApiEnvelope<null>>(`/rules/${id}`);
          return res.code === 0;
        } catch { return false; }
      });
      const ok = results.filter(Boolean).length;
      const fail = results.length - ok;
      if (fail === 0) {
        message.success(t('batchDeleteSuccess').replace('{count}', String(ok)));
      } else {
        message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
      }
      setSelectedRowKeys([]);
      await load();
    } finally {
      setBatchAction(null);
    }
  };

  /** v1.0.7: batch pause/resume. Each rule goes through PUT /rules/{id}
   *  {paused}. Resume can be rejected per-rule (403) when the rule points at a
   *  device group the user is no longer authorized for, so we tally ok/fail
   *  instead of assuming success. */
  const handleBatchSetPaused = async (paused: boolean) => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0 || loading || loadFailed || batchBusy || busyRuleId !== null) return;
    setBatchAction(paused ? 'pause' : 'resume');
    try {
      const results = await mapWithConcurrency(ids, BATCH_REQUEST_CONCURRENCY, async id => {
        try {
          const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${id}`, { paused });
          return res.code === 0;
        } catch { return false; }
      });
      const ok = results.filter(Boolean).length;
      const fail = results.length - ok;
      if (fail === 0) {
        message.success((paused ? t('batchPauseSuccess') : t('batchResumeSuccess')).replace('{count}', String(ok)));
      } else {
        message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
      }
      setSelectedRowKeys([]);
      await load();
    } finally {
      setBatchAction(null);
    }
  };

  /** v1.2.0: restart one rule — drop its live connections and rebuild its
   *  listeners on every node of its inbound group. The rule's paused state is
   *  untouched; this is not a pause/resume round-trip.
   *
   *  `restarted` (nodes actually reached) drives the message rather than the
   *  HTTP code: the request can succeed while restarting nothing, e.g. every
   *  node is too old to understand the command. Reporting that as success would
   *  hide exactly the case the user needs to act on. */
  const handleRestart = async (r: ForwardRule) => {
    if (loading || loadFailed || busyRuleId !== null || batchBusy) return;
    setBusyRuleId(r.id);
    try {
      const res = await api.post<unknown, ApiEnvelope<RestartResponse>>(`/rules/${r.id}/restart`, {});
      if (res.code !== 0) {
        message.error(res.message || t('restartFailed'));
        return;
      }
      const data = res.data;
      const outdated = (data?.nodes ?? []).filter(n => n.state === 'unsupported').length;
      const offline = (data?.nodes ?? []).filter(n => n.state === 'control_channel_offline').length;
      if ((data?.restarted ?? 0) > 0) {
        let msg = t('restartSuccess').replace('{count}', String(data?.restarted ?? 0));
        if (outdated > 0) msg += ` ${t('restartOutdatedSuffix').replace('{count}', String(outdated))}`;
        if (offline > 0) msg += ` ${t('restartOfflineSuffix').replace('{count}', String(offline))}`;
        if (outdated > 0 || offline > 0) message.warning(msg);
        else message.success(msg);
      } else if (outdated > 0) {
        message.warning(t('restartAllOutdated').replace('{count}', String(outdated)));
      } else if (offline > 0) {
        message.warning(t('restartAllOffline').replace('{count}', String(offline)));
      } else {
        message.warning(t('restartNoNodes'));
      }
    } catch {
      message.error(t('restartFailed'));
    } finally {
      setBusyRuleId(null);
    }
  };

  /** v1.2.0: batch restart. Per-rule POST like batch pause/resume — there is no
   *  bulk endpoint. A rule can fail individually (paused → 400, or not owned →
   *  404), so tally ok/fail rather than assuming Promise.all means success. */
  const handleBatchRestart = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0 || loading || loadFailed || batchBusy || busyRuleId !== null) return;
    setBatchAction('restart');
    try {
      const results = await mapWithConcurrency(ids, BATCH_REQUEST_CONCURRENCY, async id => {
        try {
          const res = await api.post<unknown, ApiEnvelope<RestartResponse>>(`/rules/${id}/restart`, {});
          // Reaching zero nodes is not a success worth reporting as one.
          return res.code === 0 && (res.data?.restarted ?? 0) > 0;
        } catch { return false; }
      });
      const ok = results.filter(Boolean).length;
      const fail = results.length - ok;
      if (fail === 0) {
        message.success(t('batchRestartSuccess').replace('{count}', String(ok)));
      } else {
        // NOT batchPartial: that message blames "unauthorized lines can't be
        // resumed", which is the batch-resume failure mode and has nothing to do
        // with a restart. A restart fails when the rule is paused or every node is
        // old/offline — say that instead of pointing at the wrong cause.
        message.warning(
          t('batchRestartPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail))
        );
      }
      setSelectedRowKeys([]);
    } finally {
      setBatchAction(null);
    }
  };

  /** v0.4.8: run a diagnosis for a rule. The panel fans the probe out to the
   *  rule's inbound-group nodes over WS and waits up to 8s for results. */
  const handleDiagnose = async (r: ForwardRule) => {
    if (diagnoseLoading || mutationsBlocked) return;
    const requestId = ++diagnoseGenerationRef.current;
    const requestScope = loadScope;
    setDiagnosing(r);
    setDiagnoseResult(null);
    setDiagnoseLoading(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<DiagnoseResponse>>(`/rules/${r.id}/diagnose`);
      if (requestId !== diagnoseGenerationRef.current || desiredLoadScopeRef.current !== requestScope) return;
      if (res.code === 0 && res.data) {
        setDiagnoseResult(res.data);
      } else {
        message.error(res.message || t('diagnoseFailed'));
      }
    } catch {
      if (requestId === diagnoseGenerationRef.current && desiredLoadScopeRef.current === requestScope) {
        message.error(t('diagnoseFailed'));
      }
    } finally {
      if (requestId === diagnoseGenerationRef.current && desiredLoadScopeRef.current === requestScope) {
        setDiagnoseLoading(false);
      }
    }
  };

  const closeDiagnose = () => {
    ++diagnoseGenerationRef.current;
    setDiagnosing(null);
    setDiagnoseLoading(false);
    setDiagnoseResult(null);
  };

  /** Toggle a rule's paused state via the dedicated paused field on the update
   *  API. Paused rules stay in the DB but the node stops forwarding (get_config
   *  filters WHERE paused = 0). This is the only way to pause a rule — before
   *  v0.3.0 the paused column existed but had no API to flip it. */
  const handleTogglePause = async (r: ForwardRule) => {
    if (loading || loadFailed || busyRuleId !== null || batchBusy) return;
    const nextPaused = !r.paused;
    setBusyRuleId(r.id);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${r.id}`, { paused: nextPaused });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(nextPaused ? t('rulePaused') : t('ruleResumed'));
      await load();
    } catch { message.error(t('failedUpdateRule')); }
    finally { setBusyRuleId(null); }
  };

  const protoTags = (p: string) => {
    if (p === 'tcp_udp') return <><Tag color="blue">TCP</Tag><Tag color="purple">UDP</Tag></>;
    if (p === 'udp') return <Tag color="purple">UDP</Tag>;
    return <Tag color="blue">TCP</Tag>;
  };

  const confirmRestart = (r: ForwardRule) => {
    Modal.confirm({
      title: t('restartConfirmTitle'),
      content: t('restartConfirmDesc'),
      okButtonProps: { danger: true },
      onOk: () => handleRestart(r),
    });
  };

  const confirmDelete = (r: ForwardRule) => {
    Modal.confirm({
      title: t('deleteRuleConfirm'),
      okButtonProps: { danger: true },
      onOk: () => handleDelete(r.id),
    });
  };

  const ruleMoreMenu = (r: ForwardRule): MenuProps => ({
    items: [
      { key: 'copy', label: t('copy'), icon: <CopyOutlined />, disabled: mutationsBlocked },
      { key: 'diagnose', label: t('diagnose'), icon: <MedicineBoxOutlined />, disabled: r.protocol === 'udp' || mutationsBlocked },
      { key: 'restart', label: t('restart'), icon: <ThunderboltOutlined />, disabled: r.paused || mutationsBlocked },
      { type: 'divider' },
      { key: 'delete', label: t('delete'), icon: <DeleteOutlined />, danger: true, disabled: mutationsBlocked },
    ],
    onClick: ({ key }) => {
      if (key === 'copy') handleCopy(r);
      if (key === 'diagnose') handleDiagnose(r);
      if (key === 'restart') confirmRestart(r);
      if (key === 'delete') confirmDelete(r);
    },
  });

  const renderRuleActions = (r: ForwardRule) => (
    <Space size={2} className="rp-rule-actions">
      <Button
        size="small" type="text"
        icon={r.paused ? <PlayCircleOutlined /> : <PauseCircleOutlined />}
        loading={busyRuleId === r.id}
        disabled={loading || loadFailed || saving || batchBusy || (busyRuleId !== null && busyRuleId !== r.id)}
        onClick={() => handleTogglePause(r)}
      >
        {r.paused ? t('resume') : t('pause')}
      </Button>
      <Button size="small" type="text" icon={<EditOutlined />} disabled={mutationsBlocked} onClick={() => handleEdit(r)}>{t('edit')}</Button>
      <Dropdown menu={ruleMoreMenu(r)} trigger={['click']}>
        <Button size="small" type="text" icon={<MoreOutlined />} disabled={mutationsBlocked} aria-label={t('action')} />
      </Dropdown>
    </Space>
  );

  const allColumns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    // v0.4.9: inbound group name. Hidden on small screens (responsive md+) so
    // the mobile view keeps the core columns. Lookup misses → "未知分组 (#ID)".
    {
      title: t('groupName'), key: 'group_name', width: 140,
      render: (_: unknown, r: ForwardRule) => {
        const g = groupInfo.get(r.device_group_in);
        return g
          ? <Tag>{g.name}</Tag>
          : <Text type="secondary">{t('unknownGroup')} (#{r.device_group_in})</Text>;
      },
    },
    {
      title: t('chainPath'), key: 'chain_path', width: 190,
      render: (_: unknown, r: ForwardRule) => {
        if (r.route_mode !== 'chain' && r.forward_mode !== 'chain') {
          return <Text type="secondary">{t('modeDirect')}</Text>;
        }
        if (r.tunnel_id) {
          const tunnel = tunnelMap.get(r.tunnel_id);
          return (
            <Space size={4} orientation="vertical">
              <Tag color={r.tunnel_enabled === false ? 'red' : 'geekblue'}>
                {r.tunnel_name || tunnel?.name || `#${r.tunnel_id}`}
              </Tag>
              {r.tunnel_enabled === false && <Text type="danger" style={{ fontSize: 12 }}>{t('tunnelDisabled')}</Text>}
            </Space>
          );
        }
        const labels = (r.hops ?? []).map(h =>
          h.group_name || groupInfo.get(h.device_group_id)?.name || `#${h.device_group_id}`
        );
        if (labels.length === 0) {
          return <Tag color="blue">{t('modeChain')}</Tag>;
        }
        const path = labels.join(' → ');
        return <Text ellipsis={{ tooltip: path }} style={{ display: 'block', maxWidth: 170, fontSize: 12 }}>{path}</Text>;
      },
    },
    {
      title: t('name'), dataIndex: 'name', key: 'name', width: 140,
      render: (v: string) => <Text ellipsis={{ tooltip: v }} style={{ display: 'block', maxWidth: 120 }}>{v}</Text>,
    },
    {
      title: t('listenIp'), key: 'listen_ip', width: 160,
      render: (_: unknown, r: ForwardRule) => {
        const host = groupInfo.get(r.device_group_in)?.connect_host ?? '';
        return host
          ? <span className="rp-mono">{host}</span>
          : <Text type="secondary">{t('notConfigured')}</Text>;
      },
    },
    { title: t('listenPort'), dataIndex: 'listen_port', key: 'listen_port', width: 90, render: (v: number) => <span className="rp-mono">{v}</span> },
    {
      title: t('protocol'), dataIndex: 'protocol', key: 'protocol', width: 170,
      render: (p: string, r: ForwardRule) => (
        <Space size={4}>
          {protoTags(p)}
          {r.paused && <Tag color="red">{t('paused')}</Tag>}
          {!r.paused && ruleOverQuota(r) && (
            <Tooltip title={t('quotaExhaustedHint')}>
              <Tag color="orange">{t('quotaExhausted')}</Tag>
            </Tooltip>
          )}
        </Space>
      ),
    },
    {
      title: t('target'), key: 'target', width: 190,
      render: (_: unknown, r: ForwardRule) => {
        // v1.0.9: a multi-target rule shows "first (+N)"; hovering lists every
        // enabled target IP so the admin can see the failover/round-robin pool.
        const all = ruleTargets(r).filter(t => t.enabled).map(t => `${t.host}:${t.port}`);
        const summary = <span className="rp-mono">{targetSummary(r)}</span>;
        return (
          <Space size={4} wrap>
            {all.length > 1 ? (
              <Tooltip title={<div>{all.map((s, i) => <div key={i} className="rp-mono">{s}</div>)}</div>}>
                {summary}
              </Tooltip>
            ) : summary}
            {r.load_balance_strategy && r.load_balance_strategy !== 'first' && (
              <Tag color="cyan">{{
                round_robin: t('lbRoundRobin'),
                failover: t('lbFailover'),
                weighted: t('lbWeighted'),
                least_latency: t('lbLeastLatency'),
                least_connections: t('lbLeastConnections'),
              }[r.load_balance_strategy] ?? r.load_balance_strategy}</Tag>
            )}
          </Space>
        );
      },
    },
    {
      // v0.4.14 PR3: owner is the rule's OWN uid — NOT the inbound group's uid.
      // An admin can create a rule on behalf of a user, and a regular user can
      // attach to an admin-owned shared group, so the rule owner and the group
      // owner often differ. Resolve the username from the rule's uid; fall back
      // to "#uid" when the user list isn't available.
      title: t('owner'), key: 'owner', width: 110,
      render: (_: unknown, r: ForwardRule) =>
        <Text>{userMap.get(r.uid) ?? `#${r.uid}`}</Text>,
    },
    { title: t('traffic'), dataIndex: 'traffic_used', key: 'traffic_used', width: 100, render: (v: number) => formatBytes(v) },
    {
      title: t('action'), key: 'action', width: 176, fixed: 'right' as const,
      render: (_: unknown, r: ForwardRule) => renderRuleActions(r),
    },
  ];
  // v0.4.10: hide the owner column for regular users — they only ever own
  // their own rules, and /admin/users is never fetched for them (so userMap
  // is empty and the column would show "-" everywhere).
  const columns = isAdmin ? allColumns : allColumns.filter(c => c.key !== 'owner');

  const isInboundGroup = (g: { group_type: string }) => g.group_type === 'in' || g.group_type === 'both';
  const isForwardingGroup = (g: { group_type: string }) => g.group_type !== 'monitor';
  const inGroups = groups.filter(isInboundGroup);
  // v0.4.12 PR1: inbound group selection. Admins pick from their OWN 'in'
  // groups. Regular users pick ONLY from admin-owned shared 'in' groups
  // (/groups/shared) — never their own historical groups, which the backend
  // also rejects. This keeps the UI and the API invariant in lock-step.
  const sharedInGroups = sharedGroups.filter(isInboundGroup);
  const allInGroups = isAdmin ? inGroups : sharedInGroups;
  const inboundGroupOptions = allInGroups.map(g => ({
    value: g.id,
    searchLabel: g.name,
    label: (
      <Space size={4}>
        <span>{g.name} (#{g.id})</span>
        {g.blocked_protocols?.includes('tls') && <Tag color="red">{t('tlsBlocked')}</Tag>}
      </Space>
    ),
  }));
  // Chain hops: entry must be inbound-capable; mid/exit can be any forwarding
  // group. `both` is intentionally available in either position.
  const hopGroupOptions = (isAdmin
    ? groups.filter(isForwardingGroup)
    : sharedInGroups
  ).map(g => ({
    value: g.id,
    label: `${g.name} (${g.group_type}${g.connect_host ? ` · ${g.connect_host}` : ''})${g.blocked_protocols?.includes('tls') ? ` · ${t('tlsBlocked')}` : ''}`,
  }));
  const protocolOptions = [
    { value: 'tcp_udp', label: t('tcpUdp') },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
  ];
  const strategyOptions = [
    { value: 'first', label: t('lbFirst') },
    { value: 'round_robin', label: t('lbRoundRobin') },
    { value: 'failover', label: t('lbFailover') },
    { value: 'weighted', label: t('lbWeighted') },
    { value: 'least_latency', label: t('lbLeastLatency') },
    { value: 'least_connections', label: t('lbLeastConnections') },
  ];
  const isUdp = (p?: string) => p === 'udp' || p === 'tcp_udp';

  const createGroupId = Form.useWatch('device_group_in', createForm);
  const createRouteMode = Form.useWatch('route_mode', createForm);
  const createTunnelId = Form.useWatch('tunnel_id', createForm);
  const editRouteMode = Form.useWatch('route_mode', editForm);
  const editTunnelId = Form.useWatch('tunnel_id', editForm);
  const editGroupId = Form.useWatch('device_group_in', editForm);
  const createProto = Form.useWatch('protocol', createForm);
  const editProto = Form.useWatch('protocol', editForm);
  const hopPathText = (hops?: Tunnel['hops']) => hops
    ?.map(hop => hop.group_name || groupInfo.get(hop.device_group_id)?.name || `#${hop.device_group_id}`)
    .join(' → ') || '-';
  const tunnelPathText = (tunnel?: Tunnel) => hopPathText(tunnel?.hops);
  const tunnelBlocksTls = (tunnel?: Tunnel) => {
    const entryGroupId = tunnel?.hops[0]?.device_group_id;
    return entryGroupId !== undefined
      && groupInfo.get(entryGroupId)?.blocked_protocols?.includes('tls') === true;
  };
  const selectedCreateTunnel = createTunnelId ? tunnelMap.get(createTunnelId) : undefined;
  const selectedEditTunnel = editTunnelId
    ? tunnelMap.get(editTunnelId) ?? (editing?.tunnel_id === editTunnelId ? {
      id: editTunnelId,
      name: editing.tunnel_name || `#${editTunnelId}`,
      enabled: editing.tunnel_enabled ?? false,
      shared: editing.tunnel_shared ?? false,
      uid: 0,
      created_at: editing.created_at,
      hops: editing.tunnel_hops ?? [],
      bound_rule_count: 1,
    } : undefined)
    : undefined;

  const renderTunnelPicker = (selected?: Tunnel) => (
    <>
      <Form.Item
        name="tunnel_id"
        label={t('modePresetTunnel')}
        rules={[{ required: true, message: t('tunnelSelectHint') }]}
        extra={t('tunnelSelectHint')}
      >
        <Select
          showSearch
          optionFilterProp="searchLabel"
          options={(selected && !tunnelMap.has(selected.id) ? [selected, ...tunnels] : tunnels).map(tunnel => ({
            value: tunnel.id,
            searchLabel: `${tunnel.name} · ${tunnelPathText(tunnel)}`,
            label: (
              <Space size={4}>
                <span>{tunnel.name} · {tunnelPathText(tunnel)}</span>
                {tunnelBlocksTls(tunnel) && <Tag color="red">{t('tlsBlocked')}</Tag>}
              </Space>
            ),
            disabled: !tunnelMap.has(tunnel.id) || (!tunnel.enabled && tunnel.id !== selected?.id),
          }))}
          placeholder={t('select')}
        />
      </Form.Item>
      {selected && (
        <Alert
          type={selected.enabled ? 'success' : 'warning'}
          showIcon
          style={{ marginBottom: 16 }}
          title={selected.enabled ? (
            <Space size={4}>
              <span>{tunnelPathText(selected)}</span>
              {tunnelBlocksTls(selected) && <Tag color="red">{t('tlsBlocked')}</Tag>}
            </Space>
          ) : t('tunnelDisabled')}
          description={t('tunnelPortsReused')}
        />
      )}
    </>
  );

  const hostForForm = (gid?: number) => {
    if (!gid) return '';
    // v1.0.7: a regular user doesn't own the admin device groups, so `groups`
    // is empty for them — resolve the connect host from the merged groupInfo
    // (which also folds in their authorized shared groups) instead.
    return groupInfo.get(gid)?.connect_host ?? '';
  };
  const renderHostHint = (gid?: number) => {
    const host = hostForForm(gid);
    return (
      <Alert
        type="info" showIcon style={{ marginBottom: 12, padding: '4px 12px' }}
        title={t('currentInboundHost').replace('{host}', host || t('notConfigured'))}
      />
    );
  };

  /** v1.2.0: connection cap + scheduled restart. Shared by the create and edit
   *  forms so the two can't drift (the rate-limit block above predates this and
   *  is still duplicated).
   *
   *  Both fields are 0 = off. The cap's `extra` says the count is PER NODE,
   *  because that isn't guessable: a rule on 3 nodes admits 3x the number typed
   *  here.
   *
   *  The cap is disabled for a UDP-ONLY rule. It is enforced at accept(), which
   *  UDP doesn't have — the panel would happily store the number and ship it to
   *  the node, where nothing would ever read it. Showing an editable field that
   *  silently does nothing is worse than showing a disabled one that says why.
   *  A tcp_udp rule keeps it: the cap governs its TCP half. */
  const renderConnectionControls = (proto?: string) => {
    const udpOnly = proto === 'udp';
    return (
    <>
      <Form.Item
        name="max_connections"
        label={t('maxConnections')}
        extra={udpOnly ? t('maxConnectionsUdpUnsupported') : t('maxConnectionsHint')}
        initialValue={0}
      >
        <InputNumber min={0} precision={0} style={{ width: '100%' }} placeholder="0" disabled={udpOnly} />
      </Form.Item>
      <Form.Item
        name="auto_restart_minutes"
        label={t('autoRestart')}
        extra={t('autoRestartHint').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))}
        initialValue={0}
        rules={[{
          // Mirrors the API's floor. 0 = off is always allowed; anything between
          // 1 and the floor would drop connections faster than clients reconnect.
          validator: (_, value) => {
            const v = Number(value ?? 0);
            if (Number.isInteger(v) && (v === 0 || v >= MIN_AUTO_RESTART_MINUTES)) return Promise.resolve();
            return Promise.reject(new Error(
              t('autoRestartTooSmall').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))
            ));
          },
        }]}
      >
        <InputNumber min={0} precision={0} style={{ width: '100%' }} addonAfter={t('minutes')} placeholder="0" />
      </Form.Item>
    </>
    );
  };

  const closeImport = () => {
    if (saving) return;
    setImportOpen(false);
    setImportText('');
    setImportResults([]);
  };

  const renderTargetsEditor = () => (
    <Form.List name="targets" initialValue={[{ host: '', port: undefined as unknown as number, enabled: true, weight: 1 }]}>
      {(fields, { add, remove, move }) => (
        <Space orientation="vertical" style={{ width: '100%' }} className="rp-target-editor">
          <Text strong>{t('targets')}</Text>
          {fields.map((field, index) => {
            const { key, ...fieldProps } = field;
            return (
            <div key={key} className="rp-target-row">
              <Form.Item
                {...fieldProps}
                name={[field.name, 'host']}
                label={t('address')}
                rules={[{ required: true }]}
                className="rp-target-host"
              >
                <Input placeholder={t('targetAddress')} />
              </Form.Item>
              <Form.Item
                {...fieldProps}
                name={[field.name, 'weight']}
                label={t('targetWeight')}
                initialValue={1}
                rules={[{ required: true }]}
                className="rp-target-weight"
              >
                <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item
                {...fieldProps}
                name={[field.name, 'port']}
                label={t('port')}
                rules={[
                  { required: true, message: t('targetPortInvalid') },
                  {
                    validator: (_, v) => {
                      if (v == null || v === '' || !Number.isInteger(Number(v)) || Number(v) < 1 || Number(v) > 65535) {
                        return Promise.reject(new Error(t('targetPortInvalid')));
                      }
                      return Promise.resolve();
                    },
                  },
                ]}
                className="rp-target-port"
              >
                <InputNumber min={1} max={65535} precision={0} placeholder={t('targetPort')} style={{ width: '100%' }} />
              </Form.Item>
              <div className="rp-target-actions">
                <Form.Item
                  {...fieldProps}
                  name={[field.name, 'enabled']}
                  valuePropName="checked"
                  initialValue={true}
                  noStyle
                >
                  <Switch size="small" aria-label={t('enabled')} />
                </Form.Item>
                <Button type="text" size="small" icon={<ArrowUpOutlined />} title={t('moveTargetUp')} aria-label={t('moveTargetUp')} disabled={index === 0} onClick={() => move(index, index - 1)} />
                <Button type="text" size="small" icon={<ArrowDownOutlined />} title={t('moveTargetDown')} aria-label={t('moveTargetDown')} disabled={index === fields.length - 1} onClick={() => move(index, index + 1)} />
                <Button type="text" size="small" danger icon={<DeleteOutlined />} title={t('deleteTarget')} aria-label={t('deleteTarget')} disabled={fields.length <= 1} onClick={() => remove(field.name)} />
              </div>
            </div>
            );
          })}
          <Button type="dashed" icon={<PlusOutlined />} block onClick={() => add({ host: '', port: undefined as unknown as number, enabled: true, weight: 1 })}>{t('addTarget')}</Button>
        </Space>
      )}
    </Form.List>
  );

  const loadBalanceLabel = (
    <span>
      {t('loadBalanceStrategy')}{' '}
      <Tooltip
        placement="top"
        overlayStyle={{ maxWidth: 440 }}
        title={(
          <div className="rp-load-balance-help">
            <strong>{t('lbStrategyBlockTitle')}</strong>
            <div>• {t('lbFirstDesc')}</div>
            <div>• {t('lbRoundRobinDesc')}</div>
            <div>• {t('lbFailoverDesc')}</div>
            <div>• {t('lbWeightedDesc')}</div>
            <div>• {t('lbLeastLatencyDesc')}</div>
            <div>• {t('lbLeastConnectionsDesc')}</div>
            <div className="rp-load-balance-help-footer">{t('lbStrategyBlockFooter')}</div>
          </div>
        )}
      >
        <QuestionCircleOutlined className="rp-inline-help-icon" />
      </Tooltip>
    </span>
  );

  const exportMenuItems: MenuProps['items'] = [
    { key: 'export-all', label: t('exportAll'), icon: <DownloadOutlined />, onClick: handleExportAll },
    { key: 'import', label: t('import'), icon: <UploadOutlined />, disabled: mutationsBlocked || (!isAdmin && sharedLoadFailed), onClick: () => setImportOpen(true) },
  ];

  const confirmBatchRestart = () => {
    Modal.confirm({
      title: t('batchRestartConfirm').replace('{count}', String(selectedRowKeys.length)),
      content: t('restartConfirmDesc'),
      okButtonProps: { danger: true },
      onOk: handleBatchRestart,
    });
  };

  const confirmBatchDelete = () => {
    Modal.confirm({
      title: t('batchDeleteConfirm').replace('{count}', String(selectedRowKeys.length)),
      okButtonProps: { danger: true },
      onOk: handleBatchDelete,
    });
  };

  const batchMenu: MenuProps = {
    items: [
      { key: 'export', label: t('batchExport'), icon: <DownloadOutlined /> },
      { key: 'resume', label: t('batchResume'), icon: <PlayCircleOutlined />, disabled: mutationsBlocked },
      { key: 'pause', label: t('batchPause'), icon: <PauseCircleOutlined />, disabled: mutationsBlocked },
      { key: 'restart', label: t('batchRestart'), icon: <ThunderboltOutlined />, disabled: mutationsBlocked },
      { type: 'divider' },
      { key: 'delete', label: t('batchDelete'), icon: <DeleteOutlined />, danger: true, disabled: mutationsBlocked },
    ],
    onClick: ({ key }) => {
      if (key === 'export') handleExportSelected();
      if (key === 'resume') handleBatchSetPaused(false);
      if (key === 'pause') handleBatchSetPaused(true);
      if (key === 'restart') confirmBatchRestart();
      if (key === 'delete') confirmBatchDelete();
    },
  };

  const ruleGroupName = (r: ForwardRule) => {
    const group = groupInfo.get(r.device_group_in);
    return group?.name ?? `${t('unknownGroup')} (#${r.device_group_in})`;
  };

  const ruleChainPath = (r: ForwardRule) => {
    if (r.route_mode !== 'chain' && r.forward_mode !== 'chain') return t('modeDirect');
    if (r.tunnel_id) {
      const tunnel = tunnelMap.get(r.tunnel_id);
      const prefix = r.tunnel_name || tunnel?.name || `#${r.tunnel_id}`;
      return `${prefix}${r.tunnel_enabled === false ? ` · ${t('tunnelDisabled')}` : ''}`;
    }
    const labels = (r.hops ?? []).map(h =>
      h.group_name || groupInfo.get(h.device_group_id)?.name || `#${h.device_group_id}`
    );
    return labels.length > 0 ? labels.join(' → ') : t('modeChain');
  };

  const setRuleSelected = (id: number, checked: boolean) => {
    setSelectedRowKeys(current => checked
      ? Array.from(new Set([...current, id]))
      : current.filter(key => key !== id));
  };

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><ApiOutlined /> {t('forwardRules')}</h2>
        <Space className="rp-page-actions rp-rules-toolbar" wrap size={[8, 8]}>
          <Input
            className="rp-rules-search"
            allowClear
            prefix={<SearchOutlined />}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setSelectedRowKeys([]); }}
            placeholder={t('searchRules')}
            aria-label={t('searchRules')}
          />
          {/* v0.4.9: filter by inbound group. Only groups that actually have
              rules are offered, so the list stays short for large fleets. */}
          <Select
            className="rp-toolbar-filter"
            allowClear
            placeholder={t('filterByGroup')}
            value={selectedGroup ?? undefined}
            onChange={(v: number | undefined) => { setSelectedGroup(v ?? null); setSelectedRowKeys([]); }}
            options={Array.from(new Set(rules.map(r => r.device_group_in)))
              .map(gid => {
                const g = groupInfo.get(gid);
                return { value: gid, label: g ? g.name : `${t('unknownGroup')} (#${gid})` };
              })}
          />
          {!isMobile && selectedRowKeys.length > 0 && (
            <Button icon={<DownloadOutlined />} onClick={handleExportSelected}>
              {t('batchExport')} ({selectedRowKeys.length})
            </Button>
          )}
          {!isMobile && selectedRowKeys.length > 0 && (
            <Button icon={<PlayCircleOutlined />} loading={batchAction === 'resume'} disabled={mutationsBlocked} onClick={() => handleBatchSetPaused(false)}>
              {t('batchResume')} ({selectedRowKeys.length})
            </Button>
          )}
          {!isMobile && selectedRowKeys.length > 0 && (
            <Button icon={<PauseCircleOutlined />} loading={batchAction === 'pause'} disabled={mutationsBlocked} onClick={() => handleBatchSetPaused(true)}>
              {t('batchPause')} ({selectedRowKeys.length})
            </Button>
          )}
          {!isMobile && selectedRowKeys.length > 0 && (
            <Popconfirm
              title={t('batchRestartConfirm').replace('{count}', String(selectedRowKeys.length))}
              description={t('restartConfirmDesc')}
              onConfirm={handleBatchRestart}
              okButtonProps={{ danger: true }}
            >
              <Button icon={<ThunderboltOutlined />} loading={batchAction === 'restart'} disabled={mutationsBlocked}>
                {t('batchRestart')} ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          {!isMobile && selectedRowKeys.length > 0 && (
            <Popconfirm
              title={t('batchDeleteConfirm').replace('{count}', String(selectedRowKeys.length))}
              onConfirm={handleBatchDelete}
              okButtonProps={{ danger: true }}
            >
              <Button danger icon={<DeleteOutlined />} loading={batchAction === 'delete'} disabled={mutationsBlocked}>
                {t('batchDelete')} ({selectedRowKeys.length})
              </Button>
            </Popconfirm>
          )}
          {isMobile && selectedRowKeys.length > 0 && (
            <Dropdown menu={batchMenu} trigger={['click']}>
              <Button icon={<MoreOutlined />} loading={batchBusy} disabled={loading || loadFailed || saving || busyRuleId !== null}>
                {t('selectedCount').replace('{count}', String(selectedRowKeys.length))}
              </Button>
            </Dropdown>
          )}
          <Button icon={<ReloadOutlined />} loading={loading} disabled={saving || batchBusy || busyRuleId !== null || createOpen || editOpen || importOpen || !!diagnosing} onClick={load}><span className="rp-mobile-hide">{t('refresh')}</span></Button>
          <Dropdown menu={{ items: exportMenuItems }} trigger={['click']}>
            <Button icon={<DownloadOutlined />}><span className="rp-mobile-hide">{t('exportImport')}</span></Button>
          </Dropdown>
          <Button type="primary" icon={<PlusOutlined />} disabled={mutationsBlocked || (!isAdmin && sharedLoadFailed)} onClick={() => { setEditing(null); setCreateTab('basic'); createForm.resetFields(); setCreateOpen(true); }}>{t('addRule')}</Button>
        </Space>
      </div>
      {loadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('loadFailed')}
          description={t('loadFailedRetry')}
        />
      )}
      {/* v0.4.20: admin viewing another user's rules — show who. */}
      {filterOwnerUid && (
        <Alert type="info" showIcon style={{ marginBottom: 12 }}
          title={t('viewingUserRules').replace('{user}', userMap.get(filterOwnerUid) ?? `#${filterOwnerUid}`)}
        />
      )}
      {/* v0.4.12 PR1: a regular user whose shared-lines fetch failed sees a
          load-failure notice; rule creation is disabled above so they can't
          submit against an empty/unknown inbound list. */}
      {!loadFailed && !isAdmin && sharedLoadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('loadFailed')}
          description={t('loadFailedRetry')}
        />
      )}
      {isMobile ? (
        <List
          className="rp-rule-mobile-list"
          loading={loading}
          dataSource={visibleRules}
          locale={{ emptyText: t('noRules') }}
          pagination={{ pageSize: 10, size: 'small', hideOnSinglePage: true, showSizeChanger: false }}
          renderItem={(r) => {
            const listenHost = groupInfo.get(r.device_group_in)?.connect_host ?? t('notConfigured');
            const overQuota = !r.paused && ruleOverQuota(r);
            return (
              <List.Item key={r.id}>
                <Card size="small" className="rp-rule-card">
                  <div className="rp-rule-card-header">
                    <Checkbox
                      checked={selectedRowKeys.includes(r.id)}
                      disabled={mutationsBlocked}
                      onChange={event => setRuleSelected(r.id, event.target.checked)}
                      aria-label={`${t('select')} #${r.id}`}
                    />
                    <div className="rp-rule-card-title">
                      <Text strong ellipsis={{ tooltip: r.name }}>{r.name}</Text>
                      <Text type="secondary" className="rp-rule-card-id">#{r.id}</Text>
                    </div>
                    <Space size={4} wrap className="rp-rule-card-status">
                      {protoTags(r.protocol)}
                      {r.paused && <Tag color="red">{t('paused')}</Tag>}
                      {overQuota && <Tag color="orange">{t('quotaExhausted')}</Tag>}
                    </Space>
                  </div>
                  <div className="rp-rule-card-grid">
                    <div className="rp-rule-card-field rp-rule-card-field-wide">
                      <span className="rp-rule-card-label">{t('chainPath')}</span>
                      <span className="rp-rule-card-value">{ruleChainPath(r)}</span>
                    </div>
                    <div className="rp-rule-card-field">
                      <span className="rp-rule-card-label">{t('groupName')}</span>
                      <span className="rp-rule-card-value">{ruleGroupName(r)}</span>
                    </div>
                    <div className="rp-rule-card-field">
                      <span className="rp-rule-card-label">{t('traffic')}</span>
                      <span className="rp-rule-card-value">{formatBytes(r.traffic_used)}</span>
                    </div>
                    <div className="rp-rule-card-field rp-rule-card-field-wide">
                      <span className="rp-rule-card-label">{t('listenIp')} / {t('listenPort')}</span>
                      <span className="rp-rule-card-value rp-mono">{listenHost}:{r.listen_port}</span>
                    </div>
                    <div className="rp-rule-card-field rp-rule-card-field-wide">
                      <span className="rp-rule-card-label">{t('target')}</span>
                      <span className="rp-rule-card-value rp-mono">{targetSummary(r)}</span>
                    </div>
                    {isAdmin && (
                      <div className="rp-rule-card-field rp-rule-card-field-wide">
                        <span className="rp-rule-card-label">{t('owner')}</span>
                        <span className="rp-rule-card-value">{userMap.get(r.uid) ?? `#${r.uid}`}</span>
                      </div>
                    )}
                  </div>
                  <div className="rp-rule-card-footer">{renderRuleActions(r)}</div>
                </Card>
              </List.Item>
            );
          }}
        />
      ) : (
        <Table
          className="rp-responsive-table rp-rules-table"
          rowSelection={{
            selectedRowKeys,
            onChange: (keys) => setSelectedRowKeys(keys as number[]),
            getCheckboxProps: () => ({ disabled: mutationsBlocked }),
          }}
          dataSource={visibleRules} columns={columns} rowKey="id" loading={loading}
          pagination={{ pageSize: 20 }} scroll={{ x: 1480 }}
        />
      )}

      <Modal title={t('addRule')} open={createOpen} onCancel={() => { if (!saving) setCreateOpen(false); }} onOk={() => createForm.submit()} confirmLoading={saving} okButtonProps={{ disabled: loadFailed || loading }} okText={t('create')} cancelText={t('cancel')} width={680}>
        <Form
          form={createForm}
          disabled={saving || loadFailed || loading}
          onFinish={handleCreate}
          onFinishFailed={({ errorFields }) => {
            setCreateTab(ruleFormTabForErrors(errorFields));
          }}
          layout="vertical"
          onValuesChange={(changed) => {
            if (changed.route_mode !== undefined) {
              createForm.setFieldValue('forward_mode', changed.route_mode === 'direct' ? 'direct' : 'chain');
              if (changed.route_mode === 'chain') {
                const hops = createForm.getFieldValue('hops');
                if (!hops || hops.length < 2) {
                  createForm.setFieldValue('hops', [undefined, undefined]);
                }
              }
            }
          }}
        >
          <Tabs activeKey={createTab} onChange={setCreateTab} items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')} rules={[{ required: true, whitespace: true }]}><Input placeholder="my-rule" /></Form.Item>
                {/* v0.4.20: owner is determined by the entry point — admins use
                    /rules?owner_uid=X from the user management page; regular
                    users always own their own rules. */}
                {filterOwnerUid && (
                  <Alert type="info" showIcon style={{ marginBottom: 12 }}
                    title={t('creatingRuleFor').replace('{user}', userMap.get(filterOwnerUid) ?? `#${filterOwnerUid}`)}
                  />
                )}
                {renderHostHint(createRouteMode === 'tunnel' ? selectedCreateTunnel?.hops[0]?.device_group_id : createGroupId)}
                <Form.Item name="listen_port" label={t('listenPort')} extra={t('listenPortHint')}><InputNumber min={1} max={65535} precision={0} style={{ width: '100%' }} placeholder="auto" /></Form.Item>
                <Form.Item name="protocol" label={t('protocol')} rules={[{ required: true }]} initialValue="tcp_udp"
                  extra={isUdp(createProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                  <Select
                    options={protocolOptions}
                  />
                </Form.Item>
                {/* v0.4.20: WS/TLS tunnel hidden — public_transport always raw. */}
                <Form.Item name="public_transport" hidden initialValue="raw"><Input /></Form.Item>
                <Form.Item name="route_mode" label={t('forwardMode')} initialValue="direct" rules={[{ required: true }]}>
                  <Select options={[
                    { value: 'direct', label: t('modeDirect') },
                    { value: 'chain', label: t('modeChain') },
                    { value: 'tunnel', label: t('modePresetTunnel') },
                  ]} />
                </Form.Item>
                <Form.Item name="forward_mode" hidden initialValue="direct"><Input /></Form.Item>
                {createRouteMode === 'direct' && (
                  <Form.Item name="device_group_in" label={t('inboundGroup')} rules={[{ required: true }]}>
                    <Select options={inboundGroupOptions} optionFilterProp="searchLabel" placeholder={allInGroups.length ? t('select') : t('createGroupFirst')} />
                  </Form.Item>
                )}
                {createRouteMode === 'chain' && (
                  <Form.List name="hops" initialValue={[undefined, undefined]}>
                    {(fields, { add, remove }) => (
                      <Form.Item label={t('chainHops')} extra={t('chainHopsHint')} required>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          {fields.map((field, idx) => {
                            const { key, ...fieldProps } = field;
                            return (
                            <Space key={key} align="baseline" style={{ display: 'flex' }} className="rp-chain-row">
                              <Tag>{idx === 0 ? t('hopEntry') : idx === fields.length - 1 ? t('hopExit') : `${t('hopMid')} ${idx}`}</Tag>
                              <Form.Item {...fieldProps} rules={[{ required: true, message: t('select') }]} style={{ marginBottom: 0, flex: 1 }} className="rp-chain-select">
                                <Select options={hopGroupOptions} placeholder={t('select')} showSearch optionFilterProp="label" />
                              </Form.Item>
                              {fields.length > 2 && (
                                <Button type="text" danger onClick={() => remove(field.name)} icon={<DeleteOutlined />} />
                              )}
                            </Space>
                            );
                          })}
                          {fields.length < 8 && (
                            <Button type="dashed" onClick={() => add()} block icon={<PlusOutlined />}>{t('addHop')}</Button>
                          )}
                        </Space>
                      </Form.Item>
                    )}
                  </Form.List>
                )}
                {createRouteMode === 'tunnel' && renderTunnelPicker(selectedCreateTunnel)}
              </>),
            },
            {
              key: 'forward',
              forceRender: true,
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor()}
                <Form.Item name="load_balance_strategy" label={loadBalanceLabel} initialValue="first">
                  <Select options={strategyOptions} />
                </Form.Item>
                <Form.Item
                  label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                  extra={t('rateLimitsHint')}
                >
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} precision={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                    <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} precision={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                  </Space>
                </Form.Item>
                {renderConnectionControls(createProto)}
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal title={t('editRule')} open={editOpen} onCancel={() => { if (!saving) setEditOpen(false); }} onOk={() => editForm.submit()} confirmLoading={saving} okButtonProps={{ disabled: loadFailed || loading }} okText={t('save')} cancelText={t('cancel')} width={680}>
        <Form
          form={editForm}
          disabled={saving || loadFailed || loading}
          onFinish={handleUpdate}
          onFinishFailed={({ errorFields }) => {
            setEditTab(ruleFormTabForErrors(errorFields));
          }}
          layout="vertical"
          onValuesChange={(changed) => {
            if (changed.route_mode !== undefined) {
              editForm.setFieldValue('forward_mode', changed.route_mode === 'direct' ? 'direct' : 'chain');
              if (changed.route_mode === 'chain') {
                const hops = editForm.getFieldValue('hops');
                if (!hops || hops.length < 2) {
                  editForm.setFieldValue('hops', [undefined, undefined]);
                }
              }
            }
          }}
        >
          <Tabs activeKey={editTab} onChange={setEditTab} items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')} rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>
                {renderHostHint(editRouteMode === 'tunnel' ? selectedEditTunnel?.hops[0]?.device_group_id : editGroupId)}
                <Form.Item name="listen_port" label={t('listenPort')}><InputNumber min={1} max={65535} precision={0} style={{ width: '100%' }} /></Form.Item>
                <Form.Item name="protocol" label={t('protocol')}
                  extra={isUdp(editProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                  <Select
                    options={protocolOptions}
                  />
                </Form.Item>
                <Form.Item name="public_transport" hidden initialValue="raw"><Input /></Form.Item>
                <Form.Item name="route_mode" label={t('forwardMode')} rules={[{ required: true }]}>
                  <Select options={[
                    { value: 'direct', label: t('modeDirect') },
                    { value: 'chain', label: t('modeChain') },
                    { value: 'tunnel', label: t('modePresetTunnel') },
                  ]} />
                </Form.Item>
                <Form.Item name="forward_mode" hidden><Input /></Form.Item>
                {editRouteMode === 'direct' && (
                  <Form.Item name="device_group_in" label={t('inboundGroup')}><Select options={inboundGroupOptions} optionFilterProp="searchLabel" /></Form.Item>
                )}
                {editRouteMode === 'chain' && (
                  <Form.List name="hops">
                    {(fields, { add, remove }) => (
                      <Form.Item label={t('chainHops')} extra={t('chainHopsHint')} required>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          {fields.map((field, idx) => {
                            const { key, ...fieldProps } = field;
                            return (
                            <Space key={key} align="baseline" style={{ display: 'flex' }} className="rp-chain-row">
                              <Tag>{idx === 0 ? t('hopEntry') : idx === fields.length - 1 ? t('hopExit') : `${t('hopMid')} ${idx}`}</Tag>
                              <Form.Item {...fieldProps} rules={[{ required: true, message: t('select') }]} style={{ marginBottom: 0, flex: 1 }} className="rp-chain-select">
                                <Select options={hopGroupOptions} placeholder={t('select')} showSearch optionFilterProp="label" />
                              </Form.Item>
                              {fields.length > 2 && (
                                <Button type="text" danger onClick={() => remove(field.name)} icon={<DeleteOutlined />} />
                              )}
                            </Space>
                            );
                          })}
                          {fields.length < 8 && (
                            <Button type="dashed" onClick={() => add()} block icon={<PlusOutlined />}>{t('addHop')}</Button>
                          )}
                        </Space>
                      </Form.Item>
                    )}
                  </Form.List>
                )}
                {editRouteMode === 'tunnel' && renderTunnelPicker(selectedEditTunnel)}
              </>),
            },
            {
              key: 'forward',
              // v1.0.9: force-render so the targets Form.List mounts even while
              // the Basic tab is active. Without this, editing only a Basic field
              // (e.g. listen_port) and submitting without opening this tab left
              // `values.targets` unregistered — handleUpdate then read it as
              // "targets cleared" and rejected with "add at least one target".
              forceRender: true,
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor()}
                <Form.Item name="load_balance_strategy" label={loadBalanceLabel} initialValue="first">
                  <Select options={strategyOptions} />
                </Form.Item>
                <Form.Item
                  label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                  extra={t('rateLimitsHint')}
                >
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} precision={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                    <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} precision={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                  </Space>
                </Form.Item>
                {renderConnectionControls(editProto)}
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal title={t('import')} open={importOpen} onCancel={closeImport}
        onOk={importResults.length > 0 ? undefined : handleImport}
        okText={importResults.length > 0 ? t('close') : t('import')}
        cancelText={t('cancel')} width={600} confirmLoading={saving}
        closable={!saving} mask={{ closable: !saving }} keyboard={!saving}
        okButtonProps={{ disabled: loadFailed || loading }}
        cancelButtonProps={{ disabled: saving }}
        footer={importResults.length > 0 ? <Button disabled={saving} onClick={closeImport}>{t('close')}</Button> : undefined}
      >
        {importResults.length === 0 ? (
          <>
            <Form.Item label={t('selectInboundGroup')}>
              <Select value={importGroupId} onChange={setImportGroupId} disabled={saving || loading || loadFailed}
                options={inboundGroupOptions}
                placeholder={t('selectDeviceGroups')} style={{ width: '100%' }} />
            </Form.Item>
            <Alert type="info" showIcon style={{ marginBottom: 12 }}
              title={t('importHint')} />
            <TextArea value={importText} onChange={e => setImportText(e.target.value)} disabled={saving || loading || loadFailed}
              rows={10} placeholder='[{"dest":["1.2.3.4:8080"],"listen_port":38446,"name":"SK5"}]' />
          </>
        ) : (
          <div style={{ maxHeight: 300, overflowY: 'auto' }} aria-live="polite" aria-label={t('import')}>
            {importResults.map((r, i) => <div key={i} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 13, lineHeight: 1.8 }}>{r}</div>)}
          </div>
        )}
      </Modal>

      {/* Relay-node listener and downstream TCP probe results. */}
      <Modal
        title={diagnosing ? `${t('diagnoseTitle')} · ${diagnosing.name} (#${diagnosing.id})` : t('diagnoseTitle')}
        open={!!diagnosing}
        onCancel={closeDiagnose}
        footer={<Button onClick={closeDiagnose}>{t('close')}</Button>}
        width={720}
      >
        {diagnoseLoading ? (
          <div style={{ textAlign: 'center', padding: 32 }} aria-live="polite" aria-busy="true"><Spin tip={t('diagnoseRunning')} /></div>
        ) : diagnoseResult ? (
          <>
            {/* v0.4.14: only the relay-node's OWN TCP diagnosis is shown — the
                node's listener status + its node→target TCP connectivity/latency.
                The latency is the node→target TCP handshake time, NOT a client
                end-to-end latency. */}
            <Typography.Title level={5}>{t('diagnoseIngress')}</Typography.Title>
            {diagnoseResult.nodes.length === 0 ? (
              <Text type="secondary">{t('diagnoseNoNodes')}</Text>
            ) : (
              <Space orientation="vertical" style={{ width: '100%' }}>
                {diagnoseResult.nodes.map((n, i) => (
                  <DiagnoseNodeRow key={i} node={n} t={t} isAdmin={isAdmin} />
                ))}
              </Space>
            )}
          </>
        ) : (
          <Text type="secondary">{t('diagnoseIdle')}</Text>
        )}
      </Modal>
    </>
  );
}

/** Render one node's diagnosis row. v0.4.15: the visible label is
 *  "分组名 · 公网IP" (or "分组名 · IP 未上报"), NEVER the raw node_id. node_id is
 *  admin-only (tooltip for troubleshooting); a regular user sees just the
 *  label. Same shape across all four statuses; the status tag + details differ. */
function DiagnoseNodeRow({ node, t, isAdmin }: { node: NodeDiagnoseStatus; t: (k: string) => string; isAdmin: boolean }) {
  const label = `${node.group_name || '-'} · ${node.public_ip || t('diagnoseIpMissing')}`;
  const labelText = <Text strong>{label}</Text>;
  // node_id is internal — only an admin gets the troubleshooting tooltip.
  const labelWithId = isAdmin
    ? <Tooltip title={t('diagnoseNodeIdLabel') + node.node_id}>{labelText}</Tooltip>
    : labelText;
  return (
    <div>
      <Space wrap align="center">
        {labelWithId}
        {node.status === 'result' && (
          <>
            <Tag color={node.listener_running ? 'green' : 'red'}>
              {node.listener_running ? t('diagnoseListenerRunning') : t('diagnoseListenerStopped')}
            </Tag>
            {node.listen_port ? <Text type="secondary">:{node.listen_port}</Text> : null}
            {node.protocol ? <Tag>{node.protocol}</Tag> : null}
            {node.transport ? <Tag>{node.transport}</Tag> : null}
          </>
        )}
        {node.status === 'unsupported' && (
          <Text type="warning">{t('diagnoseUnsupportedPrefix')}{node.node_version}{t('diagnoseUnsupportedSuffix')}</Text>
        )}
        {node.status === 'control_channel_offline' && (
          <Text type="secondary">{t('diagnoseOffline')}</Text>
        )}
        {node.status === 'timeout' && (
          <Tag color="orange">{t('diagnoseTimeout')}</Tag>
        )}
      </Space>
      {node.status === 'result' && node.results.length > 0 && (
        <Table<DiagnoseTargetResult> className="rp-responsive-table" size="small" pagination={false} style={{ marginTop: 8 }} scroll={{ x: 'max-content' }}
          dataSource={node.results} rowKey="address"
          columns={[
            { title: t('diagnoseTarget'), dataIndex: 'address', key: 'address', render: (v: string) => <span className="rp-mono">{v}</span> },
            { title: t('diagnoseOutcome'), key: 'outcome', render: (_: unknown, r: DiagnoseTargetResult) => <ProbeOutcomeTag o={r.outcome} t={t} /> },
          ]}
        />
      )}
    </div>
  );
}

function ProbeOutcomeTag({ o, t }: { o: DiagnoseTargetResult['outcome']; t: (k: string) => string }) {
  // v0.4.9: 'route_only' variant removed — diagnosis is TCP-only.
  if (o === 'timeout') return <Tag color="orange">{t('diagnoseOutcomeTimeout')}</Tag>;
  if ('reachable' in o) return <Tag color="green">{t('diagnoseOutcomeReachable')} {o.reachable.elapsed_ms}ms</Tag>;
  if ('failed' in o) return <Tag color="red">{t('diagnoseOutcomeFailed')}: {o.failed.error}</Tag>;
  return <Tag>?</Tag>;
}
