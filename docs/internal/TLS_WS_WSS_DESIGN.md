# TLS / WS / WSS 转发设计文档（v0.3.0 专项）

> ⚠️ **DEPRECATED (v0.4.1).** This document was the v0.3.0-era design for
> TLS/WS/WSS ingress. Business WSS is **cancelled** — see `docs/TLS-SIMPLE.md`
> for the current TLS Simple design (node terminates TLS via rustls). This
> file is kept for historical reference only; do NOT use it as a current
> design reference. The WS (plaintext) parts are still accurate; the WSS
> parts are obsolete.

> 状态：已废弃（v0.4.1）
> 适用版本：历史参考（v0.3.0 设计）
> 阅读对象：维护者（仅历史参考）

## 0. 文档约定

本文档严格区分两类内容：

- **【当前】**：v0.2.3 及之前已实现、已部署、已在生产可用的行为。
- **【v0.3.0】**：v0.3.0 计划引入的设计目标，本文档阶段尚未实现。

文档中所有"WS/WSS"必须按以下两种含义区分，**不能混淆**：

| 术语 | 含义 | 状态 |
|------|------|------|
| **控制通道 WS** | panel 与 relay-node 之间的管理通信（`/api/v1/node/ws`），用于推送配置变更、心跳保活 | 【当前】已实现，不承载用户业务流量 |
| **业务流量 WS/WSS** | 用户访问入口的协议本身就是 WebSocket / WebSocket-over-TLS，relay-node 将其作为入口协议接收并转发 | 【v0.3.0】设计中，未实现 |

文档中如不显式标注"控制通道"，所有"WS/WSS"默认指**业务流量**入口协议。

### 0.1 入口协议的两层概念（关键澄清）

本文档严格区分**两段不同的协议**，避免把"用户看到什么"和"节点实际监听什么"混为一谈：

| 概念 | 含义 | 取值 | 谁决定 |
|------|------|------|--------|
| **`public_entry_transport`** | 用户对外访问的协议（用户/客户端实际感知的） | `tcp` / `udp` / `tcp_udp` / `tls` / `ws` / `wss` | 用户在 UI 选择 |
| **`node_entry_transport`** | relay-node 实际监听的入口协议（节点 bind 的 listener 类型） | `raw` / `ws` / `tls` | 面板下发时派生 |

**派生规则**（面板在拼装 `ListenerConfig` 时执行）：

| `public_entry_transport` | 是否经反代 | `node_entry_transport` | 说明 |
|--------------------------|-----------|------------------------|------|
| `tcp` | 否 | `raw` | 直连裸 TCP |
| `udp` | 否 | `raw` | 直连裸 UDP |
| `tcp_udp` | 否 | `raw`（panel 展开 Tcp+Udp 两个 listener） | 同端口双栈 |
| `ws` | 否 | `ws` | 明文 WS 入口 |
| `wss` | **是**（Caddy/Nginx/CF 终止 TLS） | `ws` | **节点仍只跑明文 WS** |
| `wss` | 否（节点自处理 TLS） | `tls`（自管证书） | **【v0.3.0-rc 实验模式，非推荐】** |
| `tls` | 否（节点自处理 TLS） | `tls` | **【v0.3.0-rc 实验模式，非推荐】** |

**v0.3.0 推荐模型**（保守路线）：

```
用户访问 WSS  ──►  Caddy/Nginx/Cloudflare 终止 TLS  ──►  relay-node 明文 WS listener
（public=wss）        （反代层，自管证书）                  （node_entry_transport=ws）
```

因此 v0.3.0-beta 的 WSS：
- **`public_entry_transport = wss`**（UI 显示 WSS）
- **`node_entry_transport = ws`**（relay-node 实际监听明文 WS）
- **relay-node 不直接处理 TLS**

只有 v0.3.0-rc 或后续实验模式，才考虑 relay-node 自己启动 TLS/WSS listener（`node_entry_transport = tls`）。**文档和下发配置必须避免把 WSS 误派生为节点自处理 TLS。**

> **数据库字段说明**：数据库持久化的是 `forward_rules.entry_transport`，它存的是 **`public_entry_transport` 语义**（用户选择的对外协议）。面板在下发 `ListenerConfig` 时再派生出 `node_entry_transport`。relay-node 收到的 `EntryTransport` 字段是 `node_entry_transport`，不是 `public_entry_transport`。详见 §8.1。

标注图例：

| 符号 | 含义 |
|------|------|
| ✅ | 推荐方案 |
| ❌ | 不推荐方案 |
| ⚠️ | 破坏兼容性的变更 |
| 🔄 | 需要数据库迁移 |
| ❓ | 需要用户确认的问题 |
| 【当前】 | 已实现 |
| 【v0.3.0】 | 设计目标 |

---

## 1. 当前架构梳理

### 1.1 现有 TCP/UDP 转发链路 【当前】

```
用户客户端
   │  TCP/UDP (raw)
   ▼
relay-node (入口节点)
   │  TcpListener::bind / UdpSocket::bind
   │  accept() / recv_from()
   │  tokio::spawn(per-connection task)
   ▼
目标服务器 (target_addr:target_port)
```

- **链路模型**：单跳（entry → target），没有入口和出口分离的概念。
- **转发模式**：
  - `forward_mode = "direct"`：直接连接 `target_addr:target_port`
  - `forward_mode = "group"`：通过出口分组的 `connect_host` + `target_port` 连接（适用于同账号下多出口节点）
- **UDP 会话**：每个客户端源地址创建一个 connected `UdpSocket` 出口，60 秒无活动自动清理。
- **TCP 流量**：双向 `io::copy`，按 `rule_id` 累加字节数。

### 1.2 panel 如何下发规则 【当前】

下发通道有两条，互为冗余：

| 通道 | 触发 | 频率 | 用途 |
|------|------|------|------|
| WebSocket 控制通道 | 规则变更即时推送 | 实时 | `{"type":"config_changed"}` 触发节点重拉 |
| HTTP 轮询 | `POLL_INTERVAL`（默认 10 秒） | 周期性 | 节点 `GET /api/v1/node/config` |

下发数据结构：

```rust
// crates/shared/src/protocol.rs
pub struct NodeConfigResponse {
    pub listeners: Vec<ListenerConfig>,
}

pub struct ListenerConfig {
    pub rule_id: i64,
    pub port: u16,
    pub protocol: Protocol,            // Tcp | Udp | TcpUdp
    pub entry_transport: EntryTransport,
    pub targets: Vec<String>,          // "host:port" 字符串
    pub speed_limit: Option<u64>,
    pub ip_limit: Option<u32>,
}
```

### 1.3 relay-node 如何监听端口并转发 【当前】

- `ForwarderManager` 用 `HashMap<(u16, Protocol), JoinHandle<()>>` 维护当前所有监听任务。
- `apply_config()` 做 set-diff：
  - 旧集合里有、新集合没有 → `handle.abort()`
  - 新集合里有、旧集合里没有 → `tokio::spawn(start_*_listener)`
  - 两边都有 → 保留不动
- `Protocol::TcpUdp` 在 panel 端展开为两个独立 `ListenerConfig`（一个 `Tcp`、一个 `Udp`），节点永远看不到 `TcpUdp`。
- 每个 `(port, protocol)` 对应一个长生命周期 accept/recv 任务；新连接才 spawn 短任务。

### 1.4 entry_transport 字段现状 【当前】

字段已**预埋**，但**仅 `Raw` 真正生效**：

| 位置 | 类型 | 语义 | 状态 |
|------|------|------|------|
| `forward_rules.entry_transport` SQL 列 | `TEXT NOT NULL DEFAULT 'raw'` | public（用户选择） | Migration 4 已加 |
| `ForwardRule.entry_transport` Rust 字段 | `String` | public | 已存在 |
| `EntryTransport` 枚举 | `Raw \| Tls \| Ws \| Wss` | — | 已定义 |
| `CreateRuleRequest` / `UpdateRuleRequest` | API 入参 | public | 已暴露 |
| `ListenerConfig.entry_transport` | 下发字段 | **node**（节点实际监听） | 已下发 |
| 面板 admin API | — | — | **拒绝**任何非 `Raw` 值 |
| relay-node manager | — | — | **跳过**任何非 `Raw` 监听，warning 日志 |

> 【当前】public 与 node 语义恰好一致（都是 `Raw`），所以暂时无矛盾。v0.3.0 引入 WSS 后两者分离，面板必须在下发 `ListenerConfig` 时做 public→node 派生（见 §0.1、§6.2、§14.2）。

**关键 bug（v0.3.0-alpha 前置修复项）**：`crates/panel/src/api/ws.rs::build_config_snapshot` 第 256 行硬编码 `entry_transport = EntryTransport::Raw`，未读取规则实际值。这导致首次 WebSocket 控制通道推送的初始快照总是 `Raw`，节点必须轮询 HTTP `/node/config` 路径才能拿到正确值。

⚠️ **这是 v0.3.0-alpha 的前置修复项**：一旦 v0.3.0-alpha 放开 `entry_transport = ws`，首次 WebSocket 控制通道推送就会下发错误的 `Raw`，导致 WS 规则的 listener 不被启动。**必须在放开非 raw entry_transport 之前修复**，让 `build_config_snapshot` 从 `rule.entry_transport` 读取真实值（与 `crates/panel/src/api/node.rs::get_config` 保持一致）。

### 1.5 设备分组、转发规则、节点状态之间的关系 【当前】

```
users (用户)
  │
  │ 1:N
  ▼
device_groups (设备分组)
  │ group_type = 'in'         ← 入站分组，可绑定多个 relay-node
  │ group_type = 'out'        ← 出站分组，可绑定多个 relay-node
  │ group_type = 'monitor'    ← 仅上报状态，无转发能力
  │ group_type = 'chained_outbound' ← 链式出站（占位，未启用）
  │
  │ N:1 (device_group_in)
  │ N:1 (device_group_out, 可空)
  ▼
forward_rules (转发规则)
  │
  │ 由 panel 推送 NodeConfigResponse
  ▼
relay-node (按 device_group_in 过滤)
  │
  │ 周期性 POST /api/v1/node/report_status
  ▼
kvs (key = "node_status:{group_id}", value = JSON)
  │
  │ 任意认证用户 GET /api/v1/node_status
  ▼
前端 Nodes 页面（按 group_name 关联展示）
```

- 一个分组可绑定多个 relay-node（按 token 区分）。
- 一个节点只属于一个分组。
- 节点上线的判定：`last_seen` 距今小于 30 秒视为在线。

---

## 2. 产品信息架构设计

### 2.1 四个核心概念边界

#### 2.1.1 入口（Inbound）

**定义**：用户流量**进入** RelayPanel 的网络位置与协议能力。

| 维度 | 字段 | 备注 |
|------|------|------|
| 监听 IP | `device_groups.connect_host` | 分组级 |
| 监听端口范围 | `device_groups.port_range` | 分组级，节点按此约束监听 |
| 入口协议能力 | `device_groups.capabilities` 【v0.3.0 新增】 | JSON 数组，如 `["tcp","udp","tcp_udp"]`，后续扩展 `["ws","wss","tls"]` |
| 域名 | `forward_rules.domain` 【v0.3.0 新增】 | 规则级，可选 |
| TLS/WSS 支持能力 | 由 `capabilities` + 节点端的 rustls 支持共同决定 | — |

#### 2.1.2 出口（Outbound）

**定义**：流量**离开** RelayPanel 的节点或目标。

| 维度 | 字段 | 备注 |
|------|------|------|
| 出口节点 | `device_groups`（`group_type = 'out'`） | 分组级 |
| 出口能力 | `device_groups.capabilities` | 与入口同结构 |
| 地区 | `device_groups.region` 【v0.3.0 新增】 | 节点级元数据 |
| 线路 | `device_groups.line_type` 【v0.3.0 新增】 | 例：`"direct"` / `"iptv"` / `"iPLC"` |
| 是否可直连目标 | 由出口节点自身决定 | 运行时判定 |

#### 2.1.3 隧道（Tunnel）

**定义**：入口节点与出口节点**之间**的传输方式（仅当链式转发时存在；直连模式下不涉及）。

| 维度 | 字段 | 备注 |
|------|------|------|
| 隧道模板 | `tunnel_profiles.transport` | `direct` / `ws` / `wss` / `tls` / `chain` |
| TLS 处理 | `tunnel_profiles.tls_mode` | `none` / `terminate` / `passthrough` |
| WS 路径 | `tunnel_profiles.ws_path` | 例：`/relay` |
| Host Header | `tunnel_profiles.host_header` | 例：`relay.example.com` |
| SNI | `tunnel_profiles.sni` | 例：`relay.example.com` |
| 证书 | `tunnel_profiles.cert_id` | 外键，引用证书表 【v0.3.0 后续】 |

> **关键澄清**：隧道描述的是"**入口节点和出口节点之间怎么传**"，不是"用户访问协议"。用户在外部用 WSS 访问入口节点，入口节点通过 WS 隧道把流量转给出口节点，这是两段独立的协议选择。

#### 2.1.4 转发规则（Rule）

**定义**：用户访问入口的某个端口/协议后，最终转发到哪里的完整定义。

| 维度 | 字段 | 备注 |
|------|------|------|
| 入口分组 | `device_group_in` | 必填 |
| 入口协议 | `entry_transport` 【当前】+ `protocol` | 见 §4 |
| 监听端口 | `listen_port` | 必填 |
| 转发模式 | `forward_mode` | `direct` / `group` / `chain` 【v0.3.0 扩展】 |
| 出口分组 | `device_group_out` | 仅 `group` / `chain` 模式必填 |
| 隧道配置 | `tunnel_profile_id` 【v0.3.0 新增】 | 可选，缺省为 `direct` |
| 域名/Host/SNI | `forward_rules.domain` 【v0.3.0 新增】 | 可选 |
| 目标地址 | `target_addr` | 必填 |
| 目标端口 | `target_port` | 必填 |
| 限额 | `users.speed_limit` / `traffic_limit` | 用户级 |
| 用户归属 | `uid` | 必填 |

### 2.2 关键决策

#### 2.2.1 入口/出口是否拆表

✅ **保留统一 `device_groups` 表，通过 `group_type` 字段区分角色（in / out / monitor / chained_outbound）**

- 已有 `group_type` 字段天然适配，零迁移成本。
- **术语约定**：数据库字段继续叫 `group_type`，**v0.3.0 不重命名为 `role`**（避免无意义的 schema 迁移）；UI 文案可以显示为"角色"以提升可读性，但底层字段名不变。
- 同一节点可同时承担入口+出口（家中机器：既是入站也是出站），不需要拆两条记录。
- 前端只需在创建分组时让用户选择角色即可，认知成本低。
- ❌ **不推荐拆成两张表**：增加迁移代码量，对小规模自部署场景过度设计。

#### 2.2.2 是否需要新增"隧道配置"页面

✅ **新增 `tunnel_profiles` 表 + 隧道配置页面**

- 一处修改全局生效，避免 100 条规则用同一个 WS 路径却要配 100 次。
- 隧道模板可复用、可版本、可审计。
- 详见 §3.4 和 §5。

#### 2.2.3 device_group_in / device_group_out 是否够用

✅ **现有两个字段足够**，新增 `tunnel_profile_id` 即可表达链式场景。

- `device_group_in`：入口节点所在分组。
- `device_group_out`：出口节点所在分组（仅当 `forward_mode != "direct"`）。
- `tunnel_profile_id`：入口到出口的传输方式（链式转发时才生效）。

#### 2.2.4 entry_transport 放在规则上还是入口能力上

✅ **放在规则上（保持现状）**

- 同一个入口分组可以同时承载不同入口协议（TCP 规则和 WS 规则都用同一个 Tokyo 节点）。
- `device_groups.capabilities` 仅做**事前校验**：如果分组标 `["tcp"]` 但规则选 `entry_transport="ws"`，则创建时报错"该入口分组不支持 WS 协议"。
- 这样设计的好处：分组能力是**声明**（运维填），规则协议是**需求**（用户填），两者独立变化。

#### 2.2.5 tunnel_transport 与 entry_transport 关系

✅ **完全独立两个字段**

| 字段 | 作用范围 | 例子 |
|------|----------|------|
| `entry_transport`（public 语义） | 用户→入口节点（对外协议） | 用户用 WSS 访问 |
| `tunnel_profile.transport` | 入口节点→出口节点（节点间隧道） | 入口用裸 TCP 把流量转给出口 |

两段协议可以独立选择：用户用 WSS 访问（经反代终止 TLS 后节点跑明文 WS），入口节点可以用裸 TCP 隧道把流量转给出口节点；反过来也可以。**这是 v0.3.0 设计的关键解耦点。**

> **注意**：`entry_transport` 持久化的是 public 语义（用户选择），节点端实际监听的 `node_entry_transport` 由面板派生（见 §0.1 和 §14.2）。`tunnel_profile.transport` 是节点间隧道的描述，与入口协议完全正交。

#### 2.2.6 forward_mode 统一命名

✅ **三态枚举：`direct` / `group` / `chain`**

| 值 | 含义 | 现有规则映射 |
|----|------|--------------|
| `direct` | 入口节点直连目标 | 【当前】`forward_mode = "direct"` 保留 |
| `group` | 入口→指定出口分组 | 【当前】`forward_mode = "group"` 保留 |
| `chain` | 入口→指定出口分组，且入口到出口走隧道配置 | 【v0.3.0 新增】 |

> **与现有命名兼容**：`direct` 和 `group` 行为完全不变，`chain` 是新引入模式，详见 §5 兼容映射。

---

## 3. 页面布局设计

### 3.1 设备分组页面调整 【v0.3.0】

**保持一个页面，按 `group_type` 分 Tab 展示**，避免拆分认知成本：

```
┌─ 设备分组 ─────────────────────────────────────────────┐
│  Tab: [ 入口分组 (in) | 出口分组 (out) | 监控 (monitor) | 链式出口 ] │
└────────────────────────────────────────────────────────┘
```

分组列表字段：

| 列 | 字段 | 说明 |
|----|------|------|
| ID | `id` | — |
| 名称 | `name` | — |
| 角色 | `group_type` | Tag 颜色：in=绿、out=青、monitor=灰、chained=蓝 |
| 协议能力 | `capabilities` 【新增】 | 显示为 Tag 列表，如 `TCP UDP WS` |
| 连接地址 | `connect_host` | 入口/出口节点的对外地址 |
| 端口范围 | `port_range` | 仅入口分组有意义 |
| 地区 | `region` 【新增】 | 例：`Tokyo`、`Singapore` |
| 线路 | `line_type` 【新增】 | 例：`Direct`、`IPLC` |
| 在线节点 | 派生：计数 30 秒内上报的节点 | — |
| Token | `token` | 现有 |
| 操作 | 编辑 / 删除 | 现有 |

创建/编辑表单字段：

| 字段 | 必填 | 备注 |
|------|------|------|
| 名称 | ✅ | — |
| 角色 | ✅ | `in` / `out` / `monitor` / `chained_outbound` |
| 连接地址 | ✅ | 入口/出口节点地址 |
| 协议能力 | ✅（仅 in/out） | 多选：`tcp` / `udp` / `tcp_udp` / `ws` / `wss` / `tls` |
| 端口范围 | ✅（仅 in） | 例：`10000-20000` |
| 地区 | ❌ | 例：`Tokyo` |
| 线路 | ❌ | 例：`Direct` |

### 3.2 转发规则页面调整 【v0.3.0】

#### 3.2.1 表格列（新版 12 列）

| # | 列 | 字段 | 宽度 | 备注 |
|---|----|------|------|------|
| 1 | ID | `id` | 60 | — |
| 2 | 用户 | `uid` → `username` | 100 | 现有 |
| 3 | 入口分组 | `device_group_in.name` | 130 | 现有 |
| 4 | 监听 IP | 派生 | 140 | 现有 |
| 5 | 监听端口 | `listen_port` | 80 | 现有 |
| 6 | 入口协议 | `protocol` + `entry_transport` | 130 | Tag：`TCP+TLS` / `UDP` / `WS` / `WSS` 等 |
| 7 | 转发模式 | `forward_mode` | 100 | Tag：`直连` / `出口分组` / `链式出口` |
| 8 | 出口分组 | `device_group_out.name` | 130 | 仅非 direct 显示 |
| 9 | 隧道协议 | `tunnel_profile.transport` | 100 | `直接` / `WS` / `WSS` / `TLS` / `链式` |
| 10 | 目标 | `target_addr:target_port` | 160 | 现有 |
| 11 | 流量 | `traffic_used` | 90 | 现有 |
| 12 | 状态 + 操作 | `status` + Edit/Copy/Export/Delete | 220 | 现有 |

#### 3.2.2 新建/编辑规则：分步表单

设计原则：**默认 TCP/UDP 用户的体验不能变复杂**。仅当用户主动选择 WS/WSS/TLS 时，才展开高级字段。

```
[步骤 1] 选择入口分组
  Select: device_group_in (in 类型)
  Alert: 当前入口分组支持协议：TCP UDP WS WSS

[步骤 2] 选择入口协议
  Radio.Group:
    ○ TCP      ○ UDP      ○ TCP + UDP
    ○ WS       ○ WSS      ○ TLS
  注：UDP/TCP+UDP 模式下 WS/WSS/TLS 禁用（TCP only）

[步骤 3] 选择转发模式
  Radio.Group:
    ○ 入口直连目标 (forward_mode = direct)
    ○ 通过出口分组 (forward_mode = group)
    ○ 链式出口（入口→隧道→出口） (forward_mode = chain) 【v0.3.0 新增】

[步骤 4] 填写目标（按模式动态）
  direct:  target_addr + target_port
  group:  device_group_out + target_port
  chain:  device_group_out + tunnel_profile_id + target_port

[步骤 5] 高级选项（仅在协议为 WS/WSS/TLS 时展开）
  ┌─────────────────────────────────┐
  │ 域名 / Host      [_____________] │
  │ SNI              [_____________] │
  │ WS 路径          [_____________] │
  │ WS Host Header   [_____________] │
  │ 证书             [选择证书 ▾]    │
  │ 备注             [_____________] │
  └─────────────────────────────────┘

[步骤 6] 名称 + 监听端口
  name        [_____________]
  listen_port [_____] （留空自动分配）
```

### 3.3 节点状态页面增强 【v0.3.0】

现有 14 列基础上扩展：

| 新增列 | 字段 | 说明 |
|--------|------|------|
| 角色 | 派生自分组 `group_type` | Tag：入口/出口/监控 |
| 公网 IP | 现有 | 增加"复制"按钮 |
| WS 控制通道 | 派生 | 30 秒内收到 WS 帧视为活跃，否则显示"轮询模式" |
| 实时网速 | 现有 `upload_bps` / `download_bps` | 保留 |
| 硬盘 | 现有 | 保留 |
| 累计流量 | 现有 | 保留 |

**多节点显示最清晰的做法**：分组名作为表头分隔，分组内多节点按 ID 排序。

```
┌─ 节点状态 ─────────────────────────────────────────────┐
│  入口分组：[Tokyo-A]                                     │
│    #101  入口  203.0.113.10  online  12%  8%  ...       │
│    #102  入口  203.0.113.11  online  15%  10% ...       │
│  出口分组：[Singapore]                                   │
│    #201  出口  198.51.100.5  online  9%   6%  ...       │
└────────────────────────────────────────────────────────┘
```

### 3.4 隧道配置页面 【v0.3.0 新增】

**是否新增**：✅ **新增**，路径 `/tunnels`。

列表字段：

| 列 | 字段 |
|----|------|
| ID | `id` |
| 名称 | `name` |
| 隧道类型 | `transport`：`direct` / `ws` / `wss` / `tls` / `chain` |
| TLS 处理 | `tls_mode`：`none` / `terminate` / `passthrough` |
| WS 路径 | `ws_path` |
| Host | `host_header` |
| SNI | `sni` |
| 引用次数 | 派生：被多少条规则引用 |
| 操作 | 编辑 / 删除（被引用时禁用删除） |

预设模板建议出厂自带（不可删）：

> **澄清**：下表 `transport` 描述的是**节点间隧道**（入口节点→出口节点），不是用户入口协议。入口协议由规则的 `entry_transport`（public 语义）决定，与隧道正交（见 §2.2.5）。`wss-via-caddy` 这类模板是隧道层的 WS-over-TLS，用于入口和出口之间加密传输。

| 名称 | transport | tls_mode | ws_path | 说明 |
|------|-----------|----------|---------|------|
| `direct` | `direct` | `none` | — | 直连，缺省模板 |
| `ws-relay` | `ws` | `none` | `/relay` | 节点间明文 WS 隧道 |
| `wss-via-caddy` | `wss` | `none` | `/relay` | 节点间 WSS 隧道（经反代终止 TLS） |
| `tls-passthrough` | `tls` | `passthrough` | — | 节点间 TLS 直通 |
| `tls-terminate` | `tls` | `terminate` | — | 入口节点终止 TLS，裸 TCP 转出口 |
| `chain` | `chain` | `none` | — | 链式：多跳隧道 |

---

## 4. 协议定义

| 协议 | 含义 | 适合场景 | 备注 |
|------|------|----------|------|
| **TCP** | 裸 TCP 转发 | 通用 TCP 服务（SSH、自定义 TCP、HTTP/1.1） | 【当前】默认 |
| **UDP** | 裸 UDP 转发 | DNS、游戏、QUIC 内部组件、VoIP | 【当前】默认 |
| **TCP+UDP** | 同端口同时监听 TCP 和 UDP | DNS over TCP+UDP、QUIC 握手 | 【当前】默认 |
| **TLS** | TLS 入口 | 客户端要求 TLS 直连（不经过反代） | 【v0.3.0】支持 passthrough / terminate |
| **WS** | 明文 WebSocket 入口 | 客户端必须用 WebSocket（绕过防火墙） | 【v0.3.0-alpha】 |
| **WSS** | TLS WebSocket 入口 | 同上 + 需要加密 | 【v0.3.0-beta 推荐经反代】 |

**关键澄清**：

- "TLS 入口"指**用户到入口节点**这段走 TLS，不是节点间隧道。
- "WS/WSS 转发"指**入口协议本身就是 WebSocket**，不是把 TCP 流量强行塞进 WebSocket（那是另一种反人类方案）。

---

## 5. 数据模型设计

### 5.1 字段变更总览

#### 5.1.1 `forward_rules` 【v0.3.0】

| 字段 | 类型 | 变更 | 备注 |
|------|------|------|------|
| `entry_transport` | `TEXT NOT NULL DEFAULT 'raw'` | 【当前】已存在 | 接受值：`raw` / `tls` / `ws` / `wss`（**注意：`tcp_udp` 不在此列，它属于 `protocol`**） |
| `protocol` | `TEXT NOT NULL DEFAULT 'tcp'` | 【当前】不变 | 保留 `tcp` / `udp` / `tcp_udp`（**`tcp_udp` 是 L4 类型，不是入口封装**） |
| `forward_mode` | `TEXT NOT NULL DEFAULT 'group'` | 【当前】扩展 | 新增 `chain` 值 |
| `tunnel_profile_id` | `INTEGER REFERENCES tunnel_profiles(id)` | 🔄 【v0.3.0 新增列】 | 可空；NULL 表示直连 |
| `device_group_in` | `INTEGER NOT NULL REFERENCES device_groups(id)` | 【当前】不变 | — |
| `device_group_out` | `INTEGER REFERENCES device_groups(id)` | 【当前】不变 | direct 模式可空，group/chain 模式必填 |
| `target_addr` | `TEXT NOT NULL` | 【当前】不变 | — |
| `target_port` | `INTEGER NOT NULL` | 【当前】不变 | — |
| `domain` | `TEXT` | 🔄 【v0.3.0 新增列】 | 可空；WS/WSS/TLS 时常用 |
| `ws_path` | `TEXT` | 🔄 【v0.3.0 新增列】 | 可空；`/relay` 等 |
| `ws_host` | `TEXT` | 🔄 【v0.3.0 新增列】 | 可空；HTTP Host header |
| `sni` | `TEXT` | 🔄 【v0.3.0 新增列】 | 可空；TLS 时使用 |
| `cert_id` | `INTEGER REFERENCES certificates(id)` | 🔄 【v0.3.0 后续】 | 证书表后续版本引入 |
| `owner_user_id` | `uid` | 【当前】不变 | — |
| `traffic_limit` | 用户表字段 | 【当前】不变 | — |

> **决策**：WS 路径/Host/SNI 既可放在规则上也可放在 `tunnel_profiles` 上。**默认放在 `tunnel_profiles` 上**，规则可选择性 override（NULL 时使用 profile 默认值）。

#### 5.1.2 `device_groups` 【v0.3.0】

| 字段 | 类型 | 变更 | 备注 |
|------|------|------|------|
| `name` | `TEXT NOT NULL` | 【当前】不变 | — |
| `group_type` | `TEXT NOT NULL` | 【当前】不变 | `in` / `out` / `monitor` / `chained_outbound` |
| `token` | `TEXT NOT NULL UNIQUE` | 【当前】不变 | — |
| `connect_host` | `TEXT NOT NULL DEFAULT ''` | 【当前】不变 | — |
| `port_range` | `TEXT NOT NULL DEFAULT '1-65535'` | 【当前】不变 | — |
| `capabilities` | `TEXT NOT NULL DEFAULT '["tcp","udp"]'` | 🔄 【v0.3.0 新增列】 | JSON 字符串数组 |
| `region` | `TEXT` | 🔄 【v0.3.0 新增列】 | 例：`Tokyo` |
| `line_type` | `TEXT` | 🔄 【v0.3.0 新增列】 | 例：`Direct` / `IPLC` / `BGP` |
| `remark` | `TEXT` | 🔄 【v0.3.0 新增列】 | 自由备注 |

#### 5.1.3 `tunnel_profiles` 【v0.3.0 新增表】

```sql
CREATE TABLE tunnel_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    transport       TEXT NOT NULL DEFAULT 'direct',  -- direct/ws/wss/tls/chain
    tls_mode        TEXT NOT NULL DEFAULT 'none',    -- none/terminate/passthrough
    ws_path         TEXT NOT NULL DEFAULT '/relay',
    host_header     TEXT NOT NULL DEFAULT '',
    sni             TEXT NOT NULL DEFAULT '',
    cert_id         INTEGER,                          -- 后续版本引用 certificates
    is_builtin      INTEGER NOT NULL DEFAULT 0,      -- 内置模板不可删
    uid             INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
```

#### 5.1.4 `certificates` 【v0.3.0 后续】

v0.3.0 不实现，列为后续版本设计：

```sql
-- 占位设计，不在 v0.3.0 实施
CREATE TABLE certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    key_pem         TEXT NOT NULL,
    issuer          TEXT,
    expires_at      TEXT,
    uid             INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 5.2 数据库迁移方案 🔄

所有变更向后兼容。**迁移顺序按外键依赖排列**：先建被引用表（`tunnel_profiles`）+ 种子数据，再加引用它的列（`forward_rules.tunnel_profile_id`），最后加其他独立列。

| 迁移 | 内容 | SQL |
|------|------|-----|
| Migration 5 | **新建 `tunnel_profiles` 表** | `CREATE TABLE tunnel_profiles (...)` |
| Migration 6 | **种子数据：内置 `tunnel_profiles`** | `INSERT INTO tunnel_profiles (name, transport, tls_mode, ws_path, is_builtin) VALUES ('direct','direct','none','',1), ('ws-relay','ws','none','/relay',1), ('wss-via-caddy','wss','none','/relay',1), ('tls-passthrough','tls','passthrough','',1), ('tls-terminate','tls','terminate','',1), ('chain','chain','none','',1)` |
| Migration 7 | 新增 `forward_rules.tunnel_profile_id`（此时 tunnel_profiles 已存在，FK 合法） | `ALTER TABLE forward_rules ADD COLUMN tunnel_profile_id INTEGER REFERENCES tunnel_profiles(id)` |
| Migration 8 | 新增 `forward_rules.domain` | `ALTER TABLE forward_rules ADD COLUMN domain TEXT` |
| Migration 9 | 新增 `forward_rules.ws_path` | `ALTER TABLE forward_rules ADD COLUMN ws_path TEXT` |
| Migration 10 | 新增 `forward_rules.ws_host` | `ALTER TABLE forward_rules ADD COLUMN ws_host TEXT` |
| Migration 11 | 新增 `forward_rules.sni` | `ALTER TABLE forward_rules ADD COLUMN sni TEXT` |
| Migration 12 | 新增 `device_groups.capabilities` | `ALTER TABLE device_groups ADD COLUMN capabilities TEXT NOT NULL DEFAULT '["tcp","udp"]'` |
| Migration 13 | 新增 `device_groups.region` | `ALTER TABLE device_groups ADD COLUMN region TEXT` |
| Migration 14 | 新增 `device_groups.line_type` | `ALTER TABLE device_groups ADD COLUMN line_type TEXT` |
| Migration 15 | 新增 `device_groups.remark` | `ALTER TABLE device_groups ADD COLUMN remark TEXT` |

所有迁移走 `crates/panel/src/db/schema.rs` 现有的 `run_migrations` 框架，幂等可重复。

### 5.3 旧字段到新模型的兼容性映射 ⚠️

#### 5.3.1 `forward_mode` 兼容

| 旧值 | 新值 | 行为 |
|------|------|------|
| `direct` | `direct` | 完全等价，不变 |
| `group` | `group` | 完全等价，不变 |
| （无）| `chain` | 仅新规则可选 |

✅ **零迁移成本**：`forward_mode` 字符串值直接保留。

#### 5.3.2 `entry_transport` 兼容（public 语义）

`forward_rules.entry_transport` 持久化的是 **`public_entry_transport`**（用户对外协议），不是节点实际监听协议。各值何时被 admin API 接受：

| 值（public 语义） | 何时被接受 | 下发到节点的 `node_entry_transport` |
|-------------------|-----------|--------------------------------------|
| `raw` | 【当前】已接受 | `raw` |
| `ws` | 【v0.3.0-alpha】开始接受 | `ws` |
| `wss` | 【v0.3.0-beta】开始接受（仅经反代路径） | `ws`（反代终止 TLS） |
| `wss` | 【v0.3.0-rc】开始接受（节点自处理路径，实验） | `tls` |
| `tls` | 【v0.3.0-rc】开始接受（实验） | `tls` |

⚠️ **【当前】admin.rs 拒绝任何非 `raw` 值**（见 §1.4）。v0.3.0-alpha 起逐步放宽限制。
⚠️ **`tcp_udp` 不在此表**——它属于 `protocol` 字段，不是 `entry_transport`。

#### 5.3.3 没有 `tunnel_profile_id` 的旧规则

✅ **处理**：旧规则的 `tunnel_profile_id = NULL`，运行时**自动 fallback 到内置 `direct` 模板**（Migration 6 种子数据，id=1）。

迁移代码逻辑：

```rust
// 在 get_config 路径里
let tunnel = rule.tunnel_profile_id
    .and_then(|id| tunnel_profiles.get(id))
    .unwrap_or_else(|| tunnel_profiles.get_builtin("direct").unwrap());
```

#### 5.3.4 `device_group_in` / `device_group_out` 兼容

✅ **完全保留**，无需迁移。

#### 5.3.5 旧节点不支持新协议时面板避免下发不兼容规则

策略：**节点能力上报（v0.3.0 引入）**

扩展 `StatusReport`：

```rust
pub struct StatusReport {
    // ... 现有字段
    pub node_capabilities: Vec<String>,  // ["tcp","udp","ws","wss","tls"] 节点实际支持
}
```

面板 `/api/v1/node/config` 在拼装 `ListenerConfig` 时：

```rust
let node_caps = get_node_capabilities(group_id);  // 从 kvs 读
for rule in rules {
    if !node_caps.contains(&rule.entry_transport) {
        warn!("skip rule {} for node {}: missing capability",
              rule.id, group_id);
        continue;
    }
    listeners.push(...)
}
```

⚠️ **v0.3.0-alpha 不实施节点能力上报**，仅靠分组 `capabilities` 字段做事前校验。v0.3.0-rc 起加 `StatusReport.node_capabilities`。

#### 5.3.6 `protocol` / `entry_transport` / `node_entry_transport` 的关系 ⚠️

**【当前】字段职责**：

- `forward_rules.protocol`：L4 类型，取值 `tcp` / `udp` / `tcp_udp`
- `forward_rules.entry_transport`：入口封装（持久化的是 `public_entry_transport` 语义），取值 `raw` / `tls` / `ws` / `wss`

**【v0.3.0】派生规则**：UI 用户选择"入口协议"后，面板按以下规则写入 DB，并在下发 `ListenerConfig` 时派生 `node_entry_transport`：

| 用户在 UI 选择 | 持久化到 DB（public 语义） | 下发到节点的 `node_entry_transport` | 说明 |
|----------------|------------------------------|--------------------------------------|------|
| TCP | `protocol='tcp', entry_transport='raw'` | `raw` | 现有 |
| UDP | `protocol='udp', entry_transport='raw'` | `raw` | 现有 |
| TCP+UDP | `protocol='tcp_udp', entry_transport='raw'` | `raw`（panel 展开 Tcp+Udp 两个 listener） | 现有 |
| WS | `protocol='tcp', entry_transport='ws'` | `ws` | 新组合 |
| WSS 经反代（推荐） | `protocol='tcp', entry_transport='wss'` | **`ws`**（节点跑明文 WS，反代终止 TLS） | 新组合 |
| WSS 节点自处理（实验） | `protocol='tcp', entry_transport='wss'` | `tls`（节点自管证书） | 仅 v0.3.0-rc |
| TLS | `protocol='tcp', entry_transport='tls'` | `tls`（节点自管证书） | 仅 v0.3.0-rc |

> **关键澄清**：
> - `tcp_udp` 永远只属于 `protocol`，**不能**出现在 `entry_transport`。
> - `entry_transport` 持久化的是用户选择的对外协议（`public` 语义）。
> - 节点收到的 `EntryTransport` 是派生后的 `node_entry_transport`，不是用户原始选择。
> - WSS 经反代时，**节点端 `node_entry_transport=ws`**，节点代码里**永远不会出现 `start_wss_listener`**（WSS 在节点端不存在，TLS 由反代终止）。

> **保持向后兼容**：所有现有规则 `protocol='tcp', entry_transport='raw'` 直接映射到 UI "TCP" 选项，零迁移。

---

## 6. 证书设计

### 6.1 三种方案比较

| 方案 | 优点 | 缺点 | v0.3.0 推荐 |
|------|------|------|-------------|
| **A. 用户手动上传证书** | 控制力强，无需依赖外部服务 | 90 天续期痛苦，多域名难管 | ❌ 不推荐首发 |
| **B. 面板集成 ACME 自动签发** | 全自动，Let's Encrypt 免费 | 需写 ACME 客户端、HTTP-01/ DNS-01 验证、面板宕机时续期失败、需穿透到控制台 | ❌ 不推荐首发 |
| **C. 推荐 Caddy/Nginx 反代负责 HTTPS，relay-node 只处理 WS** | 反代自动续期（特别是 Caddy）、职责分离、节点保持轻量 | 用户需自备域名+反代基础设施 | ✅ **v0.3.0 首选** |

### 6.2 v0.3.0 最小可行方案

✅ **方案 C：relay-node 不直接处理 TLS，由 Caddy/Nginx/Cloudflare 终止 TLS 后用明文 WS 转发到 relay-node。**

完整路径（以 WSS 经反代为例）：

```
浏览器 / 客户端
   │  wss://relay.example.com/relay        ← public_entry_transport = wss
   ▼
Caddy / Nginx / Cloudflare
   │  TLS 终止，证书自动续期
   │  反代升级：proxy_pass http://node:18888 + Upgrade/Connection
   ▼
relay-node (node_entry_transport = ws)     ← 节点实际监听明文 WS，不处理 TLS
   │  接收明文 WS 帧
   ▼
目标服务 (target_addr:target_port)
```

**面板派生逻辑**（下发 `ListenerConfig` 时）：

```rust
// 用户选择 public_entry_transport = wss，经反代模式
// 面板派生 node_entry_transport = ws（不是 tls）
let node_transport = match (rule.entry_transport, rule.tls_terminated_by_proxy) {
    (EntryTransport::Wss, true)  => EntryTransport::Ws,   // 经反代：节点跑明文 WS
    (EntryTransport::Wss, false) => EntryTransport::Tls,  // 节点自处理：实验模式
    (other, _) => other,                                   // raw/ws/tls 直接透传
};
```

**为什么 WSS 不放在 relay-node**：
- 节点通常在内网或 NAT 后面，签 ACME 证书需暴露 80/443。
- 节点镜像保持轻量（musl + rustls 已 OK，但加 ACME 客户端增加 2-5MB 二进制体积）。
- 反代天然支持自动续期（Caddy 是开箱即用）。
- 用户已有 Caddy/Nginx 经验的部署门槛最低。

**v0.3.0-alpha 范围**：不涉及证书管理，仅支持明文 `ws` 入口（`node_entry_transport = ws`）。
**v0.3.0-beta 范围**：WSS 经 Caddy/Nginx 反代（`public_entry_transport = wss`，但 `node_entry_transport` 仍为 `ws`，节点不处理 TLS）。文档引导用户用反代。
**v0.3.0-rc 范围**：可选实验节点自处理 TLS（`node_entry_transport = tls`，自带证书上传，terminate 模式）。
**后续版本**：面板内置 ACME 自动证书管理。

---

## 7. 反代设计

### 7.1 通用要求

无论 Nginx / Caddy / Cloudflare，必须满足：

| 要求 | 原因 |
|------|------|
| ✅ 支持 WebSocket Upgrade | WSS 必需 |
| ✅ 透传 `Host` header | 多域名分流 |
| ✅ 透传 `X-Forwarded-Proto` | 节点可识别原始协议 |
| ✅ 透传 `Upgrade` / `Connection` | WebSocket 必需 |
| ⚠️ 反代超时 ≥ 1 小时 | 避免长连接被切 |
| ❌ 不要 buffer WebSocket 帧 | 仅 HTTP body 可 buffer |

### 7.2 relay-node 是否需要直接暴露公网

❌ **v0.3.0 推荐：relay-node 仅监听内网或反代后端端口，公网 443 由反代负责。**

**理由**：
- 节点用 musl + rustls 二进制，部署在内网或 NAT 后。
- 反代负责 TLS 终止、证书续期、CC 防护、IP 黑白名单。
- 节点公网暴露会绕过所有这些保护层。

**例外**：节点自处理 TLS 的实验模式（`node_entry_transport = tls` 的 terminate 模式，仅 v0.3.0-rc 起），节点确实需要直接监听 443 并加载证书，此时建议用 `sni` 字段锁定单域名。**v0.3.0-beta 的 WSS 不属于此例外**——经反代的 WSS 节点端是 `node_entry_transport = ws`，不暴露 443。

### 7.3 Caddy 示例配置

Caddy 的两个常见反代场景必须区分开：

| 域名 | 反代目标 | 用途 |
|------|----------|------|
| `panel.example.com` | RelayPanel 面板（`127.0.0.1:18888`） | 用户访问管理后台 |
| `relay.example.com` | relay-node 业务流量 WS listener（`node.internal:18888`） | WSS 业务流量入口，TLS 由 Caddy 终止 |

> **关键提示**：Caddy 默认支持 WebSocket Upgrade，**一般不需要手动设置 `Upgrade` / `Connection` header**。Caddy 会在检测到客户端发起 WebSocket 握手时自动透传这两个 header 给后端。手动写 `header_up Upgrade ...` 反而可能干扰 Caddy 的自动判定。

#### 场景 A：反代 RelayPanel 面板 UI

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:18888
}
```

说明：
- 面板自身有控制通道 WS（`/api/v1/node/ws`），Caddy 默认透传即可，无需特殊配置。
- Caddy 会自动为 `panel.example.com` 申请并续期 Let's Encrypt 证书。

#### 场景 B：反代业务流量 WSS 到 relay-node WS listener

```caddyfile
relay.example.com {
    # 健康检查：默认用 Caddy 自身 respond 占位，不依赖 relay-node 是否实现 /health
    handle /health {
        respond "ok" 200
    }

    # 仅代理 /relay 路径到节点的明文 WS listener
    # 节点端 node_entry_transport = ws（不处理 TLS）
    reverse_proxy /relay* node.internal:18888
}
```

说明：
- `reverse_proxy /relay*` 只把 `/relay` 前缀的请求转发到节点的 WS listener，其他路径不暴露节点。
- 节点端跑的是**明文 WS**（`node_entry_transport = ws`），TLS 在 Caddy 这一层终止，节点不感知 WSS。
- Caddy 自动申请并续期 `relay.example.com` 的证书。
- **健康检查策略**：当前设计文档阶段默认使用 Caddy 自身 `respond "ok" 200` 作为占位，**不依赖 relay-node 已实现 `/health`**。relay-node 是否内置 `/health` 端点属于待确认项（见 §13.2 Q4）：
  - 若 relay-node 在 v0.3.0-alpha 实现了 `/health`，可改为 `reverse_proxy node.internal:18888` 反代到节点。
  - 若未实现，保持 Caddy 自身 `respond "ok" 200` 即可（仅表示 Caddy 自身可达，不验证节点状态）。
- 长连接默认不会被 Caddy 切断（Caddy 的 `reverse_proxy` 对 WebSocket 没有默认超时）。如有特殊需求可显式加：

  ```caddyfile
  relay.example.com {
      reverse_proxy /relay* node.internal:18888 {
          transport http {
              read_timeout 1h
              write_timeout 1h
          }
      }
  }
  ```

#### 两个场景合并到一个 Caddyfile

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:18888
}

relay.example.com {
    handle /health {
        respond "ok" 200
    }
    reverse_proxy /relay* node.internal:18888
}
```

> **不推荐写法**（旧版文档曾出现，已废弃）：
> ```caddyfile
> # ❌ 错误：handle_response + copy_headers 不是常规 WS 反代写法，容易误导
> handle_response @relay {
>     copy_headers
> }
> ```
> ```caddyfile
> # ❌ 不必要：Caddy 默认已透传 Upgrade/Connection，手动写反而可能干扰
> header_up Upgrade {http.request.header.Upgrade}
> header_up Connection {http.request.header.Connection}
> ```

### 7.4 Nginx 示例配置

> **与 Caddy 的差异**：Nginx 默认**不**透传 WebSocket，必须手动设置 `Upgrade` / `Connection` header（Caddy 会自动透传，所以 Caddy 示例里没有这些）。两个反代场景同样需要区分：`panel.example.com`（面板）和 `relay.example.com`（业务流量 WSS）。

#### 场景 A：反代 RelayPanel 面板 UI

```nginx
upstream panel_backend {
    server 127.0.0.1:18888;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    location / {
        proxy_pass http://panel_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 面板有控制通道 WS（/api/v1/node/ws），需要透传
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

#### 场景 B：反代业务流量 WSS 到 relay-node WS listener

```nginx
upstream relay_node {
    server node.internal:18888;   # 或 127.0.0.1:18888（同机部署）
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name relay.example.com;

    # TLS 配置（用 certbot 或自签）
    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    # 仅代理 /relay 路径到节点的明文 WS listener
    # 节点端 node_entry_transport = ws（不处理 TLS）
    location /relay {
        proxy_pass http://relay_node;

        # WebSocket 关键 header（Nginx 必需，不像 Caddy 会自动透传）
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 长连接超时
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # 健康检查：Nginx 自身 return 占位，不依赖 relay-node 是否实现 /health
    # 若 relay-node 实现了 /health，可改为 proxy_pass http://relay_node;
    location /health {
        return 200 "ok\n";
    }
}
```

### 7.5 Cloudflare 注意事项

- Cloudflare 默认支持 WebSocket，无需特殊配置。
- "Network" 选项卡确保 WebSockets 开关打开。
- 如果节点在 Cloudflare 后面，建议开启 Authenticated Origin Pulls（双向 TLS）。
- 节点 IP 不要直接暴露，否则攻击者可绕过 Cloudflare。

---

## 8. 节点端实现设计

### 8.1 manager 如何按 node_entry_transport 启动不同 listener 【v0.3.0】

**关键澄清**：节点收到的 `ListenerConfig.entry_transport` 是**派生后的 `node_entry_transport`**，不是用户原始的 `public_entry_transport`。节点代码里**不存在 `start_wss_listener`**——WSS 在节点端永远表现为明文 WS（TLS 已被反代终止）。

`ForwarderManager::apply_config` 扩展：

```rust
// lc.entry_transport 已经是面板派生后的 node_entry_transport
match (lc.protocol, lc.entry_transport) {
    (Protocol::Tcp, EntryTransport::Raw) => spawn(start_tcp_listener(...)),  // 【当前】
    (Protocol::Udp, EntryTransport::Raw) => spawn(start_udp_listener(...)),  // 【当前】
    (Protocol::Tcp, EntryTransport::Ws)  => spawn(start_ws_listener(...)),   // 【v0.3.0-alpha】明文 WS
    (Protocol::Tcp, EntryTransport::Tls) => spawn(start_tls_listener(...)),  // 【v0.3.0-rc 实验】节点自处理 TLS
    // 注意：EntryTransport::Wss 永远不会出现在节点端
    //       面板已把 public=wss 派生为 node=ws（经反代）或 node=tls（自处理）
    (Protocol::Udp, non-Raw) => warn!("skip: UDP only supports raw transport"),
    _ => warn!("skip: unknown combination"),
}
```

每种 listener 是独立 tokio 任务，互不阻塞。

### 8.2 ws listener 如何把 WebSocket stream 转为 AsyncRead/AsyncWrite 【v0.3.0】

**说明**：节点端只有 `start_ws_listener`（明文 WS）。WSS 经反代时，节点端跑的就是这个 listener；节点自处理 TLS（v0.3.0-rc 实验）时，外层套 `tokio-rustls`，内层仍是这个 WS handler。**节点代码不存在独立的 `start_wss_listener`。**

`tokio-tungstenite` 已经集成：

```rust
use tokio_tungstenite::accept_async;
use futures_util::{StreamExt, SinkExt};

async fn handle_ws_session(stream: TcpStream, targets: Vec<String>, counter: Arc<TrafficCounter>) {
    let ws = accept_async(stream).await?;
    let (mut sink, mut stream_rx) = ws.split();

    // 第一个入站帧通常是 HTTP 风格的 path/host，验证是否匹配 ws_path/ws_host
    // 之后所有帧都是 binary 或 text，封装成 AsyncRead/AsyncWrite

    // 简化方案：用 tokio_util::io::StreamReader 把 stream 包装成 AsyncRead
    // 用 tokio_util::io::SinkWriter 把 sink 包装成 AsyncWrite
    // 然后走标准的 bidirectional io::copy

    let (read_half, write_half) = tokio::io::split(stream_to_async_read(stream_rx));
    let (read_for_target, write_for_target) = tokio::io::split(sink_to_async_write(sink));

    // 与现有 TCP 路径完全相同：spawn 两个 io::copy 任务，统计流量
}
```

**关键点**：将 WebSocket 帧透明转换为 AsyncRead/AsyncWrite 后，**复用现有 TCP 转发逻辑**，零代码重复。

### 8.3 TLS listener 使用 rustls 还是 native-tls 【v0.3.0】

✅ **优先 `rustls`**，项目已经全栈使用 rustls（`reqwest = { features = ["rustls-tls"] }`）。

依赖添加：

```toml
# crates/node/Cargo.toml
[dependencies]
rustls = "0.23"
rustls-pemfile = "2"
tokio-rustls = "0.26"
```

**为什么不用 native-tls**：
- 节点二进制已 musl 静态编译，引入 OpenSSL 会破坏静态链接。
- rustls 内存安全（无心脏出血类漏洞）。
- rustls 性能与 OpenSSL 相当甚至更优。
- 团队已熟悉 rustls API（reqwest/tokio-tungstenite 都用）。

### 8.4 面板断开时节点是否继续保持已有规则转发 【当前 + v0.3.0】

✅ **保持**。节点启动时缓存配置到 `config-cache.json`，面板不可达时继续按缓存转发。

新增需求：

- 缓存文件**加密**（v0.3.0 安全增强）：用 token 派生 key，节点重启不暴露配置。
- 缓存文件**版本号**：避免 reload 旧版本协议字段。
- 缓存**自动过期**：默认 7 天未联系面板则停止转发（避免节点跑野）。

### 8.5 多规则、多端口、多协议时如何避免 CPU/内存明显增长 【v0.3.0】

策略：

| 措施 | 说明 |
|------|------|
| 共享 Tokio runtime | 【当前】已有 |
| `accept` 任务与业务任务分离 | 【当前】已有 |
| `HashMap` key 用 `(port, protocol, transport)` 复合 | 【v0.3.0】直接扩展 |
| 共享 `TrafficCounter` | 【当前】已有，原子操作 |
| 共享 `ConnectionTracker` | 【当前】已有 |
| WS 帧分片大小限制 | 【v0.3.0】默认 16KB/帧，防止恶意大包 |
| TLS session cache 上限 | 【v0.3.0-rc】rustls 默认 32 个 session，超出自动 LRU |
| 每个规则的 WS 连接上限 | 【v0.3.0】可选 `max_clients_per_rule`，超限拒绝 |
| `SO_REUSEPORT` 多 worker | 【可选后续优化】当前节点单 listener 单 worker；多核高并发场景可后续引入 SO_REUSEPORT 让多 worker 共享 accept，**不属于当前已实现能力** |

### 8.6 1000 条规则启动性能如何保持轻量 【v0.3.0】

实测目标（生产环境 4C/4G 机器）：

| 指标 | 目标 |
|------|------|
| 启动时间（1000 规则） | < 5 秒 |
| 启动 RSS | < 200 MB |
| 持续运行时 RSS | < 500 MB（含 10000 并发连接预留） |
| 单规则内存开销 | < 50 KB（仅 listener handle + 缓存） |

实现保证：

1. **listener 按需 spawn**：仅 `node_entry_transport != Raw` 的规则走额外路径（WS/TLS），TCP/UDP 规则启动路径不变。WSS 经反代的规则在节点端表现为 `node_entry_transport = ws`，复用 WS listener。
2. **零拷贝 WS**：用 `bytes::Bytes` 共享帧 buffer。
3. **batched apply_config**：1000 条规则变更合并成一次 `apply_config` 调用，set-diff 用 `HashSet` 而不是 `Vec`。
4. **证书懒加载**：SNI 多域名场景下，按需加载证书到内存。
5. **预创建连接池**：TLS 模式下按目标地址预创建 session，避免首次握手阻塞。

---

## 9. 前端交互设计

### 9.1 关键原则

1. **默认中文**：`zh-CN.ts` 为 canonical 字典源（与现有约定一致）。
2. **英文仅作为 UI 翻译层**：`en-US.ts` 镜像翻译，所有新键先在 `zh-CN.ts` 定义。
3. **文档不要混入无意义英文**：本文档本身遵循此原则，仅 UI 标签可英文。
4. **表单渐进式展开**：默认仅显示 TCP/UDP 必填字段，WS/WSS/TLS 才展开高级字段。

### 9.2 字段动态显示策略

> 以下"入口协议"指用户在 UI 选择的 `public_entry_transport`（对外协议）。节点实际监听的 `node_entry_transport` 由面板派生，UI 不直接暴露。

| 入口协议（public） | 显示字段 | 隐藏字段 |
|----------|----------|----------|
| TCP | `listen_port` / `target_addr` / `target_port` | WS/TLS 全部 |
| UDP | 同上 | 同上 |
| TCP+UDP | 同上 | 同上 |
| WS | + `ws_path` / `ws_host` / `domain` | TLS 证书 |
| WSS（经反代，推荐） | + `ws_path` / `ws_host` / `domain` / `sni` | TLS 证书（节点不处理 TLS） |
| WSS（节点自处理，实验） | + `ws_path` / `ws_host` / `domain` / `sni` / `cert_id` | — |
| TLS（节点自处理，实验） | + `domain` / `sni` / `cert_id` | WS 路径 |

### 9.3 协议切换 UX

> `entryProtocol` 是 UI 层的 public 选择；持久化到 DB 的 `entry_transport` 也是 public 语义。节点端 `node_entry_transport` 由面板在下发时派生，前端不关心。

```tsx
const [entryProtocol, setEntryProtocol] = useState<'tcp' | 'udp' | 'tcp_udp' | 'ws' | 'wss' | 'tls'>('tcp');

// 切换协议时自动重置不兼容字段
useEffect(() => {
  if (isUdp(entryProtocol) && !isRaw(form.getFieldValue('entry_transport'))) {
    form.setFieldsValue({ entry_transport: 'raw' });
  }
  if (needsWebSocket(entryProtocol)) {
    form.setFieldsValue({ entry_transport: entryProtocol });  // ws/wss → entry_transport 一致
  }
}, [entryProtocol]);
```

### 9.4 新增 i18n key（仅中文示例）

`frontend/src/i18n/zh-CN.ts` 增量：

```typescript
// 协议
protocolTcp: 'TCP',
protocolUdp: 'UDP',
protocolTcpUdp: 'TCP + UDP',
protocolWs: 'WebSocket',
protocolWss: 'WebSocket (TLS)',
protocolTls: 'TLS',

// 转发模式
modeDirect: '入口直连目标',
modeGroup: '通过出口分组',
modeChain: '链式出口',

// 隧道
tunnelTransport: '隧道传输',
tunnelDirect: '直接转发',
tunnelWs: 'WebSocket',
tunnelWss: 'WebSocket (TLS)',
tunnelTls: 'TLS 隧道',
tunnelChain: '链式隧道',
tunnelWsPath: 'WS 路径',
tunnelHostHeader: 'Host 头',
tunnelSni: 'SNI',
tunnelCert: '证书',

// 分组能力
capabilityTcp: 'TCP',
capabilityUdp: 'UDP',
capabilityWs: 'WebSocket',
capabilityWss: 'WebSocket (TLS)',
capabilityTls: 'TLS',

// 提示
warnIncompatibleProtocol: '当前入口分组不支持该协议',
warnUdpRequiresRaw: 'UDP 模式仅支持直接转发',
warnTlsCertMissing: '请选择或上传证书',
hintWsNeedsReverseProxy: 'WSS 建议通过 Caddy/Nginx 反代转发，relay-node 不直接处理 TLS',
```

---

## 10. 部署和文档影响

### 10.1 需更新的文档清单

| 文档 | 内容更新 | 优先级 |
|------|----------|--------|
| `README.md` | 架构图新增"业务流量 WS/WSS"分支；feature 列表加入 v0.3.0 新增项 | 高 |
| `README.zh-CN.md` | 同上 | 高 |
| `docs/DEPLOYMENT.md` | 新增"Caddy/Nginx 反代 WSS"章节；DEPLOYMENT.md 需 v0.3.0-rc 同步 | 高 |
| `docs/TLS_WS_WSS_DESIGN.md` | 本文档 | 高 |
| `docs/REVERSE_PROXY.md` 【v0.3.0 新增】 | 专门的反代配置文档（Caddy/Nginx/Cloudflare 示例） | 高 |
| `docs/VERSIONS.md` | 加入 v0.3.0 版本同步点（新增 `crates/panel/src/api/tunnel_profiles.rs` 的硬编码版本号等） | 中 |
| `docs/NODE.md` / `docs/NODE.zh-CN.md` | 节点端增加 WS/WSS/TLS listener 说明；新增环境变量 `NODE_TLS_CERT` / `NODE_TLS_KEY` | 中 |
| `CHANGELOG.md` | v0.3.0 发布时新增条目 | 中 |

### 10.2 节点一键对接命令更新

`scripts/relay-node-install.sh` 增加：

```bash
# WSS / TLS 相关环境变量
NODE_TLS_CERT="/etc/relay-node/cert.pem"
NODE_TLS_KEY="/etc/relay-node/key.pem"
NODE_TLS_ONLY="0"  # 1 = 仅监听 TLS，不接受明文 WS
```

模板 systemd unit `/opt/relay-node/start.sh`：

```bash
#!/bin/bash
export PANEL_URL="${PANEL_URL}"
export NODE_TOKEN="${NODE_TOKEN}"
# WSS/TLS 可选
[ -n "${NODE_TLS_CERT}" ] && export NODE_TLS_CERT
[ -n "${NODE_TLS_KEY}" ] && export NODE_TLS_KEY
exec /opt/relay-node/relay-node
```

### 10.3 Docker Compose 示例更新

`docker-compose.release.yaml`（v0.3.0 起）。镜像名遵循项目发布规范：`relay-panel-panel`（面板）和 `relay-panel-node`（节点）：

```yaml
services:
  panel:
    image: ghcr.io/aict666/relay-panel-panel:0.3.0
    ports:
      - "18888:18888"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - PANEL_KEY=${PANEL_KEY}
    volumes:
      - panel-data:/data

  caddy:
    image: caddy:2-alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    depends_on:
      - panel

  node:
    image: ghcr.io/aict666/relay-panel-node:0.3.0
    environment:
      - PANEL_URL=http://panel:18888
      - NODE_TOKEN=${NODE_TOKEN}
      # 可选：节点自处理 TLS（v0.3.0-rc 实验模式）
      # - NODE_TLS_CERT=/etc/ssl/cert.pem
      # - NODE_TLS_KEY=/etc/ssl/key.pem
    depends_on:
      - panel

volumes:
  panel-data:
  caddy-data:
  caddy-config:
```

> **镜像命名约定**：GHCR 镜像统一以 `relay-panel-` 为前缀（仓库归属），后缀区分服务类型：
> - `ghcr.io/aict666/relay-panel-panel:<version>` — 面板
> - `ghcr.io/aict666/relay-panel-node:<version>` — 转发节点
>
> 与 `docker-compose.release.yaml`、`.github/workflows/docker-release.yml`、`docs/VERSIONS.md` 保持一致。

> **Caddy 镜像选择**：v0.3.0 基础方案默认使用 `caddy:2-alpine`：
> - 体积更小（~40MB vs ~150MB），适合作为基础示例。
> - 足够满足普通反代和自动 HTTPS（HTTP-01 验证、Let's Encrypt 自动续期）。
> - **DNS 插件例外**：如果用户需要 Cloudflare DNS-01、DNSPod、AliDNS 等 DNS 验证方式（用于泛域名、纯内网签发等场景），`caddy:2-alpine` 官方镜像**不包含**这些插件，需要使用自定义 Caddy 镜像（如 `caddy:builder` 自行编译，或使用 `caddy-dns/cloudflare` 等带插件的第三方镜像）。**这属于高级方案，不在 v0.3.0 基础方案范围内**，留待 `docs/REVERSE_PROXY.md` 后续补充，或 v0.4.0+ 面板内置 ACME 时统一处理。**待确认项见 §13.2 Q9**。

### 10.4 Caddy / Nginx 示例

见 §7.3 和 §7.4，将迁入 `docs/REVERSE_PROXY.md`。

---

## 11. 测试计划

### 11.1 单元测试

| 测试 | 范围 |
|------|------|
| 协议组合校验 | `protocol=tcp` + `entry_transport=ws` 接受；`protocol=udp` + `entry_transport=ws` 拒绝 |
| **public→node 派生** | `public=wss` + 经反代 → 下发 `node=ws`；`public=wss` + 自处理 → 下发 `node=tls`；`public=tcp` → 下发 `node=raw` |
| **节点端永不见 Wss** | 构造 `ListenerConfig.entry_transport=Wss` 喂给节点 manager，应 warning 跳过（防御性） |
| 字段默认值 | 新建规则不带 `tunnel_profile_id` → fallback `direct` |
| 旧规则映射 | `forward_mode='direct'` 旧规则加载行为不变 |
| Capabilities 校验 | `group_type='in'` + `capabilities=['tcp']` + 规则 `entry_transport='ws'` → 创建失败 |
| Migration 幂等 | 5-15 号迁移各跑两次，第二次应 no-op |
| **build_config_snapshot 修复** | 规则 `entry_transport='ws'` 时，WS 控制通道初始快照应携带 `Ws`（不再是硬编码 `Raw`） |

### 11.2 集成测试

| 场景 | 步骤 | 期望 |
|------|------|------|
| TCP 回归 | 现有 e2e 测试 | 全部通过 |
| UDP 回归 | 现有 e2e 测试 | 全部通过 |
| TCP+UDP 同端口回归 | 现有 e2e 测试 | 全部通过 |
| WS 明文转发 | `wscat` → `localhost:18888/relay` → 目标 HTTP server | 收到 WS 帧 |
| WSS 经 Caddy 反代 | `wscat -c wss://localhost/relay` → Caddy → relay-node WS | 收到 WS 帧，证书由 Caddy 管理 |
| WSS 经 Nginx 反代 | 同上，Nginx 路径 | 收到 WS 帧 |
| TLS passthrough | `openssl s_client` 直连 relay-node TLS listener | 握手成功，原始字节流到目标 |
| TLS terminate | `openssl s_client` → relay-node → 目标 | relay-node 终止 TLS，明文到目标 |
| 证书错误场景 | 节点配错证书，PEM 不匹配 | 节点启动失败，错误信息明确 |
| WebSocket 断线重连 | 客户端断 60 秒后重连 | relay-node session 自动清理，重连成功 |
| 节点能力上报 | 旧节点（不支持 ws）vs 新节点 | 面板跳过 ws 规则不下发给旧节点 |

### 11.3 性能测试

| 场景 | 目标 |
|------|------|
| 100 条规则启动 | < 2 秒 |
| 500 条规则启动 | < 3 秒 |
| 1000 条规则启动 | < 5 秒 |
| 1000 条规则空闲 RSS | < 200 MB |
| 1000 并发 WS 连接 | 持续 10 分钟无内存泄漏 |
| 10000 并发 WS 连接（压测） | 内存 < 2GB，CPU < 80% |

### 11.4 部署验证

| 平台 | 验证项 |
|------|--------|
| Debian 12 | Docker Compose + Caddy 一键部署通过 |
| Ubuntu 22.04 | 同上 |
| Cloudflare 中转 | WSS 经 Cloudflare → Caddy → relay-node |
| 节点 NAT 后部署 | relay-node 在内网，Caddy 反代，零端口暴露 |

---

## 12. 分阶段建议

### 12.1 v0.3.0-alpha：产品模型 + UI 原型 + WS 明文

**目标**：让用户能用明文 WS 入口转发，UI/数据模型全部到位。

| 范围 | 内容 |
|------|------|
| **前置修复** | **修复 `crates/panel/src/api/ws.rs::build_config_snapshot` 硬编码 `EntryTransport::Raw` 的 bug**，改为从 `rule.entry_transport` 读取真实值（与 `node.rs::get_config` 一致）。**必须在放开非 raw entry_transport 之前完成**，否则首次 WS 控制通道推送会下发错误协议。 |
| 数据 | Migration 5-15 全部完成 |
| 前端 | 转发规则分步表单；隧道配置页面；分组 capabilities 字段 |
| 后端 | panel：放宽 entry_transport 接受 `ws`；relay-node：实现 WS listener（明文，`node_entry_transport = ws`） |
| 文档 | 本设计文档定稿；CHANGELOG alpha 条目 |

**不包含**：WSS、TLS、证书管理、节点能力上报。

### 12.2 v0.3.0-beta：WSS 经反代

**目标**：让用户能用 WSS，TLS 由 Caddy/Nginx 终止。**节点端仍只跑明文 WS，不引入 TLS listener。**

| 范围 | 内容 |
|------|------|
| 面板 | 实现 public→node 派生：`public_entry_transport=wss` + 经反代 → 下发 `node_entry_transport=ws`（节点端无感知 WSS） |
| 节点 | **复用 alpha 的 WS listener，无新代码**；WSS 经反代走明文 WS 路径 |
| 文档 | `docs/REVERSE_PROXY.md` 完整发布；Caddyfile/Nginx 示例 |
| Docker | `docker-compose.release.yaml` 加入 Caddy 服务 |
| 测试 | WSS 经 Caddy/Nginx 集成测试通过 |

**不包含**：节点内置 TLS terminate/passthrough（即 `node_entry_transport=tls`）。

### 12.3 v0.3.0-rc：节点自处理 TLS（实验）

**目标**：让高级用户可以脱离反代直接用 TLS（`node_entry_transport = tls`）。**这是实验模式，非 v0.3.0 推荐路径。**

| 范围 | 内容 |
|------|------|
| 面板 | public→node 派生增加：`public=wss` 不经反代 / `public=tls` → 下发 `node_entry_transport=tls` |
| 节点 | 实现 TLS listener（rustls）；证书路径 env；SNI 支持 |
| 文档 | NODE.md 新增 TLS 部署章节 |
| 测试 | 证书错误场景、断线重连、SNI 多域名 |

**不包含**：面板内置 ACME 自动证书。

### 12.4 v0.3.0：稳定版

**目标**：生产可用。

| 范围 | 内容 |
|------|------|
| 全量测试 | 11.1-11.4 全部通过 |
| 性能 | 1000 规则 / 10000 并发 WS 达标 |
| 文档 | README / DEPLOYMENT / NODE / CHANGELOG 全部同步 |
| 发布 | GitHub Release + Docker GHCR |

### 12.5 后续版本（v0.4.0+）

| 版本 | 内容 |
|------|------|
| v0.4.0 | 面板内置 ACME 自动证书管理（HTTP-01） |
| v0.4.0 | `certificates` 表引入；cert_id 字段激活 |
| v0.5.0 | DNS-01 验证（Cloudflare/AliDNS/DNSPod 插件） |
| v0.5.0 | 节点能力上报（StatusReport.node_capabilities） |
| v0.6.0 | 链式出口高级路由（多出口负载均衡、健康检查） |

---

## 13. 风险与待确认问题

### 13.1 风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| 反代成为单点 | Caddy 宕机 → WSS 不可用 | 文档建议多反代 + DNS 轮询 |
| 旧节点 WS 兼容性 | 节点升级 WS 必须 atomic swap 二进制 | `install.sh` 已实现 stop→swap→start |
| 1000 规则 set-diff 性能 | 大集群启动慢 | 后续按 group_id 分片拉取配置 |
| 反代超时切断长连接 | 1 小时超时不够某些场景 | 文档标注反代超时 ≥ 1h |

### 13.2 ❓ 需要用户确认的问题

| # | 问题 | 建议答案 |
|---|------|----------|
| Q1 | 内置 tunnel_profiles 是否允许用户编辑 `is_builtin=1` 的模板？ | 建议：不允许，只读 + 复制为新模板 |
| Q2 | WSS 是否支持同时绑定多个域名（SNI 多租户）？ | 建议：v0.3.0-rc 起支持，每规则一个 SNI；v0.4.0 升级为节点级多证书 |
| Q3 | 用户上传证书时是否校验私钥匹配、公钥格式？ | 建议：上传时 strict 校验；过期前 30 天 dashboard 警告 |
| Q4 | relay-node 是否需要内置 `/health` HTTP 端点？ | 建议：v0.3.0-alpha 可选实现。**当前设计文档阶段默认不依赖 relay-node `/health`**，Caddy/Nginx 示例使用反代自身 `respond "ok" 200` 占位。若 v0.3.0-alpha 实现了 `/health`，反代可改为 `reverse_proxy` 到节点做真实健康检查；若未实现，保持反代自身占位即可。 |
| Q5 | `protocol` 字段是否在 v0.4.0 移除，统一用 `entry_transport` 表达？ | 建议：保留到 v0.5.0 再评估 |
| Q6 | 是否在 v0.3.0 引入规则级"带宽限速"（`speed_limit`）实际生效？ | 建议：v0.3.0 不实现，v0.4.0 加令牌桶 |
| Q7 | 是否在 v0.3.0 引入"按用户限速"在节点端生效？ | 建议：v0.3.0 不实现，节点端统计上报 |
| Q8 | 中文 UI 与英文 UI 哪个是 canonical？ | 现状：中文为 canonical（已有约定），本文档遵循 |
| Q9 | 是否提供 DNS 插件版 Caddy 镜像（Cloudflare / AliDNS / DNSPod DNS-01）？ | 建议：v0.3.0 基础示例使用 `caddy:2-alpine`（仅支持 HTTP-01，体积小）。**DNS-01 插件需要自定义 Caddy 镜像**（`caddy:builder` 自编译或 `caddy-dns/cloudflare` 等第三方镜像），留待 `docs/REVERSE_PROXY.md` 高级章节或 v0.4.0+ 面板内置 ACME 时统一处理。当前不在 v0.3.0 基础方案范围内。详见 §10.3。 |

### 13.3 已决策项回顾

| # | 决策 | 依据 |
|---|------|------|
| D1 | 保留统一 `device_groups` 表，通过 `group_type` 字段区分角色；**字段名不重命名为 `role`** | 用户已确认 |
| D2 | 新增独立 `tunnel_profiles` 表 | 用户已确认 |
| D3 | 优先 rustls 而非 native-tls | 节点已 musl 静态编译 |
| D4 | TLS 终止首选反代方案 | 节点保持轻量 |
| D5 | 文档中文为主，英文仅 UI 翻译 | 用户约定 |
| D6 | v0.3.0 不实现 ACME | 复杂度高，留后续版本 |

---

## 14. 最终推荐信息架构（TL;DR）

### 14.1 最终模型概览

```
device_groups（统一表，字段名 group_type 不重命名为 role）
  ├─ group_type = 'in'           → 入口分组，含 capabilities + port_range
  ├─ group_type = 'out'          → 出口分组，含 region + line_type
  ├─ group_type = 'monitor'      → 仅监控
  └─ group_type = 'chained_outbound' → 链式出口占位

tunnel_profiles（新表）
  └─ transport: direct / ws / wss / tls / chain + 可选 ws_path/host/sni

forward_rules
  ├─ device_group_in         → 入口分组
  ├─ protocol                → L4 类型：tcp / udp / tcp_udp
  ├─ entry_transport         → 用户对外协议（public 语义）：raw / ws / wss / tls
  ├─ forward_mode            → direct / group / chain
  ├─ device_group_out        → 出口分组（group/chain 模式必填）
  ├─ tunnel_profile_id       → 入口到出口的隧道（chain 模式必填）
  ├─ target_addr + target_port
  └─ uid                     → 用户归属
```

### 14.2 两层入口协议（务必区分）

| 层 | 字段 | 取值 | 谁使用 |
|----|------|------|--------|
| **外部展示协议** | `public_entry_transport`（DB 存 `entry_transport`） | `tcp` / `udp` / `tcp_udp` / `tls` / `ws` / `wss` | 用户在 UI 选择；面板持久化 |
| **节点实际监听协议** | `node_entry_transport`（下发到 `ListenerConfig.entry_transport`） | `raw` / `ws` / `tls` | 面板派生；relay-node 实际 bind |

**派生规则**（面板下发时执行）：

| 用户选择（public） | 经反代？ | 节点监听（node） | 说明 |
|--------------------|----------|-------------------|------|
| `tcp` | 否 | `raw` | 裸 TCP |
| `udp` | 否 | `raw` | 裸 UDP |
| `tcp_udp` | 否 | `raw`（展开 Tcp+Udp） | 同端口双栈 |
| `ws` | 否 | `ws` | 明文 WS |
| `wss` | **是**（v0.3.0-beta 推荐） | **`ws`** | 反代终止 TLS，节点跑明文 WS |
| `wss` | 否（v0.3.0-rc 实验） | `tls` | 节点自处理 TLS |
| `tls` | 否（v0.3.0-rc 实验） | `tls` | 节点自处理 TLS |

### 14.3 关键不变量（实现时必须遵守）

1. **`tcp_udp` 只属于 `protocol`**，永远不会出现在 `entry_transport`。
2. **节点端永远不存在 `EntryTransport::Wss`**：面板已把 public=wss 派生为 node=ws（经反代）或 node=tls（自处理）。
3. **节点代码不存在 `start_wss_listener`**：WSS 在节点端表现为明文 WS listener。
4. **`group_type` 字段名不重命名为 `role`**：UI 可显示"角色"，但 schema 字段保持 `group_type`。
5. **旧规则零迁移**：`protocol='tcp', entry_transport='raw'` 直接映射到 UI "TCP"。

### 14.4 入站流量链路

```
客户端 ─(public_entry_transport)─► [可选反代层终止 TLS] ─► 入口节点(node_entry_transport)
        │                                                   │
        │                                                   └─(tunnel_profile)─► 出口节点 ─► target_addr:target_port
```

**v0.3.0 推荐链路示例（WSS 经 Caddy 反代）**：
```
客户端 ─(wss)─► Caddy 终止 TLS ─► relay-node(ws listener) ─(direct)─► target_addr:target_port
  public=wss        反代自管证书        node=ws                  无隧道，直连目标
```

**原则**：
- 分组只承担**网络位置**角色，不绑协议。
- 规则承担**协议选择**和**流量路由**。
- 隧道只描述**节点之间**的传输方式，与用户访问协议解耦。
- **用户看到的协议（public）和节点监听的协议（node）是两件事**，面板负责派生，节点只认 node 层。
- 所有新字段都有旧字段映射，零迁移成本。