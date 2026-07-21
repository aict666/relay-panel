# Changelog — relay-node

All notable changes to the **relay-node** binary are documented here. This is a
SEPARATE changelog from `CHANGELOG.md` (which covers the panel + cross-cutting
features): panel and node release on independent version tracks (`node-vX.Y.Z`
tags vs panel `vX.Y.Z` tags), so each has its own history. A node release's
GitHub Release body is extracted from this file by
`scripts/extract-changelog.sh <version> CHANGELOG-NODE.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased]

## [1.3.7] - 2026-07-21

### Added

- 公共 TCP 入口可尽力识别并阻断标准 HTTP/1 请求行及 HTTP/2 明文前言；分片、
  超时、不完整或不匹配的首行按 fail-open 原样回放，并独立上报 HTTP 拦截计数。

### Compatibility

- 配置协议升级到 v11；面板与节点必须协调升级后再启用 HTTP 屏蔽。

## [1.3.6] - 2026-07-21

### Fixed

- 补齐 Linux 专属 TCP Fast Open 回归测试调用中的 TLS 屏蔽开关参数，确保节点
  发布提交通过 Linux 测试编译门禁；节点运行时与配置协议 v10 保持不变。

### Compatibility

- 需要 RelayPanel **1.3.7+**，推荐与 RelayPanel **1.3.8** 一同部署。

## [1.3.5] - 2026-07-21

### Added

- **配置协议 v10 支持公共入口 TLS 屏蔽。** 节点尽力识别原始 TCP 连接开头的
  TLS ClientHello；命中时不拨目标，未命中、超时、数据不足或读取失败时完整
  回放暂存字节并继续转发。
- 节点按协议累计被阻断连接数并上报状态，限频日志包含规则、客户端和累计数量。

### Fixed

- 带入口屏蔽策略的离线配置缓存改为协议绑定格式；将节点降级到旧协议版本时，旧
  二进制无法忽略 v10 字段并从磁盘恢复未过滤监听。无策略缓存仍保留兼容格式。
- 协议检测暂存数据继续参与上传限速和流量统计，Linux 后续流量仍使用
  `splice`，TCP Fast Open 也使用暂存首包作判断。
- 分阶段路由同时改变监听键和入口策略时，旧监听代际会先按新策略重建，不会让
  新端口或新传输方式提前接收流量。

### Compatibility

- 需要 RelayPanel **1.3.7+**。面板与节点必须同时使用配置协议 v10；启用入口
  屏蔽策略时，旧节点会收到并持久化空配置以安全停止监听。

### Tests

- 增加 TLS 1.0–1.3、分片、超时、fail-open、计费/限速/TFO、策略热更新与
  跨端口 staged route 回归测试。

## [1.3.4] - 2026-07-21

### Changed

- **Maintenance rebuild against the current shared protocol models.** The node
  package is refreshed alongside RelayPanel 1.3.6 so operators can roll every
  deployed component to a single reviewed release baseline.

### Compatibility

- The forwarding configuration protocol remains version 9. RelayPanel 1.3.6
  and relay-node 1.3.4 are mutually compatible; no route migration is required.

### Tests

- Revalidated the complete workspace, node command-line contract, configuration
  manager, TCP/UDP forwarding, staged transitions, and release installer gates.

## [1.3.3] - 2026-07-20

### Changed

- **Configuration protocol v9 adds staged route activation.** Replacement entry
  listeners and shared-tunnel routes can be distributed before traffic moves,
  eliminating the cross-node remove-before-add window during live path or port
  changes.

### Fixed

- **Old route generations drain without taking new traffic.** Ordinary entry
  listeners, shared routes, TCP streams, and UDP warm channels follow explicit
  staging, overlap, and drain markers, preserving unrelated rules on the same
  shared port.
- **Credential and administrative revocation wins over availability leases.**
  Token rotation, pause, tunnel disable/unshare, and explicit termination close
  stale generations immediately and never retain an invalid HMAC route.

### Compatibility

- Requires RelayPanel **1.3.4+**. Protocol-v9 panels and nodes must be upgraded
  together; mixed versions fail the configuration-version gate.

### Tests

- Added manager regressions for pre-staged entries, shared-route overlap,
  termination precedence, idle drain cleanup, and credential rotation during a
  transition.

## [1.3.2] - 2026-07-20

### Added

- **Configuration protocol v8 reusable-tunnel data plane.** Multiple TCP, UDP,
  and `tcp_udp` rules share one internal TCP listener per non-entry hop while
  remaining isolated by an authenticated tunnel/rule route header. TCP returns
  to the raw byte stream after setup; UDP keeps per-rule warm UOT channels on
  the same shared port.
- **One-way authenticated diagnosis.** A probe uses the same per-link HMAC
  protocol, traverses every configured hop, and asks only the exit to connect
  to a panel-controlled final target.

### Security

- Fixed-length headers cover tunnel id, rule id, mode, hop, timestamp, and a
  random nonce with HMAC-SHA256. Bounded replay caches, handshake deadlines,
  unauthenticated connection caps, and route-table checks reject stale,
  replayed, unknown, paused, or unbound traffic without accepting a caller
  supplied destination.
- Device-group token rotation immediately revokes both current and draining
  credential generations, including paths already removed from the latest
  configuration snapshot.

### Fixed

- Shared-listener hot updates preserve unrelated routes and selector state,
  while rule removal, restart, tunnel disablement, and credential revocation
  cancel only their intended connection generations.
- Retired entry streams keep reporting tail traffic until drained. Snapshot
  acknowledgements are bound to the original counter allocation, preventing a
  rapidly recreated rule id from losing bytes or producing an unsigned counter
  underflow.

### Compatibility

- Requires RelayPanel **1.3.3+**. Protocol-v8 nodes and panel must be upgraded
  together; older nodes are rejected by the configuration-version gate rather
  than applying an incomplete route.

### Tests

- Added two-rule TCP sharing, UDP plus `tcp_udp` shared-port isolation,
  authenticated three-hop probes, replay/HMAC failures, credential rotation,
  entry-drain, restart, and real socket round-trip regressions.

## [1.3.1] - 2026-07-19

### Fixed

- **UDP and UOT sessions are bounded and fully cancellable.** Native UDP and
  authenticated UOT enforce per-listener admission caps, release detached
  sockets/tasks on expiry or listener replacement, and prevent stale readers
  from deleting or delivering into replacement sessions.
- **UOT tunnels close on rule, token, or listener replacement.** Authenticated
  child connections now share the listener lifecycle, so an old tunnel cannot
  survive a hot configuration update with stale routing or credentials.
- **Cached node configuration is private and crash-safe.** Cache writes use a
  same-directory atomic rename with `0600` permissions and follow the actual
  custom service installation directory.
- **Node upgrades fail closed and roll back.** The installer requires a trusted
  checksum for mirrored binaries, safely handles custom service names/paths,
  verifies the installed version and stable MainPID, and restores the previous
  binary, scripts, unit file, active state, and enabled state after failure.

### Tests

- Added Linux installer rollback checks plus real two-hop and three-hop TCP,
  UDP-over-UOT, and mixed `tcp_udp` data-plane coverage.

## [1.3.0] - 2026-07-19

### Added

- **Authenticated UOT across every UDP inter-node hop.** Both UDP-only and
  `tcp_udp` multi-hop rules can reuse a framed TCP tunnel with a dedicated,
  persisted listener port. HMAC challenge-response proves knowledge of the
  derived tunnel key without sending that key over the network.
- **TCP Fast Open for chained TCP traffic.** Inter-node dials can send initial
  payload bytes in the SYN and fall back to normal TCP when TFO is unavailable.
- **Health-aware routing telemetry.** Active reachability/latency probes, DNS
  health, circuit-breaker state, connection counts, capacity pressure, and
  anomalous traffic signals drive the new target selection strategies.

### Changed

- **UOT and TCP Fast Open are enabled by default** and can be disabled
  independently through `RELAY_ENABLE_UOT=false` and
  `RELAY_ENABLE_TCP_0RTT=false`.
- **All TCP listener backlogs are 4096,** including the Fast Open queue.
- **Config protocol version is now 7;** use this node with panel 1.3.0 or newer.

### Fixed

- **UOT cancellation is frame-safe.** Cancelling one request cannot leave a
  partial frame for the next request to consume, and tunnel authentication has
  explicit time/capacity bounds.
- **Hot configuration changes preserve stable UOT ports** while safely
  replacing listeners whose routing or security fingerprint changed.

### Tests

- Added multi-hop UOT coverage for UDP and `tcp_udp`, challenge-response and
  malformed-frame regressions, and Linux-only TCP Fast Open tests that require
  observed SYN data on normal and `splice(2)` forwarding paths.

## [1.2.1] - 2026-07-18

### Fixed

- **Linux zero-copy forwarding failures are no longer reported as successful
  connections.** A failed `splice(2)` path is logged as a warning and returned
  to the connection task, making forwarding faults visible instead of silently
  completing the handler.
- **Zero-copy pipe descriptors are now close-on-exec.** Relay pipes use
  `O_CLOEXEC` in addition to non-blocking mode so descriptors cannot leak into
  a future child process.

### Tests

- Added production-path, two-hop TCP and UDP regression coverage, including
  fragmented full-duplex frames used by encrypted protocols, and an ignored
  Linux loopback benchmark comparing `splice(2)` with userspace copying.

## [1.2.0] - 2026-07-18

### Changed

- **Downloads and self-upgrade use `aict666/relay-panel` releases** (no longer
  MoeShinX). GHCR image: `ghcr.io/aict666/relay-panel-node`.

### Added

- **`ListenerConfig.count_traffic`.** Intermediate/exit hops of a multi-hop
  chain forward without adding bytes to the rule traffic counter (entry hop
  only). Config protocol version **5** — pair with panel ≥ 1.2.0.

### Added (carry-over)

- **`restart_rule` control message.** The panel can ask the node to drop one
  rule's connections and rebuild its listeners. The node re-creates listeners
  from its OWN cached config (`ForwarderManager::last_config`), never from
  anything in the message, so a restart cannot be used to inject listener
  config. `node_id` is re-checked on arrival as defence in depth even though
  `send_node` already routed it.

  The WS dispatch arm for this MUST stay above the diagnose arm and MUST check
  `type`: `DiagnoseRuleMessage` defaults its `challenge` field and ignores
  unknown fields, so a `restart_rule` payload deserializes into it cleanly
  (`rule_id` + `request_id` are both present). Ordered after diagnose, every
  restart would silently become a target probe instead. A test in
  `relay-shared` pins the ambiguity.

- **Per-rule concurrent TCP connection cap** (`ListenerConfig.max_connections`,
  None = unlimited). Admission happens in the accept loop, not in the spawned
  connection task: the accept loop is sequential, so check-then-increment there
  is exact, whereas incrementing inside the task would let an unbounded number
  of accepts through before the first increment landed — precisely the
  connection-flood case the cap exists for. Over the cap, the socket is dropped
  immediately (the "at cap" warning is rate-limited to once per 60s per
  listener; a rule sitting at its cap rejects on every accept, and an
  unthrottled warn would itself become the outage).

  The counter lives per RULE, not per listener: a dual-stack rule runs two
  accept loops (IPv4 + IPv6), and a per-listener counter would silently grant
  double the configured cap.

### Fixed

- **Aborting a listener no longer leaves its connections forwarding.**
  Connections run on detached `tokio::spawn` tasks, so an aborted accept loop
  stopped new accepts while every established connection kept relaying —
  verified: a post-abort read/write round-trips fine. Connections now select on
  a per-rule cancellation channel (`forwarder::gate`). Consequences:
  - an explicit `restart_rule` genuinely sheds connections rather than just
    re-binding the port;
  - a rule removed from the node's config now stops forwarding, instead of
    relaying bytes for a rule whose traffic counters `apply_config` already
    pruned.

  `apply_config`'s fingerprint-driven restart (changed targets / rate caps) does
  NOT cancel: editing a rule must not kick everyone off, which has been the
  behaviour since v0.3.6.

- **A UDP-only rule's restart is no longer a silent no-op.** `restart_rule`
  returned early when the rule had no `RuleRuntime` — but only the TCP arm of
  `apply_config` creates one (UDP has no `accept()` and no cancellable
  per-connection tasks), so a UDP-only rule has no runtime while very much
  having a listener. It was never torn down or rebuilt, and its sessions never
  dropped. The panel reports success as soon as the command reaches the node, so
  the operator was told the rule had restarted while nothing happened at all.
  "No runtime" now means only "no connections to cancel"; whether there are
  listeners to rebuild is decided separately.

### Compatibility

- Requires panel **1.2.0+** to be sent `restart_rule` or a connection cap. Both
  additions are backward compatible on the wire (`#[serde(default)]`), so a
  1.2.0 node runs against an older panel unchanged — it simply never receives
  either.

## [1.1.2] - 2026-07-12

### Fixed

- **UDP forwarding now follows DDNS target IP changes.** A UDP rule's domain
  target was resolved ONCE when the listener started (rule push / node boot) and
  the resolved IP was reused forever — so a DDNS target (WireGuard, game relay,
  DNS forwarding) that changed IP kept getting blackholed to the stale address
  until the rule or node was manually restarted. New UDP sessions now resolve
  through the shared 30s DNS cache (same as TCP), so an IP change is picked up
  within the cache TTL; established sessions age out on the 60s idle timeout and
  the next datagram opens a fresh session against the current IP. This also
  removes the old "unresolvable-at-boot kills the listener → restart loop"
  behavior — a transient DNS failure no longer tears down the UDP listener.

## [1.1.1] - 2026-07-08

### Fixed

- **File-descriptor exhaustion under connection churn.** Forwarded TCP sockets
  (both the accepted client side and the dialed target side) now enable TCP
  keepalive (idle 60s, 15s probes, 4 retries). Previously a peer that vanished
  without a FIN/RST — NAT rebind, mobile handoff, cable pull, a firewall that
  drops instead of resets — left the bidirectional copy blocked on `read()`
  forever, holding two fds; under churn these dead half-open connections
  accumulated until the node hit `EMFILE` ("Too many open files", os error 24),
  even at `LimitNOFILE=65536`. Keepalive lets the kernel reap dead peers so the
  copy task ends and releases its fds.
- **Low fd limit on non-systemd launches.** The node now raises its own
  `RLIMIT_NOFILE` soft limit toward the hard limit at startup, so a docker or
  manual (bash/nohup) launch — which inherits the 1024 default instead of the
  systemd unit's `LimitNOFILE=65536` — no longer exhausts descriptors under
  moderate load. The node Docker Compose service also sets `ulimits.nofile` to
  65536 to match.

---

## [1.1.0] - 2026-07-02

The node half of the **one-click remote upgrade** release. (Panel-side changes
for the same feature are in `CHANGELOG.md` under [1.1.0].)

### Added

- **Self-upgrade.** On receiving a directed `upgrade_node` command over the WS
  control channel, a systemd node downloads the official `relay-node` release
  for its architecture from the GitHub release, **verifies the published
  sha256**, backs up its current binary, atomically swaps, and exits so systemd
  restarts it. Safety:
  - **Upgrade-only:** the target must be a valid semver strictly newer than the
    running version, so a compromised panel can't force a downgrade.
  - **Install-aware:** only systemd nodes self-upgrade; docker nodes are told to
    update the image, and manual runs are disabled (nothing would restart them).
  - **Single-flight + mandatory backup:** repeated commands can't corrupt the
    binary, and a failed backup aborts the swap.
- Binaries continue to ship for both **amd64 and arm64** (static musl + rustls).

### Notes

- Assets for 1.1.0 and earlier were published under the joint `v*` tag (panel
  and node shared a release). From 1.1.1 onward, node binaries publish under the
  dedicated `node-v*` tag. The node's self-upgrade download logic falls back to
  the `v*` URL for versions ≤ 1.1.0 so existing 1.1.0 nodes can still reach the
  historical asset; newer versions use `node-v*` exclusively.

---

_The node has no code, forwarding, protocol, or dependency changes in this
round, so no newer `node-v*` version is cut. A node release is only tagged when
something node-side actually changed._
